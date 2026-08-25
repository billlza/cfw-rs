#!/usr/bin/env python3
"""Prove the fixed updater key can sign for the embedded updater trust root.

The production ``create`` path invokes only ``updater_signing_launcher.py`` to
acquire the Keychain password and use the encrypted private key.  This module
never opens either secret.  It retains only a non-secret challenge, signature,
the source-pinned embedded-public-key verifier receipts, and a canonical proof.

``verify-preflight`` and ``verify-frozen`` are pure evidence consumers: they
rebuild the source-pinned verifier and replay the public signature check without
accessing the updater private key or its Keychain password.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable, Final, Mapping, Sequence

if __package__:
    from .publication.bounded_process import BoundedProcessError, run_bounded_process
    from .publication.common import PublicationError, canonical_json
    from .publication.durable_file import (
        exclusive_rooted_directory_lock,
        publish_private_directory_locked,
        read_private_directory_contents,
    )
    from .release_build_identity import ACTIVE_RELEASE_IDENTITY, ga_preflight_root, ga_root
    from .repository_source_identity import SourceIdentityError, current_identity
else:
    from publication.bounded_process import BoundedProcessError, run_bounded_process
    from publication.common import PublicationError, canonical_json
    from publication.durable_file import (
        exclusive_rooted_directory_lock,
        publish_private_directory_locked,
        read_private_directory_contents,
    )
    from release_build_identity import ACTIVE_RELEASE_IDENTITY, ga_preflight_root, ga_root
    from repository_source_identity import SourceIdentityError, current_identity


CHALLENGE_DOCUMENT: Final = "cfm-updater-key-possession-challenge-v1"
PROOF_DOCUMENT: Final = "cfm-updater-key-possession-proof-v1"
EMBEDDED_VERIFICATION_DOCUMENT: Final = (
    "cfw-updater-embedded-pubkey-verification-v1"
)
SCHEMA_VERSION: Final = 1
RESULT_VERIFIED: Final = "verified"

PROOF_RELATIVE: Final = Path("profiles/updater-key-possession")
SIGNING_PREFLIGHT_RELATIVE: Final = Path("profiles/signing-preflight.json")
CHALLENGE_NAME: Final = "challenge.json"
SIGNATURE_NAME: Final = f"{CHALLENGE_NAME}.sig"
VERIFICATION_NAME: Final = "embedded-pubkey-verification.json"
VERIFIER_BINDING_NAME: Final = "release-verifier-binding.json"
PROOF_NAME: Final = "proof.json"
TEMPORARY_PREFIX: Final = ".updater-key-possession."
PROOF_FILES: Final = frozenset(
    {
        CHALLENGE_NAME,
        SIGNATURE_NAME,
        VERIFICATION_NAME,
        VERIFIER_BINDING_NAME,
        PROOF_NAME,
    }
)

SYSTEM_PATH: Final = "/usr/bin:/bin:/usr/sbin:/sbin"
MAX_CHALLENGE_BYTES: Final = 64 * 1024
MAX_SIGNATURE_BYTES: Final = 16 * 1024
MAX_VERIFICATION_BYTES: Final = 64 * 1024
MAX_VERIFIER_BINDING_BYTES: Final = 4 * 1024 * 1024
MAX_PROOF_BYTES: Final = 256 * 1024
MAX_TAURI_CONFIGURATION_BYTES: Final = 4 * 1024 * 1024
MAX_SIGNER_OUTPUT_BYTES: Final = 256 * 1024
SIGNER_TIMEOUT_SECONDS: Final = 600
SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE: Final = re.compile(r"^[0-9a-f]{40}$")
NONCE_RE: Final = re.compile(r"^[0-9a-f]{64}$")

SourceIdentityReader = Callable[[Path], dict[str, str]]
EmbeddedVerifier = Callable[[Path, Path, Path], tuple[dict[str, Any], dict[str, Any]]]
ProcessRunner = Callable[..., subprocess.CompletedProcess[bytes]]


class UpdaterKeyPossessionError(RuntimeError):
    """The updater-key possession proof is absent, unsafe, or invalid."""


@dataclass(frozen=True, slots=True)
class VerifiedUpdaterKeyPossession:
    root: Path
    proof_path: Path
    proof_sha256: str
    embedded_public_key_sha256: str
    tauri_config_sha256: str


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise UpdaterKeyPossessionError(
                f"updater possession JSON repeats field {key!r}"
            )
        value[key] = item
    return value


def _reject_constant(token: str) -> Any:
    raise UpdaterKeyPossessionError(
        f"updater possession JSON contains non-finite constant {token}"
    )


def _strict_json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except UpdaterKeyPossessionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise UpdaterKeyPossessionError(f"{label} is not strict JSON") from error
    if type(value) is not dict or canonical_json(value) != data:
        raise UpdaterKeyPossessionError(f"{label} is not one canonical JSON object")
    return value


def _require_exact_fields(
    value: object, expected: set[str] | frozenset[str], label: str
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(expected):
        raise UpdaterKeyPossessionError(f"{label} has an unexpected field set")
    return value


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise UpdaterKeyPossessionError(f"{label} is not a canonical SHA-256 digest")
    return value


def _canonical_repository(repository: Path) -> Path:
    repository = Path(repository)
    if not repository.is_absolute():
        raise UpdaterKeyPossessionError("repository path must be absolute")
    try:
        resolved = repository.resolve(strict=True)
        metadata = repository.lstat()
    except OSError as error:
        raise UpdaterKeyPossessionError("release repository is unavailable") from error
    if (
        resolved != repository
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise UpdaterKeyPossessionError(
            "release repository must be one canonical owned directory"
        )
    return repository


def _candidate_root(repository: Path, root: Path) -> Path:
    root = Path(root)
    expected = {ga_preflight_root(repository), ga_root(repository)}
    if root not in expected:
        raise UpdaterKeyPossessionError(
            "updater possession proof root is not a fixed GA candidate root"
        )
    try:
        resolved = root.resolve(strict=True)
        metadata = root.lstat()
    except OSError as error:
        raise UpdaterKeyPossessionError("fixed GA candidate root is unavailable") from error
    if (
        resolved != root
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise UpdaterKeyPossessionError(
            "fixed GA candidate root is not one canonical owned 0700 directory"
        )
    return root


def _read_regular(
    path: Path,
    *,
    maximum: int,
    exact_mode: int | None,
    label: str,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise UpdaterKeyPossessionError(f"{label} is unavailable") from error
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    try:
        if (
            identity(before) != identity(opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or (exact_mode is not None and stat.S_IMODE(opened.st_mode) != exact_mode)
            or opened.st_size < 1
            or opened.st_size > maximum
        ):
            raise UpdaterKeyPossessionError(f"{label} metadata is unsafe")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        rebound = path.stat(follow_symlinks=False)
        if (
            len(data) != opened.st_size
            or len(data) > maximum
            or identity(opened) != identity(after)
            or identity(opened) != identity(rebound)
        ):
            raise UpdaterKeyPossessionError(f"{label} changed while it was read")
        return data
    except OSError as error:
        raise UpdaterKeyPossessionError(f"cannot read {label}") from error
    finally:
        os.close(descriptor)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _record(name: str, data: bytes) -> dict[str, object]:
    return {"filename": name, "sha256": _sha256(data), "size": len(data)}


def _source_identity(
    repository: Path, reader: SourceIdentityReader
) -> dict[str, str]:
    try:
        observed = reader(repository)
    except (OSError, SourceIdentityError, ValueError) as error:
        raise UpdaterKeyPossessionError(
            "clean release source identity is unavailable"
        ) from error
    if (
        type(observed) is not dict
        or set(observed) != {"repositoryCommit", "releaseSourceSha256"}
        or not isinstance(observed["repositoryCommit"], str)
        or COMMIT_RE.fullmatch(observed["repositoryCommit"]) is None
        or not isinstance(observed["releaseSourceSha256"], str)
        or SHA256_RE.fullmatch(observed["releaseSourceSha256"]) is None
    ):
        raise UpdaterKeyPossessionError("release source identity is malformed")
    return {
        "release_source_sha256": observed["releaseSourceSha256"],
        "repository_commit": observed["repositoryCommit"],
    }


def _default_source_identity_reader(repository: Path) -> dict[str, str]:
    return current_identity(repository, require_clean=True)


def _signing_preflight(root: Path) -> tuple[Path, bytes, str]:
    path = root / SIGNING_PREFLIGHT_RELATIVE
    data = _read_regular(
        path,
        maximum=4 * 1024 * 1024,
        exact_mode=0o600,
        label="signing preflight manifest",
    )
    return path, data, _sha256(data)


def _tauri_configuration_sha256(repository: Path) -> str:
    data = _read_regular(
        repository / "apps/cfw-tauri-shell/tauri.conf.json",
        maximum=MAX_TAURI_CONFIGURATION_BYTES,
        exact_mode=None,
        label="Tauri updater configuration",
    )
    return _sha256(data)


def _challenge(
    *,
    nonce: bytes,
    source: Mapping[str, str],
    signing_preflight_sha256: str,
) -> bytes:
    if not isinstance(nonce, bytes) or len(nonce) != 32:
        raise UpdaterKeyPossessionError("challenge nonce source returned the wrong size")
    value = {
        "document": CHALLENGE_DOCUMENT,
        "nonce": nonce.hex(),
        "product": {
            "build_number": ACTIVE_RELEASE_IDENTITY.ga_build,
            "version": ACTIVE_RELEASE_IDENTITY.product_version,
        },
        "schema_version": SCHEMA_VERSION,
        "signing_preflight_sha256": signing_preflight_sha256,
        "source": dict(source),
    }
    return canonical_json(value)


def _write_new_private(path: Path, data: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short updater possession challenge write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_no_residual_temporaries(directory_descriptor: int) -> None:
    try:
        entries = os.listdir(directory_descriptor)
    except OSError as error:
        raise UpdaterKeyPossessionError(
            "cannot enumerate the locked GA profiles directory"
        ) from error
    if any(name.startswith(TEMPORARY_PREFIX) for name in entries):
        raise UpdaterKeyPossessionError(
            "a residual updater possession temporary directory requires review"
        )


def _run_production_signer(
    repository: Path,
    challenge: Path,
    *,
    process_runner: ProcessRunner = run_bounded_process,
) -> None:
    launcher = repository / "scripts/updater_signing_launcher.py"
    command = [
        sys.executable,
        "-I",
        "-S",
        "-B",
        "-W",
        "error",
        str(launcher),
        str(challenge),
    ]
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": SYSTEM_PATH,
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        result = process_runner(
            command,
            cwd=repository,
            environment=environment,
            timeout=SIGNER_TIMEOUT_SECONDS,
            output_limit=MAX_SIGNER_OUTPUT_BYTES,
        )
    except (OSError, BoundedProcessError) as error:
        raise UpdaterKeyPossessionError(
            "production updater signer did not complete inside its fixed boundary"
        ) from error
    if (
        not isinstance(result.stdout, bytes)
        or not isinstance(result.stderr, bytes)
        or result.returncode != 0
        or result.stderr
    ):
        raise UpdaterKeyPossessionError(
            "production updater signer failed or emitted diagnostics"
        )


def _release_artifact_verifier_module() -> Any:
    # The release-asset module also consumes the candidate-freeze result through
    # the notarization transaction.  Keep that higher-layer adapter out of this
    # module's import graph; the injected verifier protocol remains the actual
    # possession-proof boundary.
    if __package__:
        from . import release_artifact_set
    else:
        import release_artifact_set
    return release_artifact_set


def _produce_updater_verification(
    repository: Path, challenge: Path, signature: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    return _release_artifact_verifier_module()._produce_updater_verification(
        repository, challenge, signature
    )


def _validate_release_verifier_binding(
    value: dict[str, Any], repository: Path
) -> dict[str, Any]:
    return _release_artifact_verifier_module()._validate_release_verifier_binding(
        value, repository
    )


def _production_embedded_verifier(
    repository: Path, challenge: Path, signature: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    release_artifacts = _release_artifact_verifier_module()

    try:
        verification, binding = _produce_updater_verification(
            repository, challenge, signature
        )
        binding = _validate_release_verifier_binding(binding, repository)
    except (release_artifacts.ArtifactSetError, OSError, ValueError) as error:
        raise UpdaterKeyPossessionError(
            "source-pinned embedded updater-key verification failed"
        ) from error
    return verification, binding


def _validate_embedded_verification(
    value: object,
    *,
    challenge_record: Mapping[str, object],
    signature_record: Mapping[str, object],
    tauri_config_sha256: str,
) -> dict[str, Any]:
    document = _require_exact_fields(
        value,
        {
            "archive_filename",
            "archive_sha256",
            "archive_size",
            "document",
            "embedded_public_key_sha256",
            "result",
            "schema_version",
            "signature_filename",
            "signature_sha256",
            "signature_size",
            "tauri_config_sha256",
        },
        "embedded updater-key verification",
    )
    expected = {
        "archive_filename": challenge_record["filename"],
        "archive_sha256": challenge_record["sha256"],
        "archive_size": challenge_record["size"],
        "document": EMBEDDED_VERIFICATION_DOCUMENT,
        "result": RESULT_VERIFIED,
        "schema_version": SCHEMA_VERSION,
        "signature_filename": signature_record["filename"],
        "signature_sha256": signature_record["sha256"],
        "signature_size": signature_record["size"],
    }
    if any(document[name] != item for name, item in expected.items()):
        raise UpdaterKeyPossessionError(
            "embedded updater-key verification binds different challenge bytes"
        )
    _require_sha256(
        document["embedded_public_key_sha256"], "embedded updater public key"
    )
    if (
        _require_sha256(document["tauri_config_sha256"], "Tauri configuration")
        != tauri_config_sha256
    ):
        raise UpdaterKeyPossessionError(
            "embedded updater-key verification binds another Tauri configuration"
        )
    return document


def _proof_document(
    *,
    source: Mapping[str, str],
    signing_preflight_sha256: str,
    challenge: bytes,
    signature: bytes,
    verification: bytes,
    verifier_binding: bytes,
) -> dict[str, Any]:
    return {
        "challenge": _record(CHALLENGE_NAME, challenge),
        "document": PROOF_DOCUMENT,
        "embedded_verification": _record(VERIFICATION_NAME, verification),
        "product": {
            "build_number": ACTIVE_RELEASE_IDENTITY.ga_build,
            "version": ACTIVE_RELEASE_IDENTITY.product_version,
        },
        "release_verifier_binding": _record(
            VERIFIER_BINDING_NAME, verifier_binding
        ),
        "result": RESULT_VERIFIED,
        "schema_version": SCHEMA_VERSION,
        "signature": _record(SIGNATURE_NAME, signature),
        "signing_preflight_sha256": signing_preflight_sha256,
        "source": dict(source),
    }


def _validate_artifact_record(
    value: object, *, name: str, data: bytes, label: str
) -> None:
    record = _require_exact_fields(value, {"filename", "sha256", "size"}, label)
    if record != _record(name, data):
        raise UpdaterKeyPossessionError(f"{label} binds different bytes")


def _verify_documents(
    repository: Path,
    root: Path,
    files: Mapping[str, bytes],
    *,
    source_identity_reader: SourceIdentityReader,
    embedded_verifier: EmbeddedVerifier,
) -> VerifiedUpdaterKeyPossession:
    source = _source_identity(repository, source_identity_reader)
    _preflight_path, _preflight_data, preflight_sha256 = _signing_preflight(root)
    tauri_config_sha256 = _tauri_configuration_sha256(repository)
    challenge = _strict_json(files[CHALLENGE_NAME], "updater possession challenge")
    challenge = _require_exact_fields(
        challenge,
        {
            "document",
            "nonce",
            "product",
            "schema_version",
            "signing_preflight_sha256",
            "source",
        },
        "updater possession challenge",
    )
    if (
        challenge["document"] != CHALLENGE_DOCUMENT
        or type(challenge["schema_version"]) is not int
        or challenge["schema_version"] != SCHEMA_VERSION
        or not isinstance(challenge["nonce"], str)
        or NONCE_RE.fullmatch(challenge["nonce"]) is None
        or challenge["product"]
        != {
            "build_number": ACTIVE_RELEASE_IDENTITY.ga_build,
            "version": ACTIVE_RELEASE_IDENTITY.product_version,
        }
        or challenge["source"] != source
        or challenge["signing_preflight_sha256"] != preflight_sha256
    ):
        raise UpdaterKeyPossessionError(
            "updater possession challenge differs from the fixed GA inputs"
        )

    challenge_record = _record(CHALLENGE_NAME, files[CHALLENGE_NAME])
    signature_record = _record(SIGNATURE_NAME, files[SIGNATURE_NAME])
    try:
        fresh_verification, fresh_binding = embedded_verifier(
            repository,
            root / PROOF_RELATIVE / CHALLENGE_NAME,
            root / PROOF_RELATIVE / SIGNATURE_NAME,
        )
    except UpdaterKeyPossessionError:
        raise
    except (OSError, ValueError) as error:
        raise UpdaterKeyPossessionError(
            "source-pinned embedded updater-key verification failed"
        ) from error
    fresh_verification = _validate_embedded_verification(
        fresh_verification,
        challenge_record=challenge_record,
        signature_record=signature_record,
        tauri_config_sha256=tauri_config_sha256,
    )
    verification = _strict_json(
        files[VERIFICATION_NAME], "embedded updater-key verification receipt"
    )
    _validate_embedded_verification(
        verification,
        challenge_record=challenge_record,
        signature_record=signature_record,
        tauri_config_sha256=tauri_config_sha256,
    )
    if verification != fresh_verification:
        raise UpdaterKeyPossessionError(
            "stored embedded updater-key verification does not replay exactly"
        )
    binding = _strict_json(
        files[VERIFIER_BINDING_NAME], "release verifier binding"
    )
    if binding != fresh_binding:
        raise UpdaterKeyPossessionError(
            "stored source-pinned release verifier binding does not replay exactly"
        )

    proof = _strict_json(files[PROOF_NAME], "updater key possession proof")
    proof = _require_exact_fields(
        proof,
        {
            "challenge",
            "document",
            "embedded_verification",
            "product",
            "release_verifier_binding",
            "result",
            "schema_version",
            "signature",
            "signing_preflight_sha256",
            "source",
        },
        "updater key possession proof",
    )
    if (
        proof["document"] != PROOF_DOCUMENT
        or type(proof["schema_version"]) is not int
        or proof["schema_version"] != SCHEMA_VERSION
        or proof["result"] != RESULT_VERIFIED
        or proof["product"]
        != {
            "build_number": ACTIVE_RELEASE_IDENTITY.ga_build,
            "version": ACTIVE_RELEASE_IDENTITY.product_version,
        }
        or proof["source"] != source
        or proof["signing_preflight_sha256"] != preflight_sha256
    ):
        raise UpdaterKeyPossessionError(
            "updater key possession proof differs from the fixed GA inputs"
        )
    _validate_artifact_record(
        proof["challenge"],
        name=CHALLENGE_NAME,
        data=files[CHALLENGE_NAME],
        label="possession challenge record",
    )
    _validate_artifact_record(
        proof["signature"],
        name=SIGNATURE_NAME,
        data=files[SIGNATURE_NAME],
        label="possession signature record",
    )
    _validate_artifact_record(
        proof["embedded_verification"],
        name=VERIFICATION_NAME,
        data=files[VERIFICATION_NAME],
        label="embedded verification record",
    )
    _validate_artifact_record(
        proof["release_verifier_binding"],
        name=VERIFIER_BINDING_NAME,
        data=files[VERIFIER_BINDING_NAME],
        label="release verifier binding record",
    )
    return VerifiedUpdaterKeyPossession(
        root=root / PROOF_RELATIVE,
        proof_path=root / PROOF_RELATIVE / PROOF_NAME,
        proof_sha256=_sha256(files[PROOF_NAME]),
        embedded_public_key_sha256=verification["embedded_public_key_sha256"],
        tauri_config_sha256=verification["tauri_config_sha256"],
    )


def verify_possession_proof(
    repository: Path,
    candidate_root: Path,
    *,
    source_identity_reader: SourceIdentityReader = _default_source_identity_reader,
    embedded_verifier: EmbeddedVerifier = _production_embedded_verifier,
) -> VerifiedUpdaterKeyPossession:
    """Reopen and replay one proof without accessing updater secret material."""

    repository = _canonical_repository(repository)
    root = _candidate_root(repository, candidate_root)
    proof_root = root / PROOF_RELATIVE
    try:
        files = read_private_directory_contents(
            proof_root,
            {
                CHALLENGE_NAME: MAX_CHALLENGE_BYTES,
                SIGNATURE_NAME: MAX_SIGNATURE_BYTES,
                VERIFICATION_NAME: MAX_VERIFICATION_BYTES,
                VERIFIER_BINDING_NAME: MAX_VERIFIER_BINDING_BYTES,
                PROOF_NAME: MAX_PROOF_BYTES,
            },
        )
    except (OSError, PublicationError) as error:
        raise UpdaterKeyPossessionError(
            "updater key possession proof directory is unsafe or incomplete"
        ) from error
    if set(files) != set(PROOF_FILES):
        raise UpdaterKeyPossessionError(
            "updater key possession proof has an unexpected file set"
        )
    return _verify_documents(
        repository,
        root,
        files,
        source_identity_reader=source_identity_reader,
        embedded_verifier=embedded_verifier,
    )


def create_possession_proof(
    repository: Path,
    *,
    source_identity_reader: SourceIdentityReader = _default_source_identity_reader,
    embedded_verifier: EmbeddedVerifier = _production_embedded_verifier,
    process_runner: ProcessRunner = run_bounded_process,
) -> VerifiedUpdaterKeyPossession:
    """Use the production signer once, atomically publish, then replay the proof."""

    repository = _canonical_repository(repository)
    root = _candidate_root(repository, ga_preflight_root(repository))
    profiles_root = root / "profiles"
    try:
        profiles_metadata = profiles_root.lstat()
    except OSError as error:
        raise UpdaterKeyPossessionError("GA profiles directory is unavailable") from error
    if (
        not stat.S_ISDIR(profiles_metadata.st_mode)
        or profiles_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(profiles_metadata.st_mode) != 0o700
    ):
        raise UpdaterKeyPossessionError(
            "GA profiles directory is not one owned 0700 directory"
        )
    source = _source_identity(repository, source_identity_reader)
    _preflight_path, _preflight_data, preflight_sha256 = _signing_preflight(root)
    tauri_config_sha256 = _tauri_configuration_sha256(repository)
    challenge_data = _challenge(
        nonce=secrets.token_bytes(32),
        source=source,
        signing_preflight_sha256=preflight_sha256,
    )

    try:
        with exclusive_rooted_directory_lock(
            repository, profiles_root, require_private=True
        ) as descriptor:
            _require_no_residual_temporaries(descriptor)
            previous_umask = os.umask(0o077)
            try:
                with tempfile.TemporaryDirectory(
                    prefix=TEMPORARY_PREFIX, dir=profiles_root
                ) as temporary:
                    temporary_root = Path(temporary)
                    os.chmod(temporary_root, 0o700)
                    challenge_path = temporary_root / CHALLENGE_NAME
                    signature_path = temporary_root / SIGNATURE_NAME
                    _write_new_private(challenge_path, challenge_data)
                    _run_production_signer(
                        repository, challenge_path, process_runner=process_runner
                    )
                    signature_data = _read_regular(
                        signature_path,
                        maximum=MAX_SIGNATURE_BYTES,
                        exact_mode=0o600,
                        label="updater possession signature",
                    )
                    challenge_record = _record(CHALLENGE_NAME, challenge_data)
                    signature_record = _record(SIGNATURE_NAME, signature_data)
                    try:
                        verification_value, binding_value = embedded_verifier(
                            repository, challenge_path, signature_path
                        )
                    except UpdaterKeyPossessionError:
                        raise
                    except (OSError, ValueError) as error:
                        raise UpdaterKeyPossessionError(
                            "source-pinned embedded updater-key verification failed"
                        ) from error
                    verification_value = _validate_embedded_verification(
                        verification_value,
                        challenge_record=challenge_record,
                        signature_record=signature_record,
                        tauri_config_sha256=tauri_config_sha256,
                    )
                    verification_data = canonical_json(verification_value)
                    binding_data = canonical_json(binding_value)
                    proof_value = _proof_document(
                        source=source,
                        signing_preflight_sha256=preflight_sha256,
                        challenge=challenge_data,
                        signature=signature_data,
                        verification=verification_data,
                        verifier_binding=binding_data,
                    )
                    proof_data = canonical_json(proof_value)
                    files = {
                        CHALLENGE_NAME: challenge_data,
                        SIGNATURE_NAME: signature_data,
                        VERIFICATION_NAME: verification_data,
                        VERIFIER_BINDING_NAME: binding_data,
                        PROOF_NAME: proof_data,
                    }
            finally:
                os.umask(previous_umask)
            _require_no_residual_temporaries(descriptor)
            publish_private_directory_locked(
                descriptor,
                profiles_root,
                PROOF_RELATIVE.name,
                files,
            )
    except UpdaterKeyPossessionError:
        raise
    except (OSError, PublicationError) as error:
        raise UpdaterKeyPossessionError(
            "cannot securely create or atomically publish updater key possession proof"
        ) from error
    return verify_possession_proof(
        repository,
        root,
        source_identity_reader=source_identity_reader,
        embedded_verifier=embedded_verifier,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("create", "verify-preflight", "verify-frozen")
    )
    arguments = parser.parse_args(argv)
    repository = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "create":
            result = create_possession_proof(repository)
        elif arguments.command == "verify-preflight":
            result = verify_possession_proof(
                repository, ga_preflight_root(repository)
            )
        else:
            result = verify_possession_proof(repository, ga_root(repository))
    except (OSError, UpdaterKeyPossessionError, ValueError) as error:
        print(f"error: updater key possession proof: {error}", file=sys.stderr)
        return 1
    print(f"updater key possession proof verified: {result.proof_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "PROOF_RELATIVE",
    "UpdaterKeyPossessionError",
    "VerifiedUpdaterKeyPossession",
    "create_possession_proof",
    "verify_possession_proof",
]
