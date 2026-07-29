#!/usr/bin/env python3
"""Launch the source-pinned Tauri signer with one fixed Keychain credential.

The production CLI accepts only the archive to sign. Repository, signer, key,
login Keychain, service, and account paths are source constants. Before the
password is requested, the complete Tauri toolchain tree is verified against
its exact source-pinned digest and the signer executable is independently
hashed through a held ``O_NOFOLLOW`` descriptor. The password never enters
this launcher's argv or caller-provided environment; Tauri receives it only in
the final direct ``execve`` environment because its signer API requires that
variable.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import pwd
import re
import resource
import stat
import subprocess
import sys
from typing import Callable, NoReturn, Sequence


SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
TAURI_CLI_VERSION = "2.11.4"
PINNED_TAURI_TREE_SHA256 = (
    "b824fd2404eaeb3b678761e0be8b1d593c3c53bef9450eb60d0a6c1668fdb2fd"
)
PINNED_TAURI_SIGNER_SHA256 = (
    "65e8b47fd326646e62cd501191a690232da4071826f7286c1eec0c2ce4b6027f"
)
PINNED_TAURI_SIGNER_BYTES = 37_901_376
PINNED_TAURI_METADATA = (
    "artifactKind=pinned-tauri-cli-v2",
    "crateSha256=fedac57c0291926f6c46e17a4ddd84711d026725e4becbd73573cb8cd924ba75",
    "dependencyMode=isolated-fetch-offline-locked-v1",
    "lockPatchSha256=965269f4cb086d1347c436e77f9aa4033c168fe1c26e66898bc26fe1a2eeb532",
    "macosDeploymentTarget=15.0",
    "patchedCargoLockSha256=ceb5a88c860e4238175e6ac4fe3f598c5c9e8f3e37c5d9928ac866a4be199b1b",
    "payloadLayout=bin-and-patched-source-v1",
    "platform=darwin-arm64",
    "rustToolchain=1.97.1-aarch64-apple-darwin",
    "spinCrateSha256=3763264f6b73151db08c50ff20d7d8a0b8796e021cdea7ceedad07b80155fa0e",
    "spinVersion=0.9.9",
    "upstreamCargoLockSha256=2ff3db9b36027ca10712cbebdb326f2b299f95093672eb66d7cab6a406619cc5",
    "version=2.11.4",
    "xcodeBuild=17F113",
    "xcodeVersion=26.6",
)
KEYCHAIN_SERVICE = "com.bill.clashformac.release.updater"
KEYCHAIN_ACCOUNT = "updater-v2"
PRIVATE_KEY_RELATIVE = Path(
    "Library/Application Support/Clash for Mac Release/Updater/cfw-rs-v2.key"
)
LOGIN_KEYCHAIN_RELATIVE = Path("Library/Keychains/login.keychain-db")
MAX_PASSWORD_BYTES = 1024
MAX_PRIVATE_KEY_BYTES = 1024 * 1024
TOOLCHAIN_VERIFY_TIMEOUT_SECONDS = 300
CREDENTIAL_LOOKUP_TIMEOUT_SECONDS = 15
SECRET_ENVIRONMENT_NAMES = frozenset(
    {
        "TAURI_PRIVATE_KEY",
        "TAURI_PRIVATE_KEY_PATH",
        "TAURI_PRIVATE_KEY_PASSWORD",
        "TAURI_SIGNING_PRIVATE_KEY",
        "TAURI_SIGNING_PRIVATE_KEY_PATH",
        "TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
    }
)
_ACL_ENTRY_RE = re.compile(r"^[ \t]*[0-9]+:[ \t]+")
_ACL_ACTION_RE = re.compile(r"[ \t](allow|deny)[ \t]")


class UpdaterSigningLaunchError(RuntimeError):
    """The fixed updater signing custody contract could not be established."""


@dataclass(frozen=True)
class PathIdentity:
    path: Path
    device: int
    inode: int
    mode: int
    owner: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def from_stat(cls, path: Path, metadata: os.stat_result) -> PathIdentity:
        return cls(
            path=path,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=metadata.st_mode,
            owner=metadata.st_uid,
            links=metadata.st_nlink,
            size=metadata.st_size,
            modified_ns=metadata.st_mtime_ns,
            changed_ns=metadata.st_ctime_ns,
        )


@dataclass(frozen=True)
class HeldSigner:
    """A verified signer executable held open across secret acquisition."""

    path: Path
    descriptor: int
    identity: PathIdentity


@dataclass(frozen=True)
class HeldReleaseFile:
    """A release input held open across secret acquisition."""

    path: Path
    descriptor: int
    identity: PathIdentity


def _home_directory(home: Path | None = None) -> Path:
    resolved = Path(pwd.getpwuid(os.getuid()).pw_dir) if home is None else home
    if not resolved.is_absolute():
        raise UpdaterSigningLaunchError("release user home directory is not absolute")
    return resolved


def _require_no_secret_environment(environment: dict[str, str]) -> None:
    present = sorted(SECRET_ENVIRONMENT_NAMES & environment.keys())
    if present:
        raise UpdaterSigningLaunchError(
            "caller-supplied Tauri signing secret variables are forbidden: "
            + ", ".join(present)
        )


def _disable_core_dumps() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        limits = resource.getrlimit(resource.RLIMIT_CORE)
    except (OSError, ValueError) as error:
        raise UpdaterSigningLaunchError("cannot disable signer core dumps") from error
    if limits != (0, 0):
        raise UpdaterSigningLaunchError("signer core-dump limit is not zero")


def _identity(path: Path, metadata: os.stat_result) -> PathIdentity:
    return PathIdentity.from_stat(path, metadata)


def _require_directory(
    identity: PathIdentity, *, owner: int, private: bool
) -> None:
    if not stat.S_ISDIR(identity.mode) or identity.owner != owner:
        raise UpdaterSigningLaunchError(
            f"fixed credential directory is not an owner-bound directory: {identity.path}"
        )
    if private and stat.S_IMODE(identity.mode) & 0o077:
        raise UpdaterSigningLaunchError(
            f"fixed credential directory grants group/other access: {identity.path}"
        )


def _require_regular_file(
    identity: PathIdentity,
    *,
    owner: int,
    exact_mode: int | None,
    maximum_bytes: int,
) -> None:
    if not stat.S_ISREG(identity.mode) or identity.owner != owner:
        raise UpdaterSigningLaunchError(
            f"release path is not an owner-bound regular file: {identity.path}"
        )
    if identity.links != 1:
        raise UpdaterSigningLaunchError(
            f"release file must have exactly one hard link: {identity.path}"
        )
    if exact_mode is not None and stat.S_IMODE(identity.mode) != exact_mode:
        raise UpdaterSigningLaunchError(
            f"release file mode must be {exact_mode:04o}: {identity.path}"
        )
    if identity.size < 1 or identity.size > maximum_bytes:
        raise UpdaterSigningLaunchError(
            f"release file size is outside its bound: {identity.path}"
        )


def _close_descriptors(descriptors: Sequence[int]) -> None:
    failure: OSError | None = None
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError as error:
            if failure is None:
                failure = error
    if failure is not None:
        raise UpdaterSigningLaunchError(
            "cannot close one or more held release descriptors"
        ) from failure


def _open_directory_chain(
    home: Path,
    relative: Path,
    *,
    private_from: int,
) -> tuple[list[int], list[PathIdentity]]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise UpdaterSigningLaunchError("O_NOFOLLOW is unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | nofollow
    owner = os.getuid()
    fds: list[int] = []
    identities: list[PathIdentity] = []
    try:
        current_fd = os.open(home, flags)
        fds.append(current_fd)
        home_identity = _identity(home, os.fstat(current_fd))
        _require_directory(home_identity, owner=owner, private=False)
        identities.append(home_identity)
        current_path = home
        for index, component in enumerate(relative.parts):
            current_fd = os.open(component, flags, dir_fd=current_fd)
            fds.append(current_fd)
            current_path /= component
            identity = _identity(current_path, os.fstat(current_fd))
            _require_directory(
                identity,
                owner=owner,
                private=index >= private_from,
            )
            identities.append(identity)
        return fds, identities
    except (OSError, UpdaterSigningLaunchError) as error:
        _close_descriptors(fds)
        if isinstance(error, UpdaterSigningLaunchError):
            raise
        raise UpdaterSigningLaunchError(
            f"cannot open fixed credential directory chain: {home / relative}"
        ) from error


def _lstat_identity(path: Path) -> PathIdentity:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise UpdaterSigningLaunchError(
            f"release path is unavailable: {path}"
        ) from error
    return _identity(path, metadata)


def _require_unchanged(identity: PathIdentity, descriptor: int | None = None) -> None:
    current = _lstat_identity(identity.path)
    if current != identity:
        raise UpdaterSigningLaunchError(
            f"fixed credential path changed during signing preflight: {identity.path}"
        )
    if descriptor is not None:
        try:
            held_metadata = os.fstat(descriptor)
        except OSError as error:
            raise UpdaterSigningLaunchError(
                f"held release descriptor is unavailable: {identity.path}"
            ) from error
        held = _identity(identity.path, held_metadata)
        if held != identity:
            raise UpdaterSigningLaunchError(
                f"held credential descriptor changed during preflight: {identity.path}"
            )


def _run_without_input(
    runner: Callable[..., subprocess.CompletedProcess[bytes]],
    arguments: list[str],
    *,
    environment: dict[str, str],
    timeout_seconds: int,
) -> subprocess.CompletedProcess[bytes]:
    """Run a fixed preflight child without terminal input or inherited env."""

    try:
        result = runner(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise UpdaterSigningLaunchError(
            f"release preflight command failed: {arguments[0]}"
        ) from error
    if not isinstance(result.stdout, bytes) or not isinstance(result.stderr, bytes):
        raise UpdaterSigningLaunchError(
            f"release preflight command returned non-byte output: {arguments[0]}"
        )
    return result


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    try:
        while True:
            chunk = os.pread(descriptor, 1024 * 1024, offset)
            if not chunk:
                break
            digest.update(chunk)
            offset += len(chunk)
    except OSError as error:
        raise UpdaterSigningLaunchError(
            "cannot hash the held pinned Tauri signer"
        ) from error
    return digest.hexdigest()


def _repository_from_source() -> Path:
    source = Path(__file__)
    try:
        source_identity = source.stat(follow_symlinks=False)
        resolved_source = source.resolve(strict=True)
    except OSError as error:
        raise UpdaterSigningLaunchError(
            "updater signing launcher source is unavailable"
        ) from error
    if not stat.S_ISREG(source_identity.st_mode) or source_identity.st_nlink != 1:
        raise UpdaterSigningLaunchError(
            "updater signing launcher must be a single-link regular source file"
        )
    if resolved_source != source.absolute():
        raise UpdaterSigningLaunchError(
            "updater signing launcher source must not be reached through a symlink"
        )
    return resolved_source.parent.parent


def verify_pinned_tauri_signer(
    repository: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> HeldSigner:
    """Verify the exact toolchain tree, then hold and hash its fixed signer."""

    if not repository.is_absolute():
        raise UpdaterSigningLaunchError("release repository path must be absolute")
    toolchain = repository / "target/toolchains" / f"tauri-cli-{TAURI_CLI_VERSION}"
    manifest = toolchain.with_name(f"{toolchain.name}.manifest.json")
    verifier = repository / "scripts/verify_artifact_manifest.py"
    python = _canonical_python_runtime()
    for path, label, executable in (
        (verifier, "artifact-manifest verifier", False),
        (manifest, "Tauri toolchain manifest", False),
    ):
        _validate_input_file(path, label, executable=executable)

    command = [
        str(python),
        "-S",
        "-B",
        str(verifier),
        str(toolchain),
        str(manifest),
        "--algorithm",
        "sha256-tree-v2",
        "--exact-metadata",
        "--print-tree-sha256",
    ]
    for metadata in PINNED_TAURI_METADATA:
        command.extend(("--metadata", metadata))
    result = _run_without_input(
        runner,
        command,
        environment={
            "PATH": SYSTEM_PATH,
            "PYTHONDONTWRITEBYTECODE": "1",
            "LC_ALL": "C",
            "LANG": "C",
        },
        timeout_seconds=TOOLCHAIN_VERIFY_TIMEOUT_SECONDS,
    )
    expected_output = f"{PINNED_TAURI_TREE_SHA256}\n".encode("ascii")
    if result.returncode != 0 or result.stdout != expected_output or result.stderr:
        raise UpdaterSigningLaunchError(
            "pinned Tauri toolchain tree or exact source metadata did not verify"
        )

    signer_path = toolchain / "bin/cargo-tauri"
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise UpdaterSigningLaunchError("O_NOFOLLOW is unavailable")
    signer_fd = -1
    try:
        signer_fd = os.open(signer_path, os.O_RDONLY | os.O_CLOEXEC | nofollow)
        signer_identity = _identity(signer_path, os.fstat(signer_fd))
        _require_regular_file(
            signer_identity,
            owner=os.getuid(),
            exact_mode=0o755,
            maximum_bytes=PINNED_TAURI_SIGNER_BYTES,
        )
        if signer_identity.size != PINNED_TAURI_SIGNER_BYTES:
            raise UpdaterSigningLaunchError("pinned Tauri signer size mismatch")
        if _lstat_identity(signer_path) != signer_identity:
            raise UpdaterSigningLaunchError(
                "pinned Tauri signer path differs from its held descriptor"
            )
        if _sha256_descriptor(signer_fd) != PINNED_TAURI_SIGNER_SHA256:
            raise UpdaterSigningLaunchError("pinned Tauri signer digest mismatch")
        _require_unchanged(signer_identity, signer_fd)
        return HeldSigner(signer_path, signer_fd, signer_identity)
    except (OSError, UpdaterSigningLaunchError) as error:
        if signer_fd >= 0:
            _close_descriptors((signer_fd,))
        if isinstance(error, UpdaterSigningLaunchError):
            raise
        raise UpdaterSigningLaunchError(
            "cannot open the source-pinned Tauri signer"
        ) from error


def require_no_macos_acl_grants(
    path: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> None:
    """Reject ACL grants while accepting macOS' strengthening deny-delete ACL."""

    try:
        result = _run_without_input(
            runner,
            ["/bin/ls", "-lde", "--", str(path)],
            environment={"PATH": SYSTEM_PATH, "LC_ALL": "C", "LANG": "C"},
            timeout_seconds=CREDENTIAL_LOOKUP_TIMEOUT_SECONDS,
        )
    except UpdaterSigningLaunchError as error:
        raise UpdaterSigningLaunchError(
            f"cannot inspect ACL for fixed credential path: {path}"
        ) from error
    if result.returncode != 0 or not isinstance(result.stdout, bytes):
        raise UpdaterSigningLaunchError(
            f"cannot inspect ACL for fixed credential path: {path}"
        )
    try:
        lines = result.stdout.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise UpdaterSigningLaunchError(
            f"ACL output is not UTF-8 for fixed credential path: {path}"
        ) from error
    for line in lines:
        if not _ACL_ENTRY_RE.match(line):
            continue
        actions = _ACL_ACTION_RE.findall(line)
        if actions != ["deny"]:
            raise UpdaterSigningLaunchError(
                f"fixed credential path ACL must not grant access: {path}"
            )


def _validate_input_file(path: Path, label: str, *, executable: bool) -> None:
    if not path.is_absolute():
        raise UpdaterSigningLaunchError(f"{label} path must be absolute")
    identity = _lstat_identity(path)
    _require_regular_file(
        identity,
        owner=os.getuid(),
        exact_mode=None,
        maximum_bytes=512 * 1024 * 1024,
    )
    if executable and not os.access(path, os.X_OK):
        raise UpdaterSigningLaunchError(f"{label} is not executable")


def _open_held_release_file(path: Path, label: str) -> HeldReleaseFile:
    if not path.is_absolute():
        raise UpdaterSigningLaunchError(f"{label} path must be absolute")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise UpdaterSigningLaunchError("O_NOFOLLOW is unavailable")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | nofollow)
        identity = _identity(path, os.fstat(descriptor))
        _require_regular_file(
            identity,
            owner=os.getuid(),
            exact_mode=None,
            maximum_bytes=512 * 1024 * 1024,
        )
        if _lstat_identity(path) != identity:
            raise UpdaterSigningLaunchError(
                f"{label} path differs from its held descriptor"
            )
        return HeldReleaseFile(path, descriptor, identity)
    except (OSError, UpdaterSigningLaunchError) as error:
        if descriptor >= 0:
            _close_descriptors((descriptor,))
        if isinstance(error, UpdaterSigningLaunchError):
            raise
        raise UpdaterSigningLaunchError(f"cannot open {label}") from error


def _canonical_python_runtime() -> Path:
    """Return the running interpreter's canonical, non-writable executable."""

    try:
        python = Path(sys.executable).resolve(strict=True)
    except OSError as error:
        raise UpdaterSigningLaunchError(
            "running Python interpreter cannot be resolved"
        ) from error
    identity = _lstat_identity(python)
    if (
        not stat.S_ISREG(identity.mode)
        or identity.links != 1
        or identity.owner not in {0, os.getuid()}
        or identity.size < 1
        or identity.size > 512 * 1024 * 1024
        or stat.S_IMODE(identity.mode) & 0o022
        or not stat.S_IMODE(identity.mode) & 0o111
    ):
        raise UpdaterSigningLaunchError(
            "canonical Python interpreter is not an owner-bound executable"
        )
    return python


def _validate_fixed_keychain(
    home: Path,
    *,
    acl_checker: Callable[[Path], None],
) -> tuple[list[int], list[PathIdentity], int, PathIdentity]:
    fds, directories = _open_directory_chain(
        home,
        LOGIN_KEYCHAIN_RELATIVE.parent,
        private_from=len(LOGIN_KEYCHAIN_RELATIVE.parent.parts) + 1,
    )
    keychain_path = home / LOGIN_KEYCHAIN_RELATIVE
    keychain_fd = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        keychain_fd = os.open(
            LOGIN_KEYCHAIN_RELATIVE.name,
            flags,
            dir_fd=fds[-1],
        )
        keychain = _identity(keychain_path, os.fstat(keychain_fd))
        if _lstat_identity(keychain_path) != keychain:
            raise UpdaterSigningLaunchError(
                "fixed login Keychain path differs from its held descriptor"
            )
        _require_regular_file(
            keychain,
            owner=os.getuid(),
            exact_mode=None,
            maximum_bytes=512 * 1024 * 1024,
        )
        if len(directories) < 3:
            raise UpdaterSigningLaunchError(
                "fixed login Keychain has no private Library trust anchor"
            )
        library = directories[1]
        _require_directory(library, owner=os.getuid(), private=True)
        if stat.S_IMODE(library.mode) != 0o700:
            raise UpdaterSigningLaunchError(
                f"fixed Library trust anchor mode must be 0700: {library.path}"
            )
        if stat.S_IMODE(directories[-1].mode) not in {0o700, 0o755}:
            raise UpdaterSigningLaunchError(
                "fixed Keychains directory has a nonstandard mode: "
                f"{directories[-1].path}"
            )
        if stat.S_IMODE(keychain.mode) not in {0o600, 0o644}:
            raise UpdaterSigningLaunchError(
                f"fixed login Keychain has a nonstandard mode: {keychain_path}"
            )
        acl_checker(library.path)
        acl_checker(directories[-1].path)
        acl_checker(keychain_path)
        return fds, directories, keychain_fd, keychain
    except Exception:
        if keychain_fd >= 0:
            _close_descriptors((keychain_fd,))
        _close_descriptors(fds)
        raise


def _revalidate_fixed_keychain(
    directories: Sequence[PathIdentity],
    keychain: PathIdentity,
    keychain_fd: int,
    *,
    acl_checker: Callable[[Path], None],
) -> None:
    for directory in directories:
        _require_unchanged(directory)
    _require_unchanged(keychain, keychain_fd)
    acl_checker(directories[1].path)
    acl_checker(directories[-1].path)
    acl_checker(keychain.path)


def read_fixed_keychain_password(
    *,
    home: Path | None = None,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    acl_checker: Callable[[Path], None] = require_no_macos_acl_grants,
) -> bytearray:
    """Read exactly one fixed local-login-Keychain item without logging bytes."""

    fixed_home = _home_directory(home)
    fds, directories, keychain_fd, keychain = _validate_fixed_keychain(
        fixed_home, acl_checker=acl_checker
    )
    keychain_path = fixed_home / LOGIN_KEYCHAIN_RELATIVE
    try:
        keychain_environment = {
            "HOME": str(fixed_home),
            "PATH": SYSTEM_PATH,
            "LC_ALL": "C",
            "LANG": "C",
        }
        try:
            metadata_result = _run_without_input(
                runner,
                [
                    "/usr/bin/security",
                    "find-generic-password",
                    "-s",
                    KEYCHAIN_SERVICE,
                    "-a",
                    KEYCHAIN_ACCOUNT,
                    str(keychain_path),
                ],
                environment=keychain_environment,
                timeout_seconds=CREDENTIAL_LOOKUP_TIMEOUT_SECONDS,
            )
        except UpdaterSigningLaunchError as error:
            raise UpdaterSigningLaunchError(
                "fixed updater Keychain password lookup failed"
            ) from error
        if metadata_result.returncode != 0:
            raise UpdaterSigningLaunchError(
                "fixed updater Keychain metadata lookup failed"
            )
        try:
            metadata = metadata_result.stdout.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise UpdaterSigningLaunchError(
                "fixed updater Keychain metadata is not UTF-8"
            ) from error
        expected_keychain = f'keychain: "{keychain_path}"'
        if (
            metadata.count(expected_keychain) != 1
            or metadata.count('class: "genp"') != 1
            or metadata.count(f'"acct"<blob>="{KEYCHAIN_ACCOUNT}"') != 1
            or metadata.count(f'"svce"<blob>="{KEYCHAIN_SERVICE}"') != 1
            or '"sync"' in metadata
        ):
            raise UpdaterSigningLaunchError(
                "fixed updater Keychain item is missing, duplicated, or synchronizable"
            )
        _revalidate_fixed_keychain(
            directories,
            keychain,
            keychain_fd,
            acl_checker=acl_checker,
        )
        try:
            result = _run_without_input(
                runner,
                [
                    "/usr/bin/security",
                    "find-generic-password",
                    "-s",
                    KEYCHAIN_SERVICE,
                    "-a",
                    KEYCHAIN_ACCOUNT,
                    "-w",
                    str(keychain_path),
                ],
                environment=keychain_environment,
                timeout_seconds=CREDENTIAL_LOOKUP_TIMEOUT_SECONDS,
            )
        except UpdaterSigningLaunchError as error:
            raise UpdaterSigningLaunchError(
                "fixed updater Keychain password lookup failed"
            ) from error
        if result.returncode != 0:
            raise UpdaterSigningLaunchError(
                "fixed updater Keychain password lookup failed"
            )
        raw = result.stdout[:-1] if result.stdout.endswith(b"\n") else result.stdout
        if (
            not raw
            or len(raw) > MAX_PASSWORD_BYTES
            or b"\x00" in raw
            or b"\n" in raw
            or b"\r" in raw
        ):
            raise UpdaterSigningLaunchError(
                "fixed updater Keychain password is empty, ambiguous, or malformed"
            )
        try:
            decoded = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise UpdaterSigningLaunchError(
                "fixed updater Keychain password is not UTF-8"
            ) from error
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in decoded):
            raise UpdaterSigningLaunchError(
                "fixed updater Keychain password contains control characters"
            )
        _revalidate_fixed_keychain(
            directories,
            keychain,
            keychain_fd,
            acl_checker=acl_checker,
        )
        return bytearray(raw)
    finally:
        _close_descriptors((keychain_fd,))
        _close_descriptors(fds)


def launch_updater_signer(
    archive: Path,
    *,
    home: Path | None = None,
    password_reader: Callable[[], bytearray] | None = None,
    acl_checker: Callable[[Path], None] = require_no_macos_acl_grants,
    execve: Callable[[str, Sequence[str], dict[str, str]], NoReturn] = os.execve,
) -> NoReturn:
    """Validate fixed custody, then replace this process with the Tauri signer."""

    _require_no_secret_environment(dict(os.environ))
    _disable_core_dumps()
    held_signer: HeldSigner | None = None
    held_archive: HeldReleaseFile | None = None
    directory_fds: list[int] = []
    directories: list[PathIdentity] = []
    key_fd = -1
    password = bytearray()
    password_text = ""
    signer_environment: dict[str, str] = {}
    try:
        repository = _repository_from_source()
        held_signer = verify_pinned_tauri_signer(repository)
        held_archive = _open_held_release_file(archive, "updater archive")
        acl_checker(held_archive.path)
        fixed_home = _home_directory(home)
        key_parent = PRIVATE_KEY_RELATIVE.parent
        directory_fds, directories = _open_directory_chain(
            fixed_home,
            key_parent,
            private_from=0,
        )
        if len(directories) < 2 or stat.S_IMODE(directories[1].mode) != 0o700:
            raise UpdaterSigningLaunchError(
                "fixed Library trust anchor mode must be 0700"
            )
        key_path = fixed_home / PRIVATE_KEY_RELATIVE
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise UpdaterSigningLaunchError("O_NOFOLLOW is unavailable")
        flags = os.O_RDONLY | os.O_CLOEXEC | nofollow
        key_fd = os.open(PRIVATE_KEY_RELATIVE.name, flags, dir_fd=directory_fds[-1])
        key = _identity(key_path, os.fstat(key_fd))
        _require_regular_file(
            key,
            owner=os.getuid(),
            exact_mode=0o600,
            maximum_bytes=MAX_PRIVATE_KEY_BYTES,
        )
        if _lstat_identity(key_path) != key:
            raise UpdaterSigningLaunchError(
                "fixed updater private-key path differs from its held descriptor"
            )
        for directory in directories[1:]:
            acl_checker(directory.path)
        acl_checker(key_path)

        reader = (
            (
                lambda: read_fixed_keychain_password(
                    home=fixed_home,
                    acl_checker=acl_checker,
                )
            )
            if password_reader is None
            else password_reader
        )
        password = reader()
        if not isinstance(password, bytearray) or not password:
            raise UpdaterSigningLaunchError(
                "updater password reader did not return a non-empty bytearray"
            )
        try:
            password_text = bytes(password).decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise UpdaterSigningLaunchError("updater password is not UTF-8") from error

        for directory in directories:
            _require_unchanged(directory)
        _require_unchanged(key, key_fd)
        _require_unchanged(held_signer.identity, held_signer.descriptor)
        _require_unchanged(held_archive.identity, held_archive.descriptor)
        for directory in directories[1:]:
            acl_checker(directory.path)
        acl_checker(key_path)
        acl_checker(held_archive.path)
        os.set_inheritable(key_fd, True)
        fd_path = Path("/dev/fd") / str(key_fd)
        probe_fd = os.open(fd_path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            fd_identity = _identity(key_path, os.fstat(probe_fd))
        finally:
            _close_descriptors((probe_fd,))
        if fd_identity != key:
            raise UpdaterSigningLaunchError(
                "inherited /dev/fd identity differs from the fixed updater key"
            )
        arguments = [
            str(held_signer.path),
            "signer",
            "sign",
            "-f",
            str(fd_path),
            str(held_archive.path),
        ]
        signer_environment = {
            "PATH": SYSTEM_PATH,
            "TAURI_SIGNING_PRIVATE_KEY_PASSWORD": password_text,
        }
        execve(str(held_signer.path), arguments, signer_environment)
        raise UpdaterSigningLaunchError("Tauri signer execve unexpectedly returned")
    except OSError as error:
        raise UpdaterSigningLaunchError(
            "updater signer launch failed during a fixed filesystem operation"
        ) from error
    finally:
        if "TAURI_SIGNING_PRIVATE_KEY_PASSWORD" in signer_environment:
            signer_environment["TAURI_SIGNING_PRIVATE_KEY_PASSWORD"] = ""
        signer_environment.clear()
        password_text = ""
        for index in range(len(password)):
            password[index] = 0
        if key_fd >= 0:
            _close_descriptors((key_fd,))
        _close_descriptors(directory_fds)
        if held_signer is not None:
            _close_descriptors((held_signer.descriptor,))
        if held_archive is not None:
            _close_descriptors((held_archive.descriptor,))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    arguments = parser.parse_args(argv)
    try:
        launch_updater_signer(arguments.archive)
    except UpdaterSigningLaunchError as error:
        print(f"error: updater signer launch failed closed: {error}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
