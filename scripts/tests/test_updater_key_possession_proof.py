from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import release_artifact_set
from scripts.publication import durable_file
from scripts.publication.common import PublicationError, canonical_json
from scripts.tests.test_release_artifact_transaction import (
    create_release_verifier_build,
    verified_cargo_fixture,
)
from scripts import updater_key_possession_proof as possession


SOURCE_IDENTITY = {
    "repositoryCommit": "1" * 40,
    "releaseSourceSha256": "2" * 64,
}
EMBEDDED_PUBLIC_KEY_SHA256 = "3" * 64
TAURI_CONFIG_DATA = b'{"plugins":{"updater":{"pubkey":"fixture"}}}\n'
TAURI_CONFIG_SHA256 = hashlib.sha256(TAURI_CONFIG_DATA).hexdigest()
SIGNATURE_PREFIX = b"fixture-updater-signature:"


class PossessionFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        temporary_root = Path(self.temporary.name).resolve(strict=True)
        self.repository = temporary_root / "repository"
        self.repository.mkdir(mode=0o700)
        tauri_config = self.repository / "apps/cfw-tauri-shell/tauri.conf.json"
        tauri_config.parent.mkdir(parents=True)
        tauri_config.write_bytes(TAURI_CONFIG_DATA)
        tauri_config.chmod(0o644)
        self.preflight_root = (
            self.repository / "target/candidates/0.4.0/ga-preflight/40031"
        )
        self.preflight_root.mkdir(parents=True, mode=0o700)
        self.preflight_root.chmod(0o700)
        self.profiles_root = self.preflight_root / "profiles"
        self.profiles_root.mkdir(mode=0o700)
        self.signing_preflight = self.profiles_root / "signing-preflight.json"
        self.signing_preflight.write_bytes(
            canonical_json(
                {
                    "document": "fixture-signing-preflight-v1",
                    "result": "verified",
                    "schema_version": 1,
                }
            )
        )
        self.signing_preflight.chmod(0o600)
        self.signer_calls: list[
            tuple[list[str], Path, dict[str, str], int, int]
        ] = []
        self.verifier_calls: list[tuple[Path, Path, Path]] = []

    def cleanup(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def source_reader(repository: Path) -> dict[str, str]:
        if not repository.is_dir():
            raise AssertionError("fixture repository is unavailable")
        return dict(SOURCE_IDENTITY)

    def signer(
        self,
        command: list[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        timeout: int,
        output_limit: int,
    ) -> subprocess.CompletedProcess[bytes]:
        self.signer_calls.append(
            (command, cwd, environment, timeout, output_limit)
        )
        challenge = Path(command[-1])
        self.assert_private_signer_input(challenge)
        signature = challenge.with_name(f"{challenge.name}.sig")
        signature.write_bytes(
            SIGNATURE_PREFIX + hashlib.sha256(challenge.read_bytes()).hexdigest().encode()
        )
        signature.chmod(0o600)
        return subprocess.CompletedProcess(command, 0, b"signed\n", b"")

    @staticmethod
    def assert_private_signer_input(challenge: Path) -> None:
        directory_metadata = challenge.parent.lstat()
        challenge_metadata = challenge.lstat()
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            or not stat.S_ISREG(challenge_metadata.st_mode)
            or stat.S_IMODE(challenge_metadata.st_mode) != 0o600
            or challenge_metadata.st_nlink != 1
        ):
            raise AssertionError("production signer input is not private")

    def embedded_verifier(
        self, repository: Path, challenge: Path, signature: Path
    ) -> tuple[dict[str, object], dict[str, object]]:
        self.verifier_calls.append((repository, challenge, signature))
        challenge_data = challenge.read_bytes()
        signature_data = signature.read_bytes()
        expected_signature = (
            SIGNATURE_PREFIX + hashlib.sha256(challenge_data).hexdigest().encode()
        )
        if signature_data != expected_signature:
            raise possession.UpdaterKeyPossessionError(
                "fixture signature does not verify"
            )
        verification = {
            "archive_filename": challenge.name,
            "archive_sha256": hashlib.sha256(challenge_data).hexdigest(),
            "archive_size": len(challenge_data),
            "document": possession.EMBEDDED_VERIFICATION_DOCUMENT,
            "embedded_public_key_sha256": EMBEDDED_PUBLIC_KEY_SHA256,
            "result": possession.RESULT_VERIFIED,
            "schema_version": possession.SCHEMA_VERSION,
            "signature_filename": signature.name,
            "signature_sha256": hashlib.sha256(signature_data).hexdigest(),
            "signature_size": len(signature_data),
            "tauri_config_sha256": TAURI_CONFIG_SHA256,
        }
        binding = {
            "document": "fixture-source-pinned-release-verifier-v1",
            "schema_version": 1,
            "source_sha256": "5" * 64,
        }
        return verification, binding

    def create(self) -> possession.VerifiedUpdaterKeyPossession:
        with patch.object(
            possession.secrets, "token_bytes", return_value=b"n" * 32
        ) as nonce:
            result = possession.create_possession_proof(
                self.repository,
                source_identity_reader=self.source_reader,
                embedded_verifier=self.embedded_verifier,
                process_runner=self.signer,
            )
        nonce.assert_called_once_with(32)
        return result

    def verify(
        self,
        *,
        source_reader: possession.SourceIdentityReader | None = None,
    ) -> possession.VerifiedUpdaterKeyPossession:
        return possession.verify_possession_proof(
            self.repository,
            self.preflight_root,
            source_identity_reader=source_reader or self.source_reader,
            embedded_verifier=self.embedded_verifier,
        )

    @property
    def proof_root(self) -> Path:
        return self.preflight_root / possession.PROOF_RELATIVE


class UpdaterKeyPossessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = PossessionFixture()
        self.addCleanup(self.fixture.cleanup)
        durability = patch.object(durable_file, "full_fsync", side_effect=os.fsync)
        durability.start()
        self.addCleanup(durability.stop)

    def test_create_uses_fixed_production_launcher_boundary_and_reopens(self) -> None:
        result = self.fixture.create()

        self.assertEqual(result.root, self.fixture.proof_root)
        self.assertEqual(result.proof_path, self.fixture.proof_root / "proof.json")
        self.assertEqual(result.embedded_public_key_sha256, EMBEDDED_PUBLIC_KEY_SHA256)
        self.assertEqual(result.tauri_config_sha256, TAURI_CONFIG_SHA256)
        self.assertEqual(len(self.fixture.signer_calls), 1)
        command, cwd, environment, timeout, output_limit = self.fixture.signer_calls[0]
        self.assertEqual(
            command,
            [
                possession.sys.executable,
                "-I",
                "-S",
                "-B",
                "-W",
                "error",
                str(
                    self.fixture.repository
                    / "scripts/updater_signing_launcher.py"
                ),
                str(command[-1]),
            ],
        )
        self.assertEqual(cwd, self.fixture.repository)
        self.assertEqual(
            environment,
            {
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": possession.SYSTEM_PATH,
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        self.assertEqual(timeout, possession.SIGNER_TIMEOUT_SECONDS)
        self.assertEqual(output_limit, possession.MAX_SIGNER_OUTPUT_BYTES)
        self.assertFalse(
            any("KEY" in name or "PASSWORD" in name for name in environment)
        )

        self.assertEqual(
            {path.name for path in self.fixture.proof_root.iterdir()},
            set(possession.PROOF_FILES),
        )
        self.assertEqual(
            stat.S_IMODE(self.fixture.proof_root.lstat().st_mode), 0o700
        )
        for path in self.fixture.proof_root.iterdir():
            self.assertTrue(path.is_file())
            self.assertFalse(path.is_symlink())
            self.assertEqual(path.lstat().st_nlink, 1)
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o600)

        challenge = json.loads(
            (self.fixture.proof_root / possession.CHALLENGE_NAME).read_bytes()
        )
        self.assertEqual(challenge["nonce"], (b"n" * 32).hex())
        self.assertEqual(challenge["source"]["repository_commit"], "1" * 40)
        self.assertEqual(
            challenge["signing_preflight_sha256"],
            hashlib.sha256(self.fixture.signing_preflight.read_bytes()).hexdigest(),
        )
        self.assertFalse(
            any(
                path.name.startswith(".updater-key-possession.")
                for path in self.fixture.profiles_root.iterdir()
            )
        )

    def test_pure_verify_replays_public_verifier_without_signer(self) -> None:
        created = self.fixture.create()
        signer_calls = list(self.fixture.signer_calls)
        self.fixture.verifier_calls.clear()

        verified = self.fixture.verify()

        self.assertEqual(verified, created)
        self.assertEqual(self.fixture.signer_calls, signer_calls)
        self.assertEqual(len(self.fixture.verifier_calls), 1)

    def test_production_source_pinned_verifier_binding_is_rebuilt_and_validated(
        self,
    ) -> None:
        build = create_release_verifier_build(self.fixture.repository)
        challenge = self.fixture.repository / "production-challenge.json"
        signature = self.fixture.repository / "production-challenge.json.sig"
        challenge.write_bytes(b'{"fixed":"challenge"}\n')
        signature.write_bytes(b"fixture-signature\n")

        @contextmanager
        def compiled(repository: Path):
            self.assertEqual(repository, self.fixture.repository)
            yield build

        with (
            patch.object(
                release_artifact_set,
                "_compiled_release_verifier",
                compiled,
            ),
            patch.object(
                possession,
                "_validate_release_verifier_binding",
                wraps=release_artifact_set._validate_release_verifier_binding,
            ) as binding_validator,
            verified_cargo_fixture(build),
        ):
            verification, binding = possession._production_embedded_verifier(
                self.fixture.repository, challenge, signature
            )

        self.assertEqual(verification["result"], possession.RESULT_VERIFIED)
        self.assertEqual(
            verification["archive_sha256"],
            hashlib.sha256(challenge.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            binding["document"], release_artifact_set.RELEASE_VERIFIER_BINDING_DOCUMENT
        )
        binding_validator.assert_called_once()

    def test_frozen_root_verification_uses_the_same_proof(self) -> None:
        created = self.fixture.create()
        frozen_root = self.fixture.repository / "target/candidates/0.4.0/ga/40031"
        frozen_root.parent.mkdir(parents=True)
        self.fixture.preflight_root.rename(frozen_root)

        verified = possession.verify_possession_proof(
            self.fixture.repository,
            frozen_root,
            source_identity_reader=self.fixture.source_reader,
            embedded_verifier=self.fixture.embedded_verifier,
        )

        self.assertEqual(verified.proof_sha256, created.proof_sha256)

    def test_repeated_create_refuses_to_replace_existing_proof(self) -> None:
        created = self.fixture.create()
        before = {
            path.name: path.read_bytes() for path in self.fixture.proof_root.iterdir()
        }

        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError, "atomically publish"
        ):
            self.fixture.create()

        self.assertEqual(
            {path.name: path.read_bytes() for path in self.fixture.proof_root.iterdir()},
            before,
        )
        self.assertEqual(created.proof_sha256, self.fixture.verify().proof_sha256)
        self.assertFalse(
            any(
                path.name.startswith(".updater-key-possession.")
                for path in self.fixture.profiles_root.iterdir()
            )
        )

    def test_signer_nonzero_fails_without_publication_or_residue(self) -> None:
        def failing_signer(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            return subprocess.CompletedProcess(args[0], 9, b"", b"")

        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError, "failed or emitted diagnostics"
        ):
            possession.create_possession_proof(
                self.fixture.repository,
                source_identity_reader=self.fixture.source_reader,
                embedded_verifier=self.fixture.embedded_verifier,
                process_runner=failing_signer,
            )

        self.assertFalse(self.fixture.proof_root.exists())
        self.assertEqual(
            list(self.fixture.profiles_root.iterdir()),
            [self.fixture.signing_preflight],
        )

    def test_signer_stderr_fails_closed_without_publication(self) -> None:
        def noisy_signer(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            return subprocess.CompletedProcess(args[0], 0, b"signed\n", b"warning\n")

        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError, "failed or emitted diagnostics"
        ):
            possession.create_possession_proof(
                self.fixture.repository,
                source_identity_reader=self.fixture.source_reader,
                embedded_verifier=self.fixture.embedded_verifier,
                process_runner=noisy_signer,
            )

        self.assertFalse(self.fixture.proof_root.exists())

    def test_missing_signature_fails_without_publication(self) -> None:
        def missing_signature(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            return subprocess.CompletedProcess(command, 0, b"signed\n", b"")

        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError, "signature is unavailable"
        ):
            possession.create_possession_proof(
                self.fixture.repository,
                source_identity_reader=self.fixture.source_reader,
                embedded_verifier=self.fixture.embedded_verifier,
                process_runner=missing_signature,
            )

        self.assertFalse(self.fixture.proof_root.exists())

    def test_embedded_public_key_rejection_fails_without_publication(self) -> None:
        def rejecting_verifier(
            repository: Path, challenge: Path, signature: Path
        ) -> tuple[dict[str, object], dict[str, object]]:
            raise possession.UpdaterKeyPossessionError("signature rejected")

        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError, "signature rejected"
        ):
            possession.create_possession_proof(
                self.fixture.repository,
                source_identity_reader=self.fixture.source_reader,
                embedded_verifier=rejecting_verifier,
                process_runner=self.fixture.signer,
            )

        self.assertFalse(self.fixture.proof_root.exists())
        self.assertFalse(
            any(
                path.name.startswith(possession.TEMPORARY_PREFIX)
                for path in self.fixture.profiles_root.iterdir()
            )
        )

    def test_residual_temporary_directory_blocks_signing_without_cleanup(self) -> None:
        residual = self.fixture.profiles_root / f"{possession.TEMPORARY_PREFIX}orphan"
        residual.mkdir(mode=0o700)

        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError, "residual.*requires review"
        ):
            self.fixture.create()

        self.assertTrue(residual.is_dir())
        self.assertFalse(self.fixture.proof_root.exists())
        self.assertEqual(self.fixture.signer_calls, [])

    def test_profiles_directory_permissions_fail_before_signing(self) -> None:
        self.fixture.profiles_root.chmod(0o755)

        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError, "owned 0700"
        ):
            self.fixture.create()

        self.assertEqual(self.fixture.signer_calls, [])

    def test_parent_fsync_loss_is_fail_closed_and_existing_proof_is_recoverable(
        self,
    ) -> None:
        original_fsync = durable_file.fsync_locked_directory
        parent_fsync_calls = 0

        def lose_post_rename_reply(descriptor: int, path: Path) -> None:
            nonlocal parent_fsync_calls
            if path == self.fixture.profiles_root:
                parent_fsync_calls += 1
                if parent_fsync_calls == 2:
                    raise PublicationError("simulated post-rename parent fsync loss")
            original_fsync(descriptor, path)

        with (
            patch.object(
                durable_file,
                "fsync_locked_directory",
                side_effect=lose_post_rename_reply,
            ),
            self.assertRaisesRegex(
                possession.UpdaterKeyPossessionError,
                "securely create or atomically publish",
            ),
        ):
            self.fixture.create()

        self.assertTrue(self.fixture.proof_root.is_dir())
        verified = self.fixture.verify()
        self.assertRegex(verified.proof_sha256, r"^[0-9a-f]{64}$")
        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError, "atomically publish"
        ):
            self.fixture.create()

    def test_source_or_preflight_drift_invalidates_proof(self) -> None:
        self.fixture.create()

        def changed_source(repository: Path) -> dict[str, str]:
            return {
                "repositoryCommit": "6" * 40,
                "releaseSourceSha256": "7" * 64,
            }

        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError, "fixed GA inputs"
        ):
            self.fixture.verify(source_reader=changed_source)

        self.fixture.signing_preflight.write_bytes(
            canonical_json(
                {
                    "document": "fixture-signing-preflight-v1",
                    "result": "changed",
                    "schema_version": 1,
                }
            )
        )
        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError, "fixed GA inputs"
        ):
            self.fixture.verify()

    def test_challenge_signature_and_receipts_are_cryptographically_bound(self) -> None:
        for name in (
            possession.CHALLENGE_NAME,
            possession.SIGNATURE_NAME,
            possession.VERIFICATION_NAME,
            possession.VERIFIER_BINDING_NAME,
            possession.PROOF_NAME,
        ):
            with self.subTest(name=name):
                fixture = PossessionFixture()
                self.addCleanup(fixture.cleanup)
                fixture.create()
                path = fixture.proof_root / name
                data = path.read_bytes()
                path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
                path.chmod(0o600)
                with self.assertRaises(possession.UpdaterKeyPossessionError):
                    fixture.verify()

    def test_noncanonical_or_duplicate_json_is_rejected(self) -> None:
        self.fixture.create()
        proof = self.fixture.proof_root / possession.PROOF_NAME
        value = json.loads(proof.read_bytes())
        proof.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        proof.chmod(0o600)
        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError, "canonical JSON"
        ):
            self.fixture.verify()

        fixture = PossessionFixture()
        self.addCleanup(fixture.cleanup)
        fixture.create()
        challenge = fixture.proof_root / possession.CHALLENGE_NAME
        original = challenge.read_text(encoding="utf-8")
        duplicate = original.replace(
            '"document":', '"document":"duplicate","document":', 1
        )
        challenge.write_text(duplicate, encoding="utf-8")
        challenge.chmod(0o600)
        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError, "repeats field"
        ):
            fixture.verify()

    def test_unsafe_directory_entries_fail_closed(self) -> None:
        mutations = ("extra", "mode", "directory-mode", "symlink", "hardlink")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                fixture = PossessionFixture()
                self.addCleanup(fixture.cleanup)
                fixture.create()
                signature = fixture.proof_root / possession.SIGNATURE_NAME
                if mutation == "extra":
                    extra = fixture.proof_root / "unexpected"
                    extra.write_bytes(b"unexpected")
                    extra.chmod(0o600)
                elif mutation == "mode":
                    signature.chmod(0o644)
                elif mutation == "directory-mode":
                    fixture.proof_root.chmod(0o755)
                elif mutation == "symlink":
                    signature.unlink()
                    signature.symlink_to(possession.CHALLENGE_NAME)
                else:
                    replacement = fixture.profiles_root / "hardlink-source"
                    replacement.write_bytes(b"hardlinked-signature")
                    replacement.chmod(0o600)
                    signature.unlink()
                    os.link(replacement, signature)
                with self.assertRaisesRegex(
                    possession.UpdaterKeyPossessionError,
                    "unsafe or incomplete",
                ):
                    fixture.verify()

    def test_builder_creates_proof_after_final_input_checks_before_freeze(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        script = (repository / "scripts/build_signed_candidate.sh").read_text(
            encoding="utf-8"
        )
        final_source_check = script.index(
            'die "release source identity changed while the GA candidate was building"'
        )
        signing_plan_check = script.index(
            '"$repo_root/scripts/release_signing_plan.py" verify-preflight',
            final_source_check,
        )
        possession_create = script.index(
            '"$repo_root/scripts/updater_key_possession_proof.py" create',
            signing_plan_check,
        )
        candidate_freeze = script.index(
            '"$repo_root/scripts/candidate_freeze.py" freeze', possession_create
        )
        self.assertLess(final_source_check, signing_plan_check)
        self.assertLess(signing_plan_check, possession_create)
        self.assertLess(possession_create, candidate_freeze)


if __name__ == "__main__":
    unittest.main()
