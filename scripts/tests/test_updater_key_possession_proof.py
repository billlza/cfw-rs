from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import threading
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


class ControlledReplayLock:
    def __init__(
        self,
        *,
        pause_nonblocking_acquire: bool = False,
        pause_release: bool = False,
    ) -> None:
        self._lock = threading.Lock()
        self._control = threading.Lock()
        self._pause_nonblocking_acquire = pause_nonblocking_acquire
        self._pause_release = pause_release
        self.nonblocking_acquire_paused = threading.Event()
        self.allow_nonblocking_acquire = threading.Event()
        self.release_paused = threading.Event()
        self.allow_release = threading.Event()

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        pause = False
        if not blocking:
            with self._control:
                pause = self._pause_nonblocking_acquire
                self._pause_nonblocking_acquire = False
        if pause:
            self.nonblocking_acquire_paused.set()
            if not self.allow_nonblocking_acquire.wait(timeout=5):
                raise AssertionError(
                    "controlled replay acquire was not released"
                )
        if timeout == -1:
            return self._lock.acquire(blocking)
        return self._lock.acquire(blocking, timeout)

    def release(self) -> None:
        self._lock.release()
        with self._control:
            pause = self._pause_release
            self._pause_release = False
        if pause:
            self.release_paused.set()
            if not self.allow_release.wait(timeout=5):
                raise AssertionError(
                    "controlled replay release was not released"
                )


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
            self.repository / "target/candidates/0.4.0/ga-preflight/40043"
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
            "executable": {
                "filename": "cfw-release-verifier",
                "sha256": "5" * 64,
                "size": 451_488,
            },
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

    def _production_verifier_inputs(
        self,
    ) -> tuple[release_artifact_set.ReleaseVerifierBuild, Path, Path]:
        build = create_release_verifier_build(self.fixture.repository)
        challenge = self.fixture.repository / "production-challenge.json"
        signature = self.fixture.repository / "production-challenge.json.sig"
        challenge.write_bytes(b'{"fixed":"challenge"}\n')
        signature.write_bytes(b"fixture-signature\n")
        return build, challenge, signature

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

    def test_fresh_verifier_executable_digest_drift_rejects_exact_replay(
        self,
    ) -> None:
        self.fixture.create()
        signer_calls = list(self.fixture.signer_calls)
        proof_bytes = {
            path.name: path.read_bytes()
            for path in self.fixture.proof_root.iterdir()
        }

        def drifted_verifier(
            repository: Path, challenge: Path, signature: Path
        ) -> tuple[dict[str, object], dict[str, object]]:
            verification, binding = self.fixture.embedded_verifier(
                repository, challenge, signature
            )
            binding = deepcopy(binding)
            binding["executable"]["sha256"] = "8" * 64
            return verification, binding

        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError,
            "stored source-pinned release verifier binding does not replay exactly",
        ):
            possession.verify_possession_proof(
                self.fixture.repository,
                self.fixture.preflight_root,
                source_identity_reader=self.fixture.source_reader,
                embedded_verifier=drifted_verifier,
            )

        self.assertEqual(self.fixture.signer_calls, signer_calls)
        self.assertEqual(
            {
                path.name: path.read_bytes()
                for path in self.fixture.proof_root.iterdir()
            },
            proof_bytes,
        )

    def test_embedded_verification_numeric_fields_require_strict_integers(
        self,
    ) -> None:
        self.fixture.create()

        for field, changed_value in (
            ("schema_version", True),
            ("archive_size", 1.0),
            ("signature_size", 1.0),
        ):
            with self.subTest(field=field):
                def malformed_verifier(
                    repository: Path, challenge: Path, signature: Path
                ) -> tuple[dict[str, object], dict[str, object]]:
                    verification, binding = self.fixture.embedded_verifier(
                        repository, challenge, signature
                    )
                    verification = deepcopy(verification)
                    if field == "archive_size":
                        changed = float(verification[field])
                    elif field == "signature_size":
                        changed = float(verification[field])
                    else:
                        changed = changed_value
                    verification[field] = changed
                    return verification, binding

                with self.assertRaisesRegex(
                    possession.UpdaterKeyPossessionError,
                    "malformed numeric fields",
                ):
                    possession.verify_possession_proof(
                        self.fixture.repository,
                        self.fixture.preflight_root,
                        source_identity_reader=self.fixture.source_reader,
                        embedded_verifier=malformed_verifier,
                    )

    def test_release_verifier_binding_numeric_spelling_must_replay_exactly(
        self,
    ) -> None:
        self.fixture.create()

        def float_sized_verifier(
            repository: Path, challenge: Path, signature: Path
        ) -> tuple[dict[str, object], dict[str, object]]:
            verification, binding = self.fixture.embedded_verifier(
                repository, challenge, signature
            )
            binding = deepcopy(binding)
            binding["executable"]["size"] = float(
                binding["executable"]["size"]
            )
            return verification, binding

        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError,
            "release verifier binding does not replay exactly",
        ):
            possession.verify_possession_proof(
                self.fixture.repository,
                self.fixture.preflight_root,
                source_identity_reader=self.fixture.source_reader,
                embedded_verifier=float_sized_verifier,
            )

    def test_proof_artifact_size_requires_one_strict_json_integer(self) -> None:
        self.fixture.create()
        proof_path = self.fixture.proof_root / possession.PROOF_NAME
        proof = json.loads(proof_path.read_bytes())
        record = proof["embedded_verification"]
        record["size"] = float(record["size"])
        proof_path.write_bytes(canonical_json(proof))
        proof_path.chmod(0o600)

        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError,
            "embedded verification record binds different bytes",
        ):
            self.fixture.verify()

    def test_production_source_pinned_verifier_binding_is_rebuilt_and_validated(
        self,
    ) -> None:
        build, challenge, signature = self._production_verifier_inputs()

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

    def test_production_session_compiles_once_for_three_real_replays(
        self,
    ) -> None:
        build, challenge, signature = self._production_verifier_inputs()
        compile_calls = 0

        @contextmanager
        def compiled(repository: Path):
            nonlocal compile_calls
            self.assertEqual(repository, self.fixture.repository)
            compile_calls += 1
            yield build

        real_invoke = release_artifact_set._invoke_release_verifier
        real_state_verifier = (
            release_artifact_set._verify_updater_verification_session_state
        )
        with (
            patch.object(
                release_artifact_set,
                "_compiled_release_verifier",
                compiled,
            ),
            patch.object(
                release_artifact_set,
                "_invoke_release_verifier",
                wraps=real_invoke,
            ) as invocation,
            patch.object(
                release_artifact_set,
                "_verify_updater_verification_session_state",
                wraps=real_state_verifier,
            ) as state_verifier,
            verified_cargo_fixture(build),
        ):
            environment_before = dict(os.environ)
            with possession.production_embedded_verifier_session(
                self.fixture.repository
            ) as verifier:
                first_verification, first_binding = verifier(
                    self.fixture.repository, challenge, signature
                )
                original_executable_sha256 = first_binding["executable"][
                    "sha256"
                ]
                first_binding["executable"]["sha256"] = "8" * 64
                second_verification, second_binding = verifier(
                    self.fixture.repository, challenge, signature
                )
                third_verification, third_binding = verifier(
                    self.fixture.repository, challenge, signature
                )
                escaped_verifier = verifier
            self.assertEqual(dict(os.environ), environment_before)

        self.assertEqual(compile_calls, 1)
        self.assertEqual(invocation.call_count, 3)
        self.assertEqual(state_verifier.call_count, 8)
        self.assertEqual(first_verification, second_verification)
        self.assertEqual(second_verification, third_verification)
        self.assertEqual(second_binding, third_binding)
        self.assertEqual(
            second_binding["executable"]["sha256"],
            original_executable_sha256,
        )
        self.assertIsNot(first_binding, second_binding)
        self.assertIsNot(
            first_binding["executable"], second_binding["executable"]
        )
        with self.assertRaisesRegex(
            possession.UpdaterKeyPossessionError,
            "source-pinned embedded updater-key verification failed",
        ):
            escaped_verifier(self.fixture.repository, challenge, signature)

    def test_failed_session_replay_is_not_retried_and_cleans_build_scope(
        self,
    ) -> None:
        build, challenge, signature = self._production_verifier_inputs()
        build_scope = self.fixture.repository / "fixture-verifier-build-scope"

        @contextmanager
        def compiled(repository: Path):
            self.assertEqual(repository, self.fixture.repository)
            build_scope.mkdir(mode=0o700)
            try:
                yield build
            finally:
                shutil.rmtree(build_scope)

        with (
            patch.object(
                release_artifact_set,
                "_compiled_release_verifier",
                compiled,
            ),
            patch.object(
                release_artifact_set,
                "_invoke_release_verifier",
                side_effect=release_artifact_set.ArtifactSetError(
                    "fixture verifier execution failed"
                ),
            ) as invocation,
            verified_cargo_fixture(build),
        ):
            with possession.production_embedded_verifier_session(
                self.fixture.repository
            ) as verifier:
                with self.assertRaisesRegex(
                    possession.UpdaterKeyPossessionError,
                    "source-pinned embedded updater-key verification failed",
                ) as first_failure:
                    verifier(self.fixture.repository, challenge, signature)
                with self.assertRaisesRegex(
                    possession.UpdaterKeyPossessionError,
                    "source-pinned embedded updater-key verification failed",
                ) as poisoned_failure:
                    verifier(self.fixture.repository, challenge, signature)

        self.assertEqual(invocation.call_count, 1)
        self.assertNotIsInstance(
            first_failure.exception,
            possession.UpdaterKeyPossessionOperationalError,
        )
        self.assertNotIsInstance(
            poisoned_failure.exception,
            possession.UpdaterKeyPossessionOperationalError,
        )
        self.assertFalse(build_scope.exists())

    def test_failed_replay_poisons_state_before_another_thread_can_enter(
        self,
    ) -> None:
        build, challenge, signature = self._production_verifier_inputs()
        controlled_replay_lock = ControlledReplayLock(pause_release=True)
        first_errors: list[BaseException] = []

        @contextmanager
        def compiled(repository: Path):
            self.assertEqual(repository, self.fixture.repository)
            yield build

        def run_first_replay(verifier: possession.EmbeddedVerifier) -> None:
            try:
                verifier(self.fixture.repository, challenge, signature)
            except BaseException as error:
                first_errors.append(error)

        with (
            patch.object(
                release_artifact_set,
                "_compiled_release_verifier",
                compiled,
            ),
            patch.object(
                release_artifact_set,
                "_new_updater_verification_session_lock",
                side_effect=(threading.Lock(), controlled_replay_lock),
            ),
            patch.object(
                release_artifact_set,
                "_invoke_release_verifier",
                side_effect=release_artifact_set.ArtifactSetError(
                    "fixture verifier execution failed"
                ),
            ) as invocation,
            verified_cargo_fixture(build),
        ):
            with possession.production_embedded_verifier_session(
                self.fixture.repository
            ) as verifier:
                replay = threading.Thread(
                    target=run_first_replay,
                    args=(verifier,),
                    daemon=True,
                )
                replay.start()
                try:
                    self.assertTrue(
                        controlled_replay_lock.release_paused.wait(timeout=2)
                    )
                    with self.assertRaisesRegex(
                        possession.UpdaterKeyPossessionError,
                        "source-pinned embedded updater-key verification failed",
                    ) as concurrent_failure:
                        verifier(
                            self.fixture.repository, challenge, signature
                        )
                    self.assertEqual(invocation.call_count, 1)
                    self.assertNotIsInstance(
                        concurrent_failure.exception,
                        possession.UpdaterKeyPossessionOperationalError,
                    )
                finally:
                    controlled_replay_lock.allow_release.set()
                    replay.join(timeout=5)
                self.assertFalse(replay.is_alive())

        self.assertEqual(len(first_errors), 1)
        self.assertIsInstance(
            first_errors[0], possession.UpdaterKeyPossessionError
        )
        self.assertEqual(invocation.call_count, 1)

    def test_session_exit_closes_gate_before_waiting_replay_can_enter(
        self,
    ) -> None:
        build, challenge, signature = self._production_verifier_inputs()
        build_scope = self.fixture.repository / "fixture-verifier-build-scope"
        controlled_replay_lock = ControlledReplayLock(
            pause_nonblocking_acquire=True
        )
        replay_errors: list[BaseException] = []

        @contextmanager
        def compiled(repository: Path):
            self.assertEqual(repository, self.fixture.repository)
            build_scope.mkdir(mode=0o700)
            try:
                yield build
            finally:
                shutil.rmtree(build_scope)

        def run_replay(verifier: possession.EmbeddedVerifier) -> None:
            try:
                verifier(self.fixture.repository, challenge, signature)
            except BaseException as error:
                replay_errors.append(error)

        with (
            patch.object(
                release_artifact_set,
                "_compiled_release_verifier",
                compiled,
            ),
            patch.object(
                release_artifact_set,
                "_new_updater_verification_session_lock",
                side_effect=(threading.Lock(), controlled_replay_lock),
            ),
            patch.object(
                release_artifact_set,
                "_invoke_release_verifier",
                wraps=release_artifact_set._invoke_release_verifier,
            ) as invocation,
            verified_cargo_fixture(build),
        ):
            manager = possession.production_embedded_verifier_session(
                self.fixture.repository
            )
            verifier = manager.__enter__()
            replay = threading.Thread(
                target=run_replay,
                args=(verifier,),
                daemon=True,
            )
            replay.start()
            try:
                self.assertTrue(
                    controlled_replay_lock.nonblocking_acquire_paused.wait(
                        timeout=2
                    )
                )
                self.assertFalse(manager.__exit__(None, None, None))
                self.assertFalse(build_scope.exists())
            finally:
                controlled_replay_lock.allow_nonblocking_acquire.set()
                replay.join(timeout=5)
            self.assertFalse(replay.is_alive())

        self.assertEqual(invocation.call_count, 0)
        self.assertEqual(len(replay_errors), 1)
        self.assertIsInstance(
            replay_errors[0], possession.UpdaterKeyPossessionError
        )

    def test_session_exit_waits_for_inflight_replay_before_cleanup(
        self,
    ) -> None:
        build, challenge, signature = self._production_verifier_inputs()
        build_scope = self.fixture.repository / "fixture-verifier-build-scope"
        invocation_started = threading.Event()
        allow_invocation = threading.Event()
        exit_started = threading.Event()
        exit_finished = threading.Event()
        replay_errors: list[BaseException] = []
        exit_errors: list[BaseException] = []
        real_invoke = release_artifact_set._invoke_release_verifier

        @contextmanager
        def compiled(repository: Path):
            self.assertEqual(repository, self.fixture.repository)
            build_scope.mkdir(mode=0o700)
            try:
                yield build
            finally:
                shutil.rmtree(build_scope)

        def blocked_invoke(*args: object, **kwargs: object):
            invocation_started.set()
            if not allow_invocation.wait(timeout=5):
                raise AssertionError("blocked verifier invocation was not released")
            return real_invoke(*args, **kwargs)

        def run_replay(verifier: possession.EmbeddedVerifier) -> None:
            try:
                verifier(self.fixture.repository, challenge, signature)
            except BaseException as error:
                replay_errors.append(error)

        with (
            patch.object(
                release_artifact_set,
                "_compiled_release_verifier",
                compiled,
            ),
            patch.object(
                release_artifact_set,
                "_invoke_release_verifier",
                side_effect=blocked_invoke,
            ) as invocation,
            verified_cargo_fixture(build),
        ):
            manager = possession.production_embedded_verifier_session(
                self.fixture.repository
            )
            verifier = manager.__enter__()

            def close_session() -> None:
                exit_started.set()
                try:
                    manager.__exit__(None, None, None)
                except BaseException as error:
                    exit_errors.append(error)
                finally:
                    exit_finished.set()

            replay = threading.Thread(
                target=run_replay,
                args=(verifier,),
                daemon=True,
            )
            closer = threading.Thread(target=close_session, daemon=True)
            replay.start()
            self.assertTrue(invocation_started.wait(timeout=2))
            closer.start()
            try:
                self.assertTrue(exit_started.wait(timeout=2))
                self.assertFalse(exit_finished.wait(timeout=0.1))
                self.assertTrue(build_scope.exists())
                with self.assertRaisesRegex(
                    possession.UpdaterKeyPossessionError,
                    "source-pinned embedded updater-key verification failed",
                ):
                    verifier(self.fixture.repository, challenge, signature)
            finally:
                allow_invocation.set()
                replay.join(timeout=5)
                closer.join(timeout=5)
            self.assertFalse(replay.is_alive())
            self.assertFalse(closer.is_alive())

        self.assertEqual(invocation.call_count, 1)
        self.assertEqual(replay_errors, [])
        self.assertEqual(exit_errors, [])
        self.assertTrue(exit_finished.is_set())
        self.assertFalse(build_scope.exists())

    def test_operational_replay_failure_has_one_allowlisted_typed_code(
        self,
    ) -> None:
        build, challenge, signature = self._production_verifier_inputs()

        @contextmanager
        def compiled(repository: Path):
            self.assertEqual(repository, self.fixture.repository)
            yield build

        for reason in sorted(
            release_artifact_set.RELEASE_VERIFIER_OPERATIONAL_REASONS
        ):
            with (
                self.subTest(reason=reason),
                patch.object(
                    release_artifact_set,
                    "_compiled_release_verifier",
                    compiled,
                ),
                patch.object(
                    release_artifact_set,
                    "_invoke_release_verifier",
                    side_effect=(
                        release_artifact_set.ReleaseVerifierOperationalError(
                            reason, "fixture verifier execution"
                        )
                    ),
                ),
                verified_cargo_fixture(build),
            ):
                with possession.production_embedded_verifier_session(
                    self.fixture.repository
                ) as verifier:
                    with self.assertRaises(
                        possession.UpdaterKeyPossessionOperationalError
                    ) as raised:
                        verifier(
                            self.fixture.repository, challenge, signature
                        )
            self.assertEqual(
                raised.exception.code,
                possession.EMBEDDED_VERIFIER_UNAVAILABLE,
            )
            self.assertEqual(raised.exception.reason, reason)

    def test_operational_build_failure_has_the_same_typed_code(self) -> None:
        build, _challenge, _signature = self._production_verifier_inputs()

        @contextmanager
        def unavailable(_repository: Path):
            raise release_artifact_set.ReleaseVerifierOperationalError(
                "timeout", "fixture verifier build"
            )
            yield build

        with (
            patch.object(
                release_artifact_set,
                "_compiled_release_verifier",
                unavailable,
            ),
            verified_cargo_fixture(build),
            self.assertRaises(
                possession.UpdaterKeyPossessionOperationalError
            ) as raised,
        ):
            with possession.production_embedded_verifier_session(
                self.fixture.repository
            ):
                raise AssertionError("unavailable verifier session was entered")

        self.assertEqual(
            raised.exception.code,
            possession.EMBEDDED_VERIFIER_UNAVAILABLE,
        )
        self.assertEqual(raised.exception.reason, "timeout")

    def test_session_rejects_reentrant_replay_and_cleans_build_scope(
        self,
    ) -> None:
        build, challenge, signature = self._production_verifier_inputs()
        build_scope = self.fixture.repository / "fixture-verifier-build-scope"
        active_verifier: dict[str, possession.EmbeddedVerifier] = {}

        @contextmanager
        def compiled(repository: Path):
            self.assertEqual(repository, self.fixture.repository)
            build_scope.mkdir(mode=0o700)
            try:
                yield build
            finally:
                shutil.rmtree(build_scope)

        def reenter(
            _build: release_artifact_set.ReleaseVerifierBuild,
            repository: Path,
            archive: Path,
            archive_signature: Path,
        ) -> dict[str, object]:
            active_verifier["value"](
                repository, archive, archive_signature
            )
            raise AssertionError("reentrant verifier unexpectedly returned")

        with (
            patch.object(
                release_artifact_set,
                "_compiled_release_verifier",
                compiled,
            ),
            patch.object(
                release_artifact_set,
                "_invoke_release_verifier",
                side_effect=reenter,
            ) as invocation,
            verified_cargo_fixture(build),
        ):
            with possession.production_embedded_verifier_session(
                self.fixture.repository
            ) as verifier:
                active_verifier["value"] = verifier
                with self.assertRaisesRegex(
                    possession.UpdaterKeyPossessionError,
                    "source-pinned embedded updater-key verification failed",
                ):
                    verifier(self.fixture.repository, challenge, signature)

        self.assertEqual(invocation.call_count, 1)
        self.assertFalse(build_scope.exists())

    def test_session_rejects_verification_input_drift_and_cleans_build_scope(
        self,
    ) -> None:
        build, challenge, signature = self._production_verifier_inputs()
        build_scope = self.fixture.repository / "fixture-verifier-build-scope"
        real_invoke = release_artifact_set._invoke_release_verifier

        @contextmanager
        def compiled(repository: Path):
            self.assertEqual(repository, self.fixture.repository)
            build_scope.mkdir(mode=0o700)
            try:
                yield build
            finally:
                shutil.rmtree(build_scope)

        def mutate_after_verification(*args: object, **kwargs: object):
            receipt = real_invoke(*args, **kwargs)
            challenge.write_bytes(b'{"changed":"after-verification"}\n')
            return receipt

        with (
            patch.object(
                release_artifact_set,
                "_compiled_release_verifier",
                compiled,
            ),
            patch.object(
                release_artifact_set,
                "_invoke_release_verifier",
                side_effect=mutate_after_verification,
            ) as invocation,
            verified_cargo_fixture(build),
            self.assertRaisesRegex(
                possession.UpdaterKeyPossessionError,
                "source-pinned embedded updater-key verification failed",
            ) as raised,
        ):
            with possession.production_embedded_verifier_session(
                self.fixture.repository
            ) as verifier:
                verifier(self.fixture.repository, challenge, signature)

        self.assertEqual(invocation.call_count, 1)
        self.assertNotIsInstance(
            raised.exception,
            possession.UpdaterKeyPossessionOperationalError,
        )
        self.assertIsInstance(
            raised.exception.__cause__, release_artifact_set.ArtifactSetError
        )
        self.assertIn(
            "updater archive or signature changed during embedded-key verification",
            str(raised.exception.__cause__),
        )
        self.assertFalse(build_scope.exists())

    def test_session_exit_revalidates_source_inputs_and_cleans_build_scope(
        self,
    ) -> None:
        build, challenge, signature = self._production_verifier_inputs()
        build_scope = self.fixture.repository / "fixture-verifier-build-scope"

        @contextmanager
        def compiled(repository: Path):
            self.assertEqual(repository, self.fixture.repository)
            build_scope.mkdir(mode=0o700)
            try:
                yield build
            finally:
                shutil.rmtree(build_scope)

        with (
            patch.object(
                release_artifact_set,
                "_compiled_release_verifier",
                compiled,
            ),
            verified_cargo_fixture(build),
            self.assertRaisesRegex(
                possession.UpdaterKeyPossessionError,
                "source-pinned embedded updater-key verification failed",
            ) as raised,
        ):
            with possession.production_embedded_verifier_session(
                self.fixture.repository
            ) as verifier:
                verifier(self.fixture.repository, challenge, signature)
                (self.fixture.repository / "Cargo.toml").write_text(
                    "[workspace]\nmembers = []\n",
                    encoding="utf-8",
                )

        self.assertIsInstance(
            raised.exception.__cause__, release_artifact_set.ArtifactSetError
        )
        self.assertNotIsInstance(
            raised.exception,
            possession.UpdaterKeyPossessionOperationalError,
        )
        self.assertIn(
            "release verifier source inputs changed during verification",
            str(raised.exception.__cause__),
        )
        self.assertFalse(build_scope.exists())

    def test_frozen_root_verification_uses_the_same_proof(self) -> None:
        created = self.fixture.create()
        frozen_root = self.fixture.repository / "target/candidates/0.4.0/ga/40043"
        frozen_root.parent.mkdir(parents=True)
        self.fixture.preflight_root.rename(frozen_root)

        verified = possession.verify_possession_proof(
            self.fixture.repository,
            frozen_root,
            source_identity_reader=self.fixture.source_reader,
            embedded_verifier=self.fixture.embedded_verifier,
        )

        self.assertEqual(verified.proof_sha256, created.proof_sha256)

    def test_retired_roots_are_not_active_candidates(self) -> None:
        verifier_calls = list(self.fixture.verifier_calls)
        for build_number in ("40037", "40038"):
            retired_root = (
                self.fixture.repository
                / f"target/candidates/0.4.0/ga/{build_number}"
            )

            with self.subTest(build_number=build_number), self.assertRaisesRegex(
                possession.UpdaterKeyPossessionError,
                "not a fixed GA candidate root",
            ):
                possession.verify_possession_proof(
                    self.fixture.repository,
                    retired_root,
                    source_identity_reader=self.fixture.source_reader,
                    embedded_verifier=self.fixture.embedded_verifier,
                )

        self.assertEqual(self.fixture.verifier_calls, verifier_calls)

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
