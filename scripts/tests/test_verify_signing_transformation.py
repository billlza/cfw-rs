from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts.candidate_freeze import FrozenCandidate
from scripts.hash_artifact import build_manifest
from scripts.publication import durable_file
from scripts.publication.common import PublicationError
from scripts import verify_signing_transformation as transformation


ADHOC_SIGNATURE_SUFFIX = b"\nTEST-LINKER-ADHOC-SIGNATURE"
DEVELOPER_ID_SIGNATURE_SUFFIX = b"\nTEST-DEVELOPER-ID-SIGNATURE"


class SigningTransformationFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name).resolve()
        self.root = (
            self.repository / "target/candidates/0.4.0/ga/40032"
        )
        self.pre_sign_app = self.root / transformation.PRE_SIGN_APP_RELATIVE
        self.signing_output = (
            self.root / "transactions/signing-attempts/00000001/work"
        )
        self.signing_output.mkdir(parents=True, mode=0o700)
        self.signing_output.chmod(0o700)
        self.signed_app = (
            self.signing_output / transformation.SIGNED_APP_WITHIN_OUTPUT
        )
        self.intent_path = self.root / "candidate-freeze/intent.json"
        self.calls: list[tuple[str, ...]] = []
        self._create_profiles()
        self._create_app(self.pre_sign_app)
        self._sign_fixture_app(ADHOC_SIGNATURE_SUFFIX, "adhoc")
        self._write_pre_sign_manifest()
        shutil.copytree(self.pre_sign_app, self.signed_app, symlinks=True)
        self._sign_fixture_app(DEVELOPER_ID_SIGNATURE_SUFFIX, "developer-id")
        self._embed_profiles()
        self._write_intent()

    def cleanup(self) -> None:
        self.temporary.cleanup()

    def _create_profiles(self) -> None:
        profiles = self.root / "profiles"
        profiles.mkdir(parents=True)
        for role, (relative, _embedded) in transformation.PROFILE_BINDINGS.items():
            path = self.root / relative
            path.write_bytes(f"{role}-profile\n".encode("ascii"))
            path.chmod(0o644)

    @staticmethod
    def _code_payload(path: Path) -> Path:
        return path / ".test-code" if path.is_dir() else path

    def _create_app(self, app: Path) -> None:
        (app / "Contents/Resources").mkdir(parents=True)
        (app / "Contents/Resources/config.json").write_bytes(b'{"fixed":true}\n')
        for relative in transformation.CODE_OBJECTS:
            path = app if relative == "." else app.joinpath(*Path(relative).parts)
            if relative in transformation.DIRECTORY_CODE_OBJECTS:
                path.mkdir(parents=True, exist_ok=True)
                if relative != "." and (
                    relative.endswith("CFWProxyAgent.app")
                    or relative.endswith(".systemextension")
                ):
                    (path / "Contents").mkdir()
                payload = path / ".test-code"
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                payload = path
            payload.write_bytes(f"unsigned:{relative}\n".encode("ascii"))
            payload.chmod(0o755)

    def _write_pre_sign_manifest(self) -> None:
        metadata = {
            "artifactKind": "pre-sign-application-v1",
            "buildNumber": "40032",
            "version": "0.4.0",
        }
        value = build_manifest(
            self.pre_sign_app,
            metadata=metadata,
            algorithm="sha256-tree-v1",
        )
        path = self.root / transformation.PRE_SIGN_MANIFEST_RELATIVE
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)

    def _sign_fixture_app(self, suffix: bytes, label: str) -> None:
        app = self.pre_sign_app if label == "adhoc" else self.signed_app
        for relative in transformation.CODE_OBJECTS:
            path = (
                app
                if relative == "."
                else app.joinpath(*Path(relative).parts)
            )
            payload = self._code_payload(path)
            data = payload.read_bytes()
            for existing in (
                ADHOC_SIGNATURE_SUFFIX,
                DEVELOPER_ID_SIGNATURE_SUFFIX,
            ):
                if data.endswith(existing):
                    data = data[: -len(existing)]
            payload.write_bytes(data + suffix)
            if path.is_dir() and label == "developer-id":
                signature = path / "_CodeSignature"
                signature.mkdir(exist_ok=True)
                (signature / "CodeResources").write_bytes(
                    f"{label}:{relative}\n".encode("ascii")
                )

    def _embed_profiles(self) -> None:
        for source_relative, embedded_relative in transformation.PROFILE_BINDINGS.values():
            source = self.root / source_relative
            embedded = self.signed_app.joinpath(*Path(embedded_relative).parts)
            embedded.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, embedded)

    def _write_intent(self) -> None:
        value = {
            "build_number": "40032",
            "consumption_state": "candidate_frozen_consumed",
            "document": "cfm-candidate-freeze-intent-v3",
            "pre_sign_app_tree_sha256": "a" * 64,
            "product_version": "0.4.0",
            "schema_version": 3,
        }
        self.intent_path.parent.mkdir(mode=0o700)
        self.intent_path.write_bytes(transformation.canonical_json(value))
        self.intent_path.chmod(0o600)

    def freeze_verifier(self, repository: Path) -> FrozenCandidate:
        if repository != self.repository:
            raise AssertionError(f"unexpected repository: {repository}")
        return FrozenCandidate(
            root=self.root,
            intent_path=self.intent_path,
            intent_sha256=hashlib.sha256(self.intent_path.read_bytes()).hexdigest(),
            product_version="0.4.0",
            build_number="40032",
            recovered=False,
        )

    def codesign_runner(self, command: tuple[str, ...], repository: Path) -> None:
        if repository != self.repository:
            raise AssertionError(f"unexpected repository: {repository}")
        if command[:2] != ("/usr/bin/codesign", "--remove-signature"):
            raise AssertionError(f"unexpected command: {command}")
        path = Path(command[2])
        self.calls.append(command)
        payload = self._code_payload(path)
        data = payload.read_bytes()
        for suffix in (
            ADHOC_SIGNATURE_SUFFIX,
            DEVELOPER_ID_SIGNATURE_SUFFIX,
        ):
            if data.endswith(suffix):
                payload.write_bytes(data[: -len(suffix)])
                break
        signature = path / "_CodeSignature" if path.is_dir() else None
        if signature is not None and signature.exists():
            shutil.rmtree(signature)

    def create(self) -> dict[str, object]:
        return transformation.create_attempt_receipt(
            self.repository,
            self.signing_output,
            codesign_runner=self.codesign_runner,
            freeze_verifier=self.freeze_verifier,
        )

    def verify(self) -> dict[str, object]:
        return transformation.verify_attempt_receipt(
            self.repository,
            self.signing_output,
            codesign_runner=self.codesign_runner,
            freeze_verifier=self.freeze_verifier,
        )


class SigningTransformationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = SigningTransformationFixture()
        self.addCleanup(self.fixture.cleanup)
        durability = patch.object(durable_file, "full_fsync", side_effect=os.fsync)
        durability.start()
        self.addCleanup(durability.stop)

    def test_signature_only_macho_seam_publishes_and_reopens_fixed_receipt(self) -> None:
        receipt = self.fixture.create()
        receipt_path = self.fixture.signing_output / transformation.RECEIPT_NAME
        self.assertEqual(receipt["document"], transformation.DOCUMENT)
        self.assertEqual(tuple(receipt["code_objects"]), transformation.CODE_OBJECTS)
        self.assertEqual(
            tuple(receipt["removed_signed_profiles"]),
            transformation.EMBEDDED_PROFILE_PATHS,
        )
        self.assertEqual(receipt["pre_sign_app_tree_sha256"], "a" * 64)
        self.assertRegex(receipt["signed_app_tree_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(receipt["normalized_app_tree_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            receipt["normalized_app_tree_sha256"],
            build_manifest(self.fixture.pre_sign_app, algorithm="sha256-tree-v2")[
                "sha256"
            ],
        )
        expected_profiles = {
            role: hashlib.sha256((self.fixture.root / source).read_bytes()).hexdigest()
            for role, (source, _embedded) in transformation.PROFILE_BINDINGS.items()
        }
        self.assertEqual(receipt["profiles"], expected_profiles)
        self.assertEqual(receipt_path.read_bytes(), transformation.canonical_json(receipt))
        self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(receipt_path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(len(self.fixture.calls), 24)
        for offset in range(0, 24, 6):
            observed = self.fixture.calls[offset : offset + 6]
            self.assertEqual(
                tuple(
                    "."
                    if Path(command[2]).name == "Clash for Mac.app"
                    else next(
                        relative
                        for relative in transformation.CODE_OBJECTS
                        if relative != "." and command[2].endswith(relative)
                    )
                    for command in observed
                ),
                transformation.CODE_OBJECTS,
            )
        self.assertEqual(self.fixture.verify(), receipt)

    def test_resource_tampering_is_not_a_signing_transformation(self) -> None:
        (self.fixture.signed_app / "Contents/Resources/config.json").write_bytes(
            b'{"fixed":false}\n'
        )
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "outside signatures and profiles",
        ):
            self.fixture.create()

    def test_executable_tampering_is_not_hidden_by_signature_removal(self) -> None:
        authority = self.fixture.signed_app.joinpath(
            *Path(transformation.CODE_OBJECTS[1]).parts
        )
        authority.write_bytes(
            b"different-executable" + DEVELOPER_ID_SIGNATURE_SUFFIX
        )
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "outside signatures and profiles",
        ):
            self.fixture.create()

    def test_extra_missing_and_wrong_profiles_fail_closed(self) -> None:
        cases = ("extra", "missing", "wrong")
        for case in cases:
            with self.subTest(case=case):
                fixture = SigningTransformationFixture()
                try:
                    if case == "extra":
                        extra = (
                            fixture.signed_app
                            / "Contents/Resources/embedded.provisionprofile"
                        )
                        extra.write_bytes(b"extra-profile")
                    elif case == "missing":
                        missing = fixture.signed_app.joinpath(
                            *Path(transformation.EMBEDDED_PROFILE_PATHS[0]).parts
                        )
                        missing.unlink()
                    else:
                        wrong = fixture.signed_app.joinpath(
                            *Path(transformation.EMBEDDED_PROFILE_PATHS[1]).parts
                        )
                        wrong.write_bytes(b"wrong-profile")
                    with self.assertRaisesRegex(
                        transformation.SigningTransformationError,
                        "profiles|profile differs",
                    ):
                        transformation.create_attempt_receipt(
                            fixture.repository,
                            fixture.signing_output,
                            codesign_runner=fixture.codesign_runner,
                            freeze_verifier=fixture.freeze_verifier,
                        )
                finally:
                    fixture.cleanup()

    def test_fixed_code_object_symlink_is_rejected(self) -> None:
        authority = self.fixture.signed_app.joinpath(
            *Path(transformation.CODE_OBJECTS[1]).parts
        )
        target = authority.with_name("authority-target")
        authority.rename(target)
        authority.symlink_to(target.name)
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "code object is unsafe",
        ):
            self.fixture.create()

    def test_pre_sign_manifest_drift_is_rejected(self) -> None:
        manifest_path = self.fixture.root / transformation.PRE_SIGN_MANIFEST_RELATIVE
        original_manifest = manifest_path.read_bytes()
        for build_number in ("40030", "40031"):
            manifest = json.loads(original_manifest)
            manifest["metadata"]["buildNumber"] = build_number
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            try:
                with self.subTest(
                    build_number=build_number
                ), self.assertRaisesRegex(
                    transformation.SigningTransformationError,
                    "manifest identity is invalid",
                ):
                    self.fixture.create()
            finally:
                manifest_path.write_bytes(original_manifest)

    def test_receipt_tamper_is_rejected_on_reopen(self) -> None:
        receipt = self.fixture.create()
        receipt["normalized_app_tree_sha256"] = "f" * 64
        path = self.fixture.signing_output / transformation.RECEIPT_NAME
        path.write_bytes(transformation.canonical_json(receipt))
        path.chmod(0o600)
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "differs from the current exact GA apps",
        ):
            self.fixture.verify()

    def test_receipt_symlink_is_rejected(self) -> None:
        self.fixture.create()
        receipt = self.fixture.signing_output / transformation.RECEIPT_NAME
        target = receipt.with_name("receipt-target.json")
        receipt.rename(target)
        receipt.symlink_to(target.name)
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "cannot durably reopen",
        ):
            self.fixture.verify()

    def test_duplicate_publication_never_replaces_receipt(self) -> None:
        first = self.fixture.create()
        path = self.fixture.signing_output / transformation.RECEIPT_NAME
        original = path.read_bytes()
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "already exists",
        ):
            self.fixture.create()
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(first, json.loads(original))

    def test_input_drift_after_publication_never_returns_success(self) -> None:
        original_write = transformation._write_receipt

        def write_then_mutate(
            repository: Path, signing_output: Path, data: bytes
        ) -> None:
            original_write(repository, signing_output, data)
            resource = self.fixture.signed_app / "Contents/Resources/config.json"
            resource.write_bytes(b'{"changed-after-compose":true}\n')

        with (
            patch.object(
                transformation,
                "_write_receipt",
                side_effect=write_then_mutate,
            ),
            self.assertRaisesRegex(
                transformation.SigningTransformationError,
                "outside signatures and profiles",
            ),
        ):
            self.fixture.create()

        receipt = self.fixture.signing_output / transformation.RECEIPT_NAME
        self.assertTrue(receipt.is_file())
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "outside signatures and profiles",
        ):
            self.fixture.verify()

    def test_parent_fsync_reply_loss_is_outcome_unknown_and_recoverable(self) -> None:
        with (
            patch.object(
                durable_file,
                "fsync_locked_directory",
                side_effect=PublicationError("simulated parent fsync loss"),
            ),
            self.assertRaisesRegex(
                transformation.SigningTransformationOutcomeUnknown,
                "outcome is unknown",
            ),
        ):
            self.fixture.create()
        receipt = self.fixture.signing_output / transformation.RECEIPT_NAME
        self.assertTrue(receipt.is_file())
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "already exists",
        ):
            self.fixture.create()
        self.assertEqual(self.fixture.verify()["document"], transformation.DOCUMENT)

    def test_partial_crash_receipt_is_quarantined_and_never_replaced(self) -> None:
        receipt = self.fixture.signing_output / transformation.RECEIPT_NAME
        receipt.write_bytes(b'{"document":')
        receipt.chmod(0o600)
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "strict JSON",
        ):
            self.fixture.verify()
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "already exists",
        ):
            self.fixture.create()
        self.assertEqual(receipt.read_bytes(), b'{"document":')

    def test_codesign_failure_blocks_receipt_creation(self) -> None:
        def reject(_command: tuple[str, ...], _repository: Path) -> None:
            raise transformation.SigningTransformationError("codesign failed")

        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "codesign failed",
        ):
            transformation.create_attempt_receipt(
                self.fixture.repository,
                self.fixture.signing_output,
                codesign_runner=reject,
                freeze_verifier=self.fixture.freeze_verifier,
            )
        self.assertFalse(
            (self.fixture.signing_output / transformation.RECEIPT_NAME).exists()
        )

    def test_canonical_receipt_verifies_after_atomic_container_publication(self) -> None:
        receipt = self.fixture.create()
        canonical = self.fixture.root / transformation.SIGNING_OUTPUT_RELATIVE
        self.fixture.signing_output.rename(canonical)
        self.fixture.signing_output = canonical
        self.fixture.signed_app = canonical / transformation.SIGNED_APP_WITHIN_OUTPUT
        self.assertEqual(
            transformation.verify_receipt(
                self.fixture.repository,
                codesign_runner=self.fixture.codesign_runner,
                freeze_verifier=self.fixture.freeze_verifier,
            ),
            receipt,
        )

    def test_build_wires_signing_transaction_before_notary_submission(self) -> None:
        script = (
            Path(__file__).resolve().parents[2] / "scripts/build_signed_candidate.sh"
        ).read_text(encoding="utf-8")
        transaction = script.index('signing_attempt_transaction.py"')
        verify = script.index('verify_signing_transformation.py" verify')
        notary = script.index('"$repo_root/scripts/notarization_transaction.py"')
        helper = (
            Path(__file__).resolve().parents[2]
            / "scripts/run_ga_signing_attempt.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('"$repo_root/scripts/verify_release_app.sh"', helper)
        self.assertLess(transaction, verify)
        self.assertLess(verify, notary)


if __name__ == "__main__":
    unittest.main()
