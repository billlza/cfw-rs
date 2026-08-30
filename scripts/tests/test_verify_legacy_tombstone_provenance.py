from __future__ import annotations

from contextlib import redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts.hash_artifact import build_manifest
from scripts.promote_signed_native_manifest import promote_manifest
from scripts import verify_legacy_tombstone_provenance as provenance


class LegacyTombstoneProvenanceTests(unittest.TestCase):
    BUILD_NUMBER = "40037"
    DEPLOYMENT_TARGET = "15.0"
    RUST_VERSION = "1.97.1"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name).resolve()
        source_root = self.repository / "crates/cfw-legacy-tombstone"
        (source_root / "src").mkdir(parents=True)
        (source_root / "src/main.rs").write_text("fn main() {}\n", encoding="utf-8")
        (source_root / "Cargo.toml").write_text(
            '[package]\nname = "cfw-legacy-tombstone"\nversion = "0.4.0"\n',
            encoding="utf-8",
        )
        (self.repository / "Cargo.lock").write_text(
            "version = 4\n", encoding="utf-8"
        )

        ga_root = (
            self.repository
            / "target/candidates/0.4.0/ga"
            / self.BUILD_NUMBER
        )
        self.pre_sign_root = ga_root / "native-products"
        self.unsigned = self.pre_sign_root / provenance.ARTIFACT_NAME
        self.unsigned.mkdir(parents=True)
        self.unsigned_binary = self.unsigned / provenance.BINARY_NAME
        self.unsigned_binary.write_bytes(b"safe unsigned tombstone")
        self.unsigned_binary.chmod(0o755)
        self.unsigned_manifest = self.pre_sign_root / provenance.MANIFEST_NAME

        transactions = ga_root / "transactions"
        attempts = transactions / "signing-attempts"
        attempt = attempts / "00000001"
        self.attempt_output = attempt / "work"
        signing_input = self.attempt_output / "signing-input"
        self.signed_root = self.attempt_output / "signed-native-products"
        for private_directory in (
            transactions,
            attempts,
            attempt,
            self.attempt_output,
            signing_input,
            self.signed_root,
        ):
            private_directory.mkdir(parents=True, exist_ok=True)
            private_directory.chmod(0o700)
        self.signed = self.signed_root / provenance.ARTIFACT_NAME
        self.signed.mkdir()
        self.signed_binary = self.signed / provenance.BINARY_NAME
        self.signed_binary.write_bytes(b"safe unsigned tombstone\nsignature envelope")
        self.signed_binary.chmod(0o755)
        self.signed_manifest = self.signed_root / provenance.MANIFEST_NAME
        self.embedded_app = signing_input / "Clash for Mac.app"
        self.bundle_plists = (
            self.embedded_app / "Contents/Info.plist",
            self.embedded_app
            / "Contents/Frameworks/CFWNativeBridge.framework/Versions/A/Resources/Info.plist",
            self.embedded_app
            / "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/Info.plist",
            self.embedded_app
            / "Contents/Library/SystemExtensions/"
            "com.bill.clashformac.packet-tunnel.systemextension/Contents/Info.plist",
        )
        self.write_bundle_identity(self.BUILD_NUMBER)
        self.embedded_binary = (
            self.embedded_app
            / "Contents/Library/HelperTools"
            / provenance.BINARY_NAME
        )
        self.embedded_binary.parent.mkdir(parents=True)
        self.embedded_binary.write_bytes(self.signed_binary.read_bytes())
        self.embedded_binary.chmod(0o755)
        self.write_pre_sign_manifest()
        self.write_signed_manifest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def digest(self, relative: str) -> str:
        return hashlib.sha256((self.repository / relative).read_bytes()).hexdigest()

    def write_bundle_identity(self, build_number: str) -> None:
        value = {
            "CFBundleShortVersionString": "0.4.0",
            "CFBundleVersion": build_number,
        }
        for path in self.bundle_plists:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(plistlib.dumps(value, sort_keys=True))
            path.chmod(0o644)

    def base_metadata(self) -> dict[str, str]:
        return {
            "architecture": "arm64",
            "artifactKind": "legacy-service-tombstone-v1",
            "buildNumber": self.BUILD_NUMBER,
            "cargoLockSha256": self.digest("Cargo.lock"),
            "cargoManifestSha256": self.digest(
                "crates/cfw-legacy-tombstone/Cargo.toml"
            ),
            "deploymentTarget": self.DEPLOYMENT_TARGET,
            "rustVersion": self.RUST_VERSION,
            "signingMode": "pre-sign",
            "sourceSha256": self.digest(
                "crates/cfw-legacy-tombstone/src/main.rs"
            ),
        }

    def write_pre_sign_manifest(
        self,
        metadata: dict[str, str] | None = None,
        *,
        algorithm: str = "sha256-tree-v1",
    ) -> None:
        value = build_manifest(
            self.unsigned,
            metadata=self.base_metadata() if metadata is None else metadata,
            algorithm=algorithm,
        )
        self.unsigned_manifest.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def write_signed_manifest(self) -> None:
        value = promote_manifest(
            self.unsigned,
            self.unsigned_manifest,
            self.signed,
        )
        self.signed_manifest.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def verify(
        self,
        *,
        build_number: str | None = None,
        unsigned_artifact: Path | None = None,
        unsigned_manifest: Path | None = None,
        signed_artifact: Path | None = None,
        signed_manifest: Path | None = None,
        embedded_app: Path | None = None,
        context: provenance.CandidateBundleContext = (
            provenance.CandidateBundleContext.SIGNING_ATTEMPT_WORK
        ),
    ) -> dict[str, object]:
        return provenance.verify_legacy_tombstone_provenance(
            self.repository,
            build_number=self.BUILD_NUMBER if build_number is None else build_number,
            deployment_target=self.DEPLOYMENT_TARGET,
            rust_version=self.RUST_VERSION,
            unsigned_artifact=(
                self.unsigned if unsigned_artifact is None else unsigned_artifact
            ),
            unsigned_manifest=(
                self.unsigned_manifest
                if unsigned_manifest is None
                else unsigned_manifest
            ),
            signed_artifact=(
                self.signed if signed_artifact is None else signed_artifact
            ),
            signed_manifest=(
                self.signed_manifest if signed_manifest is None else signed_manifest
            ),
            embedded_app=(
                self.embedded_app if embedded_app is None else embedded_app
            ),
            context=context,
        )

    def cli_arguments(self) -> list[str]:
        return [
            "--repository",
            str(self.repository),
            "--build-number",
            self.BUILD_NUMBER,
            "--deployment-target",
            self.DEPLOYMENT_TARGET,
            "--rust-version",
            self.RUST_VERSION,
            "--pre-sign-artifact",
            str(self.unsigned),
            "--pre-sign-manifest",
            str(self.unsigned_manifest),
            "--signed-artifact",
            str(self.signed),
            "--signed-manifest",
            str(self.signed_manifest),
            "--embedded-app",
            str(self.embedded_app),
            "--context",
            provenance.CandidateBundleContext.SIGNING_ATTEMPT_WORK.value,
        ]

    def test_exact_production_promotion_is_accepted(self) -> None:
        value = self.verify()

        metadata = value["metadata"]
        self.assertEqual(
            set(metadata),
            set(self.base_metadata())
            | {"preSignArtifactSha256", "preSignManifestSha256"},
        )
        self.assertEqual(metadata["signingMode"], "developer-id")

    def test_all_signed_candidate_contexts_accept_exact_bound_copies(self) -> None:
        publish_ready = self.attempt_output.with_name("publish-ready")
        shutil.copytree(self.attempt_output, publish_ready)
        ready_app = publish_ready / "signing-input/Clash for Mac.app"
        ready_native = publish_ready / "signed-native-products"

        active_ga_root = self.pre_sign_root.parent
        canonical_output = active_ga_root / "signing-output"
        canonical_native = canonical_output / "signed-native-products"
        canonical_output.mkdir(mode=0o700)
        canonical_native.mkdir(mode=0o700)
        shutil.copytree(
            self.signed,
            canonical_native / provenance.ARTIFACT_NAME,
        )
        shutil.copy2(
            self.signed_manifest,
            canonical_native / provenance.MANIFEST_NAME,
        )
        canonical_app_root = active_ga_root / "signed"
        canonical_app_root.mkdir()
        canonical_app = canonical_app_root / "Clash for Mac.app"
        shutil.copytree(self.embedded_app, canonical_app)

        cases = (
            (
                provenance.CandidateBundleContext.SIGNING_ATTEMPT_PUBLISH_READY,
                ready_app,
                ready_native,
            ),
            (
                provenance.CandidateBundleContext.CANONICAL_NATIVE_CONTENT,
                canonical_app,
                canonical_native,
            ),
        )
        for context, app, native_root in cases:
            with self.subTest(context=context):
                value = self.verify(
                    signed_artifact=native_root / provenance.ARTIFACT_NAME,
                    signed_manifest=native_root / provenance.MANIFEST_NAME,
                    embedded_app=app,
                    context=context,
                )

                self.assertEqual(value["root"], provenance.ARTIFACT_NAME)

    def test_pre_sign_inputs_must_use_the_fixed_native_products_root(self) -> None:
        alternate_root = self.pre_sign_root.parent / "alternate-native-products"
        alternate_root.mkdir()
        alternate_artifact = alternate_root / provenance.ARTIFACT_NAME
        alternate_manifest = alternate_root / provenance.MANIFEST_NAME
        shutil.copytree(self.unsigned, alternate_artifact)
        shutil.copy2(self.unsigned_manifest, alternate_manifest)

        with self.assertRaisesRegex(
            provenance.LegacyTombstoneProvenanceError,
            "pre-sign native-products root is not the fixed active GA root",
        ):
            self.verify(
                unsigned_artifact=alternate_artifact,
                unsigned_manifest=alternate_manifest,
            )

    def test_exact_promoted_lineage_is_required(self) -> None:
        for field in ("preSignArtifactSha256", "preSignManifestSha256"):
            with self.subTest(field=field):
                self.write_signed_manifest()
                value = json.loads(self.signed_manifest.read_bytes())
                value["metadata"][field] = "0" * 64
                self.signed_manifest.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaisesRegex(
                    provenance.LegacyTombstoneProvenanceError,
                    "promotion lineage is invalid: signed native manifest differs",
                ):
                    self.verify()

    def test_candidate_bundle_binding_rejects_untrusted_app_inputs(self) -> None:
        relative_app = Path(os.path.relpath(self.embedded_app, Path.cwd()))
        arbitrary_app = self.repository / "arbitrary/Clash for Mac.app"
        shutil.copytree(self.embedded_app, arbitrary_app)
        cases = (
            (
                self.signed,
                provenance.CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                "candidate application name is invalid",
            ),
            (
                arbitrary_app,
                provenance.CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                "outside the fixed active GA root",
            ),
            (
                relative_app,
                provenance.CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                "canonical absolute path",
            ),
            (
                self.embedded_app,
                provenance.CandidateBundleContext.SIGNING_ATTEMPT_PUBLISH_READY,
                "do not share one exact output",
            ),
        )
        for embedded_app, context, diagnostic in cases:
            with self.subTest(embedded_app=embedded_app, context=context):
                with self.assertRaisesRegex(
                    provenance.LegacyTombstoneProvenanceError,
                    diagnostic,
                ):
                    self.verify(embedded_app=embedded_app, context=context)

        with self.assertRaisesRegex(
            provenance.LegacyTombstoneProvenanceError,
            "requires one signed candidate bundle context",
        ):
            self.verify(context=provenance.CandidateBundleContext.UNSIGNED_HOST)

        missing_plist = self.bundle_plists[-1]
        plist_contents = missing_plist.read_bytes()
        missing_plist.unlink()
        try:
            with self.assertRaisesRegex(
                provenance.LegacyTombstoneProvenanceError,
                "candidate bundle binding is invalid",
            ):
                self.verify()
        finally:
            missing_plist.write_bytes(plist_contents)

    def test_arbitrary_same_name_binary_cannot_replace_the_bound_app_binary(
        self,
    ) -> None:
        decoy = self.repository / "decoy" / provenance.BINARY_NAME
        decoy.parent.mkdir()
        decoy.write_bytes(b"arbitrary same-name decoy")
        decoy.chmod(0o755)

        value = self.verify()

        self.assertEqual(value["root"], provenance.ARTIFACT_NAME)

    def test_cli_rejects_the_removed_arbitrary_binary_argument(self) -> None:
        arguments = self.cli_arguments() + [
            "--embedded-binary",
            str(self.signed_binary),
        ]
        diagnostics = io.StringIO()

        with redirect_stderr(diagnostics), self.assertRaises(SystemExit) as raised:
            provenance.main(arguments)

        self.assertEqual(raised.exception.code, 2)
        self.assertIn(
            "unrecognized arguments: --embedded-binary",
            diagnostics.getvalue(),
        )

    def test_cli_rejects_noncanonical_spelling_for_every_path_argument(self) -> None:
        for value_index in (1, 9, 11, 13, 15, 17):
            with self.subTest(value_index=value_index):
                arguments = self.cli_arguments()
                arguments[value_index] += "/./"
                diagnostics = io.StringIO()

                with redirect_stderr(diagnostics), self.assertRaises(
                    SystemExit
                ) as raised:
                    provenance.main(arguments)

                self.assertEqual(raised.exception.code, 2)
                self.assertIn(
                    "release path must be one canonical absolute path",
                    diagnostics.getvalue(),
                )

    def test_build_number_must_match_the_bound_candidate_app(self) -> None:
        metadata = self.base_metadata()
        metadata["buildNumber"] = "40034"
        self.write_pre_sign_manifest(metadata)
        self.write_signed_manifest()

        with self.assertRaisesRegex(
            provenance.LegacyTombstoneProvenanceError,
            "build number differs from the bound candidate application",
        ):
            self.verify(build_number="40034")

    def test_retired_candidate_build_is_rejected_even_when_coherent(self) -> None:
        for build_number in ("40034", "40035", "40036"):
            with self.subTest(build_number=build_number):
                metadata = self.base_metadata()
                metadata["buildNumber"] = build_number
                self.write_pre_sign_manifest(metadata)
                self.write_signed_manifest()
                self.write_bundle_identity(build_number)

                with self.assertRaisesRegex(
                    provenance.LegacyTombstoneProvenanceError,
                    "not the fixed active GA identity",
                ):
                    self.verify(build_number=build_number)

    def test_current_source_and_lock_bindings_are_required(self) -> None:
        mutations = {
            "sourceSha256": "source binding is invalid",
            "cargoManifestSha256": "Cargo manifest binding is invalid",
            "cargoLockSha256": "Cargo.lock binding is invalid",
        }
        for field, diagnostic in mutations.items():
            with self.subTest(field=field):
                metadata = self.base_metadata()
                metadata[field] = "0" * 64
                self.write_pre_sign_manifest(metadata)
                self.write_signed_manifest()
                with self.assertRaisesRegex(
                    provenance.LegacyTombstoneProvenanceError, diagnostic
                ):
                    self.verify()

    def test_current_source_files_cannot_drift_after_manifest_creation(self) -> None:
        mutations = {
            "crates/cfw-legacy-tombstone/src/main.rs": "source binding is invalid",
            "crates/cfw-legacy-tombstone/Cargo.toml": (
                "Cargo manifest binding is invalid"
            ),
            "Cargo.lock": "Cargo.lock binding is invalid",
        }
        for relative, diagnostic in mutations.items():
            with self.subTest(relative=relative):
                path = self.repository / relative
                original = path.read_bytes()
                path.write_bytes(original + b"# drift\n")
                try:
                    with self.assertRaisesRegex(
                        provenance.LegacyTombstoneProvenanceError,
                        diagnostic,
                    ):
                        self.verify()
                finally:
                    path.write_bytes(original)

    def test_release_identity_and_exact_field_set_are_required(self) -> None:
        mutations = ("buildNumber", "deploymentTarget", "rustVersion")
        for field in mutations:
            with self.subTest(field=field):
                metadata = self.base_metadata()
                metadata[field] = "99999" if field == "buildNumber" else "99.9"
                self.write_pre_sign_manifest(metadata)
                self.write_signed_manifest()
                with self.assertRaisesRegex(
                    provenance.LegacyTombstoneProvenanceError,
                    "release identity is invalid",
                ):
                    self.verify()

        metadata = self.base_metadata()
        metadata["unexpected"] = "value"
        self.write_pre_sign_manifest(metadata)
        self.write_signed_manifest()
        with self.assertRaisesRegex(
            provenance.LegacyTombstoneProvenanceError,
            "metadata field set is invalid",
        ):
            self.verify()

    def test_source_or_artifact_drift_is_rejected(self) -> None:
        (self.repository / "Cargo.lock").write_text(
            "version = 4\n# drift\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            provenance.LegacyTombstoneProvenanceError,
            "Cargo.lock binding is invalid",
        ):
            self.verify()

        (self.repository / "Cargo.lock").write_text(
            "version = 4\n", encoding="utf-8"
        )
        self.unsigned_binary.write_bytes(b"changed frozen input")
        self.unsigned_binary.chmod(0o755)
        with self.assertRaisesRegex(
            provenance.LegacyTombstoneProvenanceError,
            "promotion lineage is invalid",
        ):
            self.verify()

    def test_signed_artifact_drift_and_retired_markers_are_rejected(self) -> None:
        self.signed_binary.write_bytes(b"changed signed output")
        self.signed_binary.chmod(0o755)
        with self.assertRaisesRegex(
            provenance.LegacyTombstoneProvenanceError,
            "promotion lineage is invalid",
        ):
            self.verify()

        for marker in provenance.RETIRED_MARKERS:
            with self.subTest(marker=marker):
                self.signed_binary.write_bytes(b"forbidden " + marker + b" marker")
                self.signed_binary.chmod(0o755)
                self.embedded_binary.write_bytes(self.signed_binary.read_bytes())
                self.embedded_binary.chmod(0o755)
                self.write_signed_manifest()
                with self.assertRaisesRegex(
                    provenance.LegacyTombstoneProvenanceError,
                    "retired supervisor markers",
                ):
                    self.verify()

    def test_embedded_binary_must_equal_the_exact_promoted_binary(self) -> None:
        self.embedded_binary.write_bytes(
            self.signed_binary.read_bytes() + b"\nembedded drift"
        )
        self.embedded_binary.chmod(0o755)

        with self.assertRaisesRegex(
            provenance.LegacyTombstoneProvenanceError,
            "differs from the exact promoted signed binary",
        ):
            self.verify()

    def test_all_tombstone_binaries_require_exact_distribution_mode(self) -> None:
        targets = (
            (self.unsigned_binary, "pre-sign legacy tombstone binary"),
            (self.signed_binary, "signed legacy tombstone binary"),
            (self.embedded_binary, "embedded legacy tombstone binary"),
        )
        for path, label in targets:
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
            for mode in (0o644, 0o700):
                with self.subTest(path=path, mode=f"{mode:04o}"):
                    path.chmod(mode)
                    try:
                        with self.assertRaisesRegex(
                            provenance.LegacyTombstoneProvenanceError,
                            f"{label} mode is {mode:04o}, expected 0755",
                        ):
                            self.verify()
                    finally:
                        path.chmod(0o755)

        self.verify()

    def test_pre_sign_binary_and_artifact_roots_are_safe(self) -> None:
        original = self.unsigned_binary.read_bytes()
        cases = ("group-writable", "empty", "oversize", "hardlink")
        for case in cases:
            with self.subTest(case=case):
                self.unsigned_binary.write_bytes(original)
                self.unsigned_binary.chmod(0o755)
                hardlink = self.repository / "pre-sign-hardlink"
                if hardlink.exists():
                    hardlink.unlink()
                if case == "group-writable":
                    self.unsigned_binary.chmod(0o775)
                elif case == "empty":
                    self.unsigned_binary.write_bytes(b"")
                elif case == "oversize":
                    with self.unsigned_binary.open("r+b") as handle:
                        handle.truncate(provenance.MAX_SOURCE_BYTES + 1)
                else:
                    os.link(self.unsigned_binary, hardlink)
                diagnostic = (
                    "mode is 0775, expected 0755"
                    if case == "group-writable"
                    else "bounded owned single-link regular file"
                )
                try:
                    with self.assertRaisesRegex(
                        provenance.LegacyTombstoneProvenanceError,
                        diagnostic,
                    ):
                        self.verify()
                finally:
                    if hardlink.exists():
                        hardlink.unlink()

        self.unsigned_binary.write_bytes(original)
        self.unsigned_binary.chmod(0o755)
        self.unsigned.chmod(0o775)
        try:
            with self.assertRaisesRegex(
                provenance.LegacyTombstoneProvenanceError,
                "canonical owned directory",
            ):
                self.verify()
        finally:
            self.unsigned.chmod(0o755)

    def test_safe_reader_detects_open_and_read_races_and_closes(self) -> None:
        path = self.repository / "race-input"
        path.write_bytes(b"a" * (2 * 1024 * 1024))
        original_close = os.close
        closed: list[int] = []

        def closing(descriptor: int) -> None:
            closed.append(descriptor)
            original_close(descriptor)

        with (
            patch(
                "scripts.release_regular_file._file_identity",
                side_effect=[(1,), (2,)],
            ),
            patch(
                "scripts.release_regular_file.os.close",
                side_effect=closing,
            ),
        ):
            with self.assertRaisesRegex(
                provenance.LegacyTombstoneProvenanceError,
                "changed while opening",
            ):
                provenance._read_regular(path, label="race input")
        self.assertEqual(len(closed), 1)

        original_read = os.read
        linked = False

        def linking_read(descriptor: int, count: int) -> bytes:
            nonlocal linked
            chunk = original_read(descriptor, count)
            if chunk and not linked:
                linked = True
                os.link(path, self.repository / "race-hardlink")
            return chunk

        with patch(
            "scripts.release_regular_file.os.read",
            side_effect=linking_read,
        ):
            with self.assertRaisesRegex(
                provenance.LegacyTombstoneProvenanceError,
                "changed while reading",
            ):
                provenance._read_regular(path, label="race input")
        self.assertTrue(linked)

    def test_safe_reader_detects_path_rebinding(self) -> None:
        path = self.repository / "rebound-input"
        parked = self.repository / "rebound-original"
        replacement = self.repository / "rebound-replacement"
        path.write_bytes(b"a" * (2 * 1024 * 1024))
        replacement.write_bytes(b"b" * (2 * 1024 * 1024))
        original_read = os.read
        rebound = False

        def rebinding_read(descriptor: int, count: int) -> bytes:
            nonlocal rebound
            chunk = original_read(descriptor, count)
            if chunk and not rebound:
                rebound = True
                path.rename(parked)
                replacement.rename(path)
            return chunk

        with patch(
            "scripts.release_regular_file.os.read",
            side_effect=rebinding_read,
        ):
            with self.assertRaisesRegex(
                provenance.LegacyTombstoneProvenanceError,
                "changed while reading",
            ):
                provenance._read_regular(path, label="rebound input")
        self.assertTrue(rebound)

    def test_v2_tree_manifest_is_rejected(self) -> None:
        self.write_pre_sign_manifest(algorithm="sha256-tree-v2")
        self.write_signed_manifest()

        with self.assertRaisesRegex(
            provenance.LegacyTombstoneProvenanceError,
            "tree identity is invalid",
        ):
            self.verify()

    def test_additional_tree_entry_is_rejected(self) -> None:
        (self.unsigned / "unexpected").write_bytes(b"unsigned extra")
        (self.signed / "unexpected").write_bytes(b"signed extra")
        self.write_pre_sign_manifest()
        self.write_signed_manifest()

        with self.assertRaisesRegex(
            provenance.LegacyTombstoneProvenanceError,
            "tree identity is invalid",
        ):
            self.verify()


if __name__ == "__main__":
    unittest.main()
