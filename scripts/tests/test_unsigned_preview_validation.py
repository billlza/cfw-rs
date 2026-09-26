from __future__ import annotations

import json
import os
import sys
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

from scripts import native_ui_artifact as ui
from scripts import release_build_identity as identity
from scripts.hash_artifact import build_manifest
from scripts.promote_signed_native_manifest import promote_manifest, SignedNativeManifestError


class UnsignedPreviewValidationTests(unittest.TestCase):
    def pair(self, repository: Path, *, build="50000", version="0.5.0"):
        native = identity.unsigned_preview_native_products_root(repository)
        native.mkdir(parents=True)
        app = identity.unsigned_preview_root(repository) / "cargo/release/bundle/macos/Clash for Mac.app"
        for relative in ("Contents/Info.plist", "Contents/Frameworks/CFWNativeBridge.framework/Versions/A/Resources/Info.plist",
                         "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/Info.plist",
                         "Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension/Contents/Info.plist"):
            path = app / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(plistlib.dumps({"CFBundleShortVersionString": version, "CFBundleVersion": build}))
            path.chmod(0o644)
        return app, native

    def test_one_unsigned_preview_pair_is_accepted_and_every_other_context_rejects_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            app, native = self.pair(repository)
            expected = identity.CandidateBundleContext.UNSIGNED_PREVIEW_HOST
            result = identity.candidate_bundle_verification_paths(repository, app, native, expected)
            self.assertEqual(result.build_identity, identity.BundleBuildIdentity("0.5.0", "50000"))
            for context in identity.CandidateBundleContext:
                if context is expected:
                    continue
                with self.subTest(context=context), self.assertRaises(identity.BuildIdentityError):
                    identity.candidate_bundle_verification_paths(repository, app, native, context)
            for classifier in (identity.candidate_signing_output, identity.preview_signing_output):
                with self.assertRaises(identity.BuildIdentityError):
                    classifier(repository, native)

    def test_new_context_refuses_wrong_or_mixed_component_identity(self):
        for build, version in (("40000", "0.5.0"), ("40073", "0.5.0"), ("50013", "0.5.0"), ("50014", "0.5.0"), ("50015", "0.5.0"), ("50016", "0.5.0"), ("50000", "0.4.0")):
            with self.subTest(build=build, version=version), tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary).resolve()
                app, native = self.pair(repository, build=build, version=version)
                with self.assertRaises(identity.BuildIdentityError):
                    identity.candidate_bundle_verification_paths(repository, app, native, identity.CandidateBundleContext.UNSIGNED_PREVIEW_HOST)
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            app, native = self.pair(repository)
            info = app / "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/Info.plist"
            info.write_bytes(plistlib.dumps({"CFBundleShortVersionString": "0.5.0", "CFBundleVersion": "50016"}))
            with self.assertRaisesRegex(identity.BuildIdentityError, "build versions differ"):
                identity.candidate_bundle_verification_paths(repository, app, native, identity.CandidateBundleContext.UNSIGNED_PREVIEW_HOST)

    def test_build_and_root_cross_matrix_remains_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            roots = {
                "40000": repository / "target/candidates/0.4.0/unsigned/native-products",
                "40073": identity.ga_pre_sign_native_products_root(repository),
                "50000": identity.unsigned_preview_native_products_root(repository),
                "50016": identity.preview_native_products_root(repository),
            }
            for build, expected in roots.items():
                for declared, root in roots.items():
                    with self.subTest(build=build, root=declared):
                        if declared == build:
                            self.assertEqual(identity.candidate_native_products_output(repository, str(root), build), expected)
                        else:
                            with self.assertRaises(identity.BuildIdentityError):
                                identity.candidate_native_products_output(repository, str(root), build)

    def test_unsigned_and_production_modes_reject_cross_role_builds_before_tool_calls(self):
        for build, signing, context in (
            ("50000", "pre-sign", ui.NativeUiContext.SIGNED_PREVIEW),
            ("50000", "developer-id", ui.NativeUiContext.UNSIGNED_PREVIEW_VALIDATION),
            ("50000", "pre-sign", ui.NativeUiContext.UNSIGNED_PREVIEW_VALIDATION),
            ("50013", "pre-sign", ui.NativeUiContext.SIGNED_PREVIEW),
            ("50014", "pre-sign", ui.NativeUiContext.SIGNED_PREVIEW),
            ("50015", "pre-sign", ui.NativeUiContext.SIGNED_PREVIEW),
            ("50017", "pre-sign", ui.NativeUiContext.SIGNED_PREVIEW),
            ("50013", "unsigned-validation", ui.NativeUiContext.UNSIGNED_PREVIEW_VALIDATION),
            ("50014", "unsigned-validation", ui.NativeUiContext.UNSIGNED_PREVIEW_VALIDATION),
            ("50015", "unsigned-validation", ui.NativeUiContext.UNSIGNED_PREVIEW_VALIDATION),
            ("50016", "unsigned-validation", ui.NativeUiContext.UNSIGNED_PREVIEW_VALIDATION),
            ("40000", "unsigned-validation", ui.NativeUiContext.UNSIGNED_PREVIEW_VALIDATION),
        ):
            with self.subTest(build=build, signing=signing, context=context), patch.object(ui, "command") as tool:
                with self.assertRaises(ui.NativeUiArtifactError):
                    ui.expected_metadata(Path("/never-read"), build, signing=signing, clean=False, context=context)
                tool.assert_not_called()
        identity.require_native_product_build_mode("50000", "unsigned-validation")
        identity.require_native_product_build_mode("50016", "pre-sign")
        for build, mode in (("50000", "pre-sign"), ("50016", "unsigned-validation")):
            with self.assertRaises(identity.BuildIdentityError):
                identity.require_native_product_build_mode(build, mode)

    def test_ui_unsigned_context_uses_closed_validation_identity_and_production_refuses_selectors(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            (repository / "scripts").mkdir()
            (repository / "scripts/dependency_pins.env").write_text("XCODE_VERSION=27.0\nXCODE_BUILD_VERSION=27A266a\n")
            with patch("scripts.apple_validation_policy.unsigned_runtime_apple_identity", return_value=("27.0", "27A5252f")) as admission, \
                 patch.object(ui, "command", return_value="Xcode 27.0\nBuild version 27A5252f\n"), \
                 patch.object(ui, "source_digest", return_value="a" * 64), \
                 patch.object(ui, "current_identity", return_value={"repositoryCommit": "b" * 40, "releaseSourceSha256": "c" * 64}), \
                 patch.object(ui, "swift_compiler_version", return_value="observed Swift"):
                value = ui.expected_metadata(repository, "50000", signing="unsigned-validation", clean=False,
                                             context=ui.NativeUiContext.UNSIGNED_PREVIEW_VALIDATION)
                self.assertEqual(value["buildNumber"], "50000")
                self.assertEqual(value["signingMode"], "unsigned-validation")
                self.assertEqual(value["xcodeBuildVersion"], "27A5252f")
                admission.assert_called_once()
            for selector in ({"CFW_UNSIGNED_VALIDATION_PYTHON": sys.executable},
                             {"CFW_UNSIGNED_VALIDATION_XCODE_VERSION": "27.0", "CFW_UNSIGNED_VALIDATION_XCODE_BUILD_VERSION": "27A266a"}):
                with self.subTest(selector=selector), patch.dict(os.environ, selector, clear=True), patch.object(ui, "command") as tool:
                    with self.assertRaisesRegex(ui.NativeUiArtifactError, "refuses unsigned-validation"):
                        ui.expected_metadata(repository, "50016", signing="pre-sign", clean=False)
                    tool.assert_not_called()

    def test_unsigned_intermediate_directory_symlink_is_rejected_before_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            parent = repository / "target/candidates/0.5.0"
            parent.mkdir(parents=True)
            outside = repository / "outside"
            outside.mkdir()
            (parent / "unsigned").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(identity.BuildIdentityError, "ancestor is not a real directory"):
                identity.candidate_native_products_output(repository, str(identity.unsigned_preview_native_products_root(repository)), "50000")
            self.assertEqual(list(outside.iterdir()), [])

    def test_unsigned_native_manifest_cannot_be_promoted_by_the_signing_transform(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            native = repository / "before/library"
            signed = repository / "after/library"
            native.parent.mkdir()
            signed.parent.mkdir()
            native.write_bytes(b"test bytes")
            signed.write_bytes(b"test bytes")
            manifest = repository / "manifest.json"
            manifest.write_text(json.dumps(build_manifest(native, {"signingMode": "unsigned-validation", "buildNumber": "50000"})))
            with self.assertRaisesRegex(SignedNativeManifestError, "pre-sign native metadata"):
                promote_manifest(native, manifest, signed)


if __name__ == "__main__":
    unittest.main()
