from __future__ import annotations

import json
from pathlib import Path
import plistlib
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts import native_ui_artifact as ui
from scripts.hash_artifact import build_manifest
from scripts.promote_signed_native_manifest import promote_manifest, SignedNativeManifestError


def load_commands(*paths: str, name: str = ui.INSTALL_NAME) -> str:
    value = f"cmd LC_ID_DYLIB\ncmdsize 64\nname {name} (offset 24)\n"
    return value + "".join(f"cmd LC_RPATH\ncmdsize 80\npath {path} (offset 12)\n" for path in paths)


def linked(*dependencies: str) -> str:
    return "library:\n" + "".join(f"\t{name} (compatibility version 0.0.0)\n" for name in (ui.INSTALL_NAME, *dependencies))


def resources(root: Path) -> None:
    base = root / "Contents/Resources"
    base.mkdir(parents=True)
    (root / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleDevelopmentRegion": "en", "CFBundlePackageType": "BNDL",
        "CFBundleName": "CFMNativeDashboard_CFMNativeDashboard", "CFBundleSupportedPlatforms": ["MacOSX"],
        "LSMinimumSystemVersion": "15.0",
    }))
    for locale in ui.LOCALES:
        directory = base / (locale + ".lproj")
        directory.mkdir()
        (directory / "Localizable.strings").write_text('"key" = "value";\n')


class NativeUiArtifactTests(unittest.TestCase):
    def test_build_paths_and_unresolved_loader_dependencies_are_rejected(self) -> None:
        good = load_commands("/usr/lib/swift", "@loader_path")
        dependencies = linked("/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/SwiftUI.framework/SwiftUI")
        ui.verify_load_paths(good, dependencies)
        for invalid in (
            load_commands("/Applications/Xcode.app/toolchain/lib"),
            load_commands("/tmp/debug"), load_commands("@executable_path/../../outside"),
            load_commands("@loader_path", "@loader_path"),
            load_commands(name="/tmp/libCFMNativeDashboard.dylib"),
        ):
            with self.subTest(commands=invalid), self.assertRaises(ui.NativeUiArtifactError):
                ui.verify_load_paths(invalid, dependencies)
        for invalid in ("/tmp/other.dylib", "@rpath/unpackaged.dylib", "/usr/lib/../outside.dylib"):
            with self.subTest(dependency=invalid), self.assertRaises(ui.NativeUiArtifactError):
                ui.verify_load_paths(good, linked(invalid))

    def test_only_the_pinned_compiler_search_path_is_normalized_before_signing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            library = Path(temporary) / ui.LIBRARY
            library.write_bytes(b"test Mach-O calls are mocked at tool boundary")
            library.chmod(0o755)
            compiler_root = "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr"
            compiler_path = compiler_root + "/lib/swift-6.2/macosx"
            calls = []
            def tool(arguments):
                calls.append(arguments)
                if arguments[1:2] == ["--find"]:
                    return compiler_root + "/bin/swift\n"
                if arguments[1:2] == ["-l"]:
                    return load_commands("/usr/lib/swift", "@loader_path", compiler_path)
                return ""
            with patch.object(ui, "command", side_effect=tool), patch.object(ui, "verify_library") as verify:
                ui.remove_build_rpaths(library)
            self.assertIn(["/usr/bin/codesign", "--remove-signature", str(library)], calls)
            self.assertIn(["/usr/bin/install_name_tool", "-delete_rpath", compiler_path, str(library)], calls)
            verify.assert_called_once_with(library)
            calls.clear()
            with patch.object(ui, "command", side_effect=lambda args: compiler_root + "/bin/swift\n" if "--find" in args else load_commands("/tmp/injected")):
                with self.assertRaisesRegex(ui.NativeUiArtifactError, "unexpected Swift compiler"):
                    ui.remove_build_rpaths(library)

    def test_resource_bundle_requires_all_languages_and_no_external_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / ui.RESOURCES
            resources(bundle)
            ui.verify_resources(bundle)
            ja = bundle / "Contents/Resources/ja.lproj/Localizable.strings"
            ja.unlink()
            with self.assertRaises(FileNotFoundError):
                ui.verify_resources(bundle)
            outside = Path(temporary) / "outside.strings"
            outside.write_text("outside")
            ja.symlink_to(outside)
            with self.assertRaises(ui.NativeUiArtifactError):
                ui.verify_resources(bundle)

    def test_signed_products_retain_pre_sign_binding_and_unchanged_resources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            pre_sign = repository / "pre-sign"
            signed = repository / "signed"
            pre_sign.mkdir()
            signed.mkdir()
            (pre_sign / ui.LIBRARY).write_bytes(b"pre-sign fixture library")
            (pre_sign / ui.LIBRARY).chmod(0o755)
            resources(pre_sign / ui.RESOURCES)
            metadata = {key: "bound" for key in ui.METADATA_KEYS}
            metadata.update(configuration="release", buildNumber="50001", productVersion="0.5.0", signingMode="pre-sign")
            for name in (ui.LIBRARY, ui.RESOURCES):
                (pre_sign / (name + ".manifest.json")).write_text(json.dumps(build_manifest(pre_sign / name, metadata)))
                if (pre_sign / name).is_dir():
                    shutil.copytree(pre_sign / name, signed / name)
                else:
                    shutil.copy2(pre_sign / name, signed / name)
            # The codesign operation is outside this manifest-unit test. Its
            # modified library is a fixture; real signing is verified separately.
            (signed / ui.LIBRARY).write_bytes(b"signed fixture library")
            def manifests():
                for name in (ui.LIBRARY, ui.RESOURCES):
                    value = promote_manifest(pre_sign / name, pre_sign / (name + ".manifest.json"), signed / name)
                    (signed / (name + ".manifest.json")).write_text(json.dumps(value))
            manifests()
            def expected(_repository, _build, *, signing, clean):
                return {**metadata, "signingMode": signing}
            with patch.object(ui, "expected_metadata", side_effect=expected), patch.object(ui, "verify_library"), patch(
                "scripts.release_build_identity.preview_native_products_root", return_value=pre_sign
            ):
                ui.verify_products(repository, signed, build="50001", signing="developer-id")
                manifest = signed / (ui.LIBRARY + ".manifest.json")
                bad = json.loads(manifest.read_text())
                bad["metadata"]["preSignArtifactSha256"] = "0" * 64
                manifest.write_text(json.dumps(bad))
                with self.assertRaisesRegex(SignedNativeManifestError, "exact pre-sign promotion"):
                    ui.verify_products(repository, signed, build="50001", signing="developer-id")
                manifests()
                (signed / ui.RESOURCES / "Contents/Resources/en.lproj/Localizable.strings").write_text('"key" = "modified";')
                manifests()
                with self.assertRaisesRegex(ui.NativeUiArtifactError, "must not modify"):
                    ui.verify_products(repository, signed, build="50001", signing="developer-id")

    def test_source_digest_covers_real_abi_and_library_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            for relative in ui.SOURCE_PATHS:
                path = repository / relative
                if relative.endswith(("Sources", "include")):
                    path.mkdir(parents=True)
                    (path / "entry").write_text("initial")
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("source")
            before = ui.source_digest(repository)
            header = repository / "native/dashboard/include/entry"
            header.write_text("ABI changed")
            self.assertNotEqual(before, ui.source_digest(repository))
            header.unlink()
            header.symlink_to(repository / "scripts/build_native_ui.sh")
            with self.assertRaises(ui.NativeUiArtifactError):
                ui.source_digest(repository)

    def test_manifest_rejects_debug_provenance_and_changed_library_or_resources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            library = root / ui.LIBRARY
            library.write_bytes(b"unsigned test fixture")
            library.chmod(0o755)
            resources(root / ui.RESOURCES)
            metadata = {key: "bound" for key in ui.METADATA_KEYS}
            metadata.update(configuration="release", buildNumber="50001", productVersion="0.5.0")
            for name in (ui.LIBRARY, ui.RESOURCES):
                (root / (name + ".manifest.json")).write_text(json.dumps(build_manifest(root / name, metadata)))
            with patch.object(ui, "expected_metadata", return_value=metadata), patch.object(ui, "verify_library"):
                ui.verify_products(root, root, build="50001")
                manifest = root / (ui.LIBRARY + ".manifest.json")
                good = manifest.read_text()
                bad = json.loads(good)
                bad["metadata"]["configuration"] = "debug"
                manifest.write_text(json.dumps(bad))
                with self.assertRaisesRegex(ui.NativeUiArtifactError, "Release inputs"):
                    ui.verify_products(root, root, build="50001")
                manifest.write_text(good)
                library.write_bytes(b"different library")
                with self.assertRaisesRegex(ui.NativeUiArtifactError, "bytes differ"):
                    ui.verify_products(root, root, build="50001")
                library.write_bytes(b"unsigned test fixture")
                (root / ui.RESOURCES / "Contents/Resources/en.lproj/Localizable.strings").write_text('"key" = "changed";')
                with self.assertRaisesRegex(ui.NativeUiArtifactError, "bytes differ"):
                    ui.verify_products(root, root, build="50001")


if __name__ == "__main__":
    unittest.main()
