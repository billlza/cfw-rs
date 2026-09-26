from __future__ import annotations

from contextlib import ExitStack
import io
import json
from pathlib import Path
import plistlib
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts import native_ui_artifact as ui
from scripts import release_build_identity as ids
from scripts import verify_candidate_bundle as bundle
from scripts.hash_artifact import build_manifest
from scripts.promote_signed_native_manifest import promote_manifest


def write(path: Path, data: bytes, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o755 if executable else 0o644)


def write_plist(path: Path, value: dict) -> None:
    write(path, plistlib.dumps(value))


def load_commands(*rpaths: str, install_name: str | None = None) -> str:
    identity = (
        f"cmd LC_ID_DYLIB\ncmdsize 64\nname {install_name} (offset 24)\n"
        if install_name else ""
    )
    return identity + "".join(
        f"cmd LC_RPATH\ncmdsize 80\npath {path} (offset 12)\n" for path in rpaths
    )


def linked(*dependencies: str) -> str:
    return "binary:\n" + "".join(
        f"\t{name} (compatibility version 0.0.0)\n" for name in dependencies
    )


class CandidateFixture:
    """Real file/plist/manifests; only external Mach-O and source tools are mocked."""

    def __init__(self, repository: Path, context: ids.CandidateBundleContext) -> None:
        self.repository = repository
        repository.mkdir()
        self.context = context
        self.unsigned_preview = context is ids.CandidateBundleContext.UNSIGNED_PREVIEW_HOST
        self.preview = context in bundle.PREVIEW_CONTEXTS or self.unsigned_preview
        self.version = "0.5.0" if self.preview else "0.4.0"
        self.build = "50000" if self.unsigned_preview else "50015" if self.preview else "40000"
        self.signing = "pre-sign"
        private = []
        if self.unsigned_preview:
            self.signing = "unsigned-validation"
            self.app = ids.unsigned_preview_root(repository) / "cargo/release/bundle/macos" / ids.SIGNED_APP_NAME
            self.native = ids.unsigned_preview_native_products_root(repository)
        elif context is ids.CandidateBundleContext.PREVIEW_PRE_SIGN:
            self.app = ids.preview_preflight_root(repository) / "pre-sign" / ids.SIGNED_APP_NAME
            self.native = ids.preview_native_products_root(repository)
        elif context is ids.CandidateBundleContext.UNSIGNED_HOST:
            self.app = repository / "unsigned" / ids.SIGNED_APP_NAME
            self.native = repository / "target/candidates/0.4.0/unsigned/native-products"
        elif context is ids.CandidateBundleContext.PREVIEW_CANONICAL_NATIVE_CONTENT:
            self.signing = "developer-id"
            self.app = ids.preview_root(repository) / "signed" / ids.SIGNED_APP_NAME
            self.native = ids.preview_signed_native_products_root(repository)
            private = [self.native.parent, self.native]
        else:
            self.signing = "developer-id"
            output = ids.preview_signing_attempt_output_root(repository, "00000001", context)
            self.app = output / ids.SIGNED_APP_WITHIN_OUTPUT
            self.native = output / ids.SIGNED_NATIVE_PRODUCTS_NAME
            attempts = ids.preview_signing_attempts_root(repository)
            private = [attempts.parent, attempts, output.parent, output, self.app.parent, self.native]
        self.native.mkdir(parents=True)
        self.native_metadata = {
            "libboxManifestSha256": "a" * 64, "libboxTreeSha256": "b" * 64,
            "nativeSourceSha256": "c" * 64, "releaseSourceSha256": "d" * 64,
            "repositoryCommit": "e" * 40,
        }
        self.ui_metadata = {key: "bound" for key in ui.METADATA_KEYS}
        self.ui_metadata.update(
            productVersion=self.version, buildNumber=self.build,
            configuration="release", target=ui.TRIPLE, signingMode=self.signing,
        )
        contents = self.app / "Contents"
        self.contents = contents
        common = {
            "CFBundleShortVersionString": self.version, "CFBundleVersion": self.build,
            "LSMinimumSystemVersion": "15.0",
        }
        host = {**common, "CFBundleIdentifier": bundle.EXPECTED_APP_ID, "CFBundlePackageType": "APPL"}
        agent = {
            **common, "CFBundleIdentifier": bundle.EXPECTED_AGENT_ID, "CFBundlePackageType": "APPL",
            "CFWProxyAgentMachServiceName": bundle.EXPECTED_AGENT_ID,
            "CFWProxyJournalKeychainAccessGroup": bundle.EXPECTED_AGENT_KEYCHAIN_GROUP,
            "CFWCredentialKeychainAccessGroup": bundle.EXPECTED_CREDENTIAL_KEYCHAIN_GROUP,
        }
        extension = {
            **common, "CFBundleIdentifier": bundle.EXPECTED_EXTENSION_ID, "CFBundlePackageType": "SYSX",
            "CFBundleExecutable": bundle.EXPECTED_EXTENSION_EXECUTABLE,
            "NetworkExtension": {
                "NEMachServiceName": "YKUPL7Z869.group.com.bill.clashformac.packet-tunnel",
                "NEProviderClasses": {"com.apple.networkextension.packet-tunnel": "CFWPacketTunnel.PacketTunnelProvider"},
            },
        }
        write_plist(contents / "Info.plist", host)
        write(contents / "MacOS/clash-for-mac", b"mach-o:host", executable=True)
        bridge_name = "CFWNativeBridge.framework"
        agent_name = "CFWProxyAgent.app"
        extension_name = bundle.EXPECTED_EXTENSION_WRAPPER
        bridge = contents / "Frameworks" / bridge_name
        agent_root = contents / "Library/LoginItems" / agent_name
        extension_root = contents / "Library/SystemExtensions" / extension_name
        write_plist(bridge / "Versions/A/Resources/Info.plist", common)
        write(bridge / "Versions/A/CFWNativeBridge", b"mach-o:bridge", executable=True)
        write_plist(agent_root / "Contents/Info.plist", agent)
        write(agent_root / "Contents/MacOS/CFWProxyAgent", b"mach-o:agent", executable=True)
        write_plist(extension_root / "Contents/Info.plist", extension)
        write(extension_root / "Contents/MacOS/CFWPacketTunnel", b"mach-o:extension", executable=True)
        metadata = {"buildNumber": self.build, **self.native_metadata}
        if self.unsigned_preview:
            metadata["signingMode"] = "unsigned-validation"
        for embedded, name in ((bridge, bridge_name), (agent_root, agent_name), (extension_root, extension_name)):
            shutil.copytree(embedded, self.native / name)
            self.manifest(self.native / name, metadata)
        authority = contents / "Library/HelperTools/CFWGlobalAuthority"
        write(authority, b"mach-o:authority", executable=True)
        shutil.copyfile(authority, self.native / authority.name)
        (self.native / authority.name).chmod(0o755)
        self.manifest(self.native / authority.name, metadata)
        tombstone = contents / "Library/HelperTools/cfw-helper-tombstone"
        write(tombstone, b"mach-o:tombstone", executable=True)
        write(self.native / "CFWLegacyTombstone/cfw-helper-tombstone", tombstone.read_bytes(), executable=True)
        self.manifest(self.native / "CFWLegacyTombstone", metadata)
        authority_plist = {
            "Label": bundle.EXPECTED_AUTHORITY_ID, "UserName": "root",
            "BundleProgram": "Contents/Library/HelperTools/CFWGlobalAuthority",
            "AssociatedBundleIdentifiers": [bundle.EXPECTED_APP_ID],
            "MachServices": {
                f"YKUPL7Z869.group.com.bill.clashformac.global-authority.{role}": True
                for role in ("host", "proxy-agent", "provider")
            },
        }
        agent_plist = {
            "Label": bundle.EXPECTED_AGENT_ID,
            "BundleProgram": "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent",
            "MachServices": {bundle.EXPECTED_AGENT_ID: True},
        }
        for filename, source, embedded, value in (
            ("com.bill.clashformac.global-authority.plist", "native/macos/Config", "Library/LaunchDaemons", authority_plist),
            ("com.bill.clashformac.proxy-agent.plist", "native/macos/Config", "Library/LaunchAgents", agent_plist),
            ("com.bill.clashformac.helper.plist", "apps/cfw-tauri-shell/macos/legacy-tombstone", "Library/LaunchDaemons", {"Label": "legacy"}),
        ):
            write_plist(repository / source / filename, value)
            write_plist(contents / embedded / filename, value)
        write(repository / "apps/cfw-tauri-shell/tauri.conf.json", json.dumps({"version": self.version}).encode())
        if self.preview:
            write(self.native / ui.LIBRARY, b"mach-o:ui", executable=True)
            resources = self.native / ui.RESOURCES
            write_plist(resources / "Contents/Info.plist", {
                "CFBundleDevelopmentRegion": "en", "CFBundlePackageType": "BNDL",
                "CFBundleName": "CFMNativeDashboard_CFMNativeDashboard",
                "CFBundleSupportedPlatforms": ["MacOSX"], "LSMinimumSystemVersion": "15.0",
            })
            for locale in ui.LOCALES:
                write(resources / f"Contents/Resources/{locale}.lproj/Localizable.strings", b'"key" = "value";\n')
            for name in (ui.LIBRARY, ui.RESOURCES):
                self.manifest(self.native / name, self.ui_metadata)
            if self.signing == "developer-id":
                pre_sign = ids.preview_native_products_root(repository)
                pre_sign.mkdir(parents=True)
                for name in (ui.LIBRARY, ui.RESOURCES):
                    source, destination = self.native / name, pre_sign / name
                    shutil.copytree(source, destination) if source.is_dir() else shutil.copy2(source, destination)
                    self.manifest(destination, {**self.ui_metadata, "signingMode": "pre-sign"})
                    promoted = promote_manifest(destination, pre_sign / (name + ".manifest.json"), source)
                    write(self.native / (name + ".manifest.json"), json.dumps(promoted).encode())
            shutil.copy2(self.native / ui.LIBRARY, contents / "Frameworks" / ui.LIBRARY)
            shutil.copytree(resources, contents / "Resources" / ui.RESOURCES)
        self.host_dependencies = [bundle.NATIVE_BRIDGE_INSTALL_NAME, "/usr/lib/libSystem.B.dylib"]
        if self.preview:
            self.host_dependencies.append(ui.INSTALL_NAME)
        self.ui_dependencies = [ui.INSTALL_NAME, "/usr/lib/libSystem.B.dylib"]
        self.host_rpaths = ["@executable_path/../Frameworks"]
        self.ui_rpaths = ["@loader_path", "/usr/lib/swift"]
        self.ui_exports = set(ui.COMPONENT_EXPORTS)
        for path in (self.app, *[p for p in self.app.rglob("*") if p.is_dir()]):
            path.chmod(0o755)
        for path in private:
            path.chmod(0o700)

    def manifest(self, path: Path, metadata: dict) -> None:
        write(path.with_name(path.name + ".manifest.json"), json.dumps(build_manifest(path, metadata)).encode())

    def external_tool(self, arguments: list[str]) -> str:
        tool = Path(arguments[0]).name
        if tool == "xcrun":
            tool = arguments[1]
        path = Path(arguments[-1])
        if tool == "file":
            return "Mach-O 64-bit executable arm64" if path.read_bytes().startswith(b"mach-o:") else "data"
        if tool == "lipo":
            return "arm64\n"
        if tool == "vtool":
            return "platform MACOS\nminos 15.0\n"
        if tool == "nm" and arguments[1] == "-gU" and path.name == ui.LIBRARY:
            return "\n".join(f"0000000000010000 T _{name}" for name in sorted(self.ui_exports))
        if tool == "otool" and "-L" in arguments:
            dependencies = self.ui_dependencies if path.name == ui.LIBRARY else self.host_dependencies if path.name == "clash-for-mac" else ["/usr/lib/libSystem.B.dylib"]
            return linked(*dependencies)
        if tool == "otool" and "-l" in arguments:
            return load_commands(*self.ui_rpaths, install_name=ui.INSTALL_NAME) if path.name == ui.LIBRARY else load_commands(*self.host_rpaths)
        raise AssertionError(f"unexpected external tool: {arguments}")


class PreviewCandidateBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)

    def fixture(self, context=ids.CandidateBundleContext.PREVIEW_PRE_SIGN) -> CandidateFixture:
        return CandidateFixture(self.root / context.value, context)

    def verify(self, fixture: CandidateFixture, *, context=None, unsigned_failure=False):
        with ExitStack() as stack:
            stack.enter_context(patch.object(bundle, "current_native_build_metadata", return_value=fixture.native_metadata))
            stack.enter_context(patch.object(
                ui, "expected_metadata",
                side_effect=lambda _repository, _build, *, signing, clean, context=ui.NativeUiContext.SIGNED_PREVIEW: {
                    **fixture.ui_metadata, "signingMode": signing,
                },
            ))
            stack.enter_context(patch.object(bundle, "command_output", side_effect=fixture.external_tool))
            stack.enter_context(patch.object(ui, "command", side_effect=fixture.external_tool))
            unsigned = stack.enter_context(patch.object(
                bundle, "verify_unsigned_host_skeleton",
                side_effect=bundle.CandidateError("unsigned Host rejected") if unsigned_failure else None,
            ))
            stack.enter_context(patch("sys.stdout", new=io.StringIO()))
            bundle.verify_candidate(fixture.repository, fixture.app, fixture.native, context=context or fixture.context)
            return unsigned.call_count

    def test_all_preview_contexts_retain_complete_bundle_checks(self) -> None:
        for context in bundle.PREVIEW_CONTEXTS:
            with self.subTest(context=context):
                fixture = self.fixture(context)
                self.assertEqual(self.verify(fixture), int(context is ids.CandidateBundleContext.PREVIEW_PRE_SIGN))

    def test_unsigned_preview_requires_real_component_composition_and_unsigned_host_state(self) -> None:
        fixture = self.fixture(ids.CandidateBundleContext.UNSIGNED_PREVIEW_HOST)
        self.assertEqual(self.verify(fixture), 1)
        with self.assertRaisesRegex(bundle.CandidateError, "unsigned Host rejected"):
            self.verify(fixture, unsigned_failure=True)
        fixture.ui_exports = set()
        with self.assertRaisesRegex(bundle.CandidateError, "C exports differ"):
            self.verify(fixture)
        fixture.ui_exports = set(ui.COMPONENT_EXPORTS)
        fixture.host_rpaths.append("/tmp/build-library")
        with self.assertRaises(bundle.CandidateError):
            self.verify(fixture)

    def test_unsigned_preview_rejects_production_manifest_modes_for_every_component(self) -> None:
        for index, name in enumerate(("CFWGlobalAuthority", "CFWNativeBridge.framework", "CFWProxyAgent.app",
                                      bundle.EXPECTED_EXTENSION_WRAPPER, "CFWLegacyTombstone", ui.LIBRARY, ui.RESOURCES)):
            fixture = CandidateFixture(self.root / str(index), ids.CandidateBundleContext.UNSIGNED_PREVIEW_HOST)
            path = fixture.native / (name + ".manifest.json")
            original = json.loads(path.read_text())
            for mode in ("pre-sign", "developer-id"):
                changed = json.loads(json.dumps(original))
                changed["metadata"]["signingMode"] = mode
                path.write_text(json.dumps(changed))
                with self.subTest(component=name, mode=mode), self.assertRaises(bundle.CandidateError):
                    self.verify(fixture)

    def test_original_unsigned_release_still_passes_without_ui(self) -> None:
        fixture = self.fixture(ids.CandidateBundleContext.UNSIGNED_HOST)
        self.assertEqual(self.verify(fixture), 1)
        self.assertFalse((fixture.app / "Contents/Frameworks" / ui.LIBRARY).exists())

    def test_preview_rejects_missing_or_unexpected_component_exports(self) -> None:
        fixture = self.fixture()
        for exports in (set(), set(ui.COMPONENT_EXPORTS) - {"cfm_profile_menu_present_v1"},
                        set(ui.COMPONENT_EXPORTS) | {"cfm_unexpected"}):
            fixture.ui_exports = exports
            with self.subTest(exports=exports), self.assertRaisesRegex(bundle.CandidateError, "C exports differ"):
                self.verify(fixture)

    def test_preview_and_release_contexts_cannot_be_crossed(self) -> None:
        preview = self.fixture()
        release = self.fixture(ids.CandidateBundleContext.UNSIGNED_HOST)
        for fixture, context in ((preview, release.context), (release, preview.context)):
            with self.subTest(context=context), self.assertRaises(bundle.CandidateError):
                self.verify(fixture, context=context)

    def test_preview_pre_sign_cannot_skip_unsigned_host_check(self) -> None:
        with self.assertRaisesRegex(bundle.CandidateError, "unsigned Host rejected"):
            self.verify(self.fixture(), unsigned_failure=True)

    def test_each_native_component_build_still_must_match(self) -> None:
        for index, relative in enumerate((
            "Contents/Info.plist", "Contents/Frameworks/CFWNativeBridge.framework/Versions/A/Resources/Info.plist",
            "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/Info.plist",
            f"Contents/Library/SystemExtensions/{bundle.EXPECTED_EXTENSION_WRAPPER}/Contents/Info.plist",
        )):
            fixture = CandidateFixture(self.root / str(index), ids.CandidateBundleContext.PREVIEW_PRE_SIGN)
            path = fixture.app / relative
            value = plistlib.loads(path.read_bytes())
            value["CFBundleVersion"] = "40073"
            write_plist(path, value)
            with self.subTest(component=relative), self.assertRaises(bundle.CandidateError):
                self.verify(fixture)

    def test_preview_rejects_release_version_in_tauri_or_native_component(self) -> None:
        fixture = self.fixture()
        config = fixture.repository / "apps/cfw-tauri-shell/tauri.conf.json"
        write(config, b'{"version":"0.4.0"}')
        with self.assertRaisesRegex(bundle.CandidateError, "Tauri configuration version"):
            self.verify(fixture)
        write(config, b'{"version":"0.5.0"}')
        path = fixture.contents / "Library/LoginItems/CFWProxyAgent.app/Contents/Info.plist"
        value = plistlib.loads(path.read_bytes())
        value["CFBundleShortVersionString"] = "0.4.0"
        write_plist(path, value)
        with self.assertRaisesRegex(bundle.CandidateError, "fixed product version"):
            self.verify(fixture)

    def test_missing_embedded_ui_library_or_resources_is_rejected(self) -> None:
        for index, relative in enumerate((f"Frameworks/{ui.LIBRARY}", f"Resources/{ui.RESOURCES}")):
            fixture = CandidateFixture(self.root / str(index), ids.CandidateBundleContext.PREVIEW_PRE_SIGN)
            path = fixture.contents / relative
            shutil.rmtree(path) if path.is_dir() else path.unlink()
            with self.subTest(relative=relative), self.assertRaises(bundle.CandidateError):
                self.verify(fixture)

    def test_embedded_ui_bytes_and_resources_must_match_inputs(self) -> None:
        for index, relative in enumerate((f"Frameworks/{ui.LIBRARY}", f"Resources/{ui.RESOURCES}/Contents/Resources/en.lproj/Localizable.strings")):
            fixture = CandidateFixture(self.root / str(index), ids.CandidateBundleContext.PREVIEW_PRE_SIGN)
            path = fixture.contents / relative
            path.write_bytes(path.read_bytes() + b"changed")
            with self.subTest(relative=relative), self.assertRaisesRegex(bundle.CandidateError, "differs|digest mismatch"):
                self.verify(fixture)

    def test_ui_manifest_source_toolchain_and_signing_stage_are_bound(self) -> None:
        for index, key in enumerate(("uiSourceSha256", "releaseSourceSha256", "xcodeVersion", "swiftVersion", "signingMode")):
            fixture = CandidateFixture(self.root / str(index), ids.CandidateBundleContext.PREVIEW_PRE_SIGN)
            path = fixture.native / (ui.LIBRARY + ".manifest.json")
            value = json.loads(path.read_bytes())
            value["metadata"][key] = "different"
            write(path, json.dumps(value).encode())
            with self.subTest(key=key), self.assertRaisesRegex(bundle.CandidateError, "not bound"):
                self.verify(fixture)

    def test_signed_ui_must_retain_exact_pre_sign_promotion(self) -> None:
        fixture = self.fixture(ids.CandidateBundleContext.PREVIEW_CANONICAL_NATIVE_CONTENT)
        manifest = fixture.native / (ui.LIBRARY + ".manifest.json")
        value = json.loads(manifest.read_bytes())
        value["metadata"]["preSignManifestSha256"] = "f" * 64
        write(manifest, json.dumps(value).encode())
        with self.assertRaisesRegex(bundle.CandidateError, "exact pre-sign promotion"):
            self.verify(fixture)

    def test_ui_extra_dependency_and_build_rpath_are_rejected(self) -> None:
        fixture = self.fixture()
        fixture.ui_dependencies.append("@rpath/unpackaged.dylib")
        with self.assertRaisesRegex(bundle.CandidateError, "non-system runtime dependency"):
            self.verify(fixture)
        fixture.ui_dependencies.pop()
        fixture.ui_rpaths.append("/tmp/swift-build")
        with self.assertRaisesRegex(bundle.CandidateError, "unexpected rpath"):
            self.verify(fixture)

    def test_host_missing_ui_extra_dependency_and_extra_rpath_are_rejected(self) -> None:
        fixture = self.fixture()
        fixture.host_dependencies.remove(ui.INSTALL_NAME)
        with self.assertRaisesRegex(bundle.CandidateError, "link exactly once"):
            self.verify(fixture)
        fixture.host_dependencies += [ui.INSTALL_NAME, "@rpath/unpackaged.dylib"]
        with self.assertRaisesRegex(bundle.CandidateError, "unexpected runtime dependency"):
            self.verify(fixture)
        fixture.host_dependencies.pop()
        fixture.host_rpaths.append("/tmp/cargo/debug")
        with self.assertRaisesRegex(bundle.CandidateError, "runtime search paths"):
            self.verify(fixture)

    def test_native_tree_and_bundle_permissions_are_not_bypassed(self) -> None:
        fixture = self.fixture()
        authority = fixture.contents / "Library/HelperTools/CFWGlobalAuthority"
        authority.write_bytes(authority.read_bytes() + b"changed")
        with self.assertRaisesRegex(bundle.CandidateError, "embedded file differs"):
            self.verify(fixture)
        authority.write_bytes((fixture.native / "CFWGlobalAuthority").read_bytes())
        (fixture.contents / "Info.plist").chmod(0o600)
        with self.assertRaises(bundle.CandidateError):
            self.verify(fixture)


if __name__ == "__main__":
    unittest.main()
