from __future__ import annotations

import hashlib
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
VERIFIER = REPOSITORY / "scripts/verify_release_app.sh"
DETAILS = """Identifier=libCFMNativeDashboard.dylib
TeamIdentifier=YKUPL7Z869
Authority=Developer ID Application: Fixture (YKUPL7Z869)
flags=0x10000(runtime)
Timestamp=Sep 22, 2026 at 12:00:00
"""


class SignedPreviewShellTests(unittest.TestCase):
    def run_function(self, code: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", "-p", "-c", 'source "$1"; shift; ' + code, "preview-verifier-test", str(VERIFIER), *arguments],
            env={**os.environ, "CFW_RELEASE_PYTHON_EXECUTABLE": sys.executable},
            capture_output=True, text=True, check=False, timeout=20,
        )

    def test_signed_contexts_select_fixed_independent_version_and_preflight_paths(self) -> None:
        for prefix, version, build, preflight in (
            ("", "0.4.0", "40073", "target/candidates/0.4.0/ga/40073"),
            ("preview-", "0.5.0", "50007", "target/candidates/0.5.0/preview-preflight/50007"),
        ):
            for stage in ("signing-attempt-work", "signing-attempt-publish-ready", "canonical-native-content"):
                context = prefix + stage
                with self.subTest(context=context):
                    result = self.run_function(
                        'configure_release_verification_context "$1" 1; '
                        'printf "%s\\n" "$expected_version" "$expected_build_number" '
                        '"$signing_preflight_manifest" "$pre_sign_native_products_root" "$preview_ui"',
                        context,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.splitlines(), [
                        version, build, str(REPOSITORY / preflight / "profiles/signing-preflight.json"),
                        str(REPOSITORY / preflight / "native-products"), "1" if prefix else "0",
                    ])

    def test_unsigned_unknown_and_post_notary_private_contexts_are_rejected(self) -> None:
        for context, pre_notary in (
            ("unsigned-host", "1"), ("preview-pre-sign", "1"), ("preview", "1"),
            ("signing-attempt-work", "0"), ("signing-attempt-publish-ready", "0"),
            ("preview-signing-attempt-work", "0"), ("preview-signing-attempt-publish-ready", "0"),
        ):
            with self.subTest(context=context):
                result = self.run_function('configure_release_verification_context "$1" "$2"', context, pre_notary)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("error:", result.stderr)
        for context in ("canonical-native-content", "preview-canonical-native-content"):
            result = self.run_function('configure_release_verification_context "$1" 0', context)
            self.assertEqual(result.returncode, 0, result.stderr)

    def verify_ui(self, root: Path, *, entitlements: bytes = b"", details: str = DETAILS,
                  wrong_certificate: bool = False, strict_failure: bool = False) -> subprocess.CompletedProcess[str]:
        library = root / "libCFMNativeDashboard.dylib"
        library.write_bytes(b"fixture: no executable is built or signed")
        library.chmod(0o755)
        (root / "details").write_text(details)
        (root / "entitlements").write_bytes(entitlements)
        (root / "certificate").write_bytes(b"different" if wrong_certificate else b"fixture certificate")
        fingerprint = hashlib.sha256(b"fixture certificate").hexdigest().upper()
        return self.run_function(
            '''temporary_root="$1"; expected_signing_certificate_sha256="$2";
certificate_capture_sequence=0; signature_fixture_failure="$3";
codesign() {
  printf '%s\n' "$*" >> "$temporary_root/queries";
  case "$1:$2" in
    --verify:--strict) [[ "$signature_fixture_failure" == 0 ]] ;;
    -d:--verbose=4) cat "$temporary_root/details" ;;
    -d:--extract-certificates=*) cp "$temporary_root/certificate" "${2#--extract-certificates=}0" ;;
    -d:--entitlements) cat "$temporary_root/entitlements" ;;
    *) return 91 ;;
  esac
}
verify_native_ui_security "$temporary_root/libCFMNativeDashboard.dylib"
''', str(root), fingerprint, "1" if strict_failure else "0",
        )

    def test_ui_uses_frozen_certificate_runtime_timestamp_and_strict_signature(self) -> None:
        mutations = (
            ({}, None),
            ({"wrong_certificate": True}, "leaf certificate differs"),
            ({"strict_failure": True}, None),
            ({"details": DETAILS.replace("Timestamp=Sep 22, 2026 at 12:00:00", "Timestamp=none")}, "timestamp is missing"),
            ({"details": DETAILS.replace("flags=0x10000(runtime)", "flags=0x0(none)")}, "runtime is missing"),
            ({"details": DETAILS.replace("TeamIdentifier=YKUPL7Z869", "TeamIdentifier=OTHER")}, "Team ID mismatch"),
            ({"details": DETAILS + "Signature=adhoc\n"}, "ad-hoc signature is forbidden"),
        )
        for arguments, diagnostic in mutations:
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                result = self.verify_ui(root, **arguments)
                if not arguments:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("--verify --strict", (root / "queries").read_text())
                    self.assertIn("--extract-certificates=", (root / "queries").read_text())
                else:
                    self.assertNotEqual(result.returncode, 0)
                    if diagnostic:
                        self.assertIn(diagnostic, result.stderr)

    def test_ui_rejects_every_entitlement_and_malformed_entitlement_output(self) -> None:
        for value in ({}, {"com.apple.security.get-task-allow": True}, {"unexpected": False}, []):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                result = self.verify_ui(Path(temporary), entitlements=plistlib.dumps(value))
                self.assertEqual(result.returncode == 0, value == {}, result.stderr)
        with tempfile.TemporaryDirectory() as temporary:
            result = self.verify_ui(Path(temporary), entitlements=b"not a plist")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("malformed", result.stderr)

    def test_preview_main_path_retains_nested_and_notarization_gates(self) -> None:
        source = VERIFIER.read_text()
        main = source[source.index('pre_notary=0\n'):]
        for required in (
            'verify_bundle_security "$app_path" host',
            'verify_bundle_security "$extension_path" packet-tunnel',
            'verify_bundle_security "$agent_path" proxy-agent',
            'verify_native_ui_security "$app_path/Contents/Frameworks/libCFMNativeDashboard.dylib"',
            'verify_macho "$candidate"', 'codesign --verify --deep --strict --verbose=4 "$app_path"',
            'xcrun stapler validate "$app_path"', '"$repo_root/scripts/gatekeeper_assessment.py"',
            '--context "$verification_context"', '"$pre_sign_native_products_root"',
        ):
            self.assertIn(required, main)


if __name__ == "__main__":
    unittest.main()
