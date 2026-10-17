from __future__ import annotations

import hashlib
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.release_build_identity import ACTIVE_RELEASE_IDENTITY
from scripts.tests.release_app_verifier_fixture import (
    PRE_NOTARY_LINE,
    SEALED_NOTARIZATION_LINE,
    verifier_closing_lines,
)


GA_BUILD = ACTIVE_RELEASE_IDENTITY.ga_build


REPOSITORY = Path(__file__).resolve().parents[2]
VERIFIER = REPOSITORY / "scripts/verify_release_app.sh"
GA_ROOT = REPOSITORY / f"target/candidates/0.5.0/ga/{GA_BUILD}"
FIXED_APP = GA_ROOT / "signed/Clash for Mac.app"
NATIVE_PRODUCTS = GA_ROOT / "signing-output/signed-native-products"
# Every call the stubbed tail makes, one line each, with bracketed arguments.
# Bash scopes variables dynamically, so the stub settings use fixture_ names.
TAIL_STUBS = r'''fixture_calls="$1"; fixture_stapler_status="$2"; fixture_gatekeeper_status="$3"
fixture_codesign_status="$4"
record() { printf '%s' "$1" >>"$fixture_calls"; shift; printf ' [%s]' "$@" >>"$fixture_calls"; printf '\n' >>"$fixture_calls"; }
codesign() { record codesign "$@"; return "$fixture_codesign_status"; }
xcrun() { record xcrun "$@"; return "$fixture_stapler_status"; }
cfw_run_release_python_script() { record python "$@"; return "$fixture_gatekeeper_status"; }
finish_release_app_verification "$5" "$6" "$7"
'''
DETAILS = """Identifier=libCFMNativeDashboard.dylib
TeamIdentifier=YKUPL7Z869
Authority=Developer ID Application: Fixture (YKUPL7Z869)
flags=0x10000(runtime)
Timestamp=Sep 22, 2026 at 12:00:00
"""


class ReleaseAppVerifierShellTests(unittest.TestCase):
    def run_function(self, code: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", "-p", "-c", 'source "$1"; shift; ' + code, "release-verifier-test", str(VERIFIER), *arguments],
            env={**os.environ, "CFW_RELEASE_PYTHON_EXECUTABLE": sys.executable},
            capture_output=True, text=True, check=False, timeout=20,
        )

    def test_signed_contexts_select_the_fixed_ga_version_and_preflight_paths(self) -> None:
        preflight = f"target/candidates/0.5.0/ga/{GA_BUILD}"
        for context in ("signing-attempt-work", "signing-attempt-publish-ready", "canonical-native-content"):
            with self.subTest(context=context):
                result = self.run_function(
                    'configure_release_verification_context "$1" pre-notary "$2"; '
                    'printf "%s\\n" "$expected_version" "$expected_build_number" '
                    '"$signing_preflight_manifest" "$pre_sign_native_products_root"',
                    context, str(FIXED_APP),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [
                    "0.5.0", GA_BUILD, str(REPOSITORY / preflight / "profiles/signing-preflight.json"),
                    str(REPOSITORY / preflight / "native-products"),
                ])

    def test_unsigned_unknown_and_post_notary_private_contexts_are_rejected(self) -> None:
        for context, mode in (
            ("unsigned-host", "pre-notary"), ("unsigned-preview-host", "pre-notary"), ("preview", "pre-notary"),
            # The removed signed-preview contexts are unknown contexts now.
            ("preview-pre-sign", "pre-notary"), ("preview-signing-attempt-work", "pre-notary"),
            ("preview-signing-attempt-publish-ready", "pre-notary"),
            ("preview-canonical-native-content", "live"),
            ("signing-attempt-work", "live"), ("signing-attempt-publish-ready", "live"),
        ):
            with self.subTest(context=context):
                result = self.run_function(
                    'configure_release_verification_context "$1" "$2" "$3"', context, mode, str(FIXED_APP)
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("error:", result.stderr)
        result = self.run_function(
            'configure_release_verification_context "$1" live "$2"', "canonical-native-content", str(FIXED_APP)
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sealed_notarization_is_admitted_only_for_the_fixed_ga_app(self) -> None:
        configure = 'configure_release_verification_context "$1" "$2" "$3"'
        result = self.run_function(configure, "canonical-native-content", "sealed", str(FIXED_APP))
        self.assertEqual(result.returncode, 0, result.stderr)
        for context in ("signing-attempt-work", "signing-attempt-publish-ready"):
            with self.subTest(context=context):
                result = self.run_function(configure, context, "sealed", str(FIXED_APP))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("requires the canonical-native-content context", result.stderr)
        other_build = str(int(GA_BUILD) + 1)
        for app in (
            # The DMG payload copy that make_dmg.sh verifies before imaging.
            str(GA_ROOT / "packages/dmg/dmg-stage.fixture/payload/Clash for Mac.app"),
            str(REPOSITORY / f"target/candidates/0.5.0/ga/{other_build}/signed/Clash for Mac.app"),
            str(REPOSITORY / f"target/release-worktrees/{GA_BUILD}") + str(FIXED_APP)[len(str(REPOSITORY)):],
            str(GA_ROOT / "signed/../signed/Clash for Mac.app"),
            str(FIXED_APP) + "/",
            str(FIXED_APP.relative_to(REPOSITORY)),
            "",
        ):
            with self.subTest(app=app):
                result = self.run_function(configure, "canonical-native-content", "sealed", app)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("only for the fixed GA signed app", result.stderr)
        for mode in ("", "offline", "0", "1", "SEALED", "--sealed-notarization"):
            with self.subTest(mode=mode):
                result = self.run_function(configure, "canonical-native-content", mode, str(FIXED_APP))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("notarization mode is invalid", result.stderr)

    def run_verifier(self, *arguments: str, verifier: Path = VERIFIER) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", "-p", str(verifier), *arguments],
            env={**os.environ, "CFW_RELEASE_PYTHON_EXECUTABLE": sys.executable},
            capture_output=True, text=True, check=False, timeout=20,
        )

    def test_command_line_admits_each_mode_for_the_fixed_app_before_reading_it(self) -> None:
        # A copy of the verifier and every file it sources while loading, so
        # its fixed GA paths point into an empty temporary checkout.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "scripts").mkdir()
            for name in (
                "verify_release_app.sh", "dependency_pins.env", "release_identity.env",
                "libbox_source_contract.sh", "release_toolchain_contract.sh",
                "release_python_launcher.sh", "apple_validation_policy.sh",
            ):
                shutil.copyfile(REPOSITORY / "scripts" / name, root / "scripts" / name)
            ga_root = root / f"target/candidates/0.5.0/ga/{GA_BUILD}"
            app = ga_root / "signed/Clash for Mac.app"
            native_products = ga_root / "signing-output/signed-native-products"
            for flags in ((), ("--pre-notary",), ("--sealed-notarization",)):
                with self.subTest(flags=flags):
                    result = self.run_verifier(
                        *flags, str(app), str(native_products), "--context", "canonical-native-content",
                        verifier=root / "scripts/verify_release_app.sh",
                    )
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(
                        result.stderr, f"error: application must be a non-symlink directory: {app}\n"
                    )

    def test_command_line_rejects_combined_repeated_or_misplaced_mode_flags(self) -> None:
        # Each rejection happens while parsing argv, before any artifact is read.
        canonical = ("--context", "canonical-native-content")
        for arguments, diagnostic in (
            (("--pre-notary", "--sealed-notarization", str(FIXED_APP), str(NATIVE_PRODUCTS), *canonical),
             "choose at most one of --pre-notary and --sealed-notarization"),
            (("--sealed-notarization", "--pre-notary", str(FIXED_APP), str(NATIVE_PRODUCTS), *canonical),
             "choose at most one of --pre-notary and --sealed-notarization"),
            (("--sealed-notarization", "--sealed-notarization", str(FIXED_APP), str(NATIVE_PRODUCTS), *canonical),
             "choose at most one of --pre-notary and --sealed-notarization"),
            ((str(FIXED_APP), str(NATIVE_PRODUCTS), *canonical, "--sealed-notarization"),
             "usage: scripts/verify_release_app.sh [--pre-notary | --sealed-notarization] APP"),
            (("--sealed-notarization", str(FIXED_APP), str(NATIVE_PRODUCTS), "--context", "signing-attempt-work"),
             "requires the canonical-native-content context"),
            (("--sealed-notarization", str(FIXED_APP) + "/", str(NATIVE_PRODUCTS), *canonical),
             "only for the fixed GA signed app"),
        ):
            with self.subTest(arguments=arguments):
                result = self.run_verifier(*arguments)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn(diagnostic, result.stderr)

    def run_tail(
        self, app: Path, mode: str, *, stapler_status: int = 0, gatekeeper_status: int = 0,
        codesign_status: int = 0,
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        calls = app.parent / "calls"
        result = self.run_function(
            TAIL_STUBS, str(calls), str(stapler_status), str(gatekeeper_status), str(codesign_status),
            str(app), mode, GA_BUILD,
        )
        return result, calls.read_text().splitlines() if calls.exists() else []

    @staticmethod
    def stapled_app(root: Path) -> Path:
        # The tail checks whichever bundle it is given; the fixed-path rule
        # lives in configure_release_verification_context, tested above.
        app = root / "Fixture.app"
        (app / "Contents").mkdir(parents=True)
        (app / "Contents/CodeResources").write_bytes(b"fixture stapled ticket")
        return app

    def test_sealed_tail_skips_stapler_and_gatekeeper_and_prints_the_sealed_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = self.stapled_app(Path(temporary).resolve())
            result, calls = self.run_tail(app, "sealed")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout.splitlines(),
                [*verifier_closing_lines(str(app), GA_BUILD), SEALED_NOTARIZATION_LINE],
            )
            self.assertEqual(result.stderr, "")
            self.assertEqual(calls, [f"codesign [--verify] [--deep] [--strict] [--verbose=4] [{app}]"])

    def test_sealed_tail_requires_the_stapled_ticket_file(self) -> None:
        def remove(ticket: Path) -> None:
            ticket.unlink()

        def symlink(ticket: Path) -> None:
            ticket.rename(ticket.with_name("ticket"))
            ticket.symlink_to("ticket")

        def directory(ticket: Path) -> None:
            ticket.unlink()
            ticket.mkdir()

        # macOS on the release host refuses to hard-link a bundle's
        # Contents/CodeResources, so require_regular_file's link-count rule
        # cannot be staged for this file here.
        for change, diagnostic in (
            (remove, "expected a regular, non-symlink file"),
            (symlink, "expected a regular, non-symlink file"),
            (directory, "expected a regular, non-symlink file"),
        ):
            with self.subTest(change=change.__name__), tempfile.TemporaryDirectory() as temporary:
                app = self.stapled_app(Path(temporary).resolve())
                change(app / "Contents/CodeResources")
                result, calls = self.run_tail(app, "sealed")
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn(diagnostic, result.stderr)
                self.assertFalse(any(call.startswith(("xcrun", "python")) for call in calls), calls)

    def test_live_tail_runs_stapler_then_gatekeeper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = self.stapled_app(Path(temporary).resolve())
            result, calls = self.run_tail(app, "live")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), verifier_closing_lines(str(app), GA_BUILD))
            self.assertEqual(calls, [
                f"codesign [--verify] [--deep] [--strict] [--verbose=4] [{app}]",
                f"xcrun [stapler] [validate] [{app}]",
                f"python [{REPOSITORY}] [{REPOSITORY}/scripts/gatekeeper_assessment.py] "
                f"[--target] [{app}] [--assessment-type] [execute]",
            ])

    def test_live_tail_reports_a_stapler_failure_neutrally(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = self.stapled_app(Path(temporary).resolve())
            result, calls = self.run_tail(app, "live", stapler_status=68)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(
                result.stderr,
                "error: stapler validate failed with exit status 68; "
                "stapler reports its diagnostic on standard output\n",
            )
            self.assertEqual(calls[-1], f"xcrun [stapler] [validate] [{app}]")

    def test_live_tail_gatekeeper_or_signature_failure_stops_before_success(self) -> None:
        for failure in ({"gatekeeper_status": 3}, {"codesign_status": 1}):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                app = self.stapled_app(Path(temporary).resolve())
                result, calls = self.run_tail(app, "live", **failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                if "codesign_status" in failure:
                    self.assertEqual(len(calls), 1, calls)

    def test_pre_notary_tail_skips_stapler_and_gatekeeper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary).resolve() / "Fixture.app"
            app.mkdir()
            result, calls = self.run_tail(app, "pre-notary")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout.splitlines(),
                [*verifier_closing_lines(str(app), GA_BUILD), PRE_NOTARY_LINE],
            )
            self.assertEqual(calls, [f"codesign [--verify] [--deep] [--strict] [--verbose=4] [{app}]"])

    def test_unknown_tail_mode_never_reports_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = self.stapled_app(Path(temporary).resolve())
            result, calls = self.run_tail(app, "offline")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertIn("notarization mode is invalid", result.stderr)
            self.assertFalse(any(call.startswith(("xcrun", "python")) for call in calls), calls)

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

    def test_main_path_retains_nested_and_notarization_gates(self) -> None:
        source = VERIFIER.read_text()
        main = source[source.index('notarization_mode="live"\n'):]
        for required in (
            'configure_release_verification_context "$verification_context" "$notarization_mode" "$app_path"',
            'verify_bundle_security "$app_path" host',
            'verify_bundle_security "$extension_path" packet-tunnel',
            'verify_bundle_security "$agent_path" proxy-agent',
            'verify_native_ui_security "$app_path/Contents/Frameworks/libCFMNativeDashboard.dylib"',
            'verify_macho "$candidate"',
            '--context "$verification_context"', '"$pre_sign_native_products_root"',
        ):
            self.assertIn(required, main)
        # The deep signature and notarization checks run, and the success
        # transcript is printed, only by the final tail exercised above.
        tail = 'finish_release_app_verification "$app_path" "$notarization_mode" "$build_number"\n'
        self.assertEqual(main.count("finish_release_app_verification"), 1)
        self.assertTrue(main.endswith(tail))
        self.assertLess(main.index('verify_macho "$candidate"'), main.index(tail))
        self.assertNotIn("echo ", main[main.index('verify_macho "$candidate"'):])


if __name__ == "__main__":
    unittest.main()
