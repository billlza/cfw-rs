from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import plistlib
import stat
import subprocess
import tempfile
import unittest

from scripts.host_release_entitlements import (
    HostReleaseEntitlementError,
    build_host_release_entitlements,
    signing_identity_sha1,
    write_release_xcent,
)
from scripts.release_entitlement_contract import (
    KNOWN_DEVELOPER_ID_NETWORK_EXTENSION_AUTHORIZATIONS,
)


REPOSITORY = Path(__file__).resolve().parents[2]
TEAM_ID = "YKUPL7Z869"
BUNDLE_ID = "com.bill.clashformac"
APP_IDENTIFIER = f"{TEAM_ID}.{BUNDLE_ID}"
SIGNING_IDENTITY = f"Developer ID Application: Release Owner ({TEAM_ID})"
CERTIFICATE = b"fixture Developer ID certificate DER"
CERTIFICATE_SHA1 = hashlib.sha1(CERTIFICATE).hexdigest().upper()
NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)


def reviewed_entitlements() -> dict[str, object]:
    return {
        "com.apple.developer.networking.networkextension": [
            "packet-tunnel-provider-systemextension"
        ],
        "com.apple.developer.system-extension.install": True,
        "com.apple.security.application-groups": [
            "$(TeamIdentifierPrefix)group.com.bill.clashformac"
        ],
        "keychain-access-groups": [
            "$(AppIdentifierPrefix)com.bill.clashformac",
            "$(AppIdentifierPrefix)com.bill.clashformac.credentials",
        ],
    }


def resolved_entitlements() -> dict[str, object]:
    return {
        "com.apple.developer.networking.networkextension": [
            "packet-tunnel-provider-systemextension"
        ],
        "com.apple.developer.system-extension.install": True,
        "com.apple.security.application-groups": [
            f"{TEAM_ID}.group.com.bill.clashformac"
        ],
        "keychain-access-groups": [
            APP_IDENTIFIER,
            f"{APP_IDENTIFIER}.credentials",
        ],
    }


def valid_profile() -> dict[str, object]:
    return {
        "ApplicationIdentifierPrefix": [TEAM_ID],
        "CreationDate": NOW - timedelta(days=1),
        "DeveloperCertificates": [CERTIFICATE],
        "Entitlements": {
            "com.apple.application-identifier": APP_IDENTIFIER,
            "com.apple.developer.team-identifier": TEAM_ID,
            "com.apple.developer.networking.networkextension": sorted(
                KNOWN_DEVELOPER_ID_NETWORK_EXTENSION_AUTHORIZATIONS
            ),
            "com.apple.developer.system-extension.install": True,
            "com.apple.security.application-groups": [
                "group.com.bill.clashformac",
                f"{TEAM_ID}.*",
            ],
            "keychain-access-groups": [f"{TEAM_ID}.*"],
        },
        "ExpirationDate": NOW + timedelta(days=30),
        "Platform": ["OSX"],
        "ProvisionsAllDevices": True,
        "TeamIdentifier": [TEAM_ID],
        "UUID": "11111111-1111-1111-1111-111111111111",
    }


def build(profile: dict[str, object] | None = None) -> dict[str, object]:
    return build_host_release_entitlements(
        profile or valid_profile(),
        reviewed_entitlements(),
        resolved_entitlements(),
        expected_team_id=TEAM_ID,
        expected_bundle_id=BUNDLE_ID,
        signing_certificate_sha1=CERTIFICATE_SHA1,
        now=NOW,
    )


class HostReleaseEntitlementTests(unittest.TestCase):
    def test_generated_entitlements_combine_profile_identity_with_reviewed_grants(
        self,
    ) -> None:
        generated = build()
        self.assertEqual(
            generated,
            {
                "com.apple.application-identifier": APP_IDENTIFIER,
                "com.apple.developer.team-identifier": TEAM_ID,
                **resolved_entitlements(),
            },
        )
        self.assertNotIn(
            "com.bill.clashformac.global-authority.client",
            generated,
        )

    def test_generated_xcent_is_comment_free_private_xml(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "Host.release.xcent"
            write_release_xcent(output, build())

            payload = output.read_bytes()
            self.assertNotIn(b"<!--", payload)
            self.assertEqual(plistlib.loads(payload), build())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_profile_team_mismatch_is_rejected(self) -> None:
        profile = valid_profile()
        profile["TeamIdentifier"] = ["WRONGTEAM1"]
        with self.assertRaisesRegex(HostReleaseEntitlementError, "TeamIdentifier"):
            build(profile)

    def test_profile_application_identifier_mismatch_is_rejected(self) -> None:
        profile = valid_profile()
        profile["Entitlements"]["com.apple.application-identifier"] = (
            f"{TEAM_ID}.com.example.wrong"
        )
        with self.assertRaisesRegex(
            HostReleaseEntitlementError, "application identifier"
        ):
            build(profile)

    def test_profile_must_authorize_selected_signing_certificate(self) -> None:
        profile = valid_profile()
        profile["DeveloperCertificates"] = [b"a different certificate"]
        with self.assertRaisesRegex(
            HostReleaseEntitlementError, "signing certificate is not authorized"
        ):
            build(profile)

    def test_profile_missing_functional_authorization_is_rejected(self) -> None:
        profile = valid_profile()
        del profile["Entitlements"]["com.apple.developer.system-extension.install"]
        with self.assertRaisesRegex(
            HostReleaseEntitlementError, "authorize System Extension installation"
        ):
            build(profile)

    def test_portal_superset_still_emits_minimal_reviewed_grants(self) -> None:
        profile = valid_profile()

        generated = build(profile)

        self.assertEqual(
            generated["com.apple.developer.networking.networkextension"],
            ["packet-tunnel-provider-systemextension"],
        )
        self.assertEqual(
            generated["com.apple.security.application-groups"],
            [f"{TEAM_ID}.group.com.bill.clashformac"],
        )

    def test_debuggable_profile_is_rejected(self) -> None:
        profile = valid_profile()
        profile["Entitlements"]["get-task-allow"] = True
        with self.assertRaisesRegex(HostReleaseEntitlementError, "permits debugging"):
            build(profile)

    def test_expired_profile_is_rejected(self) -> None:
        profile = valid_profile()
        profile["ExpirationDate"] = NOW
        with self.assertRaisesRegex(HostReleaseEntitlementError, "expired"):
            build(profile)

    def test_tauri_copy_must_remain_semantically_equivalent(self) -> None:
        tauri = resolved_entitlements()
        tauri["com.apple.developer.system-extension.install"] = False
        with self.assertRaisesRegex(
            HostReleaseEntitlementError, "not semantically equivalent"
        ):
            build_host_release_entitlements(
                valid_profile(),
                reviewed_entitlements(),
                tauri,
                expected_team_id=TEAM_ID,
                expected_bundle_id=BUNDLE_ID,
                signing_certificate_sha1=CERTIFICATE_SHA1,
                now=NOW,
            )

    def test_unreviewed_functional_grant_is_rejected(self) -> None:
        reviewed = reviewed_entitlements()
        reviewed["com.apple.security.cs.disable-library-validation"] = True
        with self.assertRaisesRegex(
            HostReleaseEntitlementError, "exact Host functional contract"
        ):
            build_host_release_entitlements(
                valid_profile(),
                reviewed,
                resolved_entitlements(),
                expected_team_id=TEAM_ID,
                expected_bundle_id=BUNDLE_ID,
                signing_certificate_sha1=CERTIFICATE_SHA1,
                now=NOW,
            )

    def test_custom_authority_entitlement_is_rejected(self) -> None:
        reviewed = reviewed_entitlements()
        reviewed["com.bill.clashformac.global-authority.client"] = "host-v1"
        with self.assertRaisesRegex(
            HostReleaseEntitlementError, "exact Host functional contract"
        ):
            build_host_release_entitlements(
                valid_profile(),
                reviewed,
                resolved_entitlements(),
                expected_team_id=TEAM_ID,
                expected_bundle_id=BUNDLE_ID,
                signing_certificate_sha1=CERTIFICATE_SHA1,
                now=NOW,
            )

    def test_identity_listing_must_select_one_exact_certificate(self) -> None:
        listing = f'  1) {CERTIFICATE_SHA1} "{SIGNING_IDENTITY}"\n'
        self.assertEqual(
            signing_identity_sha1(listing, SIGNING_IDENTITY), CERTIFICATE_SHA1
        )
        with self.assertRaisesRegex(HostReleaseEntitlementError, "found 0"):
            signing_identity_sha1(listing, f"{SIGNING_IDENTITY} copy")
        with self.assertRaisesRegex(HostReleaseEntitlementError, "found 2"):
            signing_identity_sha1(listing + listing, SIGNING_IDENTITY)

    def test_output_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "Host.release.xcent"
            output.write_bytes(b"existing")
            with self.assertRaisesRegex(HostReleaseEntitlementError, "cannot create"):
                write_release_xcent(output, build())
            self.assertEqual(output.read_bytes(), b"existing")


class SignedCandidateWiringTests(unittest.TestCase):
    def test_signed_candidate_uses_distribution_umask(self) -> None:
        source = (REPOSITORY / "scripts/build_signed_candidate.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("\numask 022\n", source)
        self.assertNotIn("\numask 077\n", source)

    def isolated_runner_command(self, script: Path, *arguments: str) -> list[str]:
        return [
            "/bin/bash",
            "-p",
            "-c",
            'source "$1/scripts/release_python_launcher.sh"; '
            'cfw_run_release_python_script "$1" "$2" "${@:3}"',
            "isolated-release-python-test",
            str(REPOSITORY),
            str(script),
            *arguments,
        ]

    def test_isolated_runner_supports_repository_package_imports(self) -> None:
        completed = subprocess.run(
            self.isolated_runner_command(
                REPOSITORY / "scripts/host_release_entitlements.py",
                "--help",
            ),
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--decoded-profile", completed.stdout)

    def test_isolated_runner_rejects_entrypoint_outside_repository_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            outside = Path(temporary_directory) / "outside.py"
            outside.write_text("raise SystemExit(0)\n", encoding="utf-8")
            completed = subprocess.run(
                self.isolated_runner_command(outside),
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("entrypoint is unavailable or unsafe", completed.stderr)

    def test_final_host_signature_uses_generated_release_xcent(self) -> None:
        builder = (REPOSITORY / "scripts/build_signed_candidate.sh").read_text(
            encoding="utf-8"
        )
        helper = (REPOSITORY / "scripts/run_ga_signing_attempt.sh").read_text(
            encoding="utf-8"
        )
        generation = builder.index("scripts/host_release_entitlements.py")
        freeze = builder.index("scripts/candidate_freeze.py\" freeze", generation)
        transaction = builder.index("scripts/signing_attempt_transaction.py", freeze)
        final_signing = helper.index(
            "/usr/bin/codesign --force --options runtime --timestamp \\\n"
            '  --entitlements "$host_release_xcent"',
        )

        self.assertLess(generation, freeze)
        self.assertLess(freeze, transaction)
        self.assertIn('--entitlements "$host_release_xcent"', helper[final_signing:])
        self.assertNotIn(
            '--entitlements "$repo_root/apps/cfw-tauri-shell/macos/entitlements.plist"',
            helper[final_signing:],
        )

    def test_repository_host_sources_are_semantically_equivalent(self) -> None:
        reviewed_path = REPOSITORY / "native/macos/Config/Host.entitlements"
        with reviewed_path.open("rb") as handle:
            reviewed = plistlib.load(handle)
        with (
            REPOSITORY / "apps/cfw-tauri-shell/macos/entitlements.plist"
        ).open("rb") as handle:
            tauri = plistlib.load(handle)

        self.assertEqual(reviewed, reviewed_entitlements())
        self.assertEqual(tauri, resolved_entitlements())


if __name__ == "__main__":
    unittest.main()
