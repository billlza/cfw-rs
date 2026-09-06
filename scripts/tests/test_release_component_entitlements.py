from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import plistlib
import stat
import tempfile
import unittest
from unittest import mock

from scripts import release_profile_entitlements as profile_support
from scripts.release_component_entitlements import (
    APP_GROUP,
    PACKET_TUNNEL_GROUP,
    PROXY_AGENT_GROUP,
    ReleaseComponentEntitlementError,
    build_release_component_entitlements,
    component_specification,
    main,
)
from scripts.release_entitlement_contract import (
    KNOWN_DEVELOPER_ID_NETWORK_EXTENSION_AUTHORIZATIONS,
)
from scripts.release_profile_entitlements import (
    ReleaseProfileEntitlementError,
    load_plist,
    write_release_xcent,
)


TEAM_ID = "YKUPL7Z869"
HOST_BUNDLE_ID = "com.bill.clashformac"
SIGNING_IDENTITY = f"Developer ID Application: Release Owner ({TEAM_ID})"
CERTIFICATE = b"fixture Developer ID certificate DER"
CERTIFICATE_SHA1 = hashlib.sha1(CERTIFICATE).hexdigest().upper()
NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
PROFILE_UUIDS = {
    "proxy-agent": "379ef639-4fff-4301-b083-3e49578f0910",
    "packet-tunnel": "3f275eaf-0fca-4af6-97a3-c93c4e83dc15",
}


def reviewed_entitlements(role: str) -> dict[str, object]:
    return dict(component_specification(role).functional_template)


def valid_profile(role: str) -> dict[str, object]:
    specification = component_specification(role)
    entitlements: dict[str, object] = {
        "com.apple.application-identifier": (
            f"{TEAM_ID}.{specification.bundle_id}"
        ),
        "com.apple.developer.team-identifier": TEAM_ID,
        "com.apple.security.application-groups": [
            f"group.{HOST_BUNDLE_ID}",
            f"{TEAM_ID}.*",
        ],
        "keychain-access-groups": [f"{TEAM_ID}.*"],
    }
    if role == "packet-tunnel":
        entitlements["com.apple.developer.networking.networkextension"] = sorted(
            KNOWN_DEVELOPER_ID_NETWORK_EXTENSION_AUTHORIZATIONS
        )
    return {
        "ApplicationIdentifierPrefix": [TEAM_ID],
        "CreationDate": NOW - timedelta(days=1),
        "DeveloperCertificates": [CERTIFICATE],
        "Entitlements": entitlements,
        "ExpirationDate": NOW + timedelta(days=30),
        "Platform": ["OSX"],
        "ProvisionsAllDevices": True,
        "TeamIdentifier": [TEAM_ID],
        "UUID": PROFILE_UUIDS[role],
    }


def build(
    role: str,
    *,
    profile: dict[str, object] | None = None,
    reviewed: dict[str, object] | None = None,
    expected_uuid: str | None = None,
) -> dict[str, object]:
    return build_release_component_entitlements(
        role,
        profile or valid_profile(role),
        reviewed or reviewed_entitlements(role),
        expected_profile_uuid=expected_uuid or PROFILE_UUIDS[role],
        signing_certificate_sha1=CERTIFICATE_SHA1,
        now=NOW,
    )


class ReleaseComponentEntitlementTests(unittest.TestCase):
    def test_proxy_agent_emits_only_fixed_resolved_entitlements(self) -> None:
        self.assertEqual(
            build("proxy-agent"),
            {
                "com.apple.application-identifier": PROXY_AGENT_GROUP,
                "com.apple.developer.team-identifier": TEAM_ID,
                "com.apple.security.application-groups": [APP_GROUP],
                "keychain-access-groups": [
                    PROXY_AGENT_GROUP,
                    f"{TEAM_ID}.{HOST_BUNDLE_ID}.credentials",
                ],
            },
        )

    def test_packet_tunnel_emits_only_fixed_resolved_entitlements(self) -> None:
        self.assertEqual(
            build("packet-tunnel"),
            {
                "com.apple.application-identifier": PACKET_TUNNEL_GROUP,
                "com.apple.developer.team-identifier": TEAM_ID,
                "com.apple.developer.networking.networkextension": [
                    "packet-tunnel-provider-systemextension"
                ],
                "com.apple.security.app-sandbox": True,
                "com.apple.security.application-groups": [APP_GROUP],
                "com.apple.security.network.client": True,
                "com.apple.security.network.server": True,
            },
        )

    def test_unknown_role_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            ReleaseComponentEntitlementError, "unknown release component role"
        ):
            component_specification("host")

    def test_cross_component_keychain_authorization_is_rejected(self) -> None:
        profile = valid_profile("proxy-agent")
        entitlements = profile["Entitlements"]
        self.assertIsInstance(entitlements, dict)
        entitlements["keychain-access-groups"] = [
            PROXY_AGENT_GROUP,
            f"{TEAM_ID}.{HOST_BUNDLE_ID}.credentials",
            PACKET_TUNNEL_GROUP,
        ]
        with self.assertRaisesRegex(
            ReleaseComponentEntitlementError, "another product component"
        ):
            build("proxy-agent", profile=profile)

    def test_uncontrolled_keychain_wildcard_is_rejected(self) -> None:
        profile = valid_profile("proxy-agent")
        entitlements = profile["Entitlements"]
        self.assertIsInstance(entitlements, dict)
        entitlements["keychain-access-groups"] = ["WRONGTEAM1.*"]
        with self.assertRaisesRegex(
            ReleaseComponentEntitlementError, "uncontrolled wildcard"
        ):
            build("proxy-agent", profile=profile)

    def test_expired_profile_is_rejected(self) -> None:
        profile = valid_profile("packet-tunnel")
        profile["ExpirationDate"] = NOW
        with self.assertRaisesRegex(
            ReleaseComponentEntitlementError, "has expired"
        ):
            build("packet-tunnel", profile=profile)

    def test_selected_certificate_must_be_authorized(self) -> None:
        profile = valid_profile("proxy-agent")
        profile["DeveloperCertificates"] = [b"different certificate"]
        with self.assertRaisesRegex(
            ReleaseComponentEntitlementError, "certificate is not authorized"
        ):
            build("proxy-agent", profile=profile)

    def test_profile_uuid_must_match_expected_uuid(self) -> None:
        with self.assertRaisesRegex(
            ReleaseComponentEntitlementError, "UUID does not match"
        ):
            build(
                "packet-tunnel",
                expected_uuid="11111111-1111-1111-1111-111111111111",
            )

    def test_profile_uuid_must_be_canonical_lowercase(self) -> None:
        profile = valid_profile("proxy-agent")
        profile["UUID"] = PROFILE_UUIDS["proxy-agent"].upper()
        with self.assertRaisesRegex(
            ReleaseComponentEntitlementError, "canonical lowercase"
        ):
            build("proxy-agent", profile=profile)

    def test_profile_must_be_all_device_distribution(self) -> None:
        profile = valid_profile("packet-tunnel")
        profile["ProvisionedDevices"] = []
        with self.assertRaisesRegex(
            ReleaseComponentEntitlementError, "all-device Developer ID"
        ):
            build("packet-tunnel", profile=profile)

    def test_functional_template_cannot_gain_or_lose_grants(self) -> None:
        reviewed = reviewed_entitlements("packet-tunnel")
        reviewed["com.apple.security.cs.disable-library-validation"] = True
        with self.assertRaisesRegex(
            ReleaseComponentEntitlementError, "exact functional template"
        ):
            build("packet-tunnel", reviewed=reviewed)

        reviewed = reviewed_entitlements("proxy-agent")
        del reviewed["com.apple.security.application-groups"]
        with self.assertRaisesRegex(
            ReleaseComponentEntitlementError, "exact functional template"
        ):
            build("proxy-agent", reviewed=reviewed)

    def test_profile_cannot_authorize_unknown_network_extension_role(self) -> None:
        profile = valid_profile("packet-tunnel")
        entitlements = profile["Entitlements"]
        self.assertIsInstance(entitlements, dict)
        roles = entitlements[
            "com.apple.developer.networking.networkextension"
        ]
        self.assertIsInstance(roles, list)
        roles.append("future-unreviewed-role")
        with self.assertRaisesRegex(
            ReleaseComponentEntitlementError, "unknown authorization"
        ):
            build("packet-tunnel", profile=profile)

    def test_cli_reads_public_inputs_and_writes_private_xcent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            profile_path = root / "profile.plist"
            reviewed_path = root / "ProxyAgent.entitlements"
            identities_path = root / "identities.txt"
            output_path = root / "ProxyAgent.release.xcent"
            profile_path.write_bytes(plistlib.dumps(valid_profile("proxy-agent")))
            reviewed_path.write_bytes(
                plistlib.dumps(reviewed_entitlements("proxy-agent"))
            )
            identities_path.write_text(
                f'  1) {CERTIFICATE_SHA1} "{SIGNING_IDENTITY}"\n',
                encoding="utf-8",
            )

            result = main(
                [
                    "--role",
                    "proxy-agent",
                    "--decoded-profile",
                    str(profile_path),
                    "--reviewed-entitlements",
                    str(reviewed_path),
                    "--signing-identities",
                    str(identities_path),
                    "--signing-identity",
                    SIGNING_IDENTITY,
                    "--expected-profile-uuid",
                    PROFILE_UUIDS["proxy-agent"],
                    "--output",
                    str(output_path),
                ]
            )

            self.assertEqual(result, 0)
            self.assertEqual(
                plistlib.loads(output_path.read_bytes()), build("proxy-agent")
            )
            self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o600)


class ReleaseXcentFilesystemTests(unittest.TestCase):
    def test_output_is_exclusive_and_existing_file_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "component.xcent"
            output.write_bytes(b"existing")
            with self.assertRaisesRegex(
                ReleaseProfileEntitlementError, "cannot create"
            ):
                write_release_xcent(output, build("proxy-agent"))
            self.assertEqual(output.read_bytes(), b"existing")

    def test_output_symlink_is_rejected_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "target"
            target.write_bytes(b"target")
            output = root / "component.xcent"
            output.symlink_to(target)
            with self.assertRaisesRegex(
                ReleaseProfileEntitlementError, "cannot create"
            ):
                write_release_xcent(output, build("packet-tunnel"))
            self.assertEqual(target.read_bytes(), b"target")
            self.assertTrue(output.is_symlink())

    def test_hardlinked_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            original = root / "profile.plist"
            linked = root / "profile-linked.plist"
            original.write_bytes(plistlib.dumps(valid_profile("proxy-agent")))
            os.link(original, linked)
            with self.assertRaisesRegex(
                ReleaseProfileEntitlementError, "non-hardlinked"
            ):
                load_plist(original, "decoded profile")

    def test_symlink_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            actual = root / "actual"
            actual.mkdir()
            linked_parent = root / "linked"
            linked_parent.symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(
                ReleaseProfileEntitlementError, "parent directory"
            ):
                write_release_xcent(
                    linked_parent / "component.xcent", build("proxy-agent")
                )
            self.assertFalse((actual / "component.xcent").exists())

    def test_permission_failure_removes_incomplete_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "component.xcent"
            with mock.patch.object(
                profile_support.os,
                "fchmod",
                side_effect=PermissionError("permission denied"),
            ):
                with self.assertRaisesRegex(
                    ReleaseProfileEntitlementError, "permission denied"
                ):
                    write_release_xcent(output, build("packet-tunnel"))
            self.assertFalse(output.exists())

    def test_output_file_and_parent_directory_are_fsynced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "component.xcent"
            observed_kinds: list[str] = []
            real_fsync = os.fsync

            def recording_fsync(descriptor: int) -> None:
                mode = os.fstat(descriptor).st_mode
                if stat.S_ISREG(mode):
                    observed_kinds.append("file")
                elif stat.S_ISDIR(mode):
                    observed_kinds.append("directory")
                else:
                    observed_kinds.append("other")
                real_fsync(descriptor)

            with mock.patch.object(
                profile_support.os, "fsync", side_effect=recording_fsync
            ):
                write_release_xcent(output, build("proxy-agent"))

            self.assertEqual(observed_kinds, ["file", "directory"])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
