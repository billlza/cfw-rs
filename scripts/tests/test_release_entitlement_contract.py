import unittest

from scripts.release_entitlement_contract import EntitlementContractError
from scripts.release_entitlement_contract import (
    KNOWN_DEVELOPER_ID_NETWORK_EXTENSION_AUTHORIZATIONS,
)
from scripts.release_entitlement_contract import verify_profile_capability_authorizations
from scripts.release_entitlement_contract import verify_profile_keychain_access_group
from scripts.release_entitlement_contract import verify_signed_keychain_access_group


EXPECTED_GROUP = "YKUPL7Z869.com.bill.clashformac.proxy-agent"
EXPECTED_TUNNEL_GROUP = "YKUPL7Z869.com.bill.clashformac.packet-tunnel"
EXPECTED_HOST_GROUP = "YKUPL7Z869.com.bill.clashformac"
EXPECTED_CREDENTIAL_GROUP = "YKUPL7Z869.com.bill.clashformac.credentials"
EXPECTED_APP_GROUP = "YKUPL7Z869.group.com.bill.clashformac"
REGISTERED_APP_GROUP = "group.com.bill.clashformac"
PACKET_TUNNEL_ROLE = "packet-tunnel-provider-systemextension"


def profile_entitlements(kind: str) -> dict[str, object]:
    bundle_id = {
        "host": "com.bill.clashformac",
        "packet-tunnel": "com.bill.clashformac.packet-tunnel",
        "proxy-agent": "com.bill.clashformac.proxy-agent",
    }[kind]
    entitlements: dict[str, object] = {
        "com.apple.application-identifier": f"YKUPL7Z869.{bundle_id}",
        "com.apple.developer.team-identifier": "YKUPL7Z869",
        "com.apple.security.application-groups": [
            REGISTERED_APP_GROUP,
            "YKUPL7Z869.*",
        ],
        "keychain-access-groups": ["YKUPL7Z869.*"],
    }
    if kind in {"host", "packet-tunnel"}:
        entitlements["com.apple.developer.networking.networkextension"] = sorted(
            KNOWN_DEVELOPER_ID_NETWORK_EXTENSION_AUTHORIZATIONS
        )
    if kind == "host":
        entitlements["com.apple.developer.system-extension.install"] = True
    return entitlements


def signed_capabilities(kind: str) -> dict[str, object]:
    entitlements: dict[str, object] = {
        "com.apple.developer.networking.networkextension": [PACKET_TUNNEL_ROLE]
    }
    if kind == "host":
        entitlements["com.apple.developer.system-extension.install"] = True
    return entitlements


class ReleaseEntitlementContractTests(unittest.TestCase):
    def test_portal_network_extension_superset_authorizes_minimal_signature(self) -> None:
        for kind in ("host", "packet-tunnel"):
            with self.subTest(kind=kind):
                verify_profile_capability_authorizations(
                    profile_entitlements(kind),
                    signed_capabilities(kind),
                    kind,
                    "YKUPL7Z869",
                    EXPECTED_APP_GROUP,
                )

    def test_unrestricted_app_group_may_be_absent_from_profile(self) -> None:
        profile = profile_entitlements("proxy-agent")
        profile.pop("com.apple.security.application-groups")
        verify_profile_capability_authorizations(
            profile,
            {},
            "proxy-agent",
            "YKUPL7Z869",
            EXPECTED_APP_GROUP,
        )

    def test_profile_rejects_missing_requested_network_extension_role(self) -> None:
        profile = profile_entitlements("packet-tunnel")
        profile["com.apple.developer.networking.networkextension"] = [
            "app-proxy-provider-systemextension"
        ]
        with self.assertRaises(EntitlementContractError):
            verify_profile_capability_authorizations(
                profile,
                signed_capabilities("packet-tunnel"),
                "packet-tunnel",
                "YKUPL7Z869",
                EXPECTED_APP_GROUP,
            )

    def test_profile_rejects_unknown_network_extension_authorization(self) -> None:
        profile = profile_entitlements("host")
        network_roles = profile["com.apple.developer.networking.networkextension"]
        if not isinstance(network_roles, list):
            self.fail("host profile fixture must contain a Network Extension list")
        profile["com.apple.developer.networking.networkextension"] = [
            *network_roles,
            "future-unreviewed-provider",
        ]
        with self.assertRaises(EntitlementContractError):
            verify_profile_capability_authorizations(
                profile,
                signed_capabilities("host"),
                "host",
                "YKUPL7Z869",
                EXPECTED_APP_GROUP,
            )

    def test_proxy_profile_rejects_network_extension_authorization(self) -> None:
        profile = profile_entitlements("proxy-agent")
        profile["com.apple.developer.networking.networkextension"] = [PACKET_TUNNEL_ROLE]
        with self.assertRaises(EntitlementContractError):
            verify_profile_capability_authorizations(
                profile,
                {},
                "proxy-agent",
                "YKUPL7Z869",
                EXPECTED_APP_GROUP,
            )

    def test_packet_profile_rejects_system_extension_install_authorization(self) -> None:
        profile = profile_entitlements("packet-tunnel")
        profile["com.apple.developer.system-extension.install"] = True
        with self.assertRaises(EntitlementContractError):
            verify_profile_capability_authorizations(
                profile,
                signed_capabilities("packet-tunnel"),
                "packet-tunnel",
                "YKUPL7Z869",
                EXPECTED_APP_GROUP,
            )

    def test_profile_rejects_unrelated_app_group_authorization(self) -> None:
        profile = profile_entitlements("proxy-agent")
        profile["com.apple.security.application-groups"] = [
            REGISTERED_APP_GROUP,
            "group.com.example.unrelated",
        ]
        with self.assertRaises(EntitlementContractError):
            verify_profile_capability_authorizations(
                profile,
                {},
                "proxy-agent",
                "YKUPL7Z869",
                EXPECTED_APP_GROUP,
            )

    def test_proxy_agent_requires_exact_private_and_shared_groups(self) -> None:
        verify_signed_keychain_access_group(
            {"keychain-access-groups": [EXPECTED_GROUP, EXPECTED_CREDENTIAL_GROUP]},
            "proxy-agent",
            EXPECTED_GROUP,
            EXPECTED_TUNNEL_GROUP,
        )

    def test_proxy_agent_rejects_missing_group(self) -> None:
        with self.assertRaises(EntitlementContractError):
            verify_signed_keychain_access_group(
                {}, "proxy-agent", EXPECTED_GROUP, EXPECTED_TUNNEL_GROUP
            )

    def test_proxy_agent_rejects_wrong_group(self) -> None:
        with self.assertRaises(EntitlementContractError):
            verify_signed_keychain_access_group(
                {"keychain-access-groups": ["WRONG.com.bill.clashformac.proxy-agent"]},
                "proxy-agent",
                EXPECTED_GROUP,
                EXPECTED_TUNNEL_GROUP,
            )

    def test_proxy_agent_rejects_additional_group(self) -> None:
        with self.assertRaises(EntitlementContractError):
            verify_signed_keychain_access_group(
                {
                    "keychain-access-groups": [
                        EXPECTED_GROUP,
                        EXPECTED_CREDENTIAL_GROUP,
                        "unexpected.group",
                    ]
                },
                "proxy-agent",
                EXPECTED_GROUP,
                EXPECTED_TUNNEL_GROUP,
            )

    def test_host_requires_exact_private_and_shared_groups(self) -> None:
        verify_signed_keychain_access_group(
            {"keychain-access-groups": [EXPECTED_HOST_GROUP, EXPECTED_CREDENTIAL_GROUP]},
            "host",
            EXPECTED_GROUP,
            EXPECTED_TUNNEL_GROUP,
        )
        with self.assertRaises(EntitlementContractError):
            verify_signed_keychain_access_group(
                {"keychain-access-groups": [EXPECTED_GROUP, EXPECTED_CREDENTIAL_GROUP]},
                "host",
                EXPECTED_GROUP,
                EXPECTED_TUNNEL_GROUP,
            )

    def test_packet_tunnel_requires_keychain_group_absence(self) -> None:
        verify_signed_keychain_access_group(
            {},
            "packet-tunnel",
            EXPECTED_GROUP,
            EXPECTED_TUNNEL_GROUP,
        )
        for group in [
            EXPECTED_TUNNEL_GROUP,
            EXPECTED_GROUP,
            EXPECTED_CREDENTIAL_GROUP,
            "YKUPL7Z869.*",
        ]:
            with self.subTest(group=group), self.assertRaises(EntitlementContractError):
                verify_signed_keychain_access_group(
                    {"keychain-access-groups": [group]},
                    "packet-tunnel",
                    EXPECTED_GROUP,
                    EXPECTED_TUNNEL_GROUP,
                )

    def test_host_rejects_absent_group(self) -> None:
        with self.assertRaises(EntitlementContractError):
            verify_signed_keychain_access_group(
                {}, "host", EXPECTED_GROUP, EXPECTED_TUNNEL_GROUP
            )

    def test_proxy_agent_profile_accepts_exact_group(self) -> None:
        verify_profile_keychain_access_group(
            {"keychain-access-groups": [EXPECTED_GROUP, EXPECTED_CREDENTIAL_GROUP]},
            "proxy-agent",
            EXPECTED_GROUP,
            EXPECTED_TUNNEL_GROUP,
            "YKUPL7Z869",
        )

    def test_proxy_agent_profile_accepts_team_wildcard(self) -> None:
        verify_profile_keychain_access_group(
            {"keychain-access-groups": ["YKUPL7Z869.*"]},
            "proxy-agent",
            EXPECTED_GROUP,
            EXPECTED_TUNNEL_GROUP,
            "YKUPL7Z869",
        )

    def test_proxy_agent_profile_rejects_missing_authorization(self) -> None:
        with self.assertRaises(EntitlementContractError):
            verify_profile_keychain_access_group(
                {},
                "proxy-agent",
                EXPECTED_GROUP,
                EXPECTED_TUNNEL_GROUP,
                "YKUPL7Z869",
            )

    def test_proxy_agent_profile_rejects_uncontrolled_wildcard(self) -> None:
        for group in ["*", "WRONG.*", "YKUPL7Z869.com.bill.*"]:
            with self.subTest(group=group), self.assertRaises(EntitlementContractError):
                verify_profile_keychain_access_group(
                    {"keychain-access-groups": [group]},
                    "proxy-agent",
                    EXPECTED_GROUP,
                    EXPECTED_TUNNEL_GROUP,
                    "YKUPL7Z869",
                )

    def test_proxy_agent_profile_allows_unrelated_exact_authorization(self) -> None:
        for authorized_groups in [
            [EXPECTED_GROUP, EXPECTED_CREDENTIAL_GROUP],
            ["YKUPL7Z869.*"],
        ]:
            with self.subTest(authorized_groups=authorized_groups):
                verify_profile_keychain_access_group(
                    {
                        "keychain-access-groups": [
                            *authorized_groups,
                            "com.apple.token",
                        ]
                    },
                    "proxy-agent",
                    EXPECTED_GROUP,
                    EXPECTED_TUNNEL_GROUP,
                    "YKUPL7Z869",
                )

    def test_proxy_agent_profile_rejects_wrong_team_wildcard_among_extras(self) -> None:
        with self.assertRaises(EntitlementContractError):
            verify_profile_keychain_access_group(
                {
                    "keychain-access-groups": [
                        "YKUPL7Z869.*",
                        "WRONGTEAM1.*",
                    ]
                },
                "proxy-agent",
                EXPECTED_GROUP,
                EXPECTED_TUNNEL_GROUP,
                "YKUPL7Z869",
            )

    def test_proxy_agent_profile_accepts_team_wildcard(self) -> None:
        profile = {"keychain-access-groups": ["YKUPL7Z869.*"]}
        verify_profile_keychain_access_group(
            profile,
            "proxy-agent",
            EXPECTED_GROUP,
            EXPECTED_TUNNEL_GROUP,
            "YKUPL7Z869",
        )

    def test_packet_tunnel_profile_allows_only_absent_or_exact_team_wildcard(self) -> None:
        verify_profile_keychain_access_group(
            {}, "packet-tunnel", EXPECTED_GROUP, EXPECTED_TUNNEL_GROUP, "YKUPL7Z869"
        )
        verify_profile_keychain_access_group(
            {"keychain-access-groups": ["YKUPL7Z869.*"]},
            "packet-tunnel",
            EXPECTED_GROUP,
            EXPECTED_TUNNEL_GROUP,
            "YKUPL7Z869",
        )
        with self.assertRaises(EntitlementContractError):
            verify_profile_keychain_access_group(
                {"keychain-access-groups": [EXPECTED_TUNNEL_GROUP]},
                "packet-tunnel",
                EXPECTED_GROUP,
                EXPECTED_TUNNEL_GROUP,
                "YKUPL7Z869",
            )

    def test_host_profile_authorizes_its_exact_group(self) -> None:
        verify_profile_keychain_access_group(
            {"keychain-access-groups": [EXPECTED_HOST_GROUP, EXPECTED_CREDENTIAL_GROUP]},
            "host",
            EXPECTED_GROUP,
            EXPECTED_TUNNEL_GROUP,
            "YKUPL7Z869",
        )

    def test_host_profile_rejects_provider_group(self) -> None:
        with self.assertRaises(EntitlementContractError):
            verify_profile_keychain_access_group(
                {
                    "keychain-access-groups": [
                        EXPECTED_HOST_GROUP,
                        EXPECTED_CREDENTIAL_GROUP,
                        EXPECTED_GROUP,
                    ]
                },
                "host",
                EXPECTED_GROUP,
                EXPECTED_TUNNEL_GROUP,
                "YKUPL7Z869",
            )


if __name__ == "__main__":
    unittest.main()
