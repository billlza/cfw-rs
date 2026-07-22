import unittest

from scripts.release_entitlement_contract import EntitlementContractError
from scripts.release_entitlement_contract import verify_profile_keychain_access_group
from scripts.release_entitlement_contract import verify_signed_keychain_access_group


EXPECTED_GROUP = "YKUPL7Z869.com.bill.clashformac.proxy-agent"
EXPECTED_TUNNEL_GROUP = "YKUPL7Z869.com.bill.clashformac.packet-tunnel"
EXPECTED_HOST_GROUP = "YKUPL7Z869.com.bill.clashformac"
EXPECTED_CREDENTIAL_GROUP = "YKUPL7Z869.com.bill.clashformac.credentials"


class ReleaseEntitlementContractTests(unittest.TestCase):
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
