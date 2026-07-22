from __future__ import annotations

import unittest

from scripts.audit_rust_target import (
    AuditContractError,
    parse_audit_result,
    reachable_package_ids,
    render_audit_lock,
    select_locked_packages,
    target_package_keys,
)


def metadata_fixture() -> dict:
    return {
        "workspace_members": ["path+file:///repo#app@0.4.0"],
        "resolve": {
            "nodes": [
                {
                    "id": "path+file:///repo#app@0.4.0",
                    "deps": [
                        {
                            "name": "mac_only",
                            "pkg": "registry+https://example.invalid/index#mac-only@1.0.0",
                        }
                    ],
                },
                {
                    "id": "registry+https://example.invalid/index#mac-only@1.0.0",
                    "deps": [],
                },
            ]
        },
        "packages": [
            {
                "id": "path+file:///repo#app@0.4.0",
                "name": "app",
                "version": "0.4.0",
                "source": None,
            },
            {
                "id": "registry+https://example.invalid/index#mac-only@1.0.0",
                "name": "mac-only",
                "version": "1.0.0",
                "source": "registry+https://example.invalid/index",
            },
        ],
    }


class TargetAuditTests(unittest.TestCase):
    def test_reachable_graph_starts_at_every_workspace_member(self) -> None:
        self.assertEqual(
            reachable_package_ids(metadata_fixture()),
            {
                "path+file:///repo#app@0.4.0",
                "registry+https://example.invalid/index#mac-only@1.0.0",
            },
        )

    def test_target_inventory_excludes_non_resolved_platform_package(self) -> None:
        keys = target_package_keys(metadata_fixture())
        selected = select_locked_packages(
            {
                "version": 4,
                "package": [
                    {"name": "app", "version": "0.4.0"},
                    {
                        "name": "mac-only",
                        "version": "1.0.0",
                        "source": "registry+https://example.invalid/index",
                        "checksum": "abc",
                    },
                    {
                        "name": "linux-only",
                        "version": "1.0.0",
                        "source": "registry+https://example.invalid/index",
                        "checksum": "def",
                    },
                ],
            },
            keys,
        )
        self.assertEqual([package["name"] for package in selected], ["app", "mac-only"])
        rendered = render_audit_lock(selected, "aarch64-apple-darwin")
        self.assertNotIn("linux-only", rendered)
        self.assertNotIn("dependencies =", rendered)

    def test_missing_target_package_fails_closed(self) -> None:
        with self.assertRaisesRegex(AuditContractError, "absent from Cargo.lock"):
            select_locked_packages(
                {"version": 4, "package": [{"name": "app", "version": "0.4.0"}]},
                {("app", "0.4.0", None), ("missing", "1.0.0", None)},
            )

    def test_audit_result_rejects_warnings(self) -> None:
        with self.assertRaisesRegex(AuditContractError, "1 warning"):
            parse_audit_result(
                '{"lockfile":{"dependency-count":2},'
                '"vulnerabilities":{"count":0},'
                '"warnings":{"unmaintained":[{"package":"x"}]}}',
                2,
            )

    def test_audit_result_requires_complete_inventory(self) -> None:
        with self.assertRaisesRegex(AuditContractError, "complete target inventory"):
            parse_audit_result(
                '{"lockfile":{"dependency-count":1},'
                '"vulnerabilities":{"count":0},"warnings":{}}',
                2,
            )


if __name__ == "__main__":
    unittest.main()
