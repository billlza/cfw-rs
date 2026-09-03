from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts import release_signing_plan as plan


SOURCE_PLAN = {
    "description": "fixed",
    "nested": [{"name": str(index)} for index in range(5)],
    "outer": {"signedLast": True},
    "schemaVersion": 1,
    "teamIdentifier": "YKUPL7Z869",
}


class ReleaseSigningPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name).resolve()
        source = self.repository / plan.SOURCE_PLAN_RELATIVE
        source.parent.mkdir(parents=True)
        source.write_text(json.dumps(SOURCE_PLAN), encoding="utf-8")
        self.root = self.repository / "target/candidates/0.4.0/ga-preflight/40041"
        (self.root / "profiles").mkdir(parents=True)
        (self.root / "entitlements").mkdir()
        (self.root / "entitlements/signing-order.json").write_bytes(source.read_bytes())
        for relative in (
            "entitlements/GlobalAuthority.entitlements",
            "entitlements/ProxyAgent.release.xcent",
            "entitlements/PacketTunnel.release.xcent",
            "entitlements/Host.release.xcent",
            "profiles/proxy-agent.provisionprofile",
            "profiles/packet-tunnel.provisionprofile",
            "profiles/host.provisionprofile",
        ):
            (self.root / relative).write_bytes(relative.encode("utf-8"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_create_and_reopen_exact_plan(self) -> None:
        destination = plan.create_plan(self.repository, self.root)

        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        observed = plan.validate_plan(self.repository, self.root)
        self.assertEqual(tuple(observed["order"]), plan.COMPONENT_ORDER)
        self.assertEqual(set(observed["components"]), set(plan.COMPONENT_ORDER))

    def test_plan_is_exclusive(self) -> None:
        plan.create_plan(self.repository, self.root)
        with self.assertRaisesRegex(plan.SigningPlanError, "durably create"):
            plan.create_plan(self.repository, self.root)

    def test_each_profile_and_entitlement_is_bound(self) -> None:
        plan.create_plan(self.repository, self.root)
        for relative in (
            "entitlements/GlobalAuthority.entitlements",
            "entitlements/ProxyAgent.release.xcent",
            "entitlements/PacketTunnel.release.xcent",
            "entitlements/Host.release.xcent",
            "profiles/proxy-agent.provisionprofile",
            "profiles/packet-tunnel.provisionprofile",
            "profiles/host.provisionprofile",
        ):
            with self.subTest(relative=relative):
                path = self.root / relative
                original = path.read_bytes()
                path.write_bytes(original + b"drift")
                with self.assertRaisesRegex(
                    plan.SigningPlanError, "fixed signing inputs"
                ):
                    plan.validate_plan(self.repository, self.root)
                path.write_bytes(original)

    def test_source_plan_substitution_is_rejected(self) -> None:
        plan.create_plan(self.repository, self.root)
        candidate = self.root / "entitlements/signing-order.json"
        candidate.write_bytes(candidate.read_bytes() + b"\n")
        with self.assertRaisesRegex(plan.SigningPlanError, "differs from source"):
            plan.validate_plan(self.repository, self.root)

    def test_symlink_and_hardlink_inputs_are_rejected(self) -> None:
        entitlement = self.root / "entitlements/Host.release.xcent"
        entitlement.unlink()
        entitlement.symlink_to("ProxyAgent.release.xcent")
        with self.assertRaisesRegex(plan.SigningPlanError, "regular file"):
            plan.expected_plan(self.repository, self.root)

        entitlement.unlink()
        os.link(
            self.root / "entitlements/ProxyAgent.release.xcent",
            entitlement,
        )
        with self.assertRaisesRegex(plan.SigningPlanError, "regular file"):
            plan.expected_plan(self.repository, self.root)

    def test_unknown_or_reordered_component_plan_is_rejected(self) -> None:
        destination = plan.create_plan(self.repository, self.root)
        value = json.loads(destination.read_bytes())
        value["order"] = list(reversed(value["order"]))
        with self.assertRaisesRegex(plan.SigningPlanError, "fixed signing inputs"):
            plan.validate_plan(self.repository, self.root, value)
        value = json.loads(destination.read_bytes())
        value["components"]["unknown"] = "0" * 64
        with self.assertRaisesRegex(plan.SigningPlanError, "fixed signing inputs"):
            plan.validate_plan(self.repository, self.root, value)


if __name__ == "__main__":
    unittest.main()
