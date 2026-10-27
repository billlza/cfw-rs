from __future__ import annotations

import unittest

from scripts.publication.rust_targets import WINDOWS_TARGET
from scripts.verify_ci_no_masking import DEFAULT_PINS, REPO_ROOT, audit_macos_hosted_job

WINDOWS_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "windows.yml"


class WindowsSupplyChainWorkflowTests(unittest.TestCase):
    def test_supply_chain_job_audits_the_windows_program_through_the_closed_gates(
        self,
    ) -> None:
        invocations = audit_macos_hosted_job(WINDOWS_WORKFLOW, "supply-chain", DEFAULT_PINS)
        self.assertEqual(
            invocations,
            (
                ("prepare-cargo-workspace-inputs",),
                ("bootstrap-policy-tools",),
                ("rust-target-audit", "--target", WINDOWS_TARGET),
                ("cargo-deny", "--target", WINDOWS_TARGET),
            ),
        )


if __name__ == "__main__":
    unittest.main()
