from __future__ import annotations

import copy
import unittest

from scripts.harness.lifecycle_matrix import (
    HARNESS_VERSION,
    REQUIRED_PROBES,
    SCHEMA_VERSION,
    LifecycleMatrixError,
    probe_matrix,
    required_probe_ids,
    validate_lifecycle_matrix,
)

_SIGNED_APP_TREE = "a" * 64
_MACHINE = "b" * 64
_MACOS_BUILD = "24A335"
_OPERATION_ID = "op-4f8c"
_INSTALLATION_ID = "install-91ac"
_EPOCH = 3
_GENERATION = 7


def _bindings() -> dict:
    return {
        "signed_app_tree_sha256": _SIGNED_APP_TREE,
        "machine_sha256": _MACHINE,
        "macos_build": _MACOS_BUILD,
        "operation_id": _OPERATION_ID,
        "installation_id": _INSTALLATION_ID,
        "epoch": _EPOCH,
        "generation": _GENERATION,
    }


def _attributes_for(probe_id: str) -> dict:
    if probe_id == "fast-user-switching":
        return {"user_count": 2}
    if probe_id == "concurrent-starts":
        return {"concurrent_start_count": 2}
    return {}


def fixture() -> dict:
    probes = []
    for index, probe_id in enumerate(sorted(REQUIRED_PROBES)):
        # A distinct non-secret report hash per probe (report_sha256 must be
        # unique across the matrix).
        report = f"{index:02x}" + "c" * 62
        probes.append(
            {
                "id": probe_id,
                "status": "passed",
                "report_sha256": report,
                "bindings": _bindings(),
                "attributes": _attributes_for(probe_id),
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "harness_version": HARNESS_VERSION,
        "candidate": {
            "signed_app_tree_sha256": _SIGNED_APP_TREE,
            "machine_sha256": _MACHINE,
            "macos_build": _MACOS_BUILD,
            "architecture": "arm64",
            "operation_context": {
                "operation_id": _OPERATION_ID,
                "installation_id": _INSTALLATION_ID,
                "epoch": _EPOCH,
                "generation": _GENERATION,
            },
        },
        "probes": probes,
    }


class LifecycleMatrixHappyPathTests(unittest.TestCase):
    def test_full_matrix_with_complete_bound_evidence_passes(self) -> None:
        summary = validate_lifecycle_matrix(fixture())
        self.assertEqual(len(summary["probes"]), len(REQUIRED_PROBES))
        self.assertEqual(set(summary["probes"]), set(REQUIRED_PROBES))

    def test_matrix_covers_every_requirement_6_1_case(self) -> None:
        # The machine-readable matrix must exhaustively enumerate Requirement
        # 6.1's lifecycle cases.
        expected = {
            "inside-out-signatures",
            "team-id",
            "bundle-identifiers",
            "entitlements",
            "provisioning",
            "daemon-registration-approval",
            "daemon-registration-denial",
            "system-extension-approval",
            "system-extension-pending",
            "system-extension-restart",
            "upgrade",
            "replacement",
            "downgrade-refusal",
            "install-cleanup",
            "uninstall-cleanup",
            "login",
            "logout",
            "lock",
            "fast-user-switching",
            "concurrent-starts",
            "cancellation",
            "sleep-wake",
            "reboot-recovery",
            "host-crash",
            "global-authority-crash",
            "proxy-agent-crash",
            "provider-crash",
        }
        self.assertEqual(required_probe_ids(), expected)
        self.assertEqual(set(probe_matrix()), expected)


class LifecycleMatrixFailClosedTests(unittest.TestCase):
    def test_missing_probe_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"].pop()  # drop provider-crash (sorted last)
        with self.assertRaisesRegex(LifecycleMatrixError, "missing required probes"):
            validate_lifecycle_matrix(value)

    def test_unavailable_probe_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"][0]["status"] = "unavailable"
        with self.assertRaisesRegex(LifecycleMatrixError, "only 'passed' evidence"):
            validate_lifecycle_matrix(value)

    def test_skipped_probe_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"][3]["status"] = "skipped"
        with self.assertRaisesRegex(LifecycleMatrixError, "only 'passed' evidence"):
            validate_lifecycle_matrix(value)

    def test_failed_probe_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"][5]["status"] = "failed"
        with self.assertRaisesRegex(LifecycleMatrixError, "only 'passed' evidence"):
            validate_lifecycle_matrix(value)

    def test_malformed_probe_object_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"][2].pop("bindings")
        with self.assertRaisesRegex(LifecycleMatrixError, "missing required fields"):
            validate_lifecycle_matrix(value)

    def test_unknown_probe_field_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"][1]["extra"] = True
        with self.assertRaisesRegex(LifecycleMatrixError, "unknown fields"):
            validate_lifecycle_matrix(value)

    def test_unknown_probe_id_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"][0]["id"] = "not-a-real-probe"
        with self.assertRaisesRegex(LifecycleMatrixError, "unknown probe id"):
            validate_lifecycle_matrix(value)

    def test_duplicate_probe_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        clone = copy.deepcopy(value["probes"][0])
        clone["report_sha256"] = "f" * 64
        value["probes"].append(clone)
        with self.assertRaisesRegex(LifecycleMatrixError, "declares more probes"):
            validate_lifecycle_matrix(value)

    def test_missing_signed_app_tree_binding_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"][0]["bindings"].pop("signed_app_tree_sha256")
        with self.assertRaisesRegex(LifecycleMatrixError, "missing required fields"):
            validate_lifecycle_matrix(value)

    def test_mismatched_signed_app_tree_binding_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"][0]["bindings"]["signed_app_tree_sha256"] = "d" * 64
        with self.assertRaisesRegex(LifecycleMatrixError, "signed_app_tree_sha256 does not match"):
            validate_lifecycle_matrix(value)

    def test_mismatched_machine_binding_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"][1]["bindings"]["machine_sha256"] = "e" * 64
        with self.assertRaisesRegex(LifecycleMatrixError, "machine_sha256 does not match"):
            validate_lifecycle_matrix(value)

    def test_mismatched_macos_build_binding_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"][2]["bindings"]["macos_build"] = "23F79"
        with self.assertRaisesRegex(LifecycleMatrixError, "macos_build does not match"):
            validate_lifecycle_matrix(value)

    def test_mismatched_operation_context_binding_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"][4]["bindings"]["generation"] = _GENERATION + 1
        with self.assertRaisesRegex(LifecycleMatrixError, "generation does not match"):
            validate_lifecycle_matrix(value)

    def test_missing_report_hash_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"][0]["report_sha256"] = "not-a-hash"
        with self.assertRaisesRegex(LifecycleMatrixError, "report_sha256 is not a lowercase"):
            validate_lifecycle_matrix(value)

    def test_reused_report_hash_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"][1]["report_sha256"] = value["probes"][0]["report_sha256"]
        with self.assertRaisesRegex(LifecycleMatrixError, "reuses a raw report hash"):
            validate_lifecycle_matrix(value)

    def test_non_apple_silicon_candidate_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["candidate"]["architecture"] = "x86_64"
        with self.assertRaisesRegex(LifecycleMatrixError, "Apple Silicon"):
            validate_lifecycle_matrix(value)

    def test_invalid_macos_build_identity_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["candidate"]["macos_build"] = "not a build"
        with self.assertRaisesRegex(LifecycleMatrixError, "macOS build identifier"):
            validate_lifecycle_matrix(value)

    def test_fast_user_switching_below_two_users_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        for probe in value["probes"]:
            if probe["id"] == "fast-user-switching":
                probe["attributes"]["user_count"] = 1
        with self.assertRaisesRegex(LifecycleMatrixError, "user_count must be an integer >= 2"):
            validate_lifecycle_matrix(value)

    def test_concurrent_starts_below_two_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        for probe in value["probes"]:
            if probe["id"] == "concurrent-starts":
                probe["attributes"]["concurrent_start_count"] = 1
        with self.assertRaisesRegex(LifecycleMatrixError, "concurrent_start_count"):
            validate_lifecycle_matrix(value)

    def test_wrong_schema_version_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["schema_version"] = 2
        with self.assertRaisesRegex(LifecycleMatrixError, "schema_version"):
            validate_lifecycle_matrix(value)

    def test_wrong_harness_version_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["harness_version"] = "lifecycle-matrix-v2"
        with self.assertRaisesRegex(LifecycleMatrixError, "harness_version"):
            validate_lifecycle_matrix(value)

    def test_non_object_document_fails_closed(self) -> None:
        with self.assertRaisesRegex(LifecycleMatrixError, "must be a JSON object"):
            validate_lifecycle_matrix(["not", "a", "document"])

    def test_empty_probe_list_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["probes"] = []
        with self.assertRaisesRegex(LifecycleMatrixError, "at least one probe"):
            validate_lifecycle_matrix(value)


if __name__ == "__main__":
    unittest.main()
