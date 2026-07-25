from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.harness.adversarial_clients import REQUIRED_CASES as ADVERSARIAL_CASES
from scripts.harness.packet_evidence import REQUIRED_CASES as PACKET_CASES
from scripts.harness.performance_gates import percentiles
from scripts.harness.lifecycle_matrix import (
    HARNESS_VERSION,
    REQUIRED_PROBES,
    SCHEMA_VERSION as LIFECYCLE_SCHEMA_VERSION,
)
from scripts.harness.physical_evidence_aggregator import (
    AGGREGATOR_VERSION,
    EXPECTED_TOOL_VERSIONS,
    GRANTED_LEVEL,
    REQUIRED_OS,
    SCHEMA_VERSION,
    PhysicalEvidenceError,
    _canonical_report_hash,
    load_physical_evidence,
    self_check,
    validate_physical_evidence,
)

# One shared candidate identity across every embedded harness document.
APP_MANIFEST = "a" * 64
SIGNED_TREE = "b" * 64
BUILD_NUMBER = "40000"
BUILT_AT = "2026-07-01T00:00:00Z"
CAPTURED_AT = "2026-07-22T00:00:00Z"

# The two required clean physical run sets (macOS 15 and current macOS).
RUN_PARAMS = {
    "macos15": {
        "macos_version": "15.0",
        "macos_build": "24A335",
        "machine_sha256": "c" * 64,
        "operation_id": "op-15aa",
        "installation_id": "install-15aa",
        "epoch": 3,
        "generation": 7,
    },
    "current-macos": {
        "macos_version": "15.5",
        "macos_build": "24F79",
        "machine_sha256": "d" * 64,
        "operation_id": "op-cur9",
        "installation_id": "install-cur9",
        "epoch": 4,
        "generation": 9,
    },
}


def _series(samples: list[float]) -> dict:
    summary = percentiles([float(sample) for sample in samples])
    return {
        "samples": list(samples),
        "p50": summary["p50"],
        "p95": summary["p95"],
        "p99": summary["p99"],
    }


def _lifecycle_doc(run: dict) -> dict:
    bindings = {
        "signed_app_tree_sha256": SIGNED_TREE,
        "machine_sha256": run["machine_sha256"],
        "macos_build": run["macos_build"],
        "operation_id": run["operation_id"],
        "installation_id": run["installation_id"],
        "epoch": run["epoch"],
        "generation": run["generation"],
    }
    probes = []
    for index, probe_id in enumerate(sorted(REQUIRED_PROBES)):
        # A distinct non-secret report hash per probe within this document.
        report = f"{index:02x}" + "e" * 62
        attributes: dict = {}
        if probe_id == "fast-user-switching":
            attributes = {"user_count": 2}
        elif probe_id == "concurrent-starts":
            attributes = {"concurrent_start_count": 2}
        probes.append(
            {
                "id": probe_id,
                "status": "passed",
                "report_sha256": report,
                "bindings": copy.deepcopy(bindings),
                "attributes": attributes,
            }
        )
    return {
        "schema_version": LIFECYCLE_SCHEMA_VERSION,
        "harness_version": HARNESS_VERSION,
        "candidate": {
            "signed_app_tree_sha256": SIGNED_TREE,
            "machine_sha256": run["machine_sha256"],
            "macos_build": run["macos_build"],
            "architecture": "arm64",
            "operation_context": {
                "operation_id": run["operation_id"],
                "installation_id": run["installation_id"],
                "epoch": run["epoch"],
                "generation": run["generation"],
            },
        },
        "probes": probes,
    }


def _packet_doc(run: dict) -> dict:
    cases = []
    for index, (case_id, spec) in enumerate(PACKET_CASES.items()):
        method = "server_observation" if spec.protocol == "dns" else "packet_capture"
        cases.append(
            {
                "id": case_id,
                "protocol": spec.protocol,
                "family": spec.family,
                "resolver_role": spec.resolver_role,
                "token": f"unique-packet-token-{index:03d}",
                "method": method,
                "vantage": spec.vantage,
                "token_observed": spec.token_observed,
                "capture_sha256": f"{index:064x}",
                "observation_ms": 5_000,
                "captured_at": CAPTURED_AT,
                "candidate_app_manifest_sha256": APP_MANIFEST,
            }
        )
    return {
        "schema_version": 1,
        "product": {"version": "0.4.0", "build_number": BUILD_NUMBER},
        "candidate": {
            "app_manifest_sha256": APP_MANIFEST,
            "signed_app_tree_sha256": SIGNED_TREE,
        },
        "platform": {
            "architecture": "arm64",
            "macos_version": run["macos_version"],
            "hardware_model": "Mac fixture",
            "clean_install": True,
        },
        "captured_at": CAPTURED_AT,
        "cases": cases,
    }


def _performance_doc(run: dict) -> dict:
    return {
        "schema_version": 1,
        "parameters": {
            "machine": {
                "architecture": "arm64",
                "macos_version": run["macos_version"],
                "hardware_model": "Mac15,3",
            },
            "network": {"description": "lab shaping bridge", "uplink_mbps": 1000},
            "power": {"source": "ac", "low_power_mode": False},
            "build": {
                "version": "0.4.0",
                "build_number": BUILD_NUMBER,
                "app_manifest_sha256": APP_MANIFEST,
            },
        },
        "weak_network": [
            {
                "id": "latency-100ms-loss-1pct-10mbps",
                "control": {
                    "applied": True,
                    "kind": "shaping",
                    "latency_ms": 100,
                    "loss_percent": 1.0,
                    "bandwidth_mbps": 10.0,
                },
                "recovery_ms": _series([4000.0, 5000.0, 6000.0, 7000.0]),
            },
            {
                "id": "latency-300ms-loss-5pct-1mbps",
                "control": {
                    "applied": True,
                    "kind": "shaping",
                    "latency_ms": 300,
                    "loss_percent": 5.0,
                    "bandwidth_mbps": 1.0,
                },
                "recovery_ms": _series([6000.0, 7000.0, 8000.0, 9000.0]),
            },
            {
                "id": "outage-30s",
                "control": {"applied": True, "kind": "outage", "outage_seconds": 30},
                "recovery_ms": _series([7000.0, 8000.0, 9000.0, 9500.0]),
            },
        ],
        "latency": {
            "connect_ms": _series([2000.0, 3000.0, 4000.0, 4500.0]),
            "disconnect_ms": _series([1000.0, 1500.0, 2000.0, 2500.0]),
            "added_latency_percent": _series([2.0, 4.0, 6.0, 8.0]),
        },
        "throughput": {"baseline_mbps": 100.0, "measured_mbps": 95.0, "ratio_percent": 95.0},
        "resources": {
            "active_idle_cpu_percent": _series([0.2, 0.4, 0.6, 0.8]),
            "active_rss_mib": _series([90.0, 100.0, 110.0, 118.0]),
        },
        "switch_cycle": {"switch_count": 100, "rss_growth_mib": 4.0, "fd_growth": 1},
        "soak": {"duration_hours": 24, "crash_count": 0},
    }


def _adversarial_doc(run: dict) -> dict:
    cases = []
    for case_id, (category, client, denial_code, cleanup) in ADVERSARIAL_CASES.items():
        cases.append(
            {
                "id": case_id,
                "category": category,
                "client": client,
                "executed": True,
                "outcome": "denied",
                "denial_code": denial_code,
                "cleanup": cleanup,
                "secret_observed": False,
            }
        )
    return {
        "schema_version": 1,
        "product": {"version": "0.4.0", "build_number": BUILD_NUMBER},
        "app_manifest_sha256": APP_MANIFEST,
        "captured_at": CAPTURED_AT,
        "platform": {
            "architecture": "arm64",
            "macos_version": run["macos_version"],
            "hardware_model": "Mac fixture",
            "clean_install": True,
        },
        "signing": {
            "team_id": "YKUPL7Z869",
            "allowed_client": {
                "signing_id": "com.bill.clashformac",
                "cdhash": "b" * 40,
                "designated_requirement_sha256": "c" * 64,
            },
            "denied_client": {
                "signing_id": "com.bill.clashformac.adversary",
                "cdhash": "d" * 40,
                "designated_requirement_sha256": "e" * 64,
            },
        },
        "baseline": {"client": "allowed", "executed": True, "authorized": True},
        "cases": cases,
    }


_HARNESS_BUILDERS = {
    "lifecycle": _lifecycle_doc,
    "packet": _packet_doc,
    "performance": _performance_doc,
    "adversarial": _adversarial_doc,
}


def _report_entry(harness: str, document: dict) -> dict:
    return {
        "tool_version": EXPECTED_TOOL_VERSIONS[harness],
        "report_sha256": _canonical_report_hash(document),
        "captured_at": CAPTURED_AT,
        "document": document,
    }


def _rehash(report: dict) -> None:
    report["report_sha256"] = _canonical_report_hash(report["document"])


def _run(os_label: str) -> dict:
    params = RUN_PARAMS[os_label]
    reports = {
        harness: _report_entry(harness, builder(params))
        for harness, builder in _HARNESS_BUILDERS.items()
    }
    return {
        "os": os_label,
        "macos_version": params["macos_version"],
        "macos_build": params["macos_build"],
        "machine_sha256": params["machine_sha256"],
        "clean_install": True,
        "evidence_source": "harness",
        "captured_at": CAPTURED_AT,
        "reports": reports,
    }


def fixture() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "aggregator_version": AGGREGATOR_VERSION,
        "granted_level": GRANTED_LEVEL,
        "candidate": {
            "version": "0.4.0",
            "build_number": BUILD_NUMBER,
            "app_manifest_sha256": APP_MANIFEST,
            "signed_app_tree_sha256": SIGNED_TREE,
            "built_at": BUILT_AT,
        },
        "runs": [_run("macos15"), _run("current-macos")],
    }


class PhysicalEvidenceHappyPathTests(unittest.TestCase):
    def test_two_os_complete_aggregate_grants_signed_installed(self) -> None:
        summary = validate_physical_evidence(fixture())
        self.assertEqual(summary["granted_level"], GRANTED_LEVEL)
        self.assertEqual(set(summary["runs"]), set(REQUIRED_OS))
        # Four harnesses across two runs => eight distinct bound reports.
        self.assertEqual(summary["reports"], 8)
        self.assertEqual(summary["candidate"]["build_number"], BUILD_NUMBER)

    def test_required_os_set_is_macos15_and_current(self) -> None:
        self.assertEqual(REQUIRED_OS, frozenset({"macos15", "current-macos"}))

    def test_self_check_contract_holds(self) -> None:
        # Wiring self-check used by the boundary gate must not raise.
        self_check()


class PhysicalEvidenceFailClosedTests(unittest.TestCase):
    def test_missing_os_run_set_fails_closed(self) -> None:
        value = fixture()
        value["runs"] = [value["runs"][0]]  # drop current-macos
        with self.assertRaisesRegex(PhysicalEvidenceError, "each required macOS run set exactly once"):
            validate_physical_evidence(value)

    def test_duplicate_os_run_set_fails_closed(self) -> None:
        value = fixture()
        value["runs"] = [_run("macos15"), _run("macos15")]
        with self.assertRaisesRegex(PhysicalEvidenceError, "duplicates the 'macos15' run"):
            validate_physical_evidence(value)

    def test_unknown_os_run_set_fails_closed(self) -> None:
        value = fixture()
        value["runs"][1]["os"] = "macos-beta"
        with self.assertRaisesRegex(PhysicalEvidenceError, "unknown macOS run set"):
            validate_physical_evidence(value)

    def test_missing_harness_report_fails_closed(self) -> None:
        value = fixture()
        del value["runs"][0]["reports"]["packet"]
        with self.assertRaisesRegex(PhysicalEvidenceError, "missing required fields"):
            validate_physical_evidence(value)

    def test_mismatched_candidate_identity_fails_closed(self) -> None:
        value = fixture()
        # Rebuild the packet report bound to a foreign build number.
        doc = value["runs"][0]["reports"]["packet"]["document"]
        doc["product"]["build_number"] = "50000"
        _rehash(value["runs"][0]["reports"]["packet"])
        with self.assertRaisesRegex(PhysicalEvidenceError, "build number does not match"):
            validate_physical_evidence(value)

    def test_mismatched_signed_app_tree_fails_closed(self) -> None:
        value = fixture()
        doc = value["runs"][0]["reports"]["lifecycle"]["document"]
        doc["candidate"]["signed_app_tree_sha256"] = "f" * 64
        for probe in doc["probes"]:
            probe["bindings"]["signed_app_tree_sha256"] = "f" * 64
        _rehash(value["runs"][0]["reports"]["lifecycle"])
        with self.assertRaisesRegex(PhysicalEvidenceError, "signed app tree does not match"):
            validate_physical_evidence(value)

    def test_run_macos_version_inconsistent_across_reports_fails_closed(self) -> None:
        value = fixture()
        # Performance report claims a different macOS version than the run.
        doc = value["runs"][0]["reports"]["performance"]["document"]
        doc["parameters"]["machine"]["macos_version"] = "14.7"
        _rehash(value["runs"][0]["reports"]["performance"])
        with self.assertRaisesRegex(PhysicalEvidenceError, "macOS version does not match the run"):
            validate_physical_evidence(value)

    def test_stale_report_fails_closed(self) -> None:
        value = fixture()
        value["runs"][0]["reports"]["adversarial"]["captured_at"] = "2026-06-01T00:00:00Z"
        with self.assertRaisesRegex(PhysicalEvidenceError, "stale: captured before"):
            validate_physical_evidence(value)

    def test_duplicated_report_hash_fails_closed(self) -> None:
        value = fixture()
        # Replay run 0's lifecycle report verbatim into run 1.
        value["runs"][1]["reports"]["lifecycle"] = copy.deepcopy(
            value["runs"][0]["reports"]["lifecycle"]
        )
        with self.assertRaisesRegex(PhysicalEvidenceError, "reuses a raw report hash"):
            validate_physical_evidence(value)

    def test_tampered_report_hash_fails_closed(self) -> None:
        value = fixture()
        # Mutate the document but leave the declared hash untouched.
        value["runs"][0]["reports"]["packet"]["document"]["captured_at"] = "2026-07-23T00:00:00Z"
        with self.assertRaisesRegex(PhysicalEvidenceError, "does not content-address"):
            validate_physical_evidence(value)

    def test_wrong_tool_version_fails_closed(self) -> None:
        value = fixture()
        value["runs"][0]["reports"]["lifecycle"]["tool_version"] = "lifecycle-matrix-v2"
        with self.assertRaisesRegex(PhysicalEvidenceError, "tool_version is"):
            validate_physical_evidence(value)

    def test_any_harness_failure_fails_closed(self) -> None:
        value = fixture()
        # Drop a probe from the lifecycle matrix so its own validator rejects it,
        # then re-hash so the failure surfaces from the harness, not the binding.
        doc = value["runs"][1]["reports"]["lifecycle"]["document"]
        doc["probes"].pop()
        _rehash(value["runs"][1]["reports"]["lifecycle"])
        with self.assertRaisesRegex(PhysicalEvidenceError, "harness validation failed"):
            validate_physical_evidence(value)

    def test_partial_packet_matrix_fails_closed(self) -> None:
        value = fixture()
        doc = value["runs"][0]["reports"]["packet"]["document"]
        doc["cases"] = doc["cases"][:-1]
        _rehash(value["runs"][0]["reports"]["packet"])
        with self.assertRaisesRegex(PhysicalEvidenceError, "harness validation failed"):
            validate_physical_evidence(value)

    def test_manual_assertion_fails_closed(self) -> None:
        value = fixture()
        value["runs"][0]["evidence_source"] = "manual"
        with self.assertRaisesRegex(PhysicalEvidenceError, "manual assertions are rejected"):
            validate_physical_evidence(value)

    def test_non_clean_install_fails_closed(self) -> None:
        value = fixture()
        value["runs"][1]["clean_install"] = False
        with self.assertRaisesRegex(PhysicalEvidenceError, "clean physical install"):
            validate_physical_evidence(value)

    def test_non_physical_granted_level_fails_closed(self) -> None:
        value = fixture()
        value["granted_level"] = "Sealed_Release_Evidence"
        with self.assertRaisesRegex(PhysicalEvidenceError, "not the physical level"):
            validate_physical_evidence(value)

    def test_source_level_claim_fails_closed(self) -> None:
        value = fixture()
        value["granted_level"] = "Source_Implemented"
        with self.assertRaisesRegex(PhysicalEvidenceError, "not the physical level"):
            validate_physical_evidence(value)

    def test_invalid_macos_build_fails_closed(self) -> None:
        value = fixture()
        value["runs"][0]["macos_build"] = "not a build"
        with self.assertRaisesRegex(PhysicalEvidenceError, "macos_build is not a macOS build"):
            validate_physical_evidence(value)

    def test_wrong_schema_version_fails_closed(self) -> None:
        value = fixture()
        value["schema_version"] = 2
        with self.assertRaisesRegex(PhysicalEvidenceError, "schema_version"):
            validate_physical_evidence(value)

    def test_wrong_aggregator_version_fails_closed(self) -> None:
        value = fixture()
        value["aggregator_version"] = "physical-evidence-aggregator-v2"
        with self.assertRaisesRegex(PhysicalEvidenceError, "aggregator_version"):
            validate_physical_evidence(value)

    def test_unknown_top_level_field_fails_closed(self) -> None:
        value = fixture()
        value["signed_installed_verified"] = True
        with self.assertRaisesRegex(PhysicalEvidenceError, "unknown fields"):
            validate_physical_evidence(value)

    def test_non_object_document_fails_closed(self) -> None:
        with self.assertRaisesRegex(PhysicalEvidenceError, "must be a JSON object"):
            validate_physical_evidence(["not", "an", "object"])


class PhysicalEvidenceLoaderTests(unittest.TestCase):
    def test_symlink_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            real = os.path.join(tmp, "aggregate.json")
            with open(real, "w", encoding="utf-8") as handle:
                json.dump(fixture(), handle)
            link = os.path.join(tmp, "link.json")
            os.symlink(real, link)
            with self.assertRaisesRegex(PhysicalEvidenceError, "non-symlink"):
                load_physical_evidence(Path(link))

    def test_duplicate_json_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "aggregate.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"schema_version": 1, "schema_version": 1}')
            with self.assertRaisesRegex(PhysicalEvidenceError, "duplicate field"):
                load_physical_evidence(Path(path))

    def test_valid_aggregate_file_grants_level(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "aggregate.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(fixture(), handle)
            summary = load_physical_evidence(Path(path))
            self.assertEqual(summary["granted_level"], GRANTED_LEVEL)


if __name__ == "__main__":
    unittest.main()
