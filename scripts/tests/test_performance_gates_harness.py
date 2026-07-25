from __future__ import annotations

import unittest

from scripts.harness.performance_gates import (
    PerformanceGateError,
    percentiles,
    validate_performance_evidence,
)


def _series(samples: list[float]) -> dict:
    summary = percentiles([float(sample) for sample in samples])
    return {
        "samples": list(samples),
        "p50": summary["p50"],
        "p95": summary["p95"],
        "p99": summary["p99"],
    }


def fixture() -> dict:
    return {
        "schema_version": 1,
        "parameters": {
            "machine": {
                "architecture": "arm64",
                "macos_version": "15.2",
                "hardware_model": "Mac15,3",
            },
            "network": {
                "description": "lab shaping bridge",
                "uplink_mbps": 1000,
            },
            "power": {
                "source": "ac",
                "low_power_mode": False,
            },
            "build": {
                "version": "0.4.0",
                "build_number": "421",
                "app_manifest_sha256": "a" * 64,
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
                "control": {
                    "applied": True,
                    "kind": "outage",
                    "outage_seconds": 30,
                },
                "recovery_ms": _series([7000.0, 8000.0, 9000.0, 9500.0]),
            },
        ],
        "latency": {
            "connect_ms": _series([2000.0, 3000.0, 4000.0, 4500.0]),
            "disconnect_ms": _series([1000.0, 1500.0, 2000.0, 2500.0]),
            "added_latency_percent": _series([2.0, 4.0, 6.0, 8.0]),
        },
        "throughput": {
            "baseline_mbps": 100.0,
            "measured_mbps": 95.0,
            "ratio_percent": 95.0,
        },
        "resources": {
            "active_idle_cpu_percent": _series([0.2, 0.4, 0.6, 0.8]),
            "active_rss_mib": _series([90.0, 100.0, 110.0, 118.0]),
        },
        "switch_cycle": {
            "switch_count": 100,
            "rss_growth_mib": 4.0,
            "fd_growth": 1,
        },
        "soak": {
            "duration_hours": 24,
            "crash_count": 0,
        },
    }


class PerformanceGatePassTests(unittest.TestCase):
    def test_complete_in_threshold_document_passes(self) -> None:
        document = validate_performance_evidence(fixture())
        self.assertEqual(document["schema_version"], 1)

    def test_percentiles_use_nearest_rank(self) -> None:
        summary = percentiles([10.0, 20.0, 30.0, 40.0, 50.0])
        self.assertEqual(summary, {"p50": 30.0, "p95": 50.0, "p99": 50.0})


class PerformanceGateFailClosedTests(unittest.TestCase):
    def _reject(self, mutate) -> None:
        evidence = fixture()
        mutate(evidence)
        with self.assertRaises(PerformanceGateError):
            validate_performance_evidence(evidence)

    def test_recovery_p95_violation_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["weak_network"][2]["recovery_ms"] = _series(
                [9000.0, 10_000.0, 11_000.0, 12_000.0]
            )

        self._reject(mutate)

    def test_connect_p95_violation_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["latency"]["connect_ms"] = _series([4000.0, 5000.0, 6000.0, 7000.0])

        self._reject(mutate)

    def test_disconnect_p95_violation_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["latency"]["disconnect_ms"] = _series([2000.0, 3000.0, 4000.0, 5000.0])

        self._reject(mutate)

    def test_added_latency_violation_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["latency"]["added_latency_percent"] = _series([8.0, 10.0, 12.0, 14.0])

        self._reject(mutate)

    def test_throughput_below_ninety_percent_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["throughput"] = {
                "baseline_mbps": 100.0,
                "measured_mbps": 85.0,
                "ratio_percent": 85.0,
            }

        self._reject(mutate)

    def test_throughput_ratio_mismatch_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["throughput"]["ratio_percent"] = 99.0

        self._reject(mutate)

    def test_idle_cpu_violation_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["resources"]["active_idle_cpu_percent"] = _series(
                [0.5, 0.8, 1.0, 1.2]
            )

        self._reject(mutate)

    def test_active_rss_violation_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["resources"]["active_rss_mib"] = _series(
                [110.0, 118.0, 121.0, 125.0]
            )

        self._reject(mutate)

    def test_switch_count_incomplete_duration_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["switch_cycle"]["switch_count"] = 99

        self._reject(mutate)

    def test_switch_rss_growth_violation_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["switch_cycle"]["rss_growth_mib"] = 6.0

        self._reject(mutate)

    def test_switch_fd_growth_violation_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["switch_cycle"]["fd_growth"] = 3

        self._reject(mutate)

    def test_soak_incomplete_duration_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["soak"]["duration_hours"] = 23

        self._reject(mutate)

    def test_soak_crash_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["soak"]["crash_count"] = 1

        self._reject(mutate)

    def test_absent_shaping_control_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["weak_network"][0]["control"]["applied"] = False

        self._reject(mutate)

    def test_missing_weak_network_profile_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            del evidence["weak_network"][2]

        self._reject(mutate)

    def test_wrong_control_parameter_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["weak_network"][0]["control"]["latency_ms"] = 200

        self._reject(mutate)

    def test_malformed_non_numeric_sample_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["latency"]["connect_ms"]["samples"] = [2000.0, "slow", 4000.0]

        self._reject(mutate)

    def test_malformed_negative_sample_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["latency"]["connect_ms"]["samples"] = [2000.0, -1.0, 4000.0]

        self._reject(mutate)

    def test_empty_sample_series_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["latency"]["connect_ms"] = {
                "samples": [],
                "p50": 0.0,
                "p95": 0.0,
                "p99": 0.0,
            }

        self._reject(mutate)

    def test_recorded_percentile_mismatch_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["latency"]["connect_ms"]["p95"] = 1.0

        self._reject(mutate)

    def test_missing_parameters_block_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            del evidence["parameters"]["power"]

        self._reject(mutate)

    def test_non_arm64_machine_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["parameters"]["machine"]["architecture"] = "x86_64"

        self._reject(mutate)

    def test_unknown_top_level_field_fails(self) -> None:
        def mutate(evidence: dict) -> None:
            evidence["unexpected"] = True

        self._reject(mutate)


if __name__ == "__main__":
    unittest.main()
