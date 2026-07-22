from __future__ import annotations

import copy
import unittest

from scripts.release_runtime_evidence import RuntimeEvidenceError, validate_runtime_evidence


def fixture() -> dict:
    digest = "a" * 64
    cases = []
    recovery = {
        "provider-crash": ("tunnel", "TunnelActive"),
        "proxy-agent-crash": ("proxy", "ProxyActive"),
        "sleep-wake": ("tunnel", "TunnelActive"),
        "network-outage-30s": ("tunnel", "TunnelActive"),
    }
    for index, (case_id, (mode, state)) in enumerate(recovery.items()):
        cases.append(
            {
                "id": case_id,
                "mode": mode,
                "before": {
                    "generation": 7,
                    "config_sha256": digest,
                    "ready": True,
                    "state": state,
                },
                "after": {
                    "generation": 7,
                    "config_sha256": digest,
                    "ready": True,
                    "state": state,
                },
                "attempt_count": 2,
                "observed_backoff_ms": [250],
                "recovery_ms": 9000,
                "cancellation_observed": False,
                "late_callback_ignored": False,
                "data_plane": {
                    "token": f"unique-recovery-token-{index}",
                    "tcp_v4": True,
                    "tcp_v6": True,
                    "udp_quic": True,
                    "dns_a": True,
                    "dns_aaaa": True,
                },
                "busy_loop": {
                    "detected": False,
                    "idle_cpu_percent": 0.5,
                    "poll_iterations": 4,
                    "observation_ms": 30_000,
                },
            }
        )
    for case_id in ("cancel-during-start", "late-callback-after-cancel"):
        cases.append(
            {
                "id": case_id,
                "mode": "tunnel",
                "before": {
                    "generation": 7,
                    "config_sha256": digest,
                    "ready": False,
                    "state": "TunnelStarting",
                },
                "after": {
                    "generation": 7,
                    "config_sha256": digest,
                    "ready": False,
                    "state": "Off",
                },
                "attempt_count": 1,
                "observed_backoff_ms": [],
                "recovery_ms": None,
                "cancellation_observed": True,
                "late_callback_ignored": case_id == "late-callback-after-cancel",
                "data_plane": None,
                "busy_loop": {
                    "detected": False,
                    "idle_cpu_percent": 0.2,
                    "poll_iterations": 2,
                    "observation_ms": 30_000,
                },
            }
        )
    return {
        "schema_version": 1,
        "product": {"version": "0.4.0", "build_number": "40000"},
        "app_manifest_sha256": "b" * 64,
        "captured_at": "2026-07-22T00:00:00Z",
        "platform": {
            "architecture": "arm64",
            "macos_version": "15.0",
            "hardware_model": "Mac fixture",
            "clean_install": True,
        },
        "retry_policy": {
            "max_attempts": 3,
            "initial_backoff_ms": 250,
            "maximum_backoff_ms": 2000,
            "multiplier": 2,
        },
        "cases": cases,
    }


class ReleaseRuntimeEvidenceTests(unittest.TestCase):
    def test_complete_bounded_recovery_evidence_passes(self) -> None:
        self.assertEqual(validate_runtime_evidence(fixture())["schema_version"], 1)

    def test_generation_drift_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["after"]["generation"] = 8
        with self.assertRaisesRegex(RuntimeEvidenceError, "generation"):
            validate_runtime_evidence(value)

    def test_late_callback_must_be_ignored(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][-1]["late_callback_ignored"] = False
        with self.assertRaisesRegex(RuntimeEvidenceError, "late callback"):
            validate_runtime_evidence(value)

    def test_retry_bound_and_backoff_are_not_advisory(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["attempt_count"] = 4
        with self.assertRaisesRegex(RuntimeEvidenceError, "attempt"):
            validate_runtime_evidence(value)
        value = copy.deepcopy(fixture())
        value["cases"][0]["observed_backoff_ms"] = [1]
        with self.assertRaisesRegex(RuntimeEvidenceError, "backoff"):
            validate_runtime_evidence(value)

    def test_busy_loop_or_fake_status_only_recovery_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["busy_loop"]["detected"] = True
        with self.assertRaisesRegex(RuntimeEvidenceError, "busy loop"):
            validate_runtime_evidence(value)
        value = copy.deepcopy(fixture())
        value["cases"][0]["data_plane"]["dns_aaaa"] = False
        with self.assertRaisesRegex(RuntimeEvidenceError, "data-plane"):
            validate_runtime_evidence(value)


if __name__ == "__main__":
    unittest.main()
