"""Offline regression tests. No SIM, VPN, VPS, sudo or network access is needed."""
import base64
from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import observer


KEY_A = base64.b64encode(bytes(range(32))).decode()
KEY_B = base64.b64encode(bytes(reversed(range(32)))).decode()
A = observer.key_digest(KEY_A)
B = observer.key_digest(KEY_B)


def policy():
    return {
        "interface": "wg-users",
        "peers": {A: {"id": "alpha", "session_limit_bytes": 1_000, "rate_limit_bps": 800}},
    }


class ObserverTests(unittest.TestCase):
    def test_policy_requires_exact_schema_canonical_keys_and_positive_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            obj = {
                "version": 1, "interface": "wg-users",
                "peers": [
                    {"id": "alpha", "public_key": KEY_A, "session_limit_bytes": 1000, "rate_limit_bps": 800}
                ],
            }
            path.write_text(json.dumps(obj))
            self.assertEqual(observer.load_policy(path), policy())
            path.write_text(json.dumps({**obj, "unrecognized": "not allowed"}))
            with self.assertRaises(observer.GuardError):
                observer.load_policy(path)
            path.write_text('{"version":1,"version":1}')
            with self.assertRaises(observer.GuardError):
                observer.load_policy(path)
            obj["peers"][0]["rate_limit_bps"] = True
            path.write_text(json.dumps(obj))
            with self.assertRaises(observer.GuardError):
                observer.load_policy(path)
            obj["peers"][0]["rate_limit_bps"] = 800
            obj["peers"][0]["public_key"] = "AAAAAAAA"
            path.write_text(json.dumps(obj))
            with self.assertRaises(observer.GuardError):
                observer.load_policy(path)

    def test_exact_wireguard_tab_fields_and_unique_peers(self):
        pairs = observer.parse_transfer(f"{KEY_A}\t123\t456\n{KEY_B}\t0\t184\n")
        self.assertEqual(pairs, {A: (123, 456), B: (0, 184)})
        for text in (
            f"{KEY_A} 123 456\n",
            f"{KEY_A}\t-1\t1\n",
            f"{KEY_A}\t1\ttrue\n",
            f"{KEY_A}\t1\t1\n{KEY_A}\t2\t2\n",
            f"{KEY_A}\t{2**64}\t1\n",
            f"{KEY_A}\t1\t2\n\n",
        ):
            with self.subTest(text=text[:30]), self.assertRaises(observer.GuardError):
                observer.parse_transfer(text)

    def test_first_sample_then_rate_alert_and_budget_alert(self):
        initial, state = observer.evaluate(policy(), {A: (100, 100)}, None, 100_000_000_000)
        self.assertEqual(initial["status"], "ok")
        self.assertTrue(initial["first_observation"])
        self.assertIsNone(initial["peers"][0]["interval_bytes"])
        later, state = observer.evaluate(policy(), {A: (800, 700)}, state, 110_000_000_000)
        self.assertEqual(later["status"], "alert")
        self.assertEqual(later["peers"][0]["interval_bytes"], 1300)
        self.assertEqual(
            [alert["code"] for alert in later["alerts"]],
            ["session_budget_exceeded", "observed_rate_exceeded"],
        )
        self.assertNotIn(KEY_A, json.dumps(later))
        self.assertNotIn(KEY_A, json.dumps(state))


    def test_subsecond_observations_preserve_actual_rate_interval(self):
        first, state = observer.evaluate(policy(), {A: (1, 1)}, None, 1_000_000_000)
        self.assertEqual(first["status"], "ok")
        second, state = observer.evaluate(policy(), {A: (2, 2)}, state, 1_500_000_000)
        self.assertEqual(second["peers"][0]["interval_bytes"], 2)
        self.assertNotIn("observed_rate_exceeded", [a["code"] for a in second["alerts"]])
        third, state = observer.evaluate(policy(), {A: (100, 100)}, state, 1_500_000_001)
        self.assertIn("observed_rate_exceeded", [a["code"] for a in third["alerts"]])

    def test_unknown_peer_and_counter_reset_remain_visible(self):
        first, state = observer.evaluate(policy(), {A: (800, 100)}, None, 100_000_000_000)
        self.assertEqual(first["status"], "ok")
        second, state = observer.evaluate(policy(), {A: (4, 100), B: (0, 10)}, state, 101_000_000_000)
        self.assertEqual(second["status"], "alert")
        self.assertEqual({v["code"] for v in second["alerts"]},
                         {"unregistered_peer", "counter_reset_or_mismatch"})
        third, state = observer.evaluate(policy(), {A: (20, 100)}, state, 102_000_000_000)
        self.assertIn("counter_reset_or_mismatch", [v["code"] for v in third["alerts"]])
        with self.assertRaisesRegex(observer.GuardError, "clock"):
            observer.evaluate(policy(), {A: (30, 120)}, state, 102_000_000_000)

    def test_private_atomic_state_and_reject_symlink_or_loose_permissions(self):
        with tempfile.TemporaryDirectory() as root:
            destination = Path(root) / "state" / "current.json"
            with observer.exclusive_state(destination):
                self.assertIsNone(observer.load_state(destination))
                _, state = observer.evaluate(policy(), {A: (7, 8)}, None, 100_000_000_000)
                observer.save_state(destination, state)
                self.assertEqual(observer.load_state(destination), state)
                self.assertFalse(destination.stat().st_mode & 0o077)
                self.assertFalse(destination.with_name(destination.name + ".lock").stat().st_mode & 0o077)
            destination.chmod(0o644)
            with self.assertRaises(observer.GuardError):
                observer.load_state(destination)
            destination.chmod(0o600)
            symlink = destination.parent / "alias"
            symlink.symlink_to(destination)
            with self.assertRaises((observer.GuardError, OSError)):
                observer.load_state(symlink)

    @patch("observer.subprocess.run")
    def test_ssh_read_only_pinned_host_key_and_no_remote_payload(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, f"{KEY_A}\t3\t4\n".encode(), b"")
        self.assertEqual(observer.parse_transfer(observer.observe_via_ssh("trusted-vps", "wg-users")), {A: (3, 4)})
        command = run.call_args.args[0]
        self.assertIn("-oStrictHostKeyChecking=yes", command)
        self.assertIn("-oBatchMode=yes", command)
        self.assertEqual(command[-5:], ["trusted-vps", "/usr/bin/wg", "show", "wg-users", "transfer"])
        self.assertFalse(run.call_args.kwargs.get("shell", False))
        with self.assertRaises(observer.GuardError):
            observer.observe_via_ssh("bad;host", "wg-users")
        with self.assertRaises(observer.GuardError):
            observer.observe_via_ssh("trusted-vps", "wg-users;echo")
        self.assertEqual(run.call_count, 1)

    def test_cli_local_fixture_is_read_only_and_preserves_baseline(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            obj = {
                "version": 1, "interface": "wg-users",
                "peers": [{"id": "alpha", "public_key": KEY_A,
                           "session_limit_bytes": 1000, "rate_limit_bps": 800}],
            }
            policy_file = root / "policy.json"
            sample_file = root / "sample.tsv"
            state_file = root / "private" / "status.json"
            policy_file.write_text(json.dumps(obj))
            sample_file.write_text(f"{KEY_A}\t12\t15\n")
            output = StringIO()
            options = ["--policy", str(policy_file), "--sample-file", str(sample_file), "--state", str(state_file)]
            with redirect_stdout(output):
                self.assertEqual(observer.main(options), 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "ok")
            self.assertEqual(observer.load_state(state_file)["peers"][A], {"rx": 12, "tx": 15})
            self.assertNotIn(KEY_A, output.getvalue())
            sample_file.write_text(f"{KEY_A}\t2000\t15\n")
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(observer.main(options), 2)
            self.assertIn("session_budget_exceeded", output.getvalue())


if __name__ == "__main__":
    unittest.main()
