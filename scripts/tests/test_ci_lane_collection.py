#!/usr/bin/env python3
"""Fail-closed tests for the unsigned-CI lane collector (Task 12.3 input).

These tests never run a real lane: the collector's process runner is injected, so
the tests exercise exactly the recording, journal, and assembly rules that keep
the unsigned-CI gate honest - a nonzero exit can never be recorded as a pass, a
wall-clock overrun is recorded as ``timeout``, a stale or hand-edited journal
record is refused, and the assembled document is validated by the gate's own
validator.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from publication import ci_lanes  # noqa: E402
from publication.common import PublicationError, canonical_json  # noqa: E402
from publication.sealed_manifest import REQUIRED_CI_LANES  # noqa: E402

COMMIT = "a" * 40
TOOLCHAIN = "b" * 64
IDENTITY = {"document": ci_lanes.TOOLCHAIN_BINDING_KIND, "fixture": True}


def _runner(results):
    """Return a runner that replays scripted (exit_code, timed_out) outcomes."""

    def run(_repository, lane, _environment):
        exit_code, timed_out = results.get(lane.identifier, (0, False))
        return (
            f"output for {lane.identifier}".encode(),
            exit_code,
            timed_out,
            1.5,
        )

    return run


class CiLaneTableTests(unittest.TestCase):
    def test_lane_table_matches_the_gate(self) -> None:
        ci_lanes.self_check()
        self.assertEqual(
            sorted(lane.identifier for lane in ci_lanes.LANES), sorted(REQUIRED_CI_LANES)
        )

    def test_every_lane_is_bounded(self) -> None:
        for lane in ci_lanes.LANES:
            self.assertGreater(lane.timeout, 0, lane.identifier)
            self.assertLessEqual(len(lane.command), 1024, lane.identifier)
            self.assertEqual(lane.command.strip(), lane.command, lane.identifier)


class RecordingTests(unittest.TestCase):
    def lane(self) -> ci_lanes.Lane:
        return ci_lanes.LANE_INDEX["rust-fmt"]

    def record(self, exit_code, timed_out) -> dict:
        return ci_lanes.record_lane(
            self.lane(), COMMIT, TOOLCHAIN, b"log", exit_code, timed_out, 2.0, 1700000000
        )

    def test_zero_exit_is_the_only_pass(self) -> None:
        self.assertEqual(self.record(0, False)["status"], "passed")

    def test_nonzero_exit_is_failed(self) -> None:
        record = self.record(3, False)
        self.assertEqual((record["status"], record["exit_code"]), ("failed", 3))

    def test_timeout_is_recorded_as_timeout(self) -> None:
        record = self.record(None, True)
        self.assertEqual((record["status"], record["exit_code"]), ("timeout", 124))

    def test_signal_death_is_failed_with_shell_convention(self) -> None:
        record = self.record(-9, False)
        self.assertEqual((record["status"], record["exit_code"]), ("failed", 137))

    def test_missing_exit_status_fails_closed(self) -> None:
        with self.assertRaises(PublicationError):
            self.record(None, False)

    def test_log_digest_is_the_combined_output_digest(self) -> None:
        record = self.record(0, False)
        self.assertEqual(record["log_sha256"], hashlib.sha256(b"log").hexdigest())


class CollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)
        (self.root / "evidence").mkdir()
        # The collector resolves the pinned toolchain paths from the real pins
        # file; the injected runner means no lane is ever executed.
        (self.root / "scripts").mkdir()
        shutil.copyfile(
            Path(__file__).resolve().parent.parent / "dependency_pins.env",
            self.root / "scripts" / "dependency_pins.env",
        )

    def collect(self, results=None, **overrides):
        arguments = {
            "commit": COMMIT,
            "output": self.root / "evidence" / "unsigned-ci-lanes.json",
            "journal": self.root / "evidence" / "journal",
            "runner": _runner(results or {}),
            "report": lambda _message: None,
            "toolchain": (TOOLCHAIN, IDENTITY),
        }
        arguments.update(overrides)
        return ci_lanes.collect_ci_lanes(self.root, **arguments)

    def test_all_lanes_pass(self) -> None:
        result = self.collect()
        document = result["document"]
        self.assertEqual(result["failures"], [])
        self.assertEqual(document["toolchain_sha256"], TOOLCHAIN)
        self.assertEqual(len(document["lanes"]), len(REQUIRED_CI_LANES))
        for lane in document["lanes"]:
            self.assertEqual(set(lane), set(ci_lanes.DOCUMENT_LANE_FIELDS))
            self.assertEqual(lane["commit"], COMMIT)
            self.assertEqual(lane["toolchain_sha256"], TOOLCHAIN)
            self.assertEqual(lane["status"], "passed")

    def test_a_failing_lane_is_reported_not_masked(self) -> None:
        result = self.collect({"rust-test": (101, False), "node-audit": (1, False)})
        self.assertEqual(result["failures"], ["node-audit", "rust-test"])
        statuses = {lane["id"]: (lane["status"], lane["exit_code"]) for lane in result["document"]["lanes"]}
        self.assertEqual(statuses["rust-test"], ("failed", 101))
        self.assertEqual(statuses["node-audit"], ("failed", 1))

    def test_a_timed_out_lane_is_reported_as_timeout(self) -> None:
        result = self.collect({"xcode-analyze": (None, True)})
        self.assertEqual(result["failures"], ["xcode-analyze"])
        statuses = {lane["id"]: (lane["status"], lane["exit_code"]) for lane in result["document"]["lanes"]}
        self.assertEqual(statuses["xcode-analyze"], ("timeout", 124))

    def test_an_incomplete_lane_set_is_refused(self) -> None:
        with self.assertRaisesRegex(PublicationError, "missing"):
            self.collect(only=frozenset({"rust-fmt"}))
        self.assertFalse((self.root / "evidence" / "unsigned-ci-lanes.json").exists())

    def test_recorded_lanes_are_replayed_and_rerun_replaces_them(self) -> None:
        first = self.collect({"rust-fmt": (2, False)})
        self.assertEqual(first["failures"], ["rust-fmt"])
        (self.root / "evidence" / "unsigned-ci-lanes.json").unlink()
        second = self.collect(only=frozenset(), rerun=frozenset({"rust-fmt"}))
        self.assertEqual(second["failures"], [])
        self.assertEqual(second["records"]["rust-fmt"]["exit_code"], 0)

    def test_an_existing_record_is_never_replaced(self) -> None:
        self.collect()
        with self.assertRaisesRegex(PublicationError, "refusing to replace"):
            self.collect()

    def test_a_stale_journal_record_is_not_replayed(self) -> None:
        self.collect()
        (self.root / "evidence" / "unsigned-ci-lanes.json").unlink()
        journal = self.root / "evidence" / "journal"
        record = json.loads((journal / "rust-fmt.json").read_text(encoding="utf-8"))
        record["commit"] = "c" * 40
        (journal / "rust-fmt.json").write_text(
            canonical_json(record).decode("utf-8"), encoding="utf-8"
        )
        with self.assertRaisesRegex(PublicationError, "missing"):
            self.collect(assemble_only=True)

    def test_a_hand_edited_journal_status_is_rejected(self) -> None:
        self.collect({"rust-fmt": (7, False)})
        journal = self.root / "evidence" / "journal"
        record = json.loads((journal / "rust-fmt.json").read_text(encoding="utf-8"))
        record["status"] = "passed"
        (journal / "rust-fmt.json").write_text(
            canonical_json(record).decode("utf-8"), encoding="utf-8"
        )
        (self.root / "evidence" / "unsigned-ci-lanes.json").unlink()
        with self.assertRaisesRegex(PublicationError, "does not match its exit code"):
            self.collect(assemble_only=True)

    def test_a_tampered_journal_log_is_rejected(self) -> None:
        self.collect()
        journal = self.root / "evidence" / "journal"
        (journal / "rust-fmt.log").write_bytes(b"rewritten")
        (self.root / "evidence" / "unsigned-ci-lanes.json").unlink()
        with self.assertRaisesRegex(PublicationError, "log digest changed"):
            self.collect(assemble_only=True)

    def test_assemble_only_reuses_records_without_running(self) -> None:
        self.collect()
        (self.root / "evidence" / "unsigned-ci-lanes.json").unlink()

        def refuse(*_arguments):
            raise AssertionError("assemble-only must not run a lane")

        result = self.collect(runner=refuse, assemble_only=True)
        self.assertEqual(result["failures"], [])

    def test_unknown_lane_selection_is_refused(self) -> None:
        with self.assertRaisesRegex(PublicationError, "unknown unsigned CI lane"):
            self.collect(only=frozenset({"not-a-lane"}))


class AssemblyTests(unittest.TestCase):
    def records(self) -> dict:
        return {
            lane: {
                "id": lane,
                "command": ci_lanes.LANE_INDEX[lane].command,
                "status": "passed",
                "exit_code": 0,
                "log_sha256": hashlib.sha256(lane.encode()).hexdigest(),
                "commit": COMMIT,
                "toolchain_sha256": TOOLCHAIN,
            }
            for lane in REQUIRED_CI_LANES
        }

    def test_masked_pass_is_rejected_by_the_gate_validator(self) -> None:
        records = self.records()
        records["rust-test"]["exit_code"] = 1
        with self.assertRaisesRegex(PublicationError, "masks a nonzero exit status"):
            ci_lanes.assemble_document(records, COMMIT, TOOLCHAIN)

    def test_foreign_commit_is_rejected(self) -> None:
        records = self.records()
        records["rust-test"]["commit"] = "d" * 40
        with self.assertRaisesRegex(PublicationError, "different commit"):
            ci_lanes.assemble_document(records, COMMIT, TOOLCHAIN)

    def test_foreign_toolchain_is_rejected(self) -> None:
        records = self.records()
        records["rust-test"]["toolchain_sha256"] = "e" * 64
        with self.assertRaisesRegex(PublicationError, "different toolchain"):
            ci_lanes.assemble_document(records, COMMIT, TOOLCHAIN)

    def test_missing_lane_is_rejected(self) -> None:
        records = self.records()
        del records["shellcheck"]
        with self.assertRaisesRegex(PublicationError, "missing"):
            ci_lanes.assemble_document(records, COMMIT, TOOLCHAIN)


if __name__ == "__main__":
    unittest.main()
