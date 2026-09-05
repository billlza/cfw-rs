from __future__ import annotations

import copy
from contextlib import redirect_stderr
from datetime import datetime, timezone
import io
from pathlib import Path
import plistlib
import subprocess
import sys
import unittest
from unittest.mock import patch

from scripts.harness.adversarial_clients import (
    HARNESS_VERSION as ADVERSARIAL_VERSION,
    REQUIRED_RAW_SUBJECTS as REQUIRED_ADVERSARIAL_RAW_SUBJECTS,
    expected_raw_kind as expected_adversarial_raw_kind,
)
from scripts.harness.lifecycle_matrix import (
    EXPECTED_LIFECYCLE_RAW_SUBJECTS,
    HARNESS_VERSION as LIFECYCLE_VERSION,
    IDENTITY_OBSERVATION_SUBJECTS,
    expected_lifecycle_raw_kinds,
)
from scripts.harness.packet_evidence import EXPECTED_PACKET_RAW_SUBJECTS
from scripts.harness.performance_gates import HARNESS_VERSION as PERFORMANCE_VERSION
from scripts.harness.performance_ledger import (
    LEDGER_KIND as PERFORMANCE_LEDGER_KIND,
    LEDGER_SUBJECT as PERFORMANCE_LEDGER_SUBJECT,
    SHAPING_INTENT_SUBJECT,
    SHAPING_KIND as PERFORMANCE_SHAPING_KIND,
    SHAPING_RESTORATION_SUBJECT,
)
from scripts.harness import physical_collector_request
from scripts.harness.physical_collector_request import (
    PhysicalCollectorRequestError,
    build_nonce_request,
    build_receipt_request,
    initialize_context,
    self_check,
    validate_context,
    validate_nonce_response,
)
from scripts.harness.physical_machine_identity import PhysicalMachineIdentityError
from scripts.harness.raw_artifacts import (
    MAX_RECEIPT_ARTIFACT_COUNT,
    REQUIRED_RECEIPT_ARTIFACT_COUNT,
    RawArtifactError,
    canonical_json,
)


PLATFORM_UUID = "01234567-89AB-CDEF-0123-456789ABCDEF"
VOLUME_UUID = "11111111-2222-3333-4444-555555555555"
VOLUME_GROUP_UUID = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
REQUEST_SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts/harness/physical_collector_request.py"
)


def _candidate() -> dict:
    return {
        "version": "0.4.0",
        "build_number": "40043",
        "app_manifest_sha256": "a" * 64,
        "signed_app_tree_sha256": "b" * 64,
        "artifact_hash_manifest_sha256": "c" * 64,
        "built_at": "2026-07-27T00:00:00Z",
    }


def _descriptor(kind: str, path: str, identity: int) -> dict:
    return {
        "kind": kind,
        "path": path,
        "size": 100 + identity,
        "sha256": f"{identity:064x}",
    }


def _bindings(
    *,
    captured_at: str = "2026-07-29T04:00:00Z",
    completed_at: str = "2026-07-29T04:00:00Z",
) -> dict:
    report_contract = (
        ("adversarial", ADVERSARIAL_VERSION, "adversarial-report"),
        ("lifecycle", LIFECYCLE_VERSION, "lifecycle-report"),
        ("packet", "packet-evidence-v4", "packet-report"),
        ("performance", PERFORMANCE_VERSION, "performance-report"),
    )
    reports = [
        {
            "harness": harness,
            "tool_version": version,
            "captured_at": captured_at,
            "completed_at": completed_at,
            "signed_at": completed_at,
            "descriptor": _descriptor(
                kind, f"reports/{harness}.json", index
            ),
        }
        for index, (harness, version, kind) in enumerate(report_contract, start=1)
    ]
    lifecycle_contract = tuple(
        (
            subject,
            sorted(expected_lifecycle_raw_kinds(subject))[0],
        )
        for subject in sorted(EXPECTED_LIFECYCLE_RAW_SUBJECTS)
    )
    raw_artifacts = []
    identity = len(reports) + 1
    for subject, kind in lifecycle_contract:
        suffix = ".pcap" if kind == "packet-pcap" else ".rgba" if kind == "wkwebview-rgba" else ".json"
        raw_artifacts.append(
            {
                "harness": "lifecycle",
                "subject": subject,
                "descriptor": _descriptor(
                    kind,
                    f"raw/lifecycle/{subject.replace(':', '-')}{suffix}",
                    identity,
                ),
            }
        )
        identity += 1
    for subject in sorted(EXPECTED_PACKET_RAW_SUBJECTS):
        if ":" not in subject:
            kind = "packet-pcap"
            suffix = ".pcap"
        else:
            suffix_name = subject.rsplit(":", 1)[1]
            kind = {
                "product-state": "packet-product-state-observation",
                "capture-provenance": "packet-capture-provenance",
                "send-attempt": "packet-send-attempt",
            }[suffix_name]
            suffix = ".json"
        raw_artifacts.append(
            {
                "harness": "packet",
                "subject": subject,
                "descriptor": _descriptor(
                    kind, f"raw/packet/{subject.replace(':', '-')}{suffix}", identity
                ),
            }
        )
        identity += 1
    for harness, subject, kind, suffix in (
        ("performance", PERFORMANCE_LEDGER_SUBJECT, PERFORMANCE_LEDGER_KIND, ".json"),
        ("performance", SHAPING_INTENT_SUBJECT, PERFORMANCE_SHAPING_KIND, ".json"),
        ("performance", SHAPING_RESTORATION_SUBJECT, PERFORMANCE_SHAPING_KIND, ".json"),
    ):
        raw_artifacts.append(
            {
                "harness": harness,
                "subject": subject,
                "descriptor": _descriptor(
                    kind, f"raw/{harness}/{subject}{suffix}", identity
                ),
            }
        )
        identity += 1
    for subject in sorted(REQUIRED_ADVERSARIAL_RAW_SUBJECTS):
        raw_artifacts.append(
            {
                "harness": "adversarial",
                "subject": subject,
                "descriptor": _descriptor(
                    expected_adversarial_raw_kind(subject),
                    f"raw/adversarial/{subject.replace(':', '-')}.json",
                    identity,
                ),
            }
        )
        identity += 1
    return {
        "schema_version": 1,
        "captured_at": captured_at,
        "completed_at": completed_at,
        "reports": reports,
        "raw_artifacts": raw_artifacts,
    }


def _with_optional_packet_restores(bindings: dict) -> dict:
    result = copy.deepcopy(bindings)
    identity = max(
        int(binding["descriptor"]["sha256"], 16)
        for binding in result["raw_artifacts"]
    ) + 1
    for subject in (
        "stop-cleanup:restore-state",
        "ipv6-disabled-absence:restore-state",
    ):
        result["raw_artifacts"].append(
            {
                "harness": "packet",
                "subject": subject,
                "descriptor": _descriptor(
                    "packet-product-state-observation",
                    f"raw/packet/{subject.replace(':', '-')}.json",
                    identity,
                ),
            }
        )
        identity += 1
    return result


def _runner(
    *,
    platform_uuid: str = PLATFORM_UUID,
    hardware_model: str = "Mac16,1",
    macos_version: str = "15.7.8",
    macos_build: str = "24G824",
):
    outputs = {
        ("/usr/bin/uname", "-s"): b"Darwin\n",
        ("/usr/bin/uname", "-m"): b"arm64\n",
        ("/usr/sbin/sysctl", "-n", "hw.model"): hardware_model.encode() + b"\n",
        ("/usr/sbin/sysctl", "-n", "kern.hv_vmm_present"): b"0\n",
        (
            "/usr/sbin/ioreg",
            "-a",
            "-r",
            "-l",
            "-d",
            "1",
            "-c",
            "IOPlatformExpertDevice",
        ): plistlib.dumps([{"IOPlatformUUID": platform_uuid}]),
        ("/usr/sbin/diskutil", "info", "-plist", "/"): plistlib.dumps(
            {
                "APFSVolumeGroupID": VOLUME_GROUP_UUID,
                "Bootable": True,
                "FilesystemType": "apfs",
                "MountPoint": "/",
                "Sealed": "Yes",
                "SystemImage": False,
                "VolumeUUID": VOLUME_UUID,
            }
        ),
        ("/usr/bin/sw_vers", "-productVersion"): macos_version.encode() + b"\n",
        ("/usr/bin/sw_vers", "-buildVersion"): macos_build.encode() + b"\n",
    }

    def run(command, **kwargs):
        key = tuple(command)
        if key not in outputs:
            raise AssertionError(f"unexpected environment command: {key!r}")
        if kwargs["env"]["PATH"] != "/usr/bin:/bin:/usr/sbin:/sbin":
            raise AssertionError("environment command did not use the fixed PATH")
        return subprocess.CompletedProcess(command, 0, outputs[key], b"")

    return run


class PhysicalCollectorRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.observed_at = datetime(2026, 7, 29, 4, 0, tzinfo=timezone.utc)
        self.runner = _runner()
        self.context = initialize_context(
            _candidate(),
            run_id="run-40043-macos15",
            clean_install_confirmed=True,
            runner=self.runner,
            observed_at=self.observed_at,
        )

    def test_static_contract_self_check(self) -> None:
        self_check()

    def test_static_cli_self_check_accepts_the_pinned_validation_runtime(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(REQUEST_SCRIPT),
                "self-check",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")

    def test_cli_requires_fixed_isolated_no_site_runtime(self) -> None:
        accepted = subprocess.run(
            [
                "/opt/homebrew/bin/python3",
                "-I",
                "-S",
                "-B",
                str(REQUEST_SCRIPT),
                "runtime-self-check",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())

        rejected = subprocess.run(
            [
                "/opt/homebrew/bin/python3",
                "-I",
                "-B",
                str(REQUEST_SCRIPT),
                "runtime-self-check",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertEqual(rejected.returncode, 1)
        self.assertIn(b"requires the fixed Python", rejected.stderr)
        self.assertNotIn(b"Traceback", rejected.stderr)

    def test_evidence_commands_check_runtime_before_reading_or_writing(self) -> None:
        commands = (
            (
                "initialize",
                "--candidate",
                "/missing/candidate.json",
                "--run-id",
                "run-40043-macos15",
                "--confirm-clean-install",
                "--output",
                "/missing/context.json",
            ),
            (
                "nonce-request",
                "--context",
                "/missing/context.json",
                "--output",
                "/missing/nonce-request.json",
            ),
            (
                "receipt-request",
                "--context",
                "/missing/context.json",
                "--nonce-response",
                "/missing/nonce-response.json",
                "--bindings",
                "/missing/bindings.json",
                "--output",
                "/missing/receipt-request.json",
            ),
        )
        for command in commands:
            with self.subTest(command=command), patch.object(
                physical_collector_request,
                "_verify_cli_runtime",
                side_effect=PhysicalCollectorRequestError("runtime sentinel"),
            ) as verify_runtime, patch.object(
                physical_collector_request, "_load"
            ) as load, patch.object(
                physical_collector_request, "_write_new"
            ) as write:
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    result = physical_collector_request.main(command)
                self.assertEqual(result, 1)
                self.assertIn("runtime sentinel", stderr.getvalue())
                verify_runtime.assert_called_once_with()
                load.assert_not_called()
                write.assert_not_called()

    def test_initialize_collects_machine_boot_and_os_without_raw_uuid(self) -> None:
        run = self.context["run"]
        self.assertEqual(run["os"], "macos15")
        self.assertEqual(run["macos_version"], "15.7.8")
        self.assertEqual(run["macos_build"], "24G824")
        self.assertEqual(run["hardware_model"], "Mac16,1")
        self.assertRegex(run["machine_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(run["boot_environment_sha256"], r"^[0-9a-f]{64}$")
        encoded = canonical_json(self.context)
        self.assertNotIn(PLATFORM_UUID.encode(), encoded)
        self.assertNotIn(VOLUME_UUID.encode(), encoded)
        self.assertNotIn(VOLUME_GROUP_UUID.encode(), encoded)

    def test_clean_install_requires_explicit_confirmation(self) -> None:
        with self.assertRaisesRegex(
            PhysicalCollectorRequestError, "explicitly confirmed"
        ):
            initialize_context(
                _candidate(),
                run_id="run-40043-macos15",
                clean_install_confirmed=False,
                runner=self.runner,
                observed_at=self.observed_at,
            )

    def test_initialize_requires_ga_40043_build_with_signed_64_bit_bound(self) -> None:
        for build_number, message in (
            ("40002", "must be GA release build 40043"),
            ("40003", "must be GA release build 40043"),
            ("40004", "must be GA release build 40043"),
            ("40005", "must be GA release build 40043"),
            ("40019", "must be GA release build 40043"),
            ("40020", "must be GA release build 40043"),
            ("40022", "must be GA release build 40043"),
            ("40023", "must be GA release build 40043"),
            ("40026", "must be GA release build 40043"),
            ("40027", "must be GA release build 40043"),
            ("40028", "must be GA release build 40043"),
            ("40029", "must be GA release build 40043"),
            ("40030", "must be GA release build 40043"),
            ("40031", "must be GA release build 40043"),
            ("40032", "must be GA release build 40043"),
            ("40033", "must be GA release build 40043"),
            ("40034", "must be GA release build 40043"),
            ("40035", "must be GA release build 40043"),
            ("40036", "must be GA release build 40043"),
            ("40037", "must be GA release build 40043"),
            ("40038", "must be GA release build 40043"),
            ("40039", "must be GA release build 40043"),
            ("40040", "must be GA release build 40043"),
            ("40041", "must be GA release build 40043"),
            ("40042", "must be GA release build 40043"),
            (str(2**63), "signed 64-bit"),
            ("9" * 5_000, "signed 64-bit"),
        ):
            candidate = _candidate()
            candidate["build_number"] = build_number
            with self.subTest(build_number=build_number), self.assertRaisesRegex(
                PhysicalCollectorRequestError, message
            ):
                initialize_context(
                    candidate,
                    run_id="run-invalid-build",
                    clean_install_confirmed=True,
                    runner=self.runner,
                    observed_at=self.observed_at,
                )

    def test_nonce_request_has_exact_deployed_collector_shape(self) -> None:
        request = build_nonce_request(self.context, runner=self.runner)
        self.assertEqual(set(request), {"schema_version", "candidate", "run"})
        self.assertEqual(
            set(request["run"]),
            {
                "os",
                "macos_version",
                "macos_build",
                "machine_sha256",
                "clean_install",
                "run_id",
            },
        )
        self.assertNotIn("hardware_model", request["run"])

    def test_context_timestamps_require_canonical_rfc3339_utc_shape(self) -> None:
        for invalid in (
            "2026-07-29 04:00:00Z",
            "20260729T040000Z",
            "2026-07-29T04:00:00.1234567Z",
        ):
            context = copy.deepcopy(self.context)
            context["initialized_at"] = invalid
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                PhysicalCollectorRequestError, "canonical ISO-8601 UTC"
            ):
                validate_context(context, runner=self.runner)

    def test_receipt_request_reobserves_environment_and_uses_server_nonce(self) -> None:
        nonce = {
            "schema_version": 1,
            "run_nonce": "d" * 64,
            "expires_at": "2026-07-29T10:00:00Z",
        }
        bindings = _bindings()
        request = build_receipt_request(
            self.context,
            nonce,
            bindings,
            runner=self.runner,
            observed_at=self.observed_at,
        )
        self.assertEqual(request["run"]["run_nonce"], "d" * 64)
        self.assertEqual(
            request["run"]["machine_sha256"],
            self.context["run"]["machine_sha256"],
        )
        self.assertEqual(request["reports"], bindings["reports"])
        self.assertEqual(
            request["raw_artifacts"],
            sorted(
                bindings["raw_artifacts"],
                key=lambda entry: (entry["harness"], entry["subject"]),
            ),
        )
        self.assertLessEqual(len(canonical_json(request)) + 1, 1 << 20)

    def test_nonce_validation_exposes_only_the_derived_issue_time(self) -> None:
        nonce = {
            "schema_version": 1,
            "run_nonce": "d" * 64,
            "expires_at": "2026-07-29T10:00:00Z",
        }
        normalized, issued_at = validate_nonce_response(
            nonce, observed_at=self.observed_at
        )
        self.assertEqual(normalized, nonce)
        self.assertEqual(
            issued_at, datetime(2026, 7, 29, 4, 0, tzinfo=timezone.utc)
        )
        with self.assertRaisesRegex(
            PhysicalCollectorRequestError, "timezone-aware"
        ):
            validate_nonce_response(
                nonce, observed_at=datetime(2026, 7, 29, 4, 0)
            )

    def test_receipt_bindings_cannot_predate_context(self) -> None:
        nonce = {
            "schema_version": 1,
            "run_nonce": "d" * 64,
            "expires_at": "2026-07-29T10:00:00Z",
        }
        bindings = _bindings(captured_at="2026-07-29T03:59:59Z")
        with self.assertRaisesRegex(
            PhysicalCollectorRequestError, "predate the candidate/context"
        ):
            build_receipt_request(
                self.context,
                nonce,
                bindings,
                runner=self.runner,
                observed_at=self.observed_at,
            )

    def test_receipt_nonce_must_be_issued_after_raw_completion(self) -> None:
        observed_at = datetime(2026, 7, 29, 7, 0, tzinfo=timezone.utc)
        bindings = _bindings(completed_at="2026-07-29T07:00:00Z")
        preissued = {
            "schema_version": 1,
            "run_nonce": "d" * 64,
            "expires_at": "2026-07-29T10:00:00Z",
        }
        with self.assertRaisesRegex(
            PhysicalCollectorRequestError, "nonce issued before raw completion"
        ):
            build_receipt_request(
                self.context,
                preissued,
                bindings,
                runner=self.runner,
                observed_at=observed_at,
            )

        post_run = copy.deepcopy(preissued)
        post_run["expires_at"] = "2026-07-29T13:00:00Z"
        request = build_receipt_request(
            self.context,
            post_run,
            bindings,
            runner=self.runner,
            observed_at=observed_at,
        )
        self.assertEqual(request["run"]["completed_at"], "2026-07-29T07:00:00Z")

        early_report = copy.deepcopy(bindings)
        early_report["reports"][0]["completed_at"] = "2026-07-29T06:59:58Z"
        early_report["reports"][0]["signed_at"] = "2026-07-29T06:59:59Z"
        with self.assertRaisesRegex(PhysicalCollectorRequestError, "outside its run"):
            build_receipt_request(
                self.context,
                post_run,
                early_report,
                runner=self.runner,
                observed_at=observed_at,
            )

    def test_receipt_nonce_cannot_have_a_future_issue_time(self) -> None:
        nonce = {
            "schema_version": 1,
            "run_nonce": "d" * 64,
            "expires_at": "2026-07-29T10:00:01Z",
        }
        with self.assertRaisesRegex(PhysicalCollectorRequestError, "future issue time"):
            build_receipt_request(
                self.context,
                nonce,
                _bindings(),
                runner=self.runner,
                observed_at=self.observed_at,
            )

    def test_receipt_binding_objects_and_subject_bounds_are_strict(self) -> None:
        nonce = {
            "schema_version": 1,
            "run_nonce": "d" * 64,
            "expires_at": "2026-07-29T10:00:00Z",
        }
        bindings = _bindings()
        bindings["raw_artifacts"][0]["subject"] = "x" * 257
        with self.assertRaisesRegex(PhysicalCollectorRequestError, "bounded printable"):
            build_receipt_request(
                self.context,
                nonce,
                bindings,
                runner=self.runner,
                observed_at=self.observed_at,
            )

    def test_receipt_requires_all_identity_observation_subjects(self) -> None:
        nonce = {
            "schema_version": 1,
            "run_nonce": "d" * 64,
            "expires_at": "2026-07-29T10:00:00Z",
        }
        for subject in sorted(IDENTITY_OBSERVATION_SUBJECTS):
            bindings = _bindings()
            bindings["raw_artifacts"] = [
                item
                for item in bindings["raw_artifacts"]
                if item["subject"] != subject
            ]
            with self.subTest(subject=subject), self.assertRaisesRegex(
                PhysicalCollectorRequestError, "lifecycle subject set"
            ):
                build_receipt_request(
                    self.context,
                    nonce,
                    bindings,
                    runner=self.runner,
                    observed_at=self.observed_at,
                )

    def test_receipt_rejects_unknown_lifecycle_subject_and_wrong_kind(self) -> None:
        nonce = {
            "schema_version": 1,
            "run_nonce": "d" * 64,
            "expires_at": "2026-07-29T10:00:00Z",
        }
        unknown = _bindings()
        unknown["raw_artifacts"].append(
            {
                "harness": "lifecycle",
                "subject": "invented-success",
                "descriptor": _descriptor(
                    "lifecycle-event",
                    "raw/lifecycle/invented-success.json",
                    999,
                ),
            }
        )
        with self.assertRaisesRegex(
            PhysicalCollectorRequestError,
            "exact lifecycle matrix",
        ):
            build_receipt_request(
                self.context,
                nonce,
                unknown,
                runner=self.runner,
                observed_at=self.observed_at,
            )

        wrong_kind = _bindings()
        lifecycle_event = next(
            binding
            for binding in wrong_kind["raw_artifacts"]
            if binding["harness"] == "lifecycle"
            and binding["subject"] == "bundle-identifiers"
        )
        lifecycle_event["descriptor"]["kind"] = "network-extension-trace"
        with self.assertRaisesRegex(
            PhysicalCollectorRequestError,
            "kind differs from its lifecycle subject",
        ):
            build_receipt_request(
                self.context,
                nonce,
                wrong_kind,
                runner=self.runner,
                observed_at=self.observed_at,
            )

    def test_receipt_requires_exact_adversarial_subjects_and_kinds(self) -> None:
        nonce = {
            "schema_version": 1,
            "run_nonce": "d" * 64,
            "expires_at": "2026-07-29T10:00:00Z",
        }
        missing = _bindings()
        missing["raw_artifacts"] = [
            item
            for item in missing["raw_artifacts"]
            if not (
                item["harness"] == "adversarial"
                and item["subject"] == "observation:wrong-team-id"
            )
        ]
        with self.assertRaisesRegex(
            PhysicalCollectorRequestError, "adversarial subject set"
        ):
            build_receipt_request(
                self.context,
                nonce,
                missing,
                runner=self.runner,
                observed_at=self.observed_at,
            )

        wrong_kind = _bindings()
        target = next(
            item
            for item in wrong_kind["raw_artifacts"]
            if item["harness"] == "adversarial"
            and item["subject"] == "observation:wrong-team-id"
        )
        target["descriptor"]["kind"] = "adversarial-transcript"
        with self.assertRaisesRegex(
            PhysicalCollectorRequestError, "differs from its adversarial subject"
        ):
            build_receipt_request(
                self.context,
                nonce,
                wrong_kind,
                runner=self.runner,
                observed_at=self.observed_at,
            )

    def test_receipt_descriptor_count_byte_and_request_bounds_fail_closed(self) -> None:
        nonce = {
            "schema_version": 1,
            "run_nonce": "d" * 64,
            "expires_at": "2026-07-29T10:00:00Z",
        }

        required = _bindings()
        self.assertEqual(
            len(required["reports"]) + len(required["raw_artifacts"]),
            REQUIRED_RECEIPT_ARTIFACT_COUNT,
        )
        maximum = _with_optional_packet_restores(required)
        self.assertEqual(
            len(maximum["reports"]) + len(maximum["raw_artifacts"]),
            MAX_RECEIPT_ARTIFACT_COUNT,
        )
        build_receipt_request(
            self.context,
            nonce,
            maximum,
            runner=self.runner,
            observed_at=self.observed_at,
        )
        one_too_many = copy.deepcopy(maximum)
        one_too_many["raw_artifacts"].append(
            {
                "harness": "packet",
                "subject": "not-source-pinned",
                "descriptor": _descriptor(
                    "packet-product-state-observation",
                    "raw/packet/not-source-pinned.json",
                    10_000,
                ),
            }
        )
        with self.assertRaisesRegex(
            PhysicalCollectorRequestError,
            f"exceeds {MAX_RECEIPT_ARTIFACT_COUNT}",
        ):
            build_receipt_request(
                self.context,
                nonce,
                one_too_many,
                runner=self.runner,
                observed_at=self.observed_at,
            )

        wrong_kind = _bindings()
        wrong_kind["raw_artifacts"][0]["descriptor"]["kind"] = (
            "not-an-artifact-kind"
        )
        with self.assertRaisesRegex(RawArtifactError, "allowed artifact kind"):
            build_receipt_request(
                self.context,
                nonce,
                wrong_kind,
                runner=self.runner,
                observed_at=self.observed_at,
            )

        duplicate_path = _bindings()
        duplicate_path["raw_artifacts"][1]["descriptor"]["path"] = (
            duplicate_path["raw_artifacts"][0]["descriptor"]["path"]
        )
        with self.assertRaisesRegex(PhysicalCollectorRequestError, "reuses artifact path"):
            build_receipt_request(
                self.context,
                nonce,
                duplicate_path,
                runner=self.runner,
                observed_at=self.observed_at,
            )

        too_many = copy.deepcopy(one_too_many)
        with self.assertRaisesRegex(PhysicalCollectorRequestError, "descriptors"):
            build_receipt_request(
                self.context,
                nonce,
                too_many,
                runner=self.runner,
                observed_at=self.observed_at,
            )

        too_many_bytes = _bindings()
        oversized_pcaps = [
            binding
            for binding in too_many_bytes["raw_artifacts"]
            if binding["descriptor"]["kind"] == "packet-pcap"
        ][:9]
        self.assertEqual(len(oversized_pcaps), 9)
        for binding in oversized_pcaps:
            binding["descriptor"]["size"] = 32 * 1024 * 1024
        with self.assertRaisesRegex(PhysicalCollectorRequestError, "artifact bytes"):
            build_receipt_request(
                self.context,
                nonce,
                too_many_bytes,
                runner=self.runner,
                observed_at=self.observed_at,
            )

        with patch(
            "scripts.harness.physical_collector_request.MAX_COLLECTOR_REQUEST_BYTES",
            128,
        ), self.assertRaisesRegex(PhysicalCollectorRequestError, "request exceeds"):
            build_receipt_request(
                self.context,
                nonce,
                _bindings(),
                runner=self.runner,
                observed_at=self.observed_at,
            )

    def test_expired_nonce_is_rejected(self) -> None:
        nonce = {
            "schema_version": 1,
            "run_nonce": "d" * 64,
            "expires_at": "2026-07-29T04:00:00Z",
        }
        with self.assertRaisesRegex(PhysicalCollectorRequestError, "expired"):
            build_receipt_request(
                self.context,
                nonce,
                _bindings(),
                runner=self.runner,
                observed_at=self.observed_at,
            )

    def test_machine_or_boot_drift_fails_before_request_construction(self) -> None:
        drifted = _runner(platform_uuid="FEDCBA98-7654-3210-FEDC-BA9876543210")
        with self.assertRaisesRegex(PhysicalCollectorRequestError, "drifted"):
            build_nonce_request(self.context, runner=drifted)

        changed_boot = copy.deepcopy(self.context)
        changed_boot["run"]["boot_environment_sha256"] = "f" * 64
        with self.assertRaisesRegex(PhysicalCollectorRequestError, "drifted"):
            validate_context(changed_boot, runner=self.runner)

    def test_virtual_model_and_unpinned_macos_are_rejected(self) -> None:
        with self.assertRaises(PhysicalMachineIdentityError):
            initialize_context(
                _candidate(),
                run_id="run-virtual",
                clean_install_confirmed=True,
                runner=_runner(hardware_model="VirtualMac2,1"),
                observed_at=self.observed_at,
            )
        with self.assertRaisesRegex(
            PhysicalCollectorRequestError, "canonical|source-pinned release lanes"
        ):
            initialize_context(
                _candidate(),
                run_id="run-beta",
                clean_install_confirmed=True,
                runner=_runner(macos_version="27.0", macos_build="26A5388g"),
                observed_at=self.observed_at,
            )

    def test_context_policy_or_environment_fields_cannot_be_overridden(self) -> None:
        for field, replacement in (
            ("machine_sha256", "e" * 64),
            ("hardware_model", "MacStudio1,1"),
            ("os", "current-macos"),
            ("macos_version", "26.6"),
            ("macos_build", "25G72"),
        ):
            changed = copy.deepcopy(self.context)
            changed["run"][field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(
                PhysicalCollectorRequestError, "drifted"
            ):
                validate_context(changed, runner=self.runner)


if __name__ == "__main__":
    unittest.main()
