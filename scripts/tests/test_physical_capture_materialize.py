from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.harness.adversarial_clients import REQUIRED_CASES as ADVERSARIAL_CASES
from scripts.harness.lifecycle_matrix import (
    EXPECTED_LIFECYCLE_PRE_NONCE_SUBJECTS,
    EXPECTED_LIFECYCLE_RAW_SUBJECTS,
    PROBE_SPECS,
)
from scripts.harness.packet_evidence import (
    EXPECTED_PACKET_RAW_SUBJECTS,
    OPTIONAL_PACKET_RAW_SUBJECTS,
    REQUIRED_CASES as PACKET_CASES,
)
from scripts.harness import performance_ledger as performance_contract
from scripts.physical_capture.materialize import (
    PACKET_MATERIAL_FIELDS,
    PhysicalMaterializationError,
    compose_adversarial_report,
    compose_lifecycle_report,
    compose_packet_report,
    compose_performance_report,
    materialize_packet_report,
)
from scripts.physical_capture import observation
from scripts.physical_capture.archive import PhysicalCaptureArchiveError
from scripts.physical_capture.lifecycle import (
    LifecycleCaptureError,
    materialize_lifecycle_events,
)
from scripts.physical_capture.session import CaptureEvent, PhysicalCaptureSession
from scripts.harness.raw_artifacts import canonical_json
from scripts.tests.physical_evidence_fixture import (
    PhysicalEvidenceFixture,
    fixture_packet_policy,
)


class PhysicalCaptureMaterializeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.packet_policy_context = fixture_packet_policy()
        self.packet_policy_context.__enter__()
        self.addCleanup(self.packet_policy_context.__exit__, None, None, None)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture = PhysicalEvidenceFixture(self.root)
        self.documents = self.fixture.report_documents[0]
        self.raw = self.fixture.raw_bindings[0]
        self.performance_session_index = 0
        self.lifecycle_session_index = 0

    def descriptor(self, harness: str, subject: str) -> dict:
        return copy.deepcopy(
            next(
                binding["descriptor"]
                for binding in self.raw
                if binding["harness"] == harness and binding["subject"] == subject
            )
        )

    def frozen_lifecycle_session(self) -> PhysicalCaptureSession:
        self.lifecycle_session_index += 1
        repository = self.root / f"lifecycle-session-{self.lifecycle_session_index}"
        (repository / "target").mkdir(parents=True)
        session = PhysicalCaptureSession.create(
            repository,
            "physical-capture/run-lifecycle",
            intent_sha256=hashlib.sha256(b"lifecycle-intent").hexdigest(),
        )
        session.append(
            CaptureEvent.COLLECTION_STARTED,
            binding_sha256=hashlib.sha256(b"lifecycle-collection").hexdigest(),
        )
        capture = session.observation_capture()
        source_bindings = {
            binding["subject"]: copy.deepcopy(binding["descriptor"])
            for binding in self.raw
            if binding["harness"] == "lifecycle"
        }
        descriptors: dict[str, dict[str, object]] = {}
        replaced: dict[str, dict[str, object]] = {}
        for subject in sorted(
            EXPECTED_LIFECYCLE_PRE_NONCE_SUBJECTS
            - {f"{probe_id}:observation" for probe_id in PROBE_SPECS}
        ):
            source = source_bindings[subject]
            suffix = Path(source["path"]).suffix
            filename = subject.replace(":", "-") + suffix
            artifact = capture.write_bytes(
                subject=subject,
                kind=source["kind"],
                relative=f"raw/lifecycle/observations/{filename}",
                data=(self.root / source["path"]).read_bytes(),
            )
            descriptors[subject] = artifact.descriptor.as_dict()
            replaced[source["path"]] = artifact.descriptor.as_dict()

        def replace_special(value):
            if isinstance(value, dict):
                if set(value) == {"kind", "path", "size", "sha256"}:
                    replacement = replaced.get(value["path"])
                    return copy.deepcopy(value if replacement is None else replacement)
                return {key: replace_special(item) for key, item in value.items()}
            if isinstance(value, list):
                return [replace_special(item) for item in value]
            return value

        for probe_id in sorted(PROBE_SPECS):
            subject = f"{probe_id}:observation"
            source = source_bindings[subject]
            observation_value = json.loads(
                (self.root / source["path"]).read_text(encoding="utf-8")
            )
            observation_value = replace_special(observation_value)
            artifact = capture.write_bytes(
                subject=subject,
                kind="lifecycle-observation",
                relative=f"raw/lifecycle/observations/{probe_id}.json",
                data=canonical_json(observation_value) + b"\n",
            )
            descriptors[subject] = artifact.descriptor.as_dict()
        self.assertEqual(set(descriptors), EXPECTED_LIFECYCLE_PRE_NONCE_SUBJECTS)
        session.complete_observations(descriptors)
        for event in (
            CaptureEvent.NONCE_REQUEST_PREPARED,
            CaptureEvent.NONCE_ATTEMPT_STARTED,
            CaptureEvent.NONCE_RESPONSE_RECORDED,
        ):
            session.append(
                event,
                binding_sha256=hashlib.sha256(event.value.encode("ascii")).hexdigest(),
            )
        self.addCleanup(session.close)
        return session

    def frozen_packet_session(self) -> PhysicalCaptureSession:
        repository = self.root / "packet-session-repository"
        (repository / "target").mkdir(parents=True)
        session = PhysicalCaptureSession.create(
            repository,
            "physical-capture/run-packet",
            intent_sha256=hashlib.sha256(b"packet-intent").hexdigest(),
        )
        session.append(
            CaptureEvent.COLLECTION_STARTED,
            binding_sha256=hashlib.sha256(b"packet-collection").hexdigest(),
        )
        capture = session.observation_capture()
        descriptors: dict[str, dict[str, object]] = {}
        for case in self.documents["packet"]["cases"]:
            case_id = case["id"]
            state_bytes = (self.root / case["state_artifact"]["path"]).read_bytes()
            state = capture.write_bytes(
                subject=f"{case_id}:product-state",
                kind="packet-product-state-observation",
                relative=f"raw/packet/observations/{case_id}-product-state.json",
                data=state_bytes,
            )
            pcap_bytes = (self.root / case["artifact"]["path"]).read_bytes()
            pcap = capture.write_bytes(
                subject=case_id,
                kind=case["artifact"]["kind"],
                relative=f"raw/packet/observations/{case_id}.pcap",
                data=pcap_bytes,
            )
            restore_state = None
            if case["restore_state_artifact"] is not None:
                restore_source = case["restore_state_artifact"]
                restore_state = capture.write_bytes(
                    subject=f"{case_id}:restore-state",
                    kind="packet-product-state-observation",
                    relative=(
                        f"raw/packet/observations/{case_id}-restore-state.json"
                    ),
                    data=(self.root / restore_source["path"]).read_bytes(),
                )
            provenance = json.loads(
                (self.root / case["provenance_artifact"]["path"]).read_text(
                    encoding="utf-8"
                )
            )
            provenance["state_observation_sha256"] = state.descriptor.sha256
            provenance["capture_artifact_sha256"] = pcap.descriptor.sha256
            provenance["capture_command"]["stdout_size"] = pcap.descriptor.size
            provenance["capture_command"]["stdout_sha256"] = pcap.descriptor.sha256
            provenance_artifact = capture.write_bytes(
                subject=f"{case_id}:capture-provenance",
                kind="packet-capture-provenance",
                relative=f"raw/packet/observations/{case_id}-provenance.json",
                data=canonical_json(provenance) + b"\n",
            )
            attempt = json.loads(
                (self.root / case["attempt_artifact"]["path"]).read_text(
                    encoding="utf-8"
                )
            )
            attempt["state_observation_sha256"] = state.descriptor.sha256
            attempt["capture_provenance_sha256"] = provenance_artifact.descriptor.sha256
            for stage in attempt["stages"]:
                stage["command"]["argv"][4] = str(
                    repository / "scripts/physical_capture/packet_sender.py"
                )
                stage["command"]["argv_sha256"] = hashlib.sha256(
                    canonical_json(stage["command"]["argv"])
                ).hexdigest()
            attempt_artifact = capture.write_bytes(
                subject=f"{case_id}:send-attempt",
                kind="packet-send-attempt",
                relative=f"raw/packet/observations/{case_id}-attempt.json",
                data=canonical_json(attempt) + b"\n",
            )
            descriptors.update(
                {
                    case_id: pcap.descriptor.as_dict(),
                    f"{case_id}:product-state": state.descriptor.as_dict(),
                    f"{case_id}:capture-provenance": provenance_artifact.descriptor.as_dict(),
                    f"{case_id}:send-attempt": attempt_artifact.descriptor.as_dict(),
                }
            )
            if restore_state is not None:
                descriptors[f"{case_id}:restore-state"] = (
                    restore_state.descriptor.as_dict()
                )
        session.complete_observations(descriptors)
        for event in (
            CaptureEvent.NONCE_REQUEST_PREPARED,
            CaptureEvent.NONCE_ATTEMPT_STARTED,
            CaptureEvent.NONCE_RESPONSE_RECORDED,
        ):
            session.append(
                event,
                binding_sha256=hashlib.sha256(event.value.encode("ascii")).hexdigest(),
            )
        self.addCleanup(session.close)
        return session

    def frozen_performance_session(
        self, ledger_mutator=None
    ) -> PhysicalCaptureSession:
        self.performance_session_index += 1
        repository = self.root / f"performance-session-{self.performance_session_index}"
        (repository / "target").mkdir(parents=True)
        session = PhysicalCaptureSession.create(
            repository,
            "physical-capture/run-performance",
            intent_sha256=hashlib.sha256(b"performance-intent").hexdigest(),
        )
        session.append(
            CaptureEvent.COLLECTION_STARTED,
            binding_sha256=hashlib.sha256(b"performance-collection").hexdigest(),
        )
        capture = session.observation_capture()
        intent_source = self.descriptor("performance", "shaping-intent")
        intent = capture.write_bytes(
            subject="performance:shaping-intent",
            kind=performance_contract.SHAPING_KIND,
            relative="raw/performance/observations/shaping-intent.json",
            data=(self.root / intent_source["path"]).read_bytes(),
        )
        restoration_source = self.descriptor("performance", "shaping-restoration")
        restoration_value = json.loads(
            (self.root / restoration_source["path"]).read_text(encoding="utf-8")
        )
        restoration_value["intent_artifact"] = intent.descriptor.as_dict()
        restoration = capture.write_bytes(
            subject="performance:shaping-restoration",
            kind=performance_contract.SHAPING_KIND,
            relative="raw/performance/observations/shaping-restoration.json",
            data=canonical_json(restoration_value) + b"\n",
        )
        ledger_source = self.descriptor("performance", "sample-ledger")
        ledger_value = json.loads(
            (self.root / ledger_source["path"]).read_text(encoding="utf-8")
        )
        ledger_value["shaping"] = {
            "intent_artifact": intent.descriptor.as_dict(),
            "restoration_artifact": restoration.descriptor.as_dict(),
        }
        if ledger_mutator is not None:
            ledger_mutator(ledger_value)
        ledger = capture.write_bytes(
            subject="performance:sample-ledger",
            kind=performance_contract.LEDGER_KIND,
            relative="raw/performance/observations/sample-ledger.json",
            data=canonical_json(ledger_value) + b"\n",
        )
        session.complete_observations(
            {
                "performance:sample-ledger": ledger.descriptor.as_dict(),
                "performance:shaping-intent": intent.descriptor.as_dict(),
                "performance:shaping-restoration": restoration.descriptor.as_dict(),
            }
        )
        for event in (
            CaptureEvent.NONCE_REQUEST_PREPARED,
            CaptureEvent.NONCE_ATTEMPT_STARTED,
            CaptureEvent.NONCE_RESPONSE_RECORDED,
        ):
            session.append(
                event,
                binding_sha256=hashlib.sha256(event.value.encode("ascii")).hexdigest(),
            )
        self.addCleanup(session.close)
        return session

    def test_lifecycle_materializer_reopens_all_raw_and_special_evidence(self) -> None:
        events = {
            probe_id: self.descriptor("lifecycle", probe_id)
            for probe_id in PROBE_SPECS
        }
        report = compose_lifecycle_report(
            evidence_root=self.root,
            event_artifacts=events,
            signed_at=self.documents["lifecycle"]["signed_at"],
        )
        self.assertEqual(report.harness, "lifecycle")
        self.assertEqual(len(report.document["probes"]), len(PROBE_SPECS))
        self.assertGreater(len(report.raw_bindings), len(PROBE_SPECS))

    def test_lifecycle_session_materializer_is_post_nonce_and_deterministic(self) -> None:
        first_session = self.frozen_lifecycle_session()
        second_session = self.frozen_lifecycle_session()
        proof = self.documents["lifecycle"]["proof"]
        with patch.object(
            observation,
            "run_fixed_command",
            side_effect=AssertionError("postnonce lifecycle probe reran"),
        ) as runner:
            first = materialize_lifecycle_events(
                session=first_session,
                proof=proof,
            )
            second = materialize_lifecycle_events(
                session=second_session,
                proof=proof,
            )
        runner.assert_not_called()
        self.assertEqual(len(first.artifacts), 32)
        self.assertEqual(
            {binding["subject"] for binding in first.raw_bindings},
            EXPECTED_LIFECYCLE_RAW_SUBJECTS,
        )
        self.assertEqual(len(first.raw_bindings), 72)
        self.assertEqual(first.descriptor_mapping(), second.descriptor_mapping())
        report = compose_lifecycle_report(
            evidence_root=(
                first_session.archive.repository
                / "target"
                / first_session.archive.root_relative_to_target
            ),
            event_artifacts=first.descriptor_mapping(),
            signed_at=self.documents["lifecycle"]["signed_at"],
        )
        self.assertEqual(len(report.raw_bindings), 72)

    def test_lifecycle_materializer_rejects_pre_nonce_and_deleted_frozen_bytes(self) -> None:
        repository = self.root / "lifecycle-pre-nonce"
        (repository / "target").mkdir(parents=True)
        collecting = PhysicalCaptureSession.create(
            repository,
            "physical-capture/run",
            intent_sha256=hashlib.sha256(b"intent").hexdigest(),
        )
        self.addCleanup(collecting.close)
        collecting.append(
            CaptureEvent.COLLECTION_STARTED,
            binding_sha256=hashlib.sha256(b"collecting").hexdigest(),
        )
        with self.assertRaisesRegex(LifecycleCaptureError, "only after nonce"):
            materialize_lifecycle_events(
                session=collecting,
                proof=self.documents["lifecycle"]["proof"],
            )

        frozen = self.frozen_lifecycle_session()
        root = (
            frozen.archive.repository
            / "target"
            / frozen.archive.root_relative_to_target
        )
        (root / "raw/lifecycle/observations/login.json").unlink()
        with self.assertRaisesRegex(
            LifecycleCaptureError, "frozen lifecycle observation manifest"
        ):
            materialize_lifecycle_events(
                session=frozen,
                proof=self.documents["lifecycle"]["proof"],
            )

    def test_lifecycle_materializer_resumes_only_exact_existing_events(self) -> None:
        session = self.frozen_lifecycle_session()
        original_write = session.archive.write_bytes
        event_writes = 0

        def interrupt(relative, data, *, maximum):
            nonlocal event_writes
            if relative.startswith("raw/lifecycle/events/"):
                event_writes += 1
                if event_writes == 6:
                    raise PhysicalCaptureArchiveError(
                        "injected_interruption",
                        "simulated post-nonce interruption",
                    )
            return original_write(relative, data, maximum=maximum)

        with patch.object(session.archive, "write_bytes", side_effect=interrupt):
            with self.assertRaisesRegex(
                LifecycleCaptureError, "cannot archive derived lifecycle event"
            ):
                materialize_lifecycle_events(
                    session=session,
                    proof=self.documents["lifecycle"]["proof"],
                )
        events_root = (
            session.archive.repository
            / "target"
            / session.archive.root_relative_to_target
            / "raw/lifecycle/events"
        )
        self.assertEqual(len(list(events_root.glob("*.json"))), 5)
        resumed = materialize_lifecycle_events(
            session=session,
            proof=self.documents["lifecycle"]["proof"],
        )
        self.assertEqual(len(resumed.artifacts), 32)

        existing = events_root / sorted(PROBE_SPECS)[0]
        existing = existing.with_suffix(".json")
        existing.write_bytes(existing.read_bytes() + b" ")
        with self.assertRaisesRegex(
            LifecycleCaptureError, "differs on retry"
        ):
            materialize_lifecycle_events(
                session=session,
                proof=self.documents["lifecycle"]["proof"],
            )

    def test_packet_materializer_derives_matrix_fields_and_revalidates_captures(self) -> None:
        material = {
            case["id"]: {key: copy.deepcopy(case[key]) for key in PACKET_MATERIAL_FIELDS}
            for case in self.documents["packet"]["cases"]
        }
        report = compose_packet_report(
            evidence_root=self.root,
            platform=self.documents["packet"]["platform"],
            proof=self.documents["packet"]["proof"],
            case_material=material,
            signed_at=self.documents["packet"]["signed_at"],
        )
        self.assertEqual(len(report.document["cases"]), len(PACKET_CASES))
        for case in report.document["cases"]:
            spec = PACKET_CASES[case["id"]]
            self.assertEqual(case["token_observed"], spec.token_observed)

    def test_packet_session_materializer_reopens_manifest_without_commands(self) -> None:
        session = self.frozen_packet_session()
        with patch.object(
            observation,
            "run_fixed_command",
            side_effect=AssertionError("postnonce packet probe reran"),
        ) as runner:
            report = materialize_packet_report(
                session=session,
                proof=self.documents["packet"]["proof"],
                platform=self.documents["packet"]["platform"],
                signed_at=self.documents["packet"]["signed_at"],
            )
        runner.assert_not_called()
        self.assertEqual(len(report.document["cases"]), len(PACKET_CASES))
        self.assertEqual(
            len(report.raw_bindings),
            len(EXPECTED_PACKET_RAW_SUBJECTS | OPTIONAL_PACKET_RAW_SUBJECTS),
        )

    def test_packet_session_materializer_rejects_deleted_frozen_state(self) -> None:
        session = self.frozen_packet_session()
        root = (
            session.archive.repository
            / "target"
            / session.archive.root_relative_to_target
        )
        (root / "raw/packet/observations/tcp-ipv4-product-state.json").unlink()
        with self.assertRaisesRegex(
            PhysicalMaterializationError, "frozen observation manifest"
        ):
            materialize_packet_report(
                session=session,
                proof=self.documents["packet"]["proof"],
                platform=self.documents["packet"]["platform"],
                signed_at=self.documents["packet"]["signed_at"],
            )

    def test_performance_materializer_recomputes_every_summary(self) -> None:
        session = self.frozen_performance_session()
        report = compose_performance_report(
            session=session,
            proof=self.documents["performance"]["proof"],
            signed_at=self.documents["performance"]["signed_at"],
        )
        self.assertEqual(report.document["throughput"]["ratio_percent"], 95.0)
        self.assertEqual(report.document["switch_cycle"]["switch_count"], 100)
        self.assertEqual(report.document["soak"], self.documents["performance"]["soak"])
        self.assertEqual(len(report.raw_bindings), 3)

    def test_adversarial_materializer_derives_matrix_from_transcripts(self) -> None:
        transcripts = {
            subject: self.descriptor("adversarial", subject)
            for subject in {"baseline", *ADVERSARIAL_CASES}
        }
        report = compose_adversarial_report(
            evidence_root=self.root,
            platform=self.documents["adversarial"]["platform"],
            transcript_artifacts=transcripts,
            signed_at=self.documents["adversarial"]["signed_at"],
        )
        self.assertEqual(len(report.document["cases"]), len(ADVERSARIAL_CASES))
        self.assertEqual(
            report.document["secret_coverage_manifest_sha256"],
            self.documents["adversarial"]["secret_coverage_manifest_sha256"],
        )

    def test_missing_or_tampered_raw_never_materializes_a_report(self) -> None:
        events = {
            probe_id: self.descriptor("lifecycle", probe_id)
            for probe_id in PROBE_SPECS
        }
        events.pop(next(iter(events)))
        with self.assertRaisesRegex(PhysicalMaterializationError, "probe matrix"):
            compose_lifecycle_report(
                evidence_root=self.root,
                event_artifacts=events,
                signed_at=self.documents["lifecycle"]["signed_at"],
            )
        material = {
            case["id"]: {key: copy.deepcopy(case[key]) for key in PACKET_MATERIAL_FIELDS}
            for case in self.documents["packet"]["cases"]
        }
        material["tcp-ipv4"]["token"] = "not-present-in-capture"
        with self.assertRaisesRegex(PhysicalMaterializationError, "source validator"):
            compose_packet_report(
                evidence_root=self.root,
                platform=self.documents["packet"]["platform"],
                proof=self.documents["packet"]["proof"],
                case_material=material,
                signed_at=self.documents["packet"]["signed_at"],
            )

    def test_malformed_performance_samples_raise_the_materialization_error(self) -> None:
        session = self.frozen_performance_session(
            lambda ledger: ledger["samples"].pop()
        )
        with self.assertRaisesRegex(
            PhysicalMaterializationError, "exactly 353 samples"
        ):
            compose_performance_report(
                session=session,
                proof=self.documents["performance"]["proof"],
                signed_at=self.documents["performance"]["signed_at"],
            )

    def test_performance_session_materializer_never_reruns_commands(self) -> None:
        session = self.frozen_performance_session()
        with patch.object(
            observation,
            "run_fixed_command",
            side_effect=AssertionError("postnonce performance probe reran"),
        ) as runner:
            compose_performance_report(
                session=session,
                proof=self.documents["performance"]["proof"],
                signed_at=self.documents["performance"]["signed_at"],
            )
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
