from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import verify_physical_capture_readiness as readiness


def _lifecycle_contract() -> str:
    entries = ",\n".join(
        f"    {probe!r}: None" for probe in sorted(readiness.EXPECTED_LIFECYCLE_PROBES)
    )
    return f"PROBE_SPECS = {{\n{entries}\n}}\n"


def _lifecycle_producer() -> str:
    entries = ",\n".join(
        f"        {probe!r}: (capture_probe, materialize_probe)"
        for probe in sorted(readiness.EXPECTED_LIFECYCLE_PROBES)
    )
    return f"""
from types import MappingProxyType

def capture_probe(session):
    return session.observation_capture()

def materialize_probe(session, proof):
    return validate_lifecycle_event(session, proof)

LIFECYCLE_PRODUCER_REGISTRY = MappingProxyType({{
{entries}
}})

def capture_lifecycle_observations(session):
    descriptors = {{}}
    session.observation_capture()
    for probe_id in LIFECYCLE_PRODUCER_REGISTRY:
        capture, _materialize = LIFECYCLE_PRODUCER_REGISTRY[probe_id]
        descriptors[probe_id] = capture(session)
    return descriptors

def materialize_lifecycle_events(session, proof):
    events = {{}}
    session.load_observation_manifest()
    for probe_id in LIFECYCLE_PRODUCER_REGISTRY:
        _capture, materialize = LIFECYCLE_PRODUCER_REGISTRY[probe_id]
        events[probe_id] = materialize(session, proof)
    validate_lifecycle_event(events, proof)
    return events
"""


def _packet_ready_source() -> str:
    return """
UNRESOLVED_PACKET_CASES = frozenset()
UNRESOLVED_PACKET_CONTROLS = frozenset()

def capture_packet_observations(*, session, context):
    descriptors = {}
    for case_id in REQUIRED_CASES:
        descriptors.update(
            run_fixed_host_transaction(
                case_id=case_id,
                begin_capture=begin_capture,
                exercise_test=exercise_test,
                finish_capture=finish_capture,
            )
        )
    required = EXPECTED_PACKET_RAW_SUBJECTS
    optional = OPTIONAL_PACKET_RAW_SUBJECTS
    if not required <= set(descriptors) <= required | optional:
        raise PacketCaptureAdapterError("packet_observation_set_invalid", "invalid")
    return descriptors
"""


def _collector_source(*, all_handlers_real: bool = True) -> str:
    handlers = {
        "adversarial": "_collect_adversarial" if all_handlers_real else "_collect_performance",
        "lifecycle": "_collect_lifecycle" if all_handlers_real else "_collect_performance",
        "packet": "_collect_packet" if all_handlers_real else "_collect_performance",
        "performance": "_collect_performance",
    }
    registry = ",\n".join(
        f"    {harness!r}: {handler}" for harness, handler in sorted(handlers.items())
    )
    return f"""
from types import MappingProxyType
from scripts.physical_capture.adversarial import capture_adversarial_observations
from scripts.physical_capture.lifecycle import capture_lifecycle_observations
from scripts.physical_capture.packet import capture_packet_observations
from scripts.physical_capture.policy import require_current_collector_source_activation
from scripts.physical_capture.performance import capture_performance_observations

def _collect_adversarial(session, context):
    return capture_adversarial_observations(session=session)

def _collect_lifecycle(session, context):
    return capture_lifecycle_observations(session=session, context=context)

def _collect_packet(session, context):
    return capture_packet_observations(session=session, context=context)

def _collect_performance(session, context):
    return capture_performance_observations(session=session, context=context)

PRODUCER_REGISTRY = MappingProxyType({{
{registry}
}})

def _parser():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--harness", choices=tuple(PRODUCER_REGISTRY), required=True)
    return parser

def _initialize(arguments):
    require_current_collector_source_activation()

def _dispatch(arguments, session, context):
    handler = PRODUCER_REGISTRY[arguments.harness]
    descriptors = handler(session, context)
    session.complete_observations(descriptors)
    return descriptors

def main(argv=None):
    arguments = _parser().parse_args(argv)
    _initialize(arguments)
    return _dispatch(arguments, session, context)
"""


def _fixture_specs() -> dict[str, dict[str, object]]:
    specs: dict[str, dict[str, object]] = {}
    for fixture_id in sorted(readiness.EXPECTED_EXTERNAL_FIXTURES):
        target = "CFWAdversarial" + "".join(
            component.capitalize() for component in fixture_id.split("-")
        )
        specs[fixture_id] = {
            "target": target,
            "source_path": f"native/macos/PhysicalFixtures/{target}/main.swift",
            "executable": "CFWAdversarialFixture",
            "privileged": fixture_id in readiness.EXPECTED_PRIVILEGED_FIXTURES,
            "reset_required": fixture_id in readiness.EXPECTED_RESET_FIXTURES,
        }
    return specs


def _adversarial_source(specs: dict[str, dict[str, object]]) -> str:
    return (
        "SOURCE_FIXED_PRECONDITIONS = "
        + repr(dict(readiness.EXPECTED_EXTERNAL_CASE_TO_FIXTURE))
        + "\nEXTERNAL_FIXTURE_SPECS = "
        + repr(specs)
        + "\n"
    )


def _swift_package(specs: dict[str, dict[str, object]]) -> dict:
    return {
        "products": [
            {
                "name": spec["target"],
                "targets": [spec["target"]],
                "type": {"executable": None},
            }
            for spec in specs.values()
        ],
        "targets": [
            {
                "name": spec["target"],
                "type": "executable",
                "path": Path(str(spec["source_path"]))
                .relative_to("native/macos")
                .parent.as_posix(),
            }
            for spec in specs.values()
        ],
    }


class PacketReadinessTests(unittest.TestCase):
    def test_live_exact_matrix_shape_passes(self) -> None:
        _line, issues = readiness._packet_issues(_packet_ready_source())
        self.assertEqual(issues, [])

    def test_stub_strings_attributes_and_dead_code_do_not_fake_readiness(self) -> None:
        source = """
UNRESOLVED_PACKET_CASES = frozenset()
UNRESOLVED_PACKET_CONTROLS = frozenset()
def capture_packet_observations(*, session, context):
    marker = "run_fixed_host_transaction"
    raise PacketCaptureAdapterError("packet_workflow_not_enabled", "blocked")
    if False:
        for case_id in REQUIRED_CASES:
            run_fixed_host_transaction(case_id=case_id)
            EXPECTED_PACKET_RAW_SUBJECTS
            OPTIONAL_PACKET_RAW_SUBJECTS
        return {"fake": object()}
"""
        _line, issues = readiness._packet_issues(source)
        self.assertTrue(any("authenticated Host transaction" in issue for issue in issues))
        self.assertTrue(any("no reachable non-empty" in issue for issue in issues))
        self.assertTrue(any("workflow-disabled" in issue for issue in issues))

        attribute_decoy = _packet_ready_source().replace(
            "run_fixed_host_transaction(", "host.run_fixed_host_transaction("
        )
        _line, issues = readiness._packet_issues(attribute_decoy)
        self.assertTrue(any("authenticated Host transaction" in issue for issue in issues))

    def test_dynamic_unresolved_contract_is_rejected(self) -> None:
        source = _packet_ready_source().replace(
            "UNRESOLVED_PACKET_CASES = frozenset()",
            "UNRESOLVED_PACKET_CASES = current_blockers()",
        )
        _line, issues = readiness._packet_issues(source)
        self.assertTrue(any("literal closed value" in issue for issue in issues))


class LifecycleReadinessTests(unittest.TestCase):
    def test_exact_two_phase_registry_passes(self) -> None:
        _line, issues = readiness._lifecycle_issues(
            _lifecycle_contract(), _lifecycle_producer()
        )
        self.assertEqual(issues, [])

    def test_single_stage_or_proof_accepting_capture_is_rejected(self) -> None:
        source = _lifecycle_producer().replace(
            "def capture_lifecycle_observations(session):",
            "def capture_lifecycle_observations(session, proof):",
        ).replace("def materialize_lifecycle_events", "def missing_materialize")
        _line, issues = readiness._lifecycle_issues(_lifecycle_contract(), source)
        self.assertTrue(any("accepts proof" in issue for issue in issues))
        self.assertTrue(
            any("materialize_lifecycle_events is missing" in issue for issue in issues)
        )

    def test_registry_extra_probe_is_rejected(self) -> None:
        source = _lifecycle_producer().replace(
            "LIFECYCLE_PRODUCER_REGISTRY = MappingProxyType({",
            "LIFECYCLE_PRODUCER_REGISTRY = MappingProxyType({"
            "'unknown': (capture_probe, materialize_probe),",
        )
        _line, issues = readiness._lifecycle_issues(_lifecycle_contract(), source)
        self.assertTrue(any("32-probe closure" in issue for issue in issues))


class AdversarialReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name)
        self.specs = _fixture_specs()
        for spec in self.specs.values():
            path = self.repository / str(spec["source_path"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("import Foundation\n", encoding="utf-8")

    def test_exact_ten_controller_source_and_target_closure_passes(self) -> None:
        _line, issues = readiness._adversarial_issues(
            _adversarial_source(self.specs),
            self.repository,
            _swift_package(self.specs),
        )
        self.assertEqual(issues, [])

    def test_missing_target_and_missing_source_fail(self) -> None:
        missing_id = sorted(self.specs)[0]
        (self.repository / str(self.specs[missing_id]["source_path"])).unlink()
        package = _swift_package(self.specs)
        package["targets"] = [
            target
            for target in package["targets"]
            if target["name"] != self.specs[missing_id]["target"]
        ]
        _line, issues = readiness._adversarial_issues(
            _adversarial_source(self.specs), self.repository, package
        )
        self.assertTrue(
            any(missing_id in issue and "unavailable" in issue for issue in issues)
        )
        self.assertTrue(
            any(missing_id in issue and "SwiftPM" in issue for issue in issues)
        )

    def test_mapping_without_explicit_fixture_specs_fails(self) -> None:
        source = "SOURCE_FIXED_PRECONDITIONS = " + repr(
            dict(readiness.EXPECTED_EXTERNAL_CASE_TO_FIXTURE)
        )
        _line, issues = readiness._adversarial_issues(
            source, self.repository, _swift_package(self.specs)
        )
        self.assertTrue(any("EXTERNAL_FIXTURE_SPECS" in issue for issue in issues))


class CollectorReadinessTests(unittest.TestCase):
    def test_real_four_handler_dispatch_and_raw_completion_pass(self) -> None:
        _line, issues = readiness._collector_issues(_collector_source())
        self.assertEqual(issues, [])

    def test_four_names_dispatching_only_performance_fail(self) -> None:
        _line, issues = readiness._collector_issues(
            _collector_source(all_handlers_real=False)
        )
        self.assertTrue(any("adversarial handler" in issue for issue in issues))
        self.assertTrue(any("lifecycle handler" in issue for issue in issues))
        self.assertTrue(any("packet handler" in issue for issue in issues))

    def test_dead_capture_call_does_not_make_handler_ready(self) -> None:
        source = _collector_source().replace(
            "def _collect_adversarial(session, context):\n"
            "    return capture_adversarial_observations(session=session)",
            "def _collect_adversarial(session, context):\n"
            "    if False:\n"
            "        capture_adversarial_observations(session=session)\n"
            "    return capture_performance_observations(session=session)",
        )
        _line, issues = readiness._collector_issues(source)
        self.assertTrue(any("adversarial handler" in issue for issue in issues))

    def test_dynamic_or_mutated_registry_fails(self) -> None:
        source = _collector_source().replace(
            "PRODUCER_REGISTRY = MappingProxyType({",
            "PRODUCER_REGISTRY = build_registry({",
        )
        _line, issues = readiness._collector_issues(source)
        self.assertTrue(any("literal MappingProxyType" in issue for issue in issues))

        mutated = _collector_source() + "\nPRODUCER_REGISTRY.update({})\n"
        _line, issues = readiness._collector_issues(mutated)
        self.assertTrue(any("mutable after declaration" in issue for issue in issues))


class HostReadinessTests(unittest.TestCase):
    cargo = """
[package]
name = "host"
version = "0.4.0"
[features]
physical-release-evidence = []
"""
    build = """
cfw_build_tauri_host_skeleton() {
  "$contract_tauri_host_bin" build --bundles app --features physical-release-evidence
}
"""

    def test_feature_build_argv_and_reachable_non_test_caller_pass(self) -> None:
        rust = {
            "apps/cfw-tauri-shell/src/main.rs": """
fn main() { packet_evidence_transport::run_packet_evidence_transaction(); }
""",
            "apps/cfw-tauri-shell/src/packet_evidence_transport.rs": """
fn run_packet_evidence_transaction() { engine.run_packet_evidence_staged_transaction(); }
""",
            "apps/cfw-tauri-shell/src/engine/packet_evidence.rs": """
fn run_packet_evidence_staged_transaction() {}
#[cfg(test)] mod tests { fn test_only() { run_packet_evidence_staged_transaction(); } }
""",
        }
        _line, issues = readiness._host_issues(self.cargo, self.build, rust)
        self.assertEqual(issues, [])

    def test_feature_declaration_without_build_or_production_caller_fails(self) -> None:
        rust = {
            "apps/cfw-tauri-shell/src/main.rs": (
                'fn main() { println!("run_packet_evidence_staged_transaction()"); }'
            ),
            "apps/cfw-tauri-shell/src/packet_evidence_transport.rs": """
fn run_packet_evidence_transaction() {
    let decoy = r#"run_packet_evidence_staged_transaction()"#;
}
""",
            "apps/cfw-tauri-shell/src/engine/packet_evidence.rs": """
fn run_packet_evidence_staged_transaction() {}
#[cfg(test)] mod tests { fn test_only() { run_packet_evidence_staged_transaction(); } }
""",
        }
        _line, issues = readiness._host_issues(
            self.cargo, "# --features physical-release-evidence", rust
        )
        self.assertTrue(any("build argv" in issue for issue in issues))
        self.assertTrue(any("no exact production transport path" in issue for issue in issues))


class SecureReadinessInputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name)

    def write_source(self, relative: str, body: bytes = b"value = 1\n") -> Path:
        path = self.repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(0o644)
        return path

    def test_source_reader_rejects_symlink_hardlink_non_utf8_and_oversize(self) -> None:
        source = self.write_source("scripts/source.py")
        os.link(source, self.repository / "source-hardlink.py")
        with self.assertRaisesRegex(
            readiness.PhysicalCaptureReadinessError, "exactly one hard link"
        ):
            readiness._read_text(self.repository, "scripts/source.py")

        source.unlink()
        source = self.repository / "scripts/source.py"
        source.symlink_to(self.repository / "source-hardlink.py")
        with self.assertRaisesRegex(
            readiness.PhysicalCaptureReadinessError, "symlink|unsafe path"
        ):
            readiness._read_text(self.repository, "scripts/source.py")

        source.unlink()
        source.write_bytes(b"\xff")
        with self.assertRaisesRegex(
            readiness.PhysicalCaptureReadinessError, "strict UTF-8"
        ):
            readiness._read_text(self.repository, "scripts/source.py")

        source.write_bytes(b"x" * (readiness.MAX_SOURCE_BYTES + 1))
        with self.assertRaisesRegex(
            readiness.PhysicalCaptureReadinessError, "byte bound"
        ):
            readiness._read_text(self.repository, "scripts/source.py")

    def test_source_reader_rejects_real_parent_swap(self) -> None:
        source = self.write_source("scripts/source.py")
        body = source.read_bytes()
        real_open = os.open
        scripts_opens = 0

        def swap_parent_on_rebind(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal scripts_opens
            if path == "scripts" and dir_fd is not None and flags & os.O_DIRECTORY:
                scripts_opens += 1
                if scripts_opens == 2:
                    (self.repository / "scripts").rename(
                        self.repository / "scripts-before-swap"
                    )
                    (self.repository / "scripts").mkdir()
                    (self.repository / "scripts/source.py").write_bytes(body)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with (
            patch(
                "scripts.verify_pinned_build_inputs.os.open",
                side_effect=swap_parent_on_rebind,
            ),
            self.assertRaisesRegex(
                readiness.PhysicalCaptureReadinessError, "parent|changed"
            ),
        ):
            readiness._read_text(self.repository, "scripts/source.py")

    def test_rust_closure_rejects_hardlinks_and_mid_scan_injection(self) -> None:
        main = self.write_source(
            "apps/cfw-tauri-shell/src/main.rs", b"fn main() {}\n"
        )
        os.link(main, self.repository / "main-hardlink.rs")
        with self.assertRaisesRegex(
            readiness.PhysicalCaptureReadinessError, "exactly one hard link"
        ):
            readiness._load_rust_sources(self.repository)
        (self.repository / "main-hardlink.rs").unlink()

        real_read = readiness._read_text
        injected = False

        def inject_after_read(repository: Path, relative: str) -> str:
            nonlocal injected
            value = real_read(repository, relative)
            if not injected:
                injected = True
                self.write_source(
                    "apps/cfw-tauri-shell/src/injected.rs", b"fn injected() {}\n"
                )
            return value

        with patch.object(readiness, "_read_text", side_effect=inject_after_read):
            with self.assertRaisesRegex(
                readiness.PhysicalCaptureReadinessError, "closure changed"
            ):
                readiness._load_rust_sources(self.repository)

    def test_repository_root_symlink_is_rejected(self) -> None:
        link = self.repository.parent / f"{self.repository.name}-link"
        link.symlink_to(self.repository, target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaisesRegex(
            readiness.PhysicalCaptureReadinessError, "root is a symlink"
        ):
            readiness.analyze_repository(link)


class ReadinessCliAndWiringTests(unittest.TestCase):
    def test_cli_aggregates_stable_blockers_and_has_no_override(self) -> None:
        blockers = (
            readiness.Blocker("z_blocker", "z.py", 9, "z"),
            readiness.Blocker("a_blocker", "a.py", 2, "a"),
        )
        stderr = io.StringIO()
        with patch.object(readiness, "analyze_repository", return_value=blockers), patch.object(
            readiness, "_collector_activation_blocker", return_value=None
        ), patch.object(readiness, "_repository", return_value=Path("/")), redirect_stderr(
            stderr
        ):
            self.assertEqual(readiness.main([]), 1)
        self.assertLess(
            stderr.getvalue().index("a_blocker"),
            stderr.getvalue().index("z_blocker"),
        )
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            readiness.main(["--skip", "packet"])
        self.assertEqual(raised.exception.code, 2)

    def test_cli_success_has_one_explicit_message(self) -> None:
        stdout = io.StringIO()
        with patch.object(readiness, "analyze_repository", return_value=()), patch.object(
            readiness, "_collector_activation_blocker", return_value=None
        ), patch.object(readiness, "_repository", return_value=Path("/")), redirect_stdout(
            stdout
        ):
            self.assertEqual(readiness.main([]), 0)
        self.assertEqual(stdout.getvalue(), "physical capture source readiness verified\n")

    def test_cli_reports_unactivated_collector_source_as_a_distinct_blocker(self) -> None:
        blocker = readiness.Blocker(
            "collector_source_closure_unactivated",
            readiness.COLLECTOR_POLICY_PATH,
            1,
            "current collector source closure is not activated",
        )
        stderr = io.StringIO()
        with patch.object(readiness, "analyze_repository", return_value=()), patch.object(
            readiness, "_collector_activation_blocker", return_value=blocker
        ), patch.object(readiness, "_repository", return_value=Path("/")), redirect_stderr(
            stderr
        ):
            self.assertEqual(readiness.main([]), 1)
        self.assertIn("collector_source_closure_unactivated", stderr.getvalue())
        self.assertIn("physical_capture_source_not_ready", stderr.getvalue())

    def test_release_entrypoints_and_pin_name_the_fixed_gate(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        gate = "scripts/verify_physical_capture_readiness.py"
        from scripts.publication.sealed_manifest import REQUIRED_SOURCE_GATES

        self.assertEqual(REQUIRED_SOURCE_GATES["physical-capture-readiness"], gate)
        for relative in (
            "scripts/verify_build_boundaries.sh",
            "scripts/verify_release_environment.sh",
        ):
            text = (repository / relative).read_text(encoding="utf-8")
            self.assertEqual(text.count(gate), 1, relative)
        manifest = json.loads(
            (repository / "scripts/pinned_build_inputs.json").read_text(encoding="utf-8")
        )
        bindings = manifest["artifactBindings"]
        self.assertIn(gate, bindings)
        self.assertIn("scripts/physical_capture/policy.py", bindings)
        self.assertIn("scripts/physical_capture/cloud_run.py", bindings)
        self.assertIn(
            "require_current_collector_source_activation",
            bindings["scripts/physical_capture/cloud_run.py"],
        )
        self.assertIn(
            "collector_source_closure_unactivated",
            bindings[gate],
        )
        for relative in (
            "scripts/publication/sealed_manifest.py",
            "scripts/verify_build_boundaries.sh",
            "scripts/verify_release_environment.sh",
        ):
            self.assertIn(gate, bindings[relative])


if __name__ == "__main__":
    unittest.main()
