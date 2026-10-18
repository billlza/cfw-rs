#!/usr/bin/env python3
"""Property-based fail-closed test for the sealed outer Evidence Manifest.

Exercises the public ``publication.sealed_manifest`` build/validate surface
(Task 12.3, Requirements 1.1, 1.2, 4.1, 5.1, 6.5, 7.5, 8.1). It is deterministic:
the stdlib ``random`` module is seeded with fixed integers so every failure
reproduces exactly. ``hypothesis`` is intentionally not required. At least 100
accept cases and 100 single-defect reject cases run per property, and on failure
the reproducing seed, the defect label, and the offending document are printed.
Unchanged source and physical fixtures are validated for real at property-class
entry and exit, then served by strict test-only snapshots inside the
high-cardinality loop. The substituted-aggregate defect explicitly uses the
real loader, and dedicated raw-evidence drift and TOCTOU suites remain uncached.

Two properties are checked:

* **round trip** - a manifest whose composed gates authorize exactly level *L*
  builds and validates with every capability at *L*, seals to ``sealed`` only
  when every gate passes, and otherwise seals to ``blocked`` with the exact
  blocked-input set, refusing publication and refusing promotion; and
* **fail closed** - every single-defect mutation is rejected: a duplicate or
  conflicting capability level, a skipped predecessor level, an unbound report
  digest, a tampered manifest field (even with the self-seal digest recomputed),
  a stale commit/toolchain/app-tree binding, a blocked or failed input promoted
  to a higher level, and an updater-key file present in the workspace.

Reproducing a failure: rerun this module and use the printed seed with
``random.Random(seed)``; the fixtures in ``test_sealed_manifest`` are pure
functions of that seed.
"""

from __future__ import annotations

import copy
from contextlib import nullcontext
import json
import random
import tempfile
import unittest
from pathlib import Path

from scripts.evidence_manifest import LEVEL_ORDER
from scripts.publication import final_candidate as final_candidate_module
from scripts.publication import sealed_closure as sealed_closure_module
from scripts.publication import sealed_manifest as sealed_manifest_module
from scripts.publication.common import PublicationError
from scripts.release_capability_inventory import CAPABILITY_IDS
from scripts.publication.sealed_manifest import (
    BLOCKED,
    COMPOSED_INPUTS,
    GATE_ORDER,
    PASSED,
    SEALED,
    SEALED_LEVEL,
    authorize_publication_artifacts as _authorize_publication_artifacts,
    build_sealed_evidence_manifest as _build_sealed_evidence_manifest,
    load_sealed_manifest,
    seal_manifest,
    validate_sealed_evidence_manifest as _validate_sealed_evidence_manifest,
)
from scripts.tests.test_physical_evidence_aggregator import (
    PHYSICAL_EVIDENCE_ROOT,
    PHYSICAL_TRUST_POLICY,
    fixture as physical_fixture,
)
from scripts.tests.physical_evidence_fixture import fixture_packet_policy
from scripts.tests.release_property_snapshots import (
    PhysicalSnapshotInput,
    StrictReleasePropertySnapshots,
)
from scripts.tests.test_sealed_manifest import (
    COMMIT,
    REPOSITORY,
    ci_lanes,
    inner_manifest,
    request,
    reseal,
    sealed_closure_document,
)

ACCEPT_CASES = 120
REJECT_CASES = 200


def build_sealed_evidence_manifest(*args, **kwargs):
    kwargs.setdefault("physical_evidence_root", PHYSICAL_EVIDENCE_ROOT)
    kwargs.setdefault("physical_trust_policy", PHYSICAL_TRUST_POLICY)
    with fixture_packet_policy():
        return _build_sealed_evidence_manifest(*args, **kwargs)


def validate_sealed_evidence_manifest(*args, **kwargs):
    kwargs.setdefault("physical_evidence_root", PHYSICAL_EVIDENCE_ROOT)
    kwargs.setdefault("physical_trust_policy", PHYSICAL_TRUST_POLICY)
    with fixture_packet_policy():
        return _validate_sealed_evidence_manifest(*args, **kwargs)


def authorize_publication_artifacts(*args, **kwargs):
    with fixture_packet_policy():
        return _authorize_publication_artifacts(*args, **kwargs)


def _commit(rng: random.Random) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(40))


def _sha(rng: random.Random) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(64))


def _capabilities(rng: random.Random) -> tuple[str, ...]:
    capabilities = list(CAPABILITY_IDS)
    rng.shuffle(capabilities)
    return tuple(capabilities)


def _accept_request(rng: random.Random, workspace: Path, depth: int) -> dict:
    return request(
        depth,
        workspace,
        commit=COMMIT,
        capabilities=_capabilities(rng),
    )


def _dump(document: object) -> str:
    return json.dumps(document, indent=2, sort_keys=True, default=str)


# --- Request mutators: each applies one defect the builder MUST reject --------


def mutate_duplicate_capability(payload, rng, workspace):
    capabilities = payload["evidence_manifest"]["capabilities"]
    capabilities.append(copy.deepcopy(capabilities[0]))
    return "duplicate-capability"


def mutate_conflicting_capability_level(payload, rng, workspace):
    capability = rng.choice(payload["evidence_manifest"]["capabilities"])
    capability["highest_level"] = LEVEL_ORDER[rng.randint(0, 2)]
    return "conflicting-capability-level"


def mutate_skipped_predecessor(payload, rng, workspace):
    dropped = LEVEL_ORDER[rng.randint(0, 2)]
    for capability in payload["evidence_manifest"]["capabilities"]:
        capability["levels"].pop(dropped, None)
    return f"skipped-predecessor:{dropped}"


def mutate_unbound_report(payload, rng, workspace):
    payload["evidence_manifest"]["reports"].append(
        {
            "id": "orphan-report",
            "kind": "boundary_scan",
            "path": "reports/orphan-report.json",
            "sha256": _sha(rng),
            "status": "passed",
            "bindings": {"commit": payload["commit"]},
        }
    )
    return "unbound-report-digest"


def mutate_masked_inner_report(payload, rng, workspace):
    report = rng.choice(payload["evidence_manifest"]["reports"])
    report["status"] = rng.choice(("skipped", "masked", "failed", "timeout"))
    return "masked-inner-report"


def mutate_stale_lane_commit(payload, rng, workspace):
    rng.choice(payload["unsigned_ci"]["lanes"])["commit"] = _commit(rng)
    return "stale-lane-commit"


def mutate_stale_lane_toolchain(payload, rng, workspace):
    rng.choice(payload["unsigned_ci"]["lanes"])["toolchain_sha256"] = _sha(rng)
    return "stale-lane-toolchain"


def mutate_stale_lane_release_source(payload, rng, workspace):
    rng.choice(payload["unsigned_ci"]["lanes"])["release_source_sha256"] = _sha(rng)
    return "stale-lane-release-source"


def mutate_stale_source_gate_commit(payload, rng, workspace):
    rng.choice(payload["p0_source"]["gates"])["commit"] = _commit(rng)
    return "stale-source-gate-commit"


def mutate_stale_inner_toolchain(payload, rng, workspace):
    payload["unsigned_ci"] = ci_lanes(commit=payload["commit"], toolchain=_sha(rng))
    return "stale-inner-toolchain"


def mutate_stale_inner_signed_app(payload, rng, workspace):
    payload["evidence_manifest"] = inner_manifest(
        3, commit=payload["commit"], signed_app=_sha(rng)
    )
    return "stale-inner-signed-app"


def mutate_stale_closure_commit(payload, rng, workspace):
    payload["sealed_closure"] = sealed_closure_document(commit=_commit(rng))
    return "stale-closure-commit"


def mutate_stale_closure_signed_app(payload, rng, workspace):
    payload["sealed_closure"] = sealed_closure_document(
        commit=payload["commit"], signed_app=_sha(rng)
    )
    return "stale-closure-signed-app"


def mutate_substituted_aggregate(payload, rng, workspace):
    artifact = copy.deepcopy(payload["signed_installed"])
    artifact["sha256"] = _sha(rng)
    payload["signed_installed"] = artifact
    return "substituted-aggregate"


def mutate_blocked_input_promoted(payload, rng, workspace):
    dropped = rng.choice(COMPOSED_INPUTS)
    payload[dropped] = None
    return f"blocked-input-promoted:{dropped}"


def mutate_failed_lane_promoted(payload, rng, workspace):
    lane = rng.choice(payload["unsigned_ci"]["lanes"])
    lane["status"] = rng.choice(("failed", "skipped", "masked", "timeout", "malformed"))
    lane["exit_code"] = rng.randint(1, 255)
    return "failed-lane-promoted"


def mutate_lane_masks_nonzero_exit(payload, rng, workspace):
    rng.choice(payload["unsigned_ci"]["lanes"])["exit_code"] = rng.randint(1, 255)
    return "lane-masks-nonzero-exit"


def mutate_missing_lane(payload, rng, workspace):
    payload["unsigned_ci"]["lanes"].pop(rng.randrange(len(payload["unsigned_ci"]["lanes"])))
    return "missing-lane"


def mutate_unknown_result_status(payload, rng, workspace):
    rng.choice(payload["p0_source"]["gates"])["status"] = "probably-ok"
    return "unknown-result-status"


def mutate_source_gate_script(payload, rng, workspace):
    rng.choice(payload["p0_source"]["gates"])["script"] = "scripts/other_gate.sh"
    return "source-gate-script-drift"


def mutate_product_drift(payload, rng, workspace):
    payload["product"]["build_number"] = "40001"
    return "product-build-number-drift"


REQUEST_MUTATORS = (
    mutate_duplicate_capability,
    mutate_conflicting_capability_level,
    mutate_skipped_predecessor,
    mutate_unbound_report,
    mutate_masked_inner_report,
    mutate_stale_lane_commit,
    mutate_stale_lane_toolchain,
    mutate_stale_lane_release_source,
    mutate_stale_source_gate_commit,
    mutate_stale_inner_toolchain,
    mutate_stale_inner_signed_app,
    mutate_stale_closure_commit,
    mutate_stale_closure_signed_app,
    mutate_substituted_aggregate,
    mutate_blocked_input_promoted,
    mutate_failed_lane_promoted,
    mutate_lane_masks_nonzero_exit,
    mutate_missing_lane,
    mutate_unknown_result_status,
    mutate_source_gate_script,
    mutate_product_drift,
)


# --- Document mutators: hand edits the validator MUST re-derive and reject ----


def tamper_capability_level(document, rng):
    document["capabilities"][0]["highest_level"] = LEVEL_ORDER[
        max(0, LEVEL_ORDER.index(document["capabilities"][0]["highest_level"]) - 1)
    ]
    reseal(document)
    return "tampered-capability-level"


def tamper_duplicate_capability(document, rng):
    document["capabilities"].append(copy.deepcopy(document["capabilities"][0]))
    reseal(document)
    return "tampered-duplicate-capability"


def tamper_capability_report_digests(document, rng):
    document["capabilities"][0]["level_report_digests"][LEVEL_ORDER[0]] = [_sha(rng)]
    reseal(document)
    return "tampered-capability-report-digest"


def tamper_document_digest(document, rng):
    document["documents"][rng.randrange(len(document["documents"]))]["sha256"] = _sha(rng)
    reseal(document)
    return "tampered-document-digest"


def tamper_gate_status(document, rng):
    document["gates"]["unsigned_ci"] = {"status": PASSED, "evidence": None}
    reseal(document)
    return "tampered-gate-status"


def tamper_blocked_inputs(document, rng):
    document["blocked_inputs"] = []
    document["status"] = SEALED
    reseal(document)
    return "tampered-blocked-inputs"


def tamper_publication_decision(document, rng):
    document["publication"] = {"allowed": True, "artifacts_permitted": True, "refusals": []}
    reseal(document)
    return "tampered-publication-decision"


def tamper_bindings(document, rng):
    document["bindings"]["report_digests"] = [_sha(rng)]
    reseal(document)
    return "tampered-bindings"


def tamper_self_seal(document, rng):
    document["manifest_sha256"] = _sha(rng)
    return "tampered-self-seal"


def tamper_field_without_reseal(document, rng):
    document["commit"] = _commit(rng)
    return "tampered-field-without-reseal"


def tamper_platform(document, rng):
    document["platform"]["macos_min"] = "14.0"
    reseal(document)
    return "tampered-platform"


def tamper_unknown_field(document, rng):
    document["publication_override"] = True
    return "tampered-unknown-field"


def tamper_schema_numeric_type(document, rng):
    document["schema_version"] = rng.choice((1.0, True))
    reseal(document)
    return "tampered-schema-numeric-type"


DOCUMENT_MUTATORS = (
    tamper_capability_level,
    tamper_duplicate_capability,
    tamper_capability_report_digests,
    tamper_document_digest,
    tamper_gate_status,
    tamper_blocked_inputs,
    tamper_publication_decision,
    tamper_bindings,
    tamper_self_seal,
    tamper_field_without_reseal,
    tamper_platform,
    tamper_unknown_field,
    tamper_schema_numeric_type,
)

UPDATER_KEY_DEFECT = "updater-key-present"


class _CleanWorkspace(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._property_snapshots = StrictReleasePropertySnapshots(
            repository=REPOSITORY,
            source_deriver=sealed_closure_module.derive_supply_chain,
            source_consumers=(
                (sealed_closure_module, "derive_supply_chain"),
                (final_candidate_module, "derive_supply_chain"),
            ),
            physical_loader=sealed_manifest_module.load_physical_evidence_artifact,
            physical_consumers=(
                (sealed_manifest_module, "load_physical_evidence_artifact"),
                (final_candidate_module, "load_physical_evidence_artifact"),
            ),
            physical_inputs=(
                PhysicalSnapshotInput(
                    descriptor=physical_fixture(),
                    evidence_root=PHYSICAL_EVIDENCE_ROOT,
                    trust_policy=PHYSICAL_TRUST_POLICY,
                ),
            ),
        )
        cls._property_snapshots.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls._property_snapshots.__exit__(None, None, None)
        finally:
            super().tearDownClass()

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)


class SealedManifestRoundTripProperty(_CleanWorkspace):
    def test_gate_authorized_levels_build_seal_and_validate(self) -> None:
        depth_hits = {depth: 0 for depth in range(len(LEVEL_ORDER))}
        cases = 0
        for index in range(ACCEPT_CASES):
            seed = 310_000 + index
            rng = random.Random(seed)
            depth = index % len(LEVEL_ORDER)
            payload = _accept_request(rng, self.workspace, depth)
            try:
                manifest = build_sealed_evidence_manifest(
                    REPOSITORY, payload, fixture=True, workspace_root=self.workspace
                )
                validate_sealed_evidence_manifest(
                    REPOSITORY, manifest, fixture=True, workspace_root=self.workspace
                )
            except PublicationError as error:
                self.fail(
                    "a valid sealed manifest was rejected\n"
                    f"seed={seed} depth={depth} error={error}\nrequest=\n{_dump(payload)}"
                )
            expected_blocked = sorted(
                gate for gate in GATE_ORDER if manifest["gates"][gate]["status"] != PASSED
            )
            self.assertEqual(
                manifest["blocked_inputs"], expected_blocked, f"seed={seed} depth={depth}"
            )
            for capability in manifest["capabilities"]:
                self.assertEqual(
                    capability["highest_level"], LEVEL_ORDER[depth], f"seed={seed}"
                )
            if depth == len(LEVEL_ORDER) - 1:
                self.assertEqual(manifest["status"], SEALED, f"seed={seed}")
                self.assertEqual(manifest["blocked_inputs"], [], f"seed={seed}")
                self.assertFalse(
                    manifest["publication"]["artifacts_permitted"], f"seed={seed}"
                )
                self.assertIn("fixture-mode", manifest["publication"]["refusals"])
                with self.assertRaisesRegex(PublicationError, "fixture evidence"):
                    authorize_publication_artifacts(
                        REPOSITORY, manifest, workspace_root=self.workspace
                    )
            else:
                self.assertEqual(manifest["status"], BLOCKED, f"seed={seed}")
                self.assertNotEqual(manifest["blocked_inputs"], [], f"seed={seed}")
                self.assertFalse(manifest["publication"]["allowed"], f"seed={seed}")
                self.assertNotIn(
                    SEALED_LEVEL,
                    [capability["highest_level"] for capability in manifest["capabilities"]],
                    f"seed={seed}",
                )
                with self.assertRaises(PublicationError, msg=f"seed={seed}"):
                    validate_sealed_evidence_manifest(
                        REPOSITORY,
                        manifest,
                        fixture=True,
                        workspace_root=self.workspace,
                        require_sealed=True,
                    )
                with self.assertRaises(PublicationError, msg=f"seed={seed}"):
                    authorize_publication_artifacts(
                        REPOSITORY, manifest, workspace_root=self.workspace
                    )
            depth_hits[depth] += 1
            cases += 1
        self.assertGreaterEqual(cases, 100, "must run at least 100 accept cases")
        for depth, hits in depth_hits.items():
            self.assertGreater(hits, 0, f"level {LEVEL_ORDER[depth]} was never exercised")

    def test_sealed_manifest_is_written_once_and_reloads_identically(self) -> None:
        for index in range(10):
            seed = 320_000 + index
            rng = random.Random(seed)
            manifest = build_sealed_evidence_manifest(
                REPOSITORY,
                _accept_request(rng, self.workspace, index % len(LEVEL_ORDER)),
                fixture=True,
                workspace_root=self.workspace,
            )
            with tempfile.TemporaryDirectory() as output:
                path = Path(output) / "sealed-evidence-manifest.json"
                seal_manifest(path, manifest)
                with self.assertRaises(PublicationError, msg=f"seed={seed}"):
                    seal_manifest(path, manifest)
                reloaded = load_sealed_manifest(path)
                self.assertEqual(reloaded, manifest, f"seed={seed}")
                validate_sealed_evidence_manifest(
                    REPOSITORY, reloaded, fixture=True, workspace_root=self.workspace
                )


class SealedManifestFailClosedProperty(_CleanWorkspace):
    def test_single_defect_manifests_are_rejected(self) -> None:
        defects = (
            [("request", mutator) for mutator in REQUEST_MUTATORS]
            + [("document", mutator) for mutator in DOCUMENT_MUTATORS]
            + [("workspace", None)]
        )
        hits = {
            f"{kind}:{'updater-key' if mutator is None else mutator.__name__}": 0
            for kind, mutator in defects
        }
        cases = 0
        index = 0
        while cases < REJECT_CASES:
            kind, mutator = defects[cases % len(defects)]
            seed = 410_000 + index
            index += 1
            rng = random.Random(seed)
            key = f"{kind}:{'updater-key' if mutator is None else mutator.__name__}"
            if kind == "request":
                payload = request(3, self.workspace, commit=COMMIT)
                pristine = copy.deepcopy(payload)
                label = mutator(payload, rng, self.workspace)
                if payload == pristine:
                    continue
                physical_validation = (
                    self._property_snapshots.uncached_physical_validation()
                    if mutator is mutate_substituted_aggregate
                    else nullcontext()
                )
                with physical_validation:
                    try:
                        document = build_sealed_evidence_manifest(
                            REPOSITORY,
                            payload,
                            fixture=True,
                            workspace_root=self.workspace,
                        )
                    except PublicationError:
                        hits[key] += 1
                        cases += 1
                        continue
                self.fail(
                    "a single-defect sealed manifest request was wrongly ACCEPTED\n"
                    f"seed={seed} defect={label}\nmanifest=\n{_dump(document)}"
                )
            elif kind == "document":
                # Depth 1..2: a partially blocked manifest, so a hand edit that
                # claims a higher level or an empty blocked-input set is always a
                # real change the validator must re-derive and reject.
                depth = 1 + (index % 2)
                document = build_sealed_evidence_manifest(
                    REPOSITORY,
                    _accept_request(rng, self.workspace, depth),
                    fixture=True,
                    workspace_root=self.workspace,
                )
                pristine = copy.deepcopy(document)
                label = mutator(document, rng)
                if document == pristine:
                    continue
                try:
                    validate_sealed_evidence_manifest(
                        REPOSITORY, document, fixture=True, workspace_root=self.workspace
                    )
                except PublicationError:
                    hits[key] += 1
                    cases += 1
                    continue
                self.fail(
                    "a hand-edited sealed manifest was wrongly ACCEPTED on validate\n"
                    f"seed={seed} defect={label}\nmanifest=\n{_dump(document)}"
                )
            else:
                with tempfile.TemporaryDirectory() as tmp:
                    workspace = Path(tmp)
                    name = rng.choice(("cfw-rs.key", "updater.pem", "nested/release.key"))
                    target = workspace / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("never-read", encoding="utf-8")
                    payload = request(3, workspace, commit=COMMIT)
                    try:
                        document = build_sealed_evidence_manifest(
                            REPOSITORY, payload, fixture=True, workspace_root=workspace
                        )
                    except PublicationError:
                        hits[key] += 1
                        cases += 1
                        continue
                    self.fail(
                        "a sealed claim was wrongly ACCEPTED while an updater key was present\n"
                        f"seed={seed} defect={UPDATER_KEY_DEFECT}\nmanifest=\n{_dump(document)}"
                    )
        self.assertGreaterEqual(cases, 100, "must run at least 100 reject cases")
        for name, count in hits.items():
            self.assertGreater(count, 0, f"defect class {name} was never exercised")


if __name__ == "__main__":
    unittest.main()
