#!/usr/bin/env python3
"""Property-based fail-closed test for the final-candidate binder.

Exercises ``publication.final_candidate`` as a black box (Task 12.2,
Requirements 4.1, 5.1, 6.1, 6.2, 6.3, 6.4, 6.5, 8.1). It is deterministic: the
stdlib ``random`` module is seeded with fixed integers so any failure
reproduces exactly. ``hypothesis`` is intentionally not required; at least 100
generated bindings are validated per property and, on failure, the reproducing
seed and offending document are printed.

Two properties are checked:

* round trip - every fully specified reviewed binding builds and validates to
  ``verified`` with the complete installed-matrix / packet / performance /
  security / soak report set bound for both required macOS run sets, and a
  binding missing any notarization/staple/Gatekeeper/physical/post-verification
  input (or with an updater-key file in the workspace) is environment-gated to
  ``blocked`` and can never be promoted to ``verified``;
* fail closed - every single-defect mutation (unexpected inside-out identity,
  wrong Team ID, unaccepted notarization/Gatekeeper, unstapled ticket, foreign
  target, stale report, unbound app-tree hash, manifest digest drift, missing
  identity, a foreign physical app tree, a drifted or off-pin libbox
  XCFramework, a component linked against another XCFramework, a superseded
  artifact-manifest binding, a superseded raw report, or an app-tree hash that
  drifted after verification) is rejected.
"""

from __future__ import annotations

import copy
import json
import random
import tempfile
import unittest
from pathlib import Path

from scripts.publication.common import PublicationError, tree_digest
from scripts.publication.final_candidate import (
    BLOCKED,
    PHYSICAL_INPUTS,
    REPORT_CATEGORIES,
    REQUIRED_NESTED_CODE,
    TEAM_ID,
    UPDATER_KEY_BLOCK,
    VERIFIED,
    build_final_candidate_binding,
    validate_final_candidate_binding,
)
from scripts.publication.sealed_closure import derive_supply_chain
from scripts.repository_source_identity import repository_commit
from scripts.tests.test_physical_evidence_aggregator import (
    APP_MANIFEST,
    BUILD_NUMBER,
    BUILT_AT,
    SIGNED_TREE,
    fixture as physical_fixture,
)
from scripts.tests.gatekeeper_fixture import fixture as gatekeeper_fixture

REPOSITORY = Path(__file__).resolve().parent.parent.parent
REPOSITORY_COMMIT = repository_commit(REPOSITORY)
ACCEPT_CASES = 120
REJECT_CASES = 200
PHYSICAL = PHYSICAL_INPUTS
PINNED = derive_supply_chain(REPOSITORY)["patched_source"]
XCFRAMEWORK_SHA = "1" * 64
XCFRAMEWORK_MANIFEST_SHA = "2" * 64
OBSERVED_AT = "2026-08-01T00:00:00Z"


def _sha(rng: random.Random) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(64))


def _cdhash(rng: random.Random) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(40))


def _captured_at(rng: random.Random) -> str:
    # Always at or after BUILT_AT (2026-07-01) so the fresh case is not stale.
    return f"2026-07-{rng.randint(1, 28):02d}T{rng.randint(0, 23):02d}:00:00Z"


def _artifact_manifest(rng: random.Random) -> dict:
    entries = [
        {"path": "artifacts/Clash-for-Mac.app.tree.json", "sha256": SIGNED_TREE},
        {"path": "artifacts/app-manifest.json", "sha256": APP_MANIFEST},
        {"path": "artifacts/Libbox.xcframework.tree.json", "sha256": XCFRAMEWORK_SHA},
        {
            "path": "artifacts/Libbox.xcframework.manifest.json",
            "sha256": XCFRAMEWORK_MANIFEST_SHA,
        },
    ]
    for index in range(rng.randint(0, 3)):
        entries.append({"path": f"artifacts/extra-{index}.bin", "sha256": _sha(rng)})
    entries.sort(key=lambda item: item["path"])
    return {"entries": entries, "sha256": tree_digest(entries)}


def _xcframework() -> dict:
    return {
        "path": "target/native-dependencies/Libbox.xcframework",
        "xcframework_sha256": XCFRAMEWORK_SHA,
        "manifest_sha256": XCFRAMEWORK_MANIFEST_SHA,
        "upstream_commit": PINNED["upstream_commit"],
        "combined_diff_sha256": PINNED["combined_diff_sha256"],
    }


def _nested_code(rng: random.Random) -> list[dict]:
    nested = []
    for role, bundle_id in REQUIRED_NESTED_CODE.items():
        nested.append(
            {
                "role": role,
                "path": f"Contents/{role}",
                "bundle_id": bundle_id,
                "team_id": TEAM_ID,
                "cdhash": _cdhash(rng),
                "designated_requirement_sha256": _sha(rng),
                "entitlements_sha256": _sha(rng),
                "provisioning": rng.choice(("embedded-profile", "not-required", "development")),
                "libbox_xcframework_sha256": XCFRAMEWORK_SHA,
            }
        )
    rng.shuffle(nested)
    return nested


def _request(rng: random.Random, drop_physical: str | None = None) -> dict:
    captured = _captured_at(rng)
    manifest = _artifact_manifest(rng)
    request = {
        "product": {"version": "0.4.0", "build_number": BUILD_NUMBER},
        "commit": REPOSITORY_COMMIT,
        "final_artifacts": {
            "signed_app_tree_sha256": SIGNED_TREE,
            "app_manifest_sha256": APP_MANIFEST,
            "built_at": BUILT_AT,
            "artifact_hash_manifest": manifest,
        },
        "xcframework": _xcframework(),
        "nested_code": _nested_code(rng),
        "evidence_binding": {
            "artifact_hash_manifest_sha256": manifest["sha256"],
            "superseded_report_hashes": [],
        },
        "post_verification": {"app_tree_sha256": SIGNED_TREE, "observed_at": OBSERVED_AT},
        "notarization": {
            "status": "Accepted",
            "id": f"notary-{rng.randint(1000, 9999)}",
            "submission_sha256": _sha(rng),
            "target_signed_app_tree_sha256": SIGNED_TREE,
            "captured_at": captured,
        },
        "staple": {
            "stapled": True,
            "target_signed_app_tree_sha256": SIGNED_TREE,
            "captured_at": captured,
        },
        "gatekeeper": gatekeeper_fixture(SIGNED_TREE, captured),
        "physical_evidence": physical_fixture(),
    }
    if drop_physical is not None:
        request[drop_physical] = None
    return request


def _dump(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, default=str)


# --- Mutators: each applies exactly one defect that MUST be rejected ---------


def mutate_unexpected_bundle(request, rng):
    request["nested_code"][0]["bundle_id"] = "com.evil.impostor"
    return request, "unexpected-bundle"


def mutate_wrong_team(request, rng):
    request["nested_code"][0]["team_id"] = "AAAAAAAAAA"
    return request, "wrong-team"


def mutate_notarization_unaccepted(request, rng):
    request["notarization"]["status"] = "Rejected"
    return request, "notarization-unaccepted"


def mutate_unstapled(request, rng):
    request["staple"]["stapled"] = False
    return request, "unstapled"


def mutate_gatekeeper_rejected(request, rng):
    request["gatekeeper"]["assessment"] = "rejected"
    return request, "gatekeeper-rejected"


def mutate_gatekeeper_disabled(request, rng):
    request["gatekeeper"]["assessments_enabled"] = False
    return request, "gatekeeper-disabled"


def mutate_gatekeeper_output_digest(request, rng):
    request["gatekeeper"]["assessment_output_sha256"] = _sha(rng)
    return request, "gatekeeper-output-digest"


def mutate_foreign_target(request, rng):
    request["notarization"]["target_signed_app_tree_sha256"] = _sha(rng)
    return request, "foreign-target"


def mutate_stale_report(request, rng):
    request["gatekeeper"]["captured_at"] = "2026-06-15T00:00:00Z"
    return request, "stale-report"


def mutate_unbound_tree(request, rng):
    request["final_artifacts"]["signed_app_tree_sha256"] = _sha(rng)
    return request, "unbound-tree"


def mutate_manifest_digest(request, rng):
    request["final_artifacts"]["artifact_hash_manifest"]["sha256"] = _sha(rng)
    return request, "manifest-digest"


def mutate_missing_identity(request, rng):
    request["nested_code"].pop()
    return request, "missing-identity"


def mutate_foreign_physical_tree(request, rng):
    request["physical_evidence"]["candidate"]["signed_app_tree_sha256"] = "f" * 64
    return request, "foreign-physical-tree"


def mutate_unbound_xcframework(request, rng):
    request["xcframework"]["xcframework_sha256"] = _sha(rng)
    return request, "unbound-xcframework"


def mutate_offpin_xcframework(request, rng):
    request["xcframework"]["combined_diff_sha256"] = _sha(rng)
    return request, "offpin-xcframework"


def mutate_linked_other_libbox(request, rng):
    request["nested_code"][0]["libbox_xcframework_sha256"] = _sha(rng)
    return request, "linked-other-libbox"


def mutate_superseded_manifest_binding(request, rng):
    request["evidence_binding"]["artifact_hash_manifest_sha256"] = _sha(rng)
    return request, "superseded-manifest-binding"


def mutate_superseded_report(request, rng):
    # Retire a raw report that the aggregate still carries.
    report = request["physical_evidence"]["runs"][0]["reports"]["packet"]["report_sha256"]
    request["evidence_binding"]["superseded_report_hashes"] = [report]
    return request, "superseded-report"


def mutate_post_verification_drift(request, rng):
    request["post_verification"]["app_tree_sha256"] = _sha(rng)
    return request, "post-verification-drift"


def mutate_post_verification_precedes_evidence(request, rng):
    request["post_verification"]["observed_at"] = "2026-07-01T00:00:01Z"
    return request, "post-verification-precedes-evidence"


def mutate_missing_soak(request, rng):
    del request["physical_evidence"]["runs"][0]["reports"]["performance"]["document"]["soak"]
    return request, "missing-soak"


MUTATORS = (
    mutate_unexpected_bundle,
    mutate_wrong_team,
    mutate_notarization_unaccepted,
    mutate_unstapled,
    mutate_gatekeeper_rejected,
    mutate_gatekeeper_disabled,
    mutate_gatekeeper_output_digest,
    mutate_foreign_target,
    mutate_stale_report,
    mutate_unbound_tree,
    mutate_manifest_digest,
    mutate_missing_identity,
    mutate_foreign_physical_tree,
    mutate_unbound_xcframework,
    mutate_offpin_xcframework,
    mutate_linked_other_libbox,
    mutate_superseded_manifest_binding,
    mutate_superseded_report,
    mutate_post_verification_drift,
    mutate_post_verification_precedes_evidence,
    mutate_missing_soak,
)


class _CleanWorkspace(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)


class FinalCandidateRoundTripProperty(_CleanWorkspace):
    def test_full_bindings_build_and_validate(self) -> None:
        blocked_hits = {name: 0 for name in PHYSICAL}
        verified_hits = 0
        cases = 0
        for seed in range(ACCEPT_CASES):
            rng = random.Random(2_000 + seed)
            drop = rng.choice((None, *PHYSICAL))
            request = _request(rng, drop)
            try:
                binding = build_final_candidate_binding(
                    REPOSITORY, request, fixture=True, workspace_root=self.workspace
                )
                validate_final_candidate_binding(
                    REPOSITORY, binding, fixture=True, workspace_root=self.workspace
                )
            except PublicationError as error:
                self.fail(
                    f"valid binding was rejected\nseed={2000 + seed} drop={drop}\n"
                    f"error={error}\nrequest=\n{_dump(request)}"
                )
            if drop is None:
                self.assertEqual(binding["status"], VERIFIED)
                validate_final_candidate_binding(
                    REPOSITORY,
                    binding,
                    fixture=True,
                    workspace_root=self.workspace,
                    require_verified=True,
                )
                # A verified candidate always binds every raw report family for
                # both required macOS run sets.
                bound = {
                    (entry["os"], entry["category"]) for entry in binding["report_bindings"]
                }
                self.assertEqual(
                    bound,
                    {
                        (os_label, category)
                        for os_label in ("macos15", "current-macos")
                        for category in REPORT_CATEGORIES
                    },
                    f"incomplete report binding\nseed={2000 + seed}",
                )
                verified_hits += 1
            else:
                self.assertEqual(binding["status"], BLOCKED)
                self.assertIn(drop, binding["blocked_inputs"])
                blocked_hits[drop] += 1
                with self.assertRaises(PublicationError):
                    validate_final_candidate_binding(
                        REPOSITORY,
                        binding,
                        fixture=True,
                        workspace_root=self.workspace,
                        require_verified=True,
                    )
            cases += 1
        self.assertGreaterEqual(cases, 100, "must run at least 100 accept cases")
        self.assertGreater(verified_hits, 0, "verified status was never exercised")
        for name, hits in blocked_hits.items():
            self.assertGreater(hits, 0, f"blocked input {name} was never exercised")

    def test_updater_key_always_blocks(self) -> None:
        # An updater-key file in the workspace always invalidates the candidate,
        # regardless of otherwise complete evidence (Requirement 8.1).
        for seed in range(20):
            rng = random.Random(9_000 + seed)
            with tempfile.TemporaryDirectory() as tmp:
                workspace = Path(tmp)
                (workspace / "cfw-rs.key").write_text("PRIVATE", encoding="utf-8")
                binding = build_final_candidate_binding(
                    REPOSITORY, _request(rng), fixture=True, workspace_root=workspace
                )
                self.assertEqual(binding["status"], BLOCKED)
                self.assertIn(UPDATER_KEY_BLOCK, binding["blocked_inputs"])


class FinalCandidateFailClosedProperty(_CleanWorkspace):
    def test_single_defect_bindings_are_rejected(self) -> None:
        mutator_hits = {m.__name__: 0 for m in MUTATORS}
        cases = 0
        seed = 0
        while cases < REJECT_CASES:
            rng = random.Random(60_000 + seed)
            seed += 1
            mutator = MUTATORS[cases % len(MUTATORS)]
            request = _request(rng)
            mutated, label = mutator(copy.deepcopy(request), rng)
            if mutated == request:
                continue
            try:
                build_final_candidate_binding(
                    REPOSITORY, mutated, fixture=True, workspace_root=self.workspace
                )
            except PublicationError:
                mutator_hits[mutator.__name__] += 1
                cases += 1
                continue
            self.fail(
                "a single-defect final-candidate binding was wrongly ACCEPTED\n"
                f"seed={60_000 + seed - 1} defect={label}\nrequest=\n{_dump(mutated)}"
            )
        self.assertGreaterEqual(cases, 100, "must run at least 100 reject cases")
        for name, hits in mutator_hits.items():
            self.assertGreater(hits, 0, f"defect class {name} was never exercised")


if __name__ == "__main__":
    unittest.main()
