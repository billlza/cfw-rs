from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.publication.common import PublicationError, canonical_json, tree_digest
from scripts.publication.final_candidate import (
    BLOCKED,
    ENVIRONMENT_INPUT_FILES,
    NOT_RUN,
    PHYSICAL_INPUTS,
    REPORT_CATEGORIES,
    REQUIRED_NESTED_CODE,
    TEAM_ID,
    UPDATER_KEY_BLOCK,
    VERIFIED,
    build_final_candidate_binding,
    environment_status,
    self_check,
    validate_final_candidate_binding,
)
from scripts.harness.physical_evidence_aggregator import _canonical_report_hash
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
from scripts.tests.gatekeeper_fixture import macos_27_fixture

REPOSITORY = Path(__file__).resolve().parent.parent.parent
REPOSITORY_COMMIT = repository_commit(REPOSITORY)
CAPTURED_AT = "2026-07-25T00:00:00Z"
OBSERVED_AT = "2026-07-26T00:00:00Z"

# The pinned patched-source identity the XCFramework must declare, taken from the
# same sealed-closure derivation the release pipeline uses.
PINNED = derive_supply_chain(REPOSITORY)["patched_source"]


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


XCFRAMEWORK_SHA = _sha("libbox-xcframework")
XCFRAMEWORK_MANIFEST_SHA = _sha("libbox-xcframework-manifest")


def _artifact_manifest() -> dict:
    # The exact final artifact hashes must include the signed app-tree hash, the
    # app-manifest hash, and the libbox XCFramework digests so the binding pins
    # one unchanged app tree built from one source-built data plane.
    entries = sorted(
        (
            {"path": "artifacts/Clash-for-Mac.app.tree.json", "sha256": SIGNED_TREE},
            {"path": "artifacts/app-manifest.json", "sha256": APP_MANIFEST},
            {"path": "artifacts/Clash-for-Mac.dmg", "sha256": _sha("dmg")},
            {"path": "artifacts/Libbox.xcframework.tree.json", "sha256": XCFRAMEWORK_SHA},
            {
                "path": "artifacts/Libbox.xcframework.manifest.json",
                "sha256": XCFRAMEWORK_MANIFEST_SHA,
            },
        ),
        key=lambda item: item["path"],
    )
    return {"entries": entries, "sha256": tree_digest(entries)}


def _xcframework() -> dict:
    return {
        "path": "target/native-dependencies/Libbox.xcframework",
        "xcframework_sha256": XCFRAMEWORK_SHA,
        "manifest_sha256": XCFRAMEWORK_MANIFEST_SHA,
        "upstream_commit": PINNED["upstream_commit"],
        "combined_diff_sha256": PINNED["combined_diff_sha256"],
    }


def _nested_code() -> list[dict]:
    nested = []
    for index, (role, bundle_id) in enumerate(sorted(REQUIRED_NESTED_CODE.items())):
        nested.append(
            {
                "role": role,
                "path": f"Contents/{role}",
                "bundle_id": bundle_id,
                "team_id": TEAM_ID,
                "cdhash": f"{index:040x}",
                "designated_requirement_sha256": _sha(role + "-dr"),
                "entitlements_sha256": _sha(role + "-ent"),
                "provisioning": "embedded-profile" if role != "global-authority" else "not-required",
                "libbox_xcframework_sha256": XCFRAMEWORK_SHA,
            }
        )
    return nested


def _request(**overrides) -> dict:
    manifest = _artifact_manifest()
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
        "nested_code": _nested_code(),
        "evidence_binding": {
            "artifact_hash_manifest_sha256": manifest["sha256"],
            "superseded_report_hashes": [],
        },
        "post_verification": {"app_tree_sha256": SIGNED_TREE, "observed_at": OBSERVED_AT},
        "notarization": {
            "status": "Accepted",
            "id": "notary-submission-0001",
            "submission_sha256": _sha("submission"),
            "target_signed_app_tree_sha256": SIGNED_TREE,
            "captured_at": CAPTURED_AT,
        },
        "staple": {
            "stapled": True,
            "target_signed_app_tree_sha256": SIGNED_TREE,
            "captured_at": CAPTURED_AT,
        },
        "gatekeeper": gatekeeper_fixture(SIGNED_TREE, CAPTURED_AT),
        "physical_evidence": physical_fixture(),
    }
    request.update(overrides)
    return request


class _CleanWorkspaceMixin(unittest.TestCase):
    """Provides a clean workspace root with no updater-key file present."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def build(self, **overrides) -> dict:
        return build_final_candidate_binding(
            REPOSITORY, _request(**overrides), fixture=True, workspace_root=self.workspace
        )

    def validate(self, binding: dict, **kwargs):
        return validate_final_candidate_binding(
            REPOSITORY, binding, fixture=True, workspace_root=self.workspace, **kwargs
        )


class FinalCandidateRoundTripTests(_CleanWorkspaceMixin):
    def test_full_inputs_produce_verified_binding(self) -> None:
        binding = self.build()
        self.assertEqual(binding["status"], VERIFIED)
        self.assertEqual(binding["blocked_inputs"], [])
        self.validate(binding, require_verified=True)

    def test_all_inside_out_identities_are_bound(self) -> None:
        binding = self.build()
        roles = {entry["role"] for entry in binding["nested_code"]}
        self.assertEqual(roles, set(REQUIRED_NESTED_CODE))

    def test_macos_27_absent_origin_gatekeeper_evidence_is_bound(self) -> None:
        request = _request()
        request["gatekeeper"] = macos_27_fixture(SIGNED_TREE, CAPTURED_AT)
        binding = build_final_candidate_binding(
            REPOSITORY,
            request,
            fixture=True,
            workspace_root=self.workspace,
        )
        self.assertEqual(binding["status"], VERIFIED)
        self.assertIsNone(binding["gatekeeper"]["origin"])
        self.assertEqual(
            binding["gatekeeper"]["identity_source"],
            "codesign-leaf-authority",
        )

    def test_missing_physical_inputs_block_and_cannot_be_promoted(self) -> None:
        for missing in PHYSICAL_INPUTS:
            binding = self.build(**{missing: None})
            self.assertEqual(binding["status"], BLOCKED)
            self.assertIn(missing, binding["blocked_inputs"])
            # A blocked binding still validates structurally...
            self.validate(binding)
            # ...but can never be promoted to verified.
            with self.assertRaisesRegex(PublicationError, "environment-gated"):
                self.validate(binding, require_verified=True)

    def test_fixture_mode_mismatch_is_rejected(self) -> None:
        binding = self.build()
        with self.assertRaisesRegex(PublicationError, "fixture mode mismatch"):
            validate_final_candidate_binding(
                REPOSITORY, binding, fixture=False, workspace_root=self.workspace
            )

    def test_legacy_v1_binding_is_rejected_after_gatekeeper_schema_hardening(self) -> None:
        binding = self.build()
        binding["schema_version"] = 1
        binding["document"] = "final-candidate-notarization-installed-binding-v1"
        with self.assertRaisesRegex(PublicationError, "unsupported schema/document"):
            self.validate(binding)


class FinalCandidateUpdaterKeyTests(_CleanWorkspaceMixin):
    def test_updater_key_presence_always_invalidates(self) -> None:
        # Any updater-key file in the workspace blocks the candidate (Req 8.1).
        (self.workspace / ".tauri").mkdir()
        (self.workspace / ".tauri" / "cfw-rs.key").write_text("PRIVATE", encoding="utf-8")
        binding = self.build()
        self.assertEqual(binding["status"], BLOCKED)
        self.assertIn(UPDATER_KEY_BLOCK, binding["blocked_inputs"])
        with self.assertRaisesRegex(PublicationError, "environment-gated"):
            self.validate(binding, require_verified=True)

    def test_pem_updater_key_also_invalidates(self) -> None:
        (self.workspace / "release.pem").write_text("KEY", encoding="utf-8")
        binding = self.build()
        self.assertIn(UPDATER_KEY_BLOCK, binding["blocked_inputs"])


class FinalCandidateFailClosedTests(_CleanWorkspaceMixin):
    def test_post_verification_tree_mutation_rejected(self) -> None:
        # The signed app-tree hash must be one of the exact final artifact hashes.
        request = _request()
        request["final_artifacts"]["signed_app_tree_sha256"] = _sha("mutated-tree")
        with self.assertRaisesRegex(PublicationError, "does not bind the signed app-tree hash"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_artifact_manifest_digest_drift_rejected(self) -> None:
        request = _request()
        request["final_artifacts"]["artifact_hash_manifest"]["sha256"] = _sha("wrong")
        with self.assertRaisesRegex(PublicationError, "artifact hash manifest digest"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_notarization_not_accepted_rejected(self) -> None:
        request = _request()
        request["notarization"]["status"] = "Rejected"
        with self.assertRaisesRegex(PublicationError, "notarization was not accepted"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_staple_not_stapled_rejected(self) -> None:
        request = _request()
        request["staple"]["stapled"] = False
        with self.assertRaisesRegex(PublicationError, "is not stapled"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_gatekeeper_not_accepted_rejected(self) -> None:
        request = _request()
        request["gatekeeper"]["assessment"] = "rejected"
        with self.assertRaisesRegex(PublicationError, "not an accepted spctl assessment"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_gatekeeper_disabled_status_rejected(self) -> None:
        request = _request()
        request["gatekeeper"]["status_output"] = "assessments disabled\n"
        request["gatekeeper"]["status_output_sha256"] = _sha(
            request["gatekeeper"]["status_output"]
        )
        with self.assertRaisesRegex(PublicationError, "not provably enabled"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_gatekeeper_security_disabled_override_rejected(self) -> None:
        request = _request()
        output = request["gatekeeper"]["assessment_output"]
        output += "override=security disabled\n"
        request["gatekeeper"]["assessment_output"] = output
        request["gatekeeper"]["assessment_output_sha256"] = _sha(output)
        with self.assertRaisesRegex(PublicationError, "security override"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_gatekeeper_assessment_output_digest_mismatch_rejected(self) -> None:
        request = _request()
        request["gatekeeper"]["assessment_output_sha256"] = _sha("foreign output")
        with self.assertRaisesRegex(PublicationError, "assessment output digest mismatch"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_gatekeeper_open_policy_cannot_substitute_for_app_execution(self) -> None:
        request = _request()
        request["gatekeeper"]["assessment_type"] = "open"
        request["gatekeeper"]["primary_signature_context"] = True
        with self.assertRaisesRegex(PublicationError, "required policy"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_notarization_target_mismatch_rejected(self) -> None:
        request = _request()
        request["notarization"]["target_signed_app_tree_sha256"] = _sha("foreign")
        with self.assertRaisesRegex(PublicationError, "does not target the final signed app tree"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_stale_notarization_rejected(self) -> None:
        request = _request()
        request["notarization"]["captured_at"] = "2026-06-01T00:00:00Z"  # before BUILT_AT
        with self.assertRaisesRegex(PublicationError, "notarization is stale"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_missing_inside_out_identity_rejected(self) -> None:
        request = _request()
        request["nested_code"] = [
            entry for entry in request["nested_code"] if entry["role"] != "global-authority"
        ]
        with self.assertRaisesRegex(PublicationError, "missing inside-out signing identities"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_wrong_team_id_rejected(self) -> None:
        request = _request()
        request["nested_code"][0]["team_id"] = "AAAAAAAAAA"
        with self.assertRaisesRegex(PublicationError, "team_id is not"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_unexpected_bundle_identity_rejected(self) -> None:
        request = _request()
        request["nested_code"][0]["bundle_id"] = "com.evil.impostor"
        with self.assertRaisesRegex(PublicationError, "is not the expected identity"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_physical_evidence_foreign_tree_rejected(self) -> None:
        request = _request()
        # Rebind the physical aggregate's signed tree to a foreign value.
        request["final_artifacts"]["signed_app_tree_sha256"] = SIGNED_TREE
        aggregate = request["physical_evidence"]
        aggregate["candidate"]["signed_app_tree_sha256"] = "f" * 64
        with self.assertRaises(PublicationError):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_physical_evidence_stale_build_time_rejected(self) -> None:
        request = _request()
        request["physical_evidence"]["candidate"]["built_at"] = "2026-01-01T00:00:00Z"
        with self.assertRaisesRegex(PublicationError, "build time does not match"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_physical_evidence_harness_failure_rejected(self) -> None:
        request = _request()
        # Corrupt an embedded harness so its own validator rejects it.
        del request["physical_evidence"]["runs"][0]["reports"]["packet"]
        with self.assertRaisesRegex(PublicationError, "physical evidence aggregate is invalid"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_xcframework_must_be_bound_by_final_artifact_hashes(self) -> None:
        request = _request()
        request["xcframework"]["xcframework_sha256"] = _sha("foreign-xcframework")
        with self.assertRaisesRegex(PublicationError, "does not bind the libbox XCFramework digest"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_xcframework_manifest_must_be_bound(self) -> None:
        request = _request()
        request["xcframework"]["manifest_sha256"] = _sha("foreign-manifest")
        with self.assertRaisesRegex(PublicationError, "XCFramework manifest digest"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_xcframework_off_pin_commit_rejected(self) -> None:
        request = _request()
        request["xcframework"]["upstream_commit"] = "0" * 40
        with self.assertRaisesRegex(PublicationError, "not the pinned sing-box commit"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_xcframework_off_pin_combined_diff_rejected(self) -> None:
        request = _request()
        request["xcframework"]["combined_diff_sha256"] = _sha("legacy-single-patch")
        with self.assertRaisesRegex(PublicationError, "not the pinned patch closure"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_component_linked_against_other_libbox_rejected(self) -> None:
        request = _request()
        request["nested_code"][1]["libbox_xcframework_sha256"] = _sha("other-libbox")
        with self.assertRaisesRegex(PublicationError, "linked against a different libbox"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_reports_bound_to_superseded_artifact_manifest_rejected(self) -> None:
        request = _request()
        request["evidence_binding"]["artifact_hash_manifest_sha256"] = _sha("older-manifest")
        with self.assertRaisesRegex(PublicationError, "superseded final artifact-hash manifest"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_superseded_raw_report_rejected(self) -> None:
        binding = self.build()
        superseded = binding["report_bindings"][0]["report_sha256"]
        request = _request()
        request["evidence_binding"]["superseded_report_hashes"] = [superseded]
        with self.assertRaisesRegex(PublicationError, "binds superseded raw reports"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_all_report_families_are_bound_for_both_run_sets(self) -> None:
        binding = self.build()
        bound = {(entry["os"], entry["category"]) for entry in binding["report_bindings"]}
        self.assertEqual(
            bound,
            {
                (os_label, category)
                for os_label in ("macos15", "current-macos")
                for category in REPORT_CATEGORIES
            },
        )
        self.assertEqual(
            [run["os"] for run in binding["installed_runs"]], ["current-macos", "macos15"]
        )

    def test_soak_mutation_changes_the_bound_soak_hash(self) -> None:
        baseline = self.build()
        soak_hashes = {
            entry["report_sha256"]
            for entry in baseline["report_bindings"]
            if entry["category"] == "soak"
        }
        request = _request()
        for run in request["physical_evidence"]["runs"]:
            run["reports"]["performance"]["document"]["soak"]["duration_hours"] = 25
            run["reports"]["performance"]["report_sha256"] = _canonical_report_hash(
                run["reports"]["performance"]["document"]
            )
        mutated = build_final_candidate_binding(
            REPOSITORY, request, fixture=True, workspace_root=self.workspace
        )
        mutated_hashes = {
            entry["report_sha256"]
            for entry in mutated["report_bindings"]
            if entry["category"] == "soak"
        }
        self.assertTrue(soak_hashes.isdisjoint(mutated_hashes))

    def test_incomplete_soak_fails_the_level(self) -> None:
        request = _request()
        run = request["physical_evidence"]["runs"][0]
        run["reports"]["performance"]["document"]["soak"]["duration_hours"] = 12
        run["reports"]["performance"]["report_sha256"] = _canonical_report_hash(
            run["reports"]["performance"]["document"]
        )
        with self.assertRaisesRegex(PublicationError, "physical evidence aggregate is invalid"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_post_verification_app_tree_drift_rejected(self) -> None:
        request = _request()
        request["post_verification"]["app_tree_sha256"] = _sha("mutated-after-verification")
        with self.assertRaisesRegex(PublicationError, "drifted after verification"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_post_verification_before_evidence_rejected(self) -> None:
        request = _request()
        request["post_verification"]["observed_at"] = "2026-07-02T00:00:00Z"
        with self.assertRaisesRegex(PublicationError, "precedes bound evidence"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_hand_edited_report_binding_rejected(self) -> None:
        binding = self.build()
        binding["report_bindings"][0]["report_sha256"] = _sha("hand-edited")
        with self.assertRaisesRegex(PublicationError, "do not match the raw physical evidence"):
            self.validate(binding)

    def test_hand_edited_installed_run_rejected(self) -> None:
        binding = self.build()
        binding["installed_runs"][0]["machine_sha256"] = _sha("other-machine")
        with self.assertRaisesRegex(PublicationError, "installed-run summary does not match"):
            self.validate(binding)

    def test_content_digest_tamper_rejected(self) -> None:
        binding = self.build()
        binding["commit"] = _sha("different-commit")[:40]
        with self.assertRaisesRegex(PublicationError, "does not match current HEAD"):
            self.validate(binding)

    def test_arbitrary_well_formed_commit_is_rejected_before_binding(self) -> None:
        request = _request()
        request["commit"] = "f" * 40
        with self.assertRaisesRegex(PublicationError, "does not match current HEAD"):
            build_final_candidate_binding(
                REPOSITORY, request, fixture=True, workspace_root=self.workspace
            )

    def test_blocked_input_set_must_be_consistent(self) -> None:
        binding = self.build()
        binding["blocked_inputs"] = ["notarization"]
        binding["binding_sha256"] = hashlib.sha256(
            canonical_json({k: v for k, v in binding.items() if k != "binding_sha256"})
        ).hexdigest()
        with self.assertRaisesRegex(PublicationError, "blocked-input set is inconsistent"):
            self.validate(binding)

    def test_unknown_top_level_field_rejected(self) -> None:
        binding = self.build()
        binding["extra"] = True
        with self.assertRaisesRegex(PublicationError, "unexpected field set"):
            self.validate(binding)


class FinalCandidateEnvironmentStatusTests(_CleanWorkspaceMixin):
    def test_absent_inputs_report_not_run_and_block(self) -> None:
        report = environment_status(
            REPOSITORY,
            evidence_directory=self.workspace / "missing",
            workspace_root=self.workspace,
        )
        self.assertEqual(report["status"], BLOCKED)
        self.assertEqual(report["blocked_inputs"], sorted(PHYSICAL_INPUTS))
        for name in PHYSICAL_INPUTS:
            self.assertEqual(report["inputs"][name]["state"], NOT_RUN)
        self.assertEqual(report["updater_key_blocks"], [])

    def test_present_inputs_are_reported_without_granting_acceptance(self) -> None:
        directory = self.workspace / "evidence"
        directory.mkdir()
        for name in PHYSICAL_INPUTS:
            (directory / ENVIRONMENT_INPUT_FILES[name]).write_text("{}", encoding="utf-8")
        report = environment_status(
            REPOSITORY, evidence_directory=directory, workspace_root=self.workspace
        )
        # "inputs-present" is not acceptance: the documents still have to build
        # and validate before anything can be verified.
        self.assertEqual(report["status"], "inputs-present")
        self.assertEqual(report["blocked_inputs"], [])
        self.assertNotEqual(report["status"], VERIFIED)

    def test_symlinked_input_is_not_run(self) -> None:
        directory = self.workspace / "evidence"
        directory.mkdir()
        target = self.workspace / "real.json"
        target.write_text("{}", encoding="utf-8")
        (directory / ENVIRONMENT_INPUT_FILES["staple"]).symlink_to(target)
        report = environment_status(
            REPOSITORY, evidence_directory=directory, workspace_root=self.workspace
        )
        self.assertEqual(report["inputs"]["staple"]["state"], NOT_RUN)
        self.assertIn("staple", report["blocked_inputs"])

    def test_updater_key_is_reported_by_path_and_name_only(self) -> None:
        secret = "TOP-SECRET-UPDATER-KEY-BYTES"
        (self.workspace / "cfw-rs.key").write_text(secret, encoding="utf-8")
        report = environment_status(
            REPOSITORY,
            evidence_directory=self.workspace / "missing",
            workspace_root=self.workspace,
        )
        self.assertIn(UPDATER_KEY_BLOCK, report["blocked_inputs"])
        self.assertEqual(len(report["updater_key_blocks"]), 1)
        block = report["updater_key_blocks"][0]
        self.assertEqual(block["name"], "cfw-rs.key")
        self.assertNotIn(secret, canonical_json(report).decode("utf-8"))

    def test_unreadable_workspace_root_fails_closed(self) -> None:
        with self.assertRaises(PublicationError):
            environment_status(
                REPOSITORY,
                evidence_directory=self.workspace,
                workspace_root=self.workspace / "does-not-exist",
            )


class FinalCandidateSelfCheckTests(unittest.TestCase):
    def test_self_check_contract_holds(self) -> None:
        self_check()

    def test_real_workspace_scan_reports_the_live_updater_key_gate(self) -> None:
        # Requirement 8.1 is conditional: *if* updater-key material sits in the
        # workspace the candidate is blocked. Whether this checkout holds a key
        # right now is a transient environment fact - the mandated remediation
        # relocates it to an access-controlled store outside the repository - so
        # this test asserts the invariant instead of the current state.
        from scripts.updater_key_release_blocker import evaluate_workspace

        # Independent path/name-only oracle for what the workspace holds now.
        live = evaluate_workspace(REPOSITORY)
        report = environment_status(REPOSITORY)

        # The reported gate mirrors the real scan exactly, key or no key.
        self.assertEqual(
            [block["path"] for block in report["updater_key_blocks"]],
            [response.detected_path for response in live],
        )
        self.assertEqual(
            UPDATER_KEY_BLOCK in report["blocked_inputs"],
            bool(report["updater_key_blocks"]),
        )
        for block in report["updater_key_blocks"]:
            # Path/name and response flags only; no key bytes are ever carried.
            self.assertEqual(
                set(block),
                {
                    "path",
                    "name",
                    "relocation_target",
                    "exposure_plausible",
                    "rotation_required",
                    "trust_migration_required",
                },
            )
            self.assertTrue(block["path"].endswith(block["name"]))
            self.assertIn(Path(block["name"]).suffix.lower(), {".key", ".pem"})
            self.assertEqual(block["rotation_required"], block["trust_migration_required"])
        # The status is derived from the blocked-input set; it is never acceptance.
        self.assertEqual(
            report["status"], BLOCKED if report["blocked_inputs"] else "inputs-present"
        )
        self.assertNotEqual(report["status"], VERIFIED)

        # An absent workspace key promotes nothing: the physical inputs are still
        # environment-gated, so the candidate stays blocked either way.
        with tempfile.TemporaryDirectory() as tmp:
            gated = environment_status(REPOSITORY, evidence_directory=Path(tmp) / "absent")
        self.assertEqual(gated["status"], BLOCKED)
        self.assertTrue(set(PHYSICAL_INPUTS).issubset(gated["blocked_inputs"]))
        for name in PHYSICAL_INPUTS:
            self.assertEqual(gated["inputs"][name]["state"], NOT_RUN)

        # The scan still fails closed: an unavailable root is never "no key".
        with self.assertRaises(PublicationError):
            environment_status(REPOSITORY, workspace_root=REPOSITORY / "no-such-workspace")


if __name__ == "__main__":
    unittest.main()
