#!/usr/bin/env python3
"""Unit tests for the immutable sealed outer Evidence Manifest (Task 12.3).

Exercises ``publication.sealed_manifest`` as a black box against Requirements
1.1, 1.2, 4.1, 5.1, 6.5, 7.5, and 8.1: exactly one highest level per capability,
predecessor closure with no level skipping and no masking, content-addressed
report/document/publication bindings, a self-sealing immutable document, and a
fail-closed publication gate with no override.

This module also provides the deterministic fixtures reused by
``test_sealed_manifest_property``.
"""

from __future__ import annotations

import copy
from contextlib import redirect_stderr
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.evidence_manifest import KIND_LEVEL, LEVEL_ORDER, REQUIRED_BINDINGS
from scripts.publication.common import PublicationError, canonical_json
from scripts.publication.final_candidate import (
    REQUIRED_NESTED_CODE,
    TEAM_ID,
    build_final_candidate_binding as _build_final_candidate_binding,
)
from scripts.publication.sealed_closure import build_sealed_closure, derive_supply_chain
from scripts.repository_source_identity import repository_commit
from scripts.release_capability_inventory import (
    CAPABILITY_IDS,
    expected_capability_levels,
    expected_report_contracts,
)
from scripts.publication.sealed_manifest import (
    BLOCKED,
    DEFAULT_EVIDENCE_DIRECTORY,
    DEFAULT_MANIFEST_PATH,
    DOCUMENT_KIND,
    FAILED,
    GATE_ORDER,
    NOT_RUN,
    PASSED,
    REQUIRED_CI_LANES,
    REQUIRED_DOCUMENTS,
    REQUIRED_SOURCE_GATES,
    SEALED,
    SEALED_LEVEL,
    SOURCE_GATE_DOCUMENT,
    SOURCE_GATE_SCHEMA_VERSION,
    _documents,
    authorize_publication_artifacts as _authorize_publication_artifacts,
    build_sealed_evidence_manifest as _build_sealed_evidence_manifest,
    environment_status,
    load_sealed_manifest,
    seal_manifest,
    self_check,
    validate_sealed_evidence_manifest as _validate_sealed_evidence_manifest,
)
from scripts.tests.test_physical_evidence_aggregator import (
    APP_MANIFEST,
    BUILD_NUMBER,
    BUILT_AT,
    PHYSICAL_EVIDENCE_ROOT,
    PHYSICAL_TRUST_POLICY,
    SIGNED_TREE,
    fixture as physical_fixture,
)
from scripts.tests.physical_evidence_fixture import (
    XCFRAMEWORK_MANIFEST_SHA,
    XCFRAMEWORK_SHA,
    final_artifact_hash_manifest,
    fixture_packet_policy,
)
from scripts.tests.gatekeeper_fixture import fixture as gatekeeper_fixture
from scripts.tests.test_sealed_closure import _request as _closure_request

REPOSITORY = Path(__file__).resolve().parent.parent.parent

COMMIT = repository_commit(REPOSITORY)
TOOLCHAIN = "4" * 64
RELEASE_SOURCE = "5" * 64
CAPTURED_AT = "2026-07-22T00:00:00Z"
OBSERVED_AT = "2026-08-01T00:00:00Z"
PINNED = derive_supply_chain(REPOSITORY)["patched_source"]
CAPABILITIES = CAPABILITY_IDS


def build_final_candidate_binding(*args, **kwargs):
    kwargs.setdefault("physical_evidence_root", PHYSICAL_EVIDENCE_ROOT)
    kwargs.setdefault("physical_trust_policy", PHYSICAL_TRUST_POLICY)
    with fixture_packet_policy():
        return _build_final_candidate_binding(*args, **kwargs)


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


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Deterministic fixtures (also used by the property test)
# --------------------------------------------------------------------------


def inner_manifest(
    depth: int,
    *,
    commit: str = COMMIT,
    toolchain: str = TOOLCHAIN,
    signed_app: str = SIGNED_TREE,
    capabilities: tuple[str, ...] = CAPABILITIES,
    salt: str = "",
) -> dict:
    """Build a canonical inner Evidence_Manifest claiming ``LEVEL_ORDER[depth]``."""
    identity = {
        "commit": commit,
        "toolchain_sha256": toolchain,
        "signed_app_sha256": signed_app,
    }
    highest = LEVEL_ORDER[depth]
    reports: list[dict] = []
    selected = tuple(capabilities)
    for contract in expected_report_contracts(highest, capabilities=selected):
        level = KIND_LEVEL[contract["kind"]]
        reports.append(
            {
                **contract,
                "sha256": digest(f"{salt}{contract['id']}"),
                "status": "passed",
                "bindings": {
                    field: identity[field] for field in REQUIRED_BINDINGS[level]
                },
            }
        )
    return {
        "schema_version": 1,
        "manifest_version": "evidence-manifest-v1",
        "identity": identity,
        "reports": reports,
        "capabilities": [
            {
                "id": capability,
                "highest_level": highest,
                "levels": expected_capability_levels(capability, highest),
            }
            for capability in capabilities
        ],
    }


def source_gates(
    *,
    commit: str = COMMIT,
    release_source: str = RELEASE_SOURCE,
) -> dict:
    return {
        "schema_version": SOURCE_GATE_SCHEMA_VERSION,
        "document": SOURCE_GATE_DOCUMENT,
        "attempt_number": 1,
        "attempt_outcome": "completed",
        "prior_attempt_sha256s": [],
        "repository_commit": commit,
        "release_source_sha256": release_source,
        "gates": [
            {
                "id": identifier,
                "script": script,
                "status": "passed",
                "exit_code": 0,
                "log_sha256": digest(f"source-gate-log-{identifier}"),
                "commit": commit,
                "release_source_sha256": release_source,
            }
            for identifier, script in sorted(REQUIRED_SOURCE_GATES.items())
        ]
    }


def ci_lanes(
    *,
    commit: str = COMMIT,
    release_source: str = RELEASE_SOURCE,
    toolchain: str = TOOLCHAIN,
) -> dict:
    return {
        "schema_version": 2,
        "document": "unsigned-ci-lanes-v2",
        "release_source_sha256": release_source,
        "toolchain_sha256": toolchain,
        "lanes": [
            {
                "id": lane,
                "command": f"scripts/ci/{lane}.sh",
                "status": "passed",
                "exit_code": 0,
                "log_sha256": digest(f"ci-lane-log-{lane}"),
                "commit": commit,
                "release_source_sha256": release_source,
                "toolchain_sha256": toolchain,
            }
            for lane in REQUIRED_CI_LANES
        ],
    }


def sealed_closure_document(*, commit: str = COMMIT, signed_app: str = SIGNED_TREE) -> dict:
    request = _closure_request(
        product={"name": "Clash for Mac", "version": "0.4.0", "build_number": BUILD_NUMBER},
        commit=commit,
        signed_app={"sha256": signed_app},
        xcframework={"sha256": XCFRAMEWORK_SHA},
    )
    return build_sealed_closure(REPOSITORY, request, fixture=True)


def _artifact_hash_manifest() -> dict:
    return copy.deepcopy(final_artifact_hash_manifest())


def final_candidate_document(
    workspace: Path, *, commit: str = COMMIT, aggregate: dict | None = None
) -> dict:
    manifest = _artifact_hash_manifest()
    request = {
        "product": {"version": "0.4.0", "build_number": BUILD_NUMBER},
        "commit": commit,
        "final_artifacts": {
            "signed_app_tree_sha256": SIGNED_TREE,
            "app_manifest_sha256": APP_MANIFEST,
            "built_at": BUILT_AT,
            "artifact_hash_manifest": manifest,
        },
        "xcframework": {
            "path": "target/native-dependencies/Libbox.xcframework",
            "xcframework_sha256": XCFRAMEWORK_SHA,
            "manifest_sha256": XCFRAMEWORK_MANIFEST_SHA,
            "upstream_commit": PINNED["upstream_commit"],
            "combined_diff_sha256": PINNED["combined_diff_sha256"],
        },
        "nested_code": [
            {
                "role": role,
                "path": f"Contents/{role}",
                "bundle_id": bundle_id,
                "team_id": TEAM_ID,
                "cdhash": digest(f"cdhash-{role}")[:40],
                "designated_requirement_sha256": digest(f"dr-{role}"),
                "entitlements_sha256": digest(f"ent-{role}"),
                "provisioning": "embedded-profile",
                "libbox_xcframework_sha256": XCFRAMEWORK_SHA,
            }
            for role, bundle_id in sorted(REQUIRED_NESTED_CODE.items())
        ],
        "notarization": {
            "status": "Accepted",
            "id": "notary-12-3",
            "submission_sha256": digest("submission"),
            "target_signed_app_tree_sha256": SIGNED_TREE,
            "captured_at": CAPTURED_AT,
        },
        "staple": {
            "stapled": True,
            "target_signed_app_tree_sha256": SIGNED_TREE,
            "captured_at": CAPTURED_AT,
        },
        "gatekeeper": gatekeeper_fixture(SIGNED_TREE, CAPTURED_AT),
        "physical_evidence": physical_fixture() if aggregate is None else aggregate,
        "post_verification": {"app_tree_sha256": SIGNED_TREE, "observed_at": OBSERVED_AT},
    }
    return build_final_candidate_binding(
        REPOSITORY, request, fixture=True, workspace_root=workspace
    )


def request(
    depth: int,
    workspace: Path,
    *,
    commit: str = COMMIT,
    capabilities: tuple[str, ...] = CAPABILITIES,
    claim_depth: int | None = None,
) -> dict:
    """Build an outer manifest request whose gates authorize exactly ``depth``.

    ``claim_depth`` lets a test claim a level the gates do not authorize.
    """
    aggregate = physical_fixture() if depth >= 2 else None
    return {
        "product": {"version": "0.4.0", "build_number": BUILD_NUMBER},
        "commit": commit,
        "evidence_manifest": inner_manifest(
            depth if claim_depth is None else claim_depth,
            commit=commit,
            capabilities=capabilities,
        ),
        "p0_source": source_gates(commit=commit) if depth >= 0 else None,
        "unsigned_ci": ci_lanes(commit=commit) if depth >= 1 else None,
        "signed_installed": aggregate,
        "sealed_closure": sealed_closure_document(commit=commit) if depth >= 3 else None,
        "final_candidate": (
            final_candidate_document(workspace, commit=commit, aggregate=aggregate)
            if depth >= 3
            else None
        ),
    }


def reseal(document: dict) -> dict:
    """Recompute the self-seal digest so validation must re-derive to reject."""
    body = {key: value for key, value in document.items() if key != "manifest_sha256"}
    document["manifest_sha256"] = hashlib.sha256(canonical_json(body)).hexdigest()
    return document


class _CleanWorkspace(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def build(self, document_request: dict, *, fixture: bool = True) -> dict:
        return build_sealed_evidence_manifest(
            REPOSITORY, document_request, fixture=fixture, workspace_root=self.workspace
        )

    def validate(self, document: dict, **kwargs) -> dict:
        return validate_sealed_evidence_manifest(
            REPOSITORY, document, fixture=True, workspace_root=self.workspace, **kwargs
        )


class SealedManifestRoundTripTests(_CleanWorkspace):
    def test_full_fixture_closure_seals_but_cannot_authorize_publication(self) -> None:
        manifest = self.build(request(3, self.workspace))
        self.assertEqual(manifest["document"], DOCUMENT_KIND)
        self.assertEqual(manifest["visibility"], "private-release-operations")
        self.assertEqual(manifest["status"], SEALED)
        self.assertEqual(manifest["blocked_inputs"], [])
        for gate in GATE_ORDER:
            self.assertEqual(manifest["gates"][gate]["status"], PASSED, gate)
        self.assertEqual(
            [capability["highest_level"] for capability in manifest["capabilities"]],
            [SEALED_LEVEL] * len(CAPABILITIES),
        )
        self.assertFalse(manifest["publication"]["allowed"])
        self.assertFalse(manifest["publication"]["artifacts_permitted"])
        self.assertEqual(manifest["publication"]["refusals"], ["fixture-mode"])
        self.validate(manifest, require_sealed=True)
        with self.assertRaisesRegex(PublicationError, "fixture evidence"):
            authorize_publication_artifacts(
                REPOSITORY, manifest, workspace_root=self.workspace
            )

    def test_omitted_release_capability_is_rejected(self) -> None:
        payload = request(3, self.workspace)
        removed = payload["evidence_manifest"]["capabilities"].pop()["id"]
        payload["evidence_manifest"]["reports"] = [
            report
            for report in payload["evidence_manifest"]["reports"]
            if not report["id"].startswith(f"{removed}-")
        ]
        with self.assertRaisesRegex(PublicationError, "inventory is incomplete"):
            self.build(payload)

    def test_unknown_release_capability_is_rejected(self) -> None:
        payload = request(3, self.workspace)
        payload["evidence_manifest"]["capabilities"][-1]["id"] = (
            "unknown-release-surface"
        )
        with self.assertRaisesRegex(PublicationError, "inventory is incomplete or unknown"):
            self.build(payload)

    def test_fixture_validation_reopens_the_private_aggregate(self) -> None:
        payload = request(3, self.workspace)
        manifest = self.build(payload)
        aggregate_path = REPOSITORY / payload["signed_installed"]["path"]
        original = aggregate_path.read_bytes()
        try:
            aggregate_path.write_bytes(original + b"drift")
            with self.assertRaisesRegex(PublicationError, "size does not match"):
                self.validate(manifest)
        finally:
            aggregate_path.write_bytes(original)

    def test_every_level_binds_its_own_gates(self) -> None:
        for depth, level in enumerate(LEVEL_ORDER):
            with self.subTest(level=level):
                manifest = self.build(request(depth, self.workspace))
                self.assertEqual(
                    manifest["capabilities"][0]["highest_level"], level
                )
                expected_blocked = sorted(
                    gate
                    for gate in GATE_ORDER
                    if manifest["gates"][gate]["status"] != PASSED
                )
                self.assertEqual(manifest["blocked_inputs"], expected_blocked)
                self.assertEqual(
                    manifest["status"], SEALED if not expected_blocked else BLOCKED
                )
                self.validate(manifest)

    def test_blocked_environment_refuses_publication_and_promotion(self) -> None:
        manifest = self.build(request(0, self.workspace))
        self.assertEqual(manifest["status"], BLOCKED)
        self.assertEqual(
            manifest["blocked_inputs"],
            ["final_candidate", "sealed_closure", "signed_installed", "unsigned_ci"],
        )
        self.assertFalse(manifest["publication"]["allowed"])
        self.assertIn("gate:unsigned_ci=not-run", manifest["publication"]["refusals"])
        self.validate(manifest)
        with self.assertRaisesRegex(PublicationError, "environment-gated"):
            self.validate(manifest, require_sealed=True)
        with self.assertRaisesRegex(PublicationError, "fixture evidence"):
            authorize_publication_artifacts(
                REPOSITORY, manifest, workspace_root=self.workspace
            )

    def test_production_authorizer_has_no_fixture_or_policy_injection_api(self) -> None:
        manifest = self.build(request(3, self.workspace))
        with self.assertRaisesRegex(TypeError, "unexpected keyword argument 'fixture'"):
            authorize_publication_artifacts(
                REPOSITORY,
                manifest,
                fixture=True,
                workspace_root=self.workspace,
            )
        with self.assertRaisesRegex(
            TypeError, "unexpected keyword argument 'physical_trust_policy'"
        ):
            authorize_publication_artifacts(
                REPOSITORY,
                manifest,
                physical_trust_policy=PHYSICAL_TRUST_POLICY,
                workspace_root=self.workspace,
            )

    def test_publication_gate_cli_has_no_fixture_option(self) -> None:
        from scripts.sealed_evidence_manifest import parser

        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            parser().parse_args(["publication-gate", "--fixture"])
        self.assertEqual(raised.exception.code, 2)

    def test_production_authorizer_rejects_fixture_evidence_under_configured_policy(
        self,
    ) -> None:
        manifest = self.build(request(3, self.workspace))
        manifest["fixture"] = False
        with patch(
            "scripts.publication.sealed_manifest.current_identity",
            return_value={
                "repositoryCommit": COMMIT,
                "releaseSourceSha256": RELEASE_SOURCE,
            },
        ), self.assertRaisesRegex(PublicationError, "source-pinned policy"):
            authorize_publication_artifacts(
                REPOSITORY, manifest, workspace_root=self.workspace
            )

    def test_bindings_carry_every_required_digest(self) -> None:
        manifest = self.build(request(3, self.workspace))
        bindings = manifest["bindings"]
        self.assertEqual(bindings["commit"], COMMIT)
        self.assertEqual(bindings["release_source_sha256"], RELEASE_SOURCE)
        self.assertEqual(bindings["product"], {"version": "0.4.0", "build_number": BUILD_NUMBER})
        self.assertEqual(bindings["signed_app_tree_sha256"], SIGNED_TREE)
        self.assertEqual(bindings["app_manifest_sha256"], APP_MANIFEST)
        self.assertIn(SIGNED_TREE, bindings["final_artifact_hashes"])
        self.assertEqual(
            bindings["sealed_closure_sha256"], manifest["sealed_closure"]["closure_sha256"]
        )
        self.assertEqual(
            bindings["final_candidate_sha256"], manifest["final_candidate"]["binding_sha256"]
        )
        self.assertEqual(sorted(bindings["installed_runs"]), ["current-macos", "macos15"])
        self.assertEqual(
            bindings["physical_aggregate_sha256"],
            manifest["signed_installed"]["sha256"],
        )
        self.assertEqual(
            bindings["physical_private_archive_sha256"],
            manifest["gates"]["signed_installed"]["evidence"]["private_archive"][
                "binding_sha256"
            ],
        )
        # Every feature document and publication document is bound by digest.
        identifiers = {entry["id"] for entry in manifest["documents"]}
        self.assertTrue(set(REQUIRED_DOCUMENTS).issubset(identifiers))
        self.assertIn("spdx-sbom", identifiers)
        self.assertIn("cyclonedx-sbom", identifiers)
        self.assertIn("corresponding-source-archive", identifiers)

    def test_required_feature_documents_use_neutral_current_contracts(self) -> None:
        self.assertEqual(
            REQUIRED_DOCUMENTS,
            {
                "requirements": "docs/release/macos15-network-extension-migration/requirements.md",
                "design": "docs/release/macos15-network-extension-migration/design.md",
                "tasks": "docs/release/macos15-network-extension-migration/tasks.md",
                "capability-inventory": "scripts/release_capability_inventory.json",
            },
        )
        stale_claims = (
            "current source does not include the mandatory Global Authority",
            "Global Authority is below level 1",
        )
        for relative in REQUIRED_DOCUMENTS.values():
            with self.subTest(document=relative):
                if relative != "scripts/release_capability_inventory.json":
                    self.assertEqual(Path(relative).parts[:2], ("docs", "release"))
                contents = (REPOSITORY / relative).read_text(encoding="utf-8")
                for claim in stale_claims:
                    self.assertNotIn(claim, contents)

    def test_fixture_mode_mismatch_is_rejected(self) -> None:
        manifest = self.build(request(0, self.workspace))
        with self.assertRaisesRegex(PublicationError, "fixture mode mismatch"):
            validate_sealed_evidence_manifest(
                REPOSITORY, manifest, fixture=False, workspace_root=self.workspace
            )

    def test_schema_version_rejects_float_and_bool(self) -> None:
        for invalid in (1.0, True):
            with self.subTest(invalid=invalid):
                manifest = self.build(request(0, self.workspace))
                manifest["schema_version"] = invalid
                reseal(manifest)
                with self.assertRaisesRegex(PublicationError, "unsupported schema/document"):
                    self.validate(manifest)


class SealedManifestCapabilityTests(_CleanWorkspace):
    def test_duplicate_capability_entry_is_rejected(self) -> None:
        payload = request(0, self.workspace)
        payload["evidence_manifest"]["capabilities"].append(
            copy.deepcopy(payload["evidence_manifest"]["capabilities"][0])
        )
        with self.assertRaises(PublicationError):
            self.build(payload)

    def test_conflicting_capability_level_is_rejected(self) -> None:
        manifest = self.build(request(1, self.workspace))
        manifest["capabilities"][0]["highest_level"] = LEVEL_ORDER[0]
        reseal(manifest)
        with self.assertRaisesRegex(PublicationError, "capability levels do not match"):
            self.validate(manifest)

    def test_duplicate_outer_capability_entry_is_rejected(self) -> None:
        manifest = self.build(request(1, self.workspace))
        manifest["capabilities"].append(copy.deepcopy(manifest["capabilities"][0]))
        reseal(manifest)
        with self.assertRaisesRegex(PublicationError, "capability levels do not match"):
            self.validate(manifest)

    def test_skipped_predecessor_level_is_rejected(self) -> None:
        payload = request(1, self.workspace)
        for capability in payload["evidence_manifest"]["capabilities"]:
            del capability["levels"][LEVEL_ORDER[0]]
        with self.assertRaisesRegex(PublicationError, "skips predecessor"):
            self.build(payload)

    def test_blocked_input_cannot_be_promoted(self) -> None:
        # Gates authorize Source_Implemented only; the capability claims installed.
        payload = request(0, self.workspace, claim_depth=2)
        with self.assertRaisesRegex(PublicationError, "unsigned_ci gate is not-run"):
            self.build(payload)

    def test_failed_lower_gate_cannot_be_masked(self) -> None:
        payload = request(1, self.workspace)
        payload["unsigned_ci"]["lanes"][3]["status"] = "masked"
        payload["unsigned_ci"]["lanes"][3]["exit_code"] = 1
        with self.assertRaisesRegex(PublicationError, "unsigned_ci gate is failed"):
            self.build(payload)

    def test_failed_gate_still_seals_a_blocked_manifest(self) -> None:
        payload = request(1, self.workspace, claim_depth=0)
        payload["unsigned_ci"]["lanes"][2]["status"] = "failed"
        payload["unsigned_ci"]["lanes"][2]["exit_code"] = 2
        manifest = self.build(payload)
        self.assertEqual(manifest["gates"]["unsigned_ci"]["status"], FAILED)
        self.assertEqual(manifest["status"], BLOCKED)
        self.assertIn("gate:unsigned_ci=failed", manifest["publication"]["refusals"])
        self.validate(manifest)

    def test_unbound_report_is_rejected(self) -> None:
        payload = request(0, self.workspace)
        payload["evidence_manifest"]["reports"].append(
            {
                "id": "orphan-report",
                "kind": "source_hash",
                "path": "reports/orphan.json",
                "sha256": digest("orphan"),
                "status": "passed",
                "bindings": {"commit": COMMIT},
            }
        )
        with self.assertRaisesRegex(PublicationError, "unbound reports"):
            self.build(payload)

    def test_masked_inner_report_status_is_rejected(self) -> None:
        payload = request(0, self.workspace)
        payload["evidence_manifest"]["reports"][0]["status"] = "skipped"
        with self.assertRaises(PublicationError):
            self.build(payload)

    def test_capability_below_sealed_level_refuses_publication(self) -> None:
        payload = request(3, self.workspace, claim_depth=2)
        manifest = self.build(payload)
        # Every gate passes, so the manifest seals, but a capability that has not
        # reached the sealed level still refuses publication.
        self.assertEqual(manifest["status"], SEALED)
        self.assertFalse(manifest["publication"]["allowed"])
        self.assertIn(
            f"capability:global-authority-peer-authentication={LEVEL_ORDER[2]}",
            manifest["publication"]["refusals"],
        )
        self.validate(manifest)
        with self.assertRaisesRegex(PublicationError, "fixture evidence"):
            authorize_publication_artifacts(
                REPOSITORY, manifest, workspace_root=self.workspace
            )


class SealedManifestBindingTests(_CleanWorkspace):
    def test_source_gate_schema_rejects_float_and_bool(self) -> None:
        for invalid in (1.0, True):
            with self.subTest(invalid=invalid):
                payload = request(0, self.workspace)
                payload["p0_source"]["schema_version"] = invalid
                with self.assertRaisesRegex(PublicationError, "unsupported schema"):
                    self.build(payload)

    def test_source_gate_attempt_outcome_rejects_non_string_values(self) -> None:
        for invalid in (None, False, [], {}):
            with self.subTest(invalid=invalid):
                payload = request(0, self.workspace)
                payload["p0_source"]["attempt_outcome"] = invalid
                with self.assertRaisesRegex(PublicationError, "outcome is unsupported"):
                    self.build(payload)

    def test_inner_manifest_schema_rejects_float_and_bool(self) -> None:
        for invalid in (1.0, True):
            with self.subTest(invalid=invalid):
                payload = request(0, self.workspace)
                payload["evidence_manifest"]["schema_version"] = invalid
                with self.assertRaisesRegex(PublicationError, "schema_version"):
                    self.build(payload)

    def test_stale_source_gate_commit_is_rejected(self) -> None:
        payload = request(0, self.workspace)
        payload["p0_source"]["gates"][0]["commit"] = "b" * 40
        with self.assertRaisesRegex(PublicationError, "different commit"):
            self.build(payload)

    def test_stale_source_gate_release_source_is_rejected(self) -> None:
        payload = request(1, self.workspace)
        payload["p0_source"]["release_source_sha256"] = "e" * 64
        for gate in payload["p0_source"]["gates"]:
            gate["release_source_sha256"] = "e" * 64
        with self.assertRaisesRegex(PublicationError, "different release sources"):
            self.build(payload)

    def test_non_fixture_seal_rechecks_current_clean_release_source(self) -> None:
        payload = request(0, self.workspace)
        with patch(
            "scripts.publication.sealed_manifest.current_identity",
            return_value={
                "repositoryCommit": COMMIT,
                "releaseSourceSha256": RELEASE_SOURCE,
            },
        ) as identity, patch(
            "scripts.publication.sealed_manifest._inner_manifest",
            return_value=({}, [], []),
        ):
            manifest = build_sealed_evidence_manifest(
                REPOSITORY,
                payload,
                fixture=False,
                workspace_root=self.workspace,
            )
        identity.assert_called_once_with(REPOSITORY, require_clean=True)
        self.assertEqual(manifest["bindings"]["release_source_sha256"], RELEASE_SOURCE)

        with patch(
            "scripts.publication.sealed_manifest.current_identity",
            return_value={
                "repositoryCommit": COMMIT,
                "releaseSourceSha256": "e" * 64,
            },
        ), patch(
            "scripts.publication.sealed_manifest._inner_manifest",
            return_value=({}, [], []),
        ), self.assertRaisesRegex(PublicationError, "different release source"):
            build_sealed_evidence_manifest(
                REPOSITORY,
                payload,
                fixture=False,
                workspace_root=self.workspace,
            )

    def test_legacy_source_gate_schema_without_source_binding_is_rejected(self) -> None:
        payload = request(0, self.workspace)
        payload["p0_source"]["schema_version"] = 1
        payload["p0_source"]["document"] = "p0-source-gates-v1"
        payload["p0_source"].pop("repository_commit")
        payload["p0_source"].pop("release_source_sha256")
        for gate in payload["p0_source"]["gates"]:
            gate.pop("release_source_sha256")
        with self.assertRaisesRegex(PublicationError, "field set|schema"):
            self.build(payload)

    def test_stale_ci_toolchain_is_rejected(self) -> None:
        payload = request(1, self.workspace)
        payload["unsigned_ci"]["lanes"][0]["toolchain_sha256"] = "e" * 64
        with self.assertRaisesRegex(PublicationError, "different toolchain"):
            self.build(payload)

    def test_stale_ci_release_source_is_rejected(self) -> None:
        payload = request(1, self.workspace)
        payload["unsigned_ci"]["lanes"][0]["release_source_sha256"] = "e" * 64
        with self.assertRaisesRegex(PublicationError, "release source"):
            self.build(payload)

    def test_legacy_ci_schema_without_source_binding_is_rejected(self) -> None:
        payload = request(1, self.workspace)
        payload["unsigned_ci"]["schema_version"] = 1
        payload["unsigned_ci"]["document"] = "unsigned-ci-lanes-v1"
        payload["unsigned_ci"].pop("release_source_sha256")
        for lane in payload["unsigned_ci"]["lanes"]:
            lane.pop("release_source_sha256")
        with self.assertRaisesRegex(PublicationError, "field set|schema"):
            self.build(payload)

    def test_inner_manifest_toolchain_must_match_ci(self) -> None:
        payload = request(1, self.workspace)
        payload["evidence_manifest"] = inner_manifest(1, toolchain="c" * 64)
        with self.assertRaisesRegex(PublicationError, "different toolchain than the CI lanes"):
            self.build(payload)

    def test_inner_manifest_signed_app_must_match_candidate(self) -> None:
        payload = request(3, self.workspace)
        payload["evidence_manifest"] = inner_manifest(3, signed_app="d" * 64)
        with self.assertRaisesRegex(PublicationError, "different signed app tree"):
            self.build(payload)

    def test_sealed_closure_commit_must_match(self) -> None:
        payload = request(3, self.workspace)
        payload["sealed_closure"] = sealed_closure_document(commit="a" * 40)
        with self.assertRaisesRegex(PublicationError, "different commit"):
            self.build(payload)

    def test_sealed_closure_signed_app_must_match_candidate(self) -> None:
        payload = request(3, self.workspace)
        payload["sealed_closure"] = sealed_closure_document(signed_app="f" * 64)
        with self.assertRaisesRegex(PublicationError, "different signed app trees"):
            self.build(payload)

    def test_final_candidate_must_bind_the_same_aggregate_artifact(self) -> None:
        payload = request(3, self.workspace)
        substituted = copy.deepcopy(payload["signed_installed"])
        source = REPOSITORY / substituted["path"]
        target = source.with_name("aggregate-substituted.json")
        target.write_bytes(source.read_bytes())
        self.addCleanup(target.unlink, missing_ok=True)
        substituted["path"] = target.relative_to(REPOSITORY).as_posix()
        payload["signed_installed"] = substituted
        with self.assertRaisesRegex(PublicationError, "different physical aggregate artifact"):
            self.build(payload)

    def test_lane_may_not_mask_a_nonzero_exit(self) -> None:
        payload = request(1, self.workspace)
        payload["unsigned_ci"]["lanes"][1]["exit_code"] = 1
        with self.assertRaisesRegex(PublicationError, "masks a nonzero exit status"):
            self.build(payload)

    def test_lane_may_not_claim_failure_with_a_successful_exit(self) -> None:
        payload = request(1, self.workspace)
        payload["unsigned_ci"]["lanes"][1]["status"] = "failed"
        with self.assertRaisesRegex(PublicationError, "successful exit status"):
            self.build(payload)

    def test_missing_required_lane_is_rejected(self) -> None:
        payload = request(1, self.workspace)
        payload["unsigned_ci"]["lanes"].pop()
        with self.assertRaisesRegex(PublicationError, "missing required results"):
            self.build(payload)

    def test_unknown_lane_is_rejected(self) -> None:
        payload = request(1, self.workspace)
        payload["unsigned_ci"]["lanes"][0]["id"] = "invented-lane"
        with self.assertRaisesRegex(PublicationError, "unknown results"):
            self.build(payload)

    def test_unknown_result_status_is_rejected(self) -> None:
        payload = request(0, self.workspace)
        payload["p0_source"]["gates"][0]["status"] = "probably-fine"
        with self.assertRaisesRegex(PublicationError, "is not a known result"):
            self.build(payload)

    def test_source_gate_must_name_its_repository_script(self) -> None:
        payload = request(0, self.workspace)
        payload["p0_source"]["gates"][0]["script"] = "scripts/other_gate.sh"
        with self.assertRaisesRegex(PublicationError, "repository gate script"):
            self.build(payload)

    def test_missing_feature_document_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            with self.assertRaisesRegex(PublicationError, "feature document is missing"):
                _documents(
                    Path(empty),
                    {"sealed_closure": {"status": NOT_RUN, "evidence": None}},
                    None,
                )


class SealedManifestImmutabilityTests(_CleanWorkspace):
    def test_tampered_field_breaks_the_self_seal(self) -> None:
        manifest = self.build(request(0, self.workspace))
        manifest["product"]["build_number"] = "40001"
        with self.assertRaisesRegex(PublicationError, "content digest mismatch"):
            self.validate(manifest)

    def test_tampered_self_seal_digest_is_rejected(self) -> None:
        manifest = self.build(request(0, self.workspace))
        manifest["manifest_sha256"] = digest("forged")
        with self.assertRaisesRegex(PublicationError, "content digest mismatch"):
            self.validate(manifest)

    def test_hand_edited_document_digest_is_rejected(self) -> None:
        manifest = self.build(request(0, self.workspace))
        manifest["documents"][0]["sha256"] = digest("swapped-document")
        reseal(manifest)
        with self.assertRaisesRegex(PublicationError, "document bindings do not match"):
            self.validate(manifest)

    def test_hand_edited_status_is_rejected(self) -> None:
        manifest = self.build(request(0, self.workspace))
        manifest["status"] = SEALED
        manifest["blocked_inputs"] = []
        reseal(manifest)
        with self.assertRaisesRegex(PublicationError, "blocked-input set is inconsistent"):
            self.validate(manifest)

    def test_hand_edited_publication_decision_is_rejected(self) -> None:
        manifest = self.build(request(0, self.workspace))
        manifest["publication"] = {
            "allowed": True,
            "artifacts_permitted": True,
            "refusals": [],
        }
        reseal(manifest)
        with self.assertRaisesRegex(PublicationError, "publication decision was hand-edited"):
            self.validate(manifest)

    def test_hand_edited_gate_status_is_rejected(self) -> None:
        manifest = self.build(request(0, self.workspace))
        manifest["gates"]["unsigned_ci"] = {"status": PASSED, "evidence": None}
        reseal(manifest)
        with self.assertRaisesRegex(PublicationError, "gate table does not match"):
            self.validate(manifest)

    def test_hand_edited_binding_is_rejected(self) -> None:
        manifest = self.build(request(0, self.workspace))
        manifest["bindings"]["report_digests"] = [digest("invented")]
        reseal(manifest)
        with self.assertRaisesRegex(PublicationError, "bindings do not match"):
            self.validate(manifest)

    def test_unknown_manifest_field_is_rejected(self) -> None:
        manifest = self.build(request(0, self.workspace))
        manifest["override"] = True
        with self.assertRaises(PublicationError):
            self.validate(manifest)

    def test_seal_refuses_to_overwrite_an_existing_manifest(self) -> None:
        manifest = self.build(request(0, self.workspace))
        with tempfile.TemporaryDirectory() as output:
            path = Path(output) / "sealed-evidence-manifest.json"
            seal_manifest(path, manifest)
            with self.assertRaisesRegex(PublicationError, "refusing to overwrite"):
                seal_manifest(path, manifest)
            loaded = load_sealed_manifest(path)
            self.assertEqual(loaded["manifest_sha256"], manifest["manifest_sha256"])
            self.validate(loaded)

    def test_duplicate_json_field_is_rejected_on_load(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            path = Path(output) / "duplicate.json"
            path.write_text('{"status": "blocked", "status": "sealed"}', encoding="utf-8")
            with self.assertRaisesRegex(PublicationError, "duplicate field"):
                load_sealed_manifest(path)


class SealedManifestUpdaterKeyTests(_CleanWorkspace):
    def test_updater_key_presence_blocks_the_sealed_level(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "cfw-rs.key").write_text("never-read", encoding="utf-8")
            payload = request(3, workspace, claim_depth=2)
            manifest = build_sealed_evidence_manifest(
                REPOSITORY, payload, fixture=True, workspace_root=workspace
            )
            self.assertEqual(manifest["gates"]["release_secret_custody"]["status"], FAILED)
            self.assertEqual(manifest["status"], BLOCKED)
            self.assertIn("release_secret_custody", manifest["blocked_inputs"])
            blocks = manifest["gates"]["release_secret_custody"]["evidence"]["blocks"]
            self.assertEqual(len(blocks), 1)
            self.assertEqual(blocks[0]["name"], "cfw-rs.key")
            # Path/name only: no content is ever recorded.
            self.assertNotIn("contents", json.dumps(blocks))
            self.assertFalse(manifest["publication"]["allowed"])
            with self.assertRaisesRegex(PublicationError, "fixture evidence"):
                authorize_publication_artifacts(
                    REPOSITORY, manifest, workspace_root=workspace
                )

    def test_updater_key_presence_refuses_a_sealed_claim(self) -> None:
        # A workspace key blocks the whole sealed level: the final-candidate
        # binding is invalidated by its own blocker and the custody gate fails,
        # so a Sealed_Release_Evidence claim can never be promoted.
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "release.pem").write_text("never-read", encoding="utf-8")
            with self.assertRaisesRegex(PublicationError, "promotion is refused"):
                build_sealed_evidence_manifest(
                    REPOSITORY, request(3, workspace), fixture=True, workspace_root=workspace
                )
            # A candidate verified in another workspace cannot be reused here.
            elsewhere = request(3, self.workspace)
            with self.assertRaisesRegex(PublicationError, "final candidate binding is invalid"):
                build_sealed_evidence_manifest(
                    REPOSITORY, elsewhere, fixture=True, workspace_root=workspace
                )
            downgraded = request(3, workspace, claim_depth=1)
            manifest = build_sealed_evidence_manifest(
                REPOSITORY, downgraded, fixture=True, workspace_root=workspace
            )
            self.assertEqual(manifest["gates"]["release_secret_custody"]["status"], FAILED)
            self.assertEqual(manifest["gates"]["final_candidate"]["status"], BLOCKED)
            self.assertIn("release_secret_custody", manifest["blocked_inputs"])
            self.assertFalse(manifest["publication"]["allowed"])

    def test_real_workspace_status_reports_the_live_custody_gate(self) -> None:
        # Whether this checkout carries updater-key material is a transient
        # environment fact (Requirement 8.1's mandated remediation moves the key
        # to an access-controlled store outside the repository), so assert the
        # invariant: the custody gate mirrors the live workspace scan by
        # path/name only, and a passing custody gate promotes nothing.
        from scripts.publication.sealed_manifest import (
            COMPOSED_INPUTS,
            RELEASE_SECRET_GATE,
            publication_decision,
        )
        from scripts.release_secret_material_blocker import evaluate_workspace

        # Independent path/name-only oracle for what the workspace holds now.
        live = evaluate_workspace(REPOSITORY)
        report = environment_status(REPOSITORY)

        self.assertEqual(
            [block["path"] for block in report["workspace_secret_blocks"]],
            [response.detected_path for response in live],
        )
        self.assertEqual(
            RELEASE_SECRET_GATE in report["blocked_inputs"],
            bool(report["workspace_secret_blocks"]),
        )
        for block in report["workspace_secret_blocks"]:
            # Path/name and response flags only; no key bytes are ever carried.
            self.assertEqual(
                set(block),
                {
                    "path",
                    "name",
                    "relocation_target",
                    "exposure_plausible",
                    "rotation_required",
                    "credential_kind",
                    "required_trust_action",
                    "updater_trust_migration_required",
                    "notary_profile_reprovision_required",
                    "trust_domain_identification_required",
                },
            )
            self.assertTrue(block["path"].endswith(block["name"]))
            self.assertIn(
                Path(block["name"]).suffix.lower(),
                {".key", ".p8", ".pem"},
            )
        self.assertNotIn("contents", json.dumps(report["workspace_secret_blocks"]))
        self.assertEqual(
            report["status"], BLOCKED if report["blocked_inputs"] else "inputs-present"
        )
        self.assertNotEqual(report["status"], SEALED)

        # An absent workspace key promotes nothing: the composed inputs remain
        # environment-gated, so the manifest status stays blocked either way.
        with tempfile.TemporaryDirectory() as tmp:
            gated = environment_status(
                REPOSITORY,
                evidence_directory=Path(tmp) / "absent",
                manifest_path=Path(tmp) / "absent" / "sealed-evidence-manifest.json",
            )
        self.assertEqual(gated["status"], BLOCKED)
        self.assertTrue(set(COMPOSED_INPUTS).issubset(gated["blocked_inputs"]))
        for name in COMPOSED_INPUTS:
            self.assertEqual(gated["inputs"][name]["state"], NOT_RUN)
        self.assertEqual(gated["manifest_state"], NOT_RUN)
        # ...and a custody gate that passes on its own never allows publication.
        gates = {name: {"status": NOT_RUN, "evidence": None} for name in GATE_ORDER}
        gates[RELEASE_SECRET_GATE] = {"status": PASSED, "evidence": {"blocks": []}}
        decision = publication_decision(gates, [])
        self.assertFalse(decision["allowed"])
        self.assertFalse(decision["artifacts_permitted"])
        self.assertNotIn(f"gate:{RELEASE_SECRET_GATE}=not-run", decision["refusals"])

        # The scan still fails closed: an unavailable root is never "no key".
        with self.assertRaises(PublicationError):
            environment_status(REPOSITORY, workspace_root=REPOSITORY / "no-such-workspace")


class SealedManifestContractTests(unittest.TestCase):
    def test_default_state_is_confined_to_the_active_ga_stage_root(self) -> None:
        self.assertEqual(
            DEFAULT_EVIDENCE_DIRECTORY,
            "target/candidates/0.4.0/ga/40032/stage-inputs/sealed-manifest",
        )
        self.assertEqual(
            DEFAULT_MANIFEST_PATH,
            f"{DEFAULT_EVIDENCE_DIRECTORY}/sealed-evidence-manifest.json",
        )

    def test_self_check_passes(self) -> None:
        self_check()

    def test_gate_order_covers_every_release_gate(self) -> None:
        self.assertEqual(
            GATE_ORDER,
            (
                "p0_source",
                "unsigned_ci",
                "signed_installed",
                "sealed_closure",
                "final_candidate",
                "release_secret_custody",
            ),
        )


if __name__ == "__main__":
    unittest.main()
