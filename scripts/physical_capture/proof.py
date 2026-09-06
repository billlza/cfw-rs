"""Derive proof-v3 material only after an immutable raw observation window."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from scripts.harness.physical_collector_request import (
    PhysicalCollectorRequestError,
    validate_context,
    validate_nonce_response,
)
from scripts.harness.physical_machine_identity import PhysicalMachineIdentityError
from scripts.harness.raw_artifacts import (
    PROOF_SCHEMA_VERSION,
    RawArtifactError,
    parse_proof_binding,
)

from .policy import PhysicalCapturePolicyError, load_source_pinned_policy


class PhysicalCaptureProofError(ValueError):
    """A nonce cannot be bound to the current run or retained observation."""


@dataclass(frozen=True, slots=True)
class ProofMaterial:
    proof: dict[str, Any]
    context: dict[str, Any]
    nonce_issued_at: datetime

    def require_observation_window(
        self,
        *,
        captured_at: datetime,
        completed_at: datetime,
    ) -> None:
        """Require one pre-nonce observation inside the initialized run."""

        initialized_at = datetime.fromisoformat(
            self.context["initialized_at"][:-1] + "+00:00"
        )
        if (
            captured_at.tzinfo is None
            or completed_at.tzinfo is None
            or captured_at.utcoffset() != timezone.utc.utcoffset(captured_at)
            or completed_at.utcoffset() != timezone.utc.utcoffset(completed_at)
            or not initialized_at <= captured_at < completed_at <= self.nonce_issued_at
        ):
            raise PhysicalCaptureProofError(
                "raw observation window is outside the initialized pre-nonce run"
            )


def build_proof_material(
    context: Any,
    nonce_response: Any,
    *,
    runner: Callable[..., Any] | None = None,
    observed_at: datetime | None = None,
) -> ProofMaterial:
    """Reobserve the machine and derive the sole proof-v3 binding."""

    try:
        validated_context = validate_context(context, runner=runner)
        nonce, nonce_issued_at = validate_nonce_response(
            nonce_response, observed_at=observed_at
        )
        policy = load_source_pinned_policy()
    except (
        OSError,
        PhysicalCapturePolicyError,
        PhysicalCollectorRequestError,
        PhysicalMachineIdentityError,
        RawArtifactError,
    ) as error:
        raise PhysicalCaptureProofError(
            "physical proof inputs cannot be revalidated"
        ) from error

    candidate = validated_context["candidate"]
    proof = {
        "schema_version": PROOF_SCHEMA_VERSION,
        "run_id": validated_context["run"]["run_id"],
        "run_nonce": nonce["run_nonce"],
        "candidate": {
            key: candidate[key]
            for key in (
                "version",
                "build_number",
                "app_manifest_sha256",
                "signed_app_tree_sha256",
                "artifact_hash_manifest_sha256",
            )
        },
        "collector": {
            "version": policy.collector_version,
            "source_sha256": policy.collector_source_sha256,
            "executable_sha256": policy.collector_executable_sha256,
            "algorithm": policy.algorithm,
            "key_version": policy.key_version,
        },
    }
    try:
        normalized = parse_proof_binding(proof, "physical proof")
    except RawArtifactError as error:
        raise PhysicalCaptureProofError(
            "derived physical proof does not satisfy proof schema v3"
        ) from error
    if normalized != proof:
        raise PhysicalCaptureProofError("derived physical proof is non-canonical")
    return ProofMaterial(
        proof=copy.deepcopy(proof),
        context=copy.deepcopy(validated_context),
        nonce_issued_at=nonce_issued_at,
    )
