"""One source-pinned production trust-policy boundary for physical capture."""

from __future__ import annotations

from scripts.harness.physical_evidence_aggregator import (
    AGGREGATOR_VERSION,
    SCHEMA_VERSION as AGGREGATE_SCHEMA_VERSION,
)
from scripts.harness.raw_artifacts import (
    COLLECTOR_SIGNATURE_ALGORITHM,
    EVIDENCE_PROFILE,
    RELEASE_TRUST_POLICY_SHA256,
    CollectorTrustPolicy,
    RawArtifactError,
    load_release_trust_policy,
)


class PhysicalCapturePolicyError(ValueError):
    """The checked-in production collector policy is absent or drifted."""


def load_source_pinned_policy() -> CollectorTrustPolicy:
    """Load the only collector policy accepted by production capture code."""

    try:
        policy = load_release_trust_policy()
    except (OSError, RawArtifactError) as error:
        raise PhysicalCapturePolicyError(
            "source-pinned physical collector trust policy is unavailable"
        ) from error
    if (
        not policy.release_source_pinned
        or policy.policy_sha256 != RELEASE_TRUST_POLICY_SHA256
        or policy.algorithm != COLLECTOR_SIGNATURE_ALGORITHM
        or policy.aggregate_schema_version != AGGREGATE_SCHEMA_VERSION
        or policy.aggregator_version != AGGREGATOR_VERSION
        or policy.boot_environment_scheme
        != EVIDENCE_PROFILE["boot_environment_scheme"]
        or policy.machine_identity_scheme
        != EVIDENCE_PROFILE["machine_identity_scheme"]
        or policy.machine_topology != EVIDENCE_PROFILE["machine_topology"]
    ):
        raise PhysicalCapturePolicyError(
            "physical collector trust policy differs from the release-source contract"
        )
    return policy
