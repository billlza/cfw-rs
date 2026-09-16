"""One source-pinned production trust-policy boundary for physical capture."""

from __future__ import annotations

import hmac
import os
from pathlib import Path
import re
import stat

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
from scripts.physical_capture.execution import (
    CommandSpec,
    ProbeExecutionError,
    run_fixed_command,
)


COLLECTOR_SOURCE_ROOT = Path(__file__).resolve().parents[2] / "tools/physical-collector"
COLLECTOR_SOURCE_DIGEST_TOOL = COLLECTOR_SOURCE_ROOT / "source_digest.sh"
COLLECTOR_SOURCE_DIGEST_RE = re.compile(rb"^[0-9a-f]{64}\n$")
COLLECTOR_SOURCE_DIGEST_TIMEOUT_SECONDS = 60.0


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


def _require_collector_source_digest_tool() -> None:
    try:
        metadata = COLLECTOR_SOURCE_DIGEST_TOOL.lstat()
    except OSError as error:
        raise PhysicalCapturePolicyError(
            "physical collector source-digest tool is unavailable"
        ) from error
    if (
        COLLECTOR_SOURCE_DIGEST_TOOL.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o022
        or not os.access(COLLECTOR_SOURCE_DIGEST_TOOL, os.X_OK)
    ):
        raise PhysicalCapturePolicyError(
            "physical collector source-digest tool has an unsafe identity"
        )


def require_current_collector_source_activation() -> CollectorTrustPolicy:
    """Require the checked-in collector policy to authorize the current closure.

    This is the local source-side precondition. Cloud Run revision and traffic
    identity are independently revalidated by the transport immediately before
    each production request.
    """

    policy = load_source_pinned_policy()
    _require_collector_source_digest_tool()
    try:
        result = run_fixed_command(
            CommandSpec(
                role="physical-collector-source-digest",
                argv=("/bin/bash", str(COLLECTOR_SOURCE_DIGEST_TOOL)),
                cwd=COLLECTOR_SOURCE_ROOT,
                timeout_seconds=COLLECTOR_SOURCE_DIGEST_TIMEOUT_SECONDS,
                stdout_limit=65,
                stderr_limit=4096,
            )
        )
    except ProbeExecutionError as error:
        raise PhysicalCapturePolicyError(
            "physical collector source closure could not be observed"
        ) from error
    if result.stderr or COLLECTOR_SOURCE_DIGEST_RE.fullmatch(result.stdout) is None:
        raise PhysicalCapturePolicyError(
            "physical collector source-digest output is not canonical"
        )
    observed = result.stdout[:-1].decode("ascii")
    if not hmac.compare_digest(observed, policy.collector_source_sha256):
        raise PhysicalCapturePolicyError(
            "physical collector source closure is not activated by the checked-in policy"
        )
    return policy
