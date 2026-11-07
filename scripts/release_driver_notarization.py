"""Recover notarization through a clean executor without rebuilding signed code."""

from __future__ import annotations

import argparse
from pathlib import Path
import re

from scripts.notarization_transaction import EXPECTED_DEPLOYMENT_TARGET
from scripts.release_build_identity import ga_signed_native_products_root
from scripts.release_driver_context import Context, DriverError, USAGE, run_entry, verified_frozen_sources
from scripts.release_signing_preflight import NOTARY_PROFILE


def recover_notarization(context: Context, arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="cfm_release.sh run build")
    parser.add_argument("--recover-notarization-id", required=True)
    parser.add_argument("--adopt-upload-observation", type=Path)
    options = parser.parse_args(arguments)
    observation = options.adopt_upload_observation
    if observation is not None:
        try:
            if not observation.is_absolute() or observation.resolve(strict=True) != observation:
                raise ValueError("not an absolute canonical path")
        except (OSError, ValueError) as error:
            raise DriverError("upload observation must name an absolute canonical file", USAGE) from error

    sources, metadata = verified_frozen_sources(context)
    artifact = context.release.artifact
    toolchain = artifact / "target/toolchains"
    command = [
        "./scripts/run_notarization_transaction.sh",
        "--build-kind", "ga",
        "--build-number", context.release.build,
        "--recover-submission-id", options.recover_notarization_id,
        "--artifact-repository", str(artifact),
        "--toolchain-root", str(toolchain),
        "--native-products", str(ga_signed_native_products_root(artifact)),
        "--notary-profile", NOTARY_PROFILE,
        "--repository-commit", sources.artifact.repository_commit,
        "--release-source-sha256", sources.artifact.release_source_sha256,
        "--deployment-target", EXPECTED_DEPLOYMENT_TARGET,
    ]
    for key, value in metadata.items():
        option = re.sub(r"(?<!^)(?=[A-Z])", "-", key).lower()
        command.extend(["--" + option, value])
    if observation is not None:
        command.extend(["--adopt-upload-observation", str(observation)])
    return run_entry(
        context, "build-recover-notarization", command,
        extra_environment={"CFW_TOOLCHAIN_ROOT": str(toolchain)},
        attach_terminal=True,
    )
