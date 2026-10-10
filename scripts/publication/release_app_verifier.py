"""Closed process adapter for the fixed release-app verifier."""

from __future__ import annotations

from pathlib import Path

from .bounded_process import BoundedProcessError, run_bounded_process
from .common import PublicationError
from .release_contract import native_products_root, signed_app
if __package__ and __package__.startswith("scripts."):
    from scripts.release_build_identity import ACTIVE_RELEASE_IDENTITY
    from scripts.release_app_verifier_output import (
        RELEASE_APP_VERIFIER_OUTPUT_LIMIT,
        RELEASE_APP_VERIFIER_TIMEOUT_SECONDS,
        ReleaseAppVerifierOutputError,
        parse_release_app_verifier_output,
    )
else:
    from release_build_identity import ACTIVE_RELEASE_IDENTITY
    from release_app_verifier_output import (
        RELEASE_APP_VERIFIER_OUTPUT_LIMIT,
        RELEASE_APP_VERIFIER_TIMEOUT_SECONDS,
        ReleaseAppVerifierOutputError,
        parse_release_app_verifier_output,
    )


def verify_release_app(
    *,
    repository: Path,
    environment: dict[str, str],
) -> None:
    """Run the verifier and accept only its typed successful transcript."""

    if not repository.is_absolute():
        raise PublicationError("release app verifier repository must be absolute")
    build_number = ACTIVE_RELEASE_IDENTITY.ga_build
    app = signed_app(repository)
    native_products = native_products_root(repository, build_number)
    command = [
        "/bin/bash",
        "-p",
        str(repository / "scripts/verify_release_app.sh"),
        str(app),
        str(native_products),
        "--context",
        "canonical-native-content",
    ]
    try:
        completed = run_bounded_process(
            command,
            cwd=repository,
            environment=environment,
            timeout=RELEASE_APP_VERIFIER_TIMEOUT_SECONDS,
            output_limit=RELEASE_APP_VERIFIER_OUTPUT_LIMIT,
        )
    except (OSError, BoundedProcessError) as error:
        if isinstance(error, BoundedProcessError) and error.reason == "timeout":
            message = "release app verifier timed out"
        elif isinstance(error, BoundedProcessError) and error.reason == "output-limit":
            message = "release app verifier output exceeded its fixed bound"
        else:
            message = "release app verifier did not complete in its closed process boundary"
        raise PublicationError(message) from error
    if completed.returncode != 0:
        raise PublicationError(
            f"release app verifier failed with exit code {completed.returncode}"
        )
    try:
        parse_release_app_verifier_output(
            completed.stdout,
            completed.stderr,
            expected_app=str(app),
            expected_build_number=build_number,
        )
    except ReleaseAppVerifierOutputError as error:
        raise PublicationError(f"release app verifier output is invalid: {error}") from error
    return None


__all__ = ["verify_release_app"]
