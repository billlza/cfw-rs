"""Closed process adapter for the fixed release-app verifier."""

from __future__ import annotations

from pathlib import Path
from typing import Final

from .bounded_process import BoundedProcessError, run_bounded_process
from .common import PublicationError, escaped_tail
from .release_contract import native_products_root, signed_app
if __package__ and __package__.startswith("scripts."):
    from scripts.release_build_identity import ACTIVE_RELEASE_IDENTITY
    from scripts.release_app_verifier_output import (
        RELEASE_APP_VERIFIER_OUTPUT_LIMIT,
        RELEASE_APP_VERIFIER_TIMEOUT_SECONDS,
        NotarizationCheck,
        ReleaseAppVerifierOutputError,
        parse_release_app_verifier_output,
    )
else:
    from release_build_identity import ACTIVE_RELEASE_IDENTITY
    from release_app_verifier_output import (
        RELEASE_APP_VERIFIER_OUTPUT_LIMIT,
        RELEASE_APP_VERIFIER_TIMEOUT_SECONDS,
        NotarizationCheck,
        ReleaseAppVerifierOutputError,
        parse_release_app_verifier_output,
    )


# A failure keeps the end of each output stream as an escaped note, standard
# error first and standard output last: the end of standard output says why a
# live stapler validation failed, and a caller that keeps only the end of its
# own diagnostics, as the GA collector keeps 4 KiB of a child's standard
# error, still sees the verifier's last lines.
RELEASE_APP_VERIFIER_DIAGNOSTIC_TAIL_BYTES: Final = 1536

# The bounded process reasons raised after the verifier ran carry the output it
# wrote before it was stopped. Every other reason means it never ran, or its
# cleanup failed, and carries none.
_BOUNDED_FAILURES_WITH_OUTPUT: Final = {
    "timeout": "release app verifier timed out",
    "output-limit": "release app verifier output exceeded its fixed bound",
    "descendant": "release app verifier left a descendant process running",
}


def _with_output_notes(
    error: PublicationError, stdout: bytes, stderr: bytes
) -> PublicationError:
    """Attach the verifier's output to ``error`` without trusting its bytes.

    The output is not redacted: the verifier runs in the closed release
    environment, which holds no credentials, and prints only paths, the team
    identifier and code-signing, stapler and Gatekeeper lines.
    """

    for name, output in (("stderr", stderr), ("stdout", stdout)):
        if not output:
            error.add_note(f"release app verifier {name} is empty")
            continue
        tail = escaped_tail(output, RELEASE_APP_VERIFIER_DIAGNOSTIC_TAIL_BYTES)
        error.add_note(
            f"release app verifier {name} ({len(output)} bytes) ends with:\n"
            + tail.rstrip("\n")
        )
    return error


def verify_release_app(
    *,
    repository: Path,
    environment: dict[str, str],
    notarization: NotarizationCheck,
) -> None:
    """Run the verifier and accept only its typed successful transcript.

    SEALED adds ``--sealed-notarization``: the stapler and Gatekeeper checks
    that need Apple's services are skipped, so the caller must bind the
    sealed notarization evidence itself.
    """

    if not repository.is_absolute():
        raise PublicationError("release app verifier repository must be absolute")
    if not isinstance(notarization, NotarizationCheck):
        raise PublicationError("release app verifier notarization check is invalid")
    build_number = ACTIVE_RELEASE_IDENTITY.ga_build
    app = signed_app(repository)
    native_products = native_products_root(repository, build_number)
    command = [
        "/bin/bash",
        "-p",
        str(repository / "scripts/verify_release_app.sh"),
    ]
    if notarization is NotarizationCheck.SEALED:
        command.append("--sealed-notarization")
    command.extend(
        [
            str(app),
            str(native_products),
            "--context",
            "canonical-native-content",
        ]
    )
    try:
        completed = run_bounded_process(
            command,
            cwd=repository,
            environment=environment,
            timeout=RELEASE_APP_VERIFIER_TIMEOUT_SECONDS,
            output_limit=RELEASE_APP_VERIFIER_OUTPUT_LIMIT,
        )
    except (OSError, BoundedProcessError) as error:
        message = (
            _BOUNDED_FAILURES_WITH_OUTPUT.get(error.reason)
            if isinstance(error, BoundedProcessError)
            else None
        )
        if message is None:
            raise PublicationError(
                "release app verifier did not complete in its closed process boundary"
            ) from error
        raise _with_output_notes(
            PublicationError(message), error.stdout, error.stderr
        ) from error
    if completed.returncode != 0:
        raise _with_output_notes(
            PublicationError(
                f"release app verifier failed with exit code {completed.returncode}"
            ),
            completed.stdout,
            completed.stderr,
        )
    try:
        parse_release_app_verifier_output(
            completed.stdout,
            completed.stderr,
            notarization=notarization,
            expected_app=str(app),
            expected_build_number=build_number,
        )
    except ReleaseAppVerifierOutputError as error:
        raise _with_output_notes(
            PublicationError(f"release app verifier output is invalid: {error}"),
            completed.stdout,
            completed.stderr,
        ) from error
    return None


__all__ = ["NotarizationCheck", "verify_release_app"]
