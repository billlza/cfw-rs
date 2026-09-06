"""Strict parser for the fixed macOS release-app verifier transcript."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import os
import re
import unicodedata


class ReleaseAppVerifierOutputError(ValueError):
    """The verifier output did not match the fixed success contract."""


@dataclass(frozen=True)
class ReleaseAppVerifierOutput:
    app: str
    stdout: str
    stderr: str


RELEASE_APP_VERIFIER_OUTPUT_LIMIT = 384 * 1024
RELEASE_APP_VERIFIER_TIMEOUT_SECONDS = 600

_ARTIFACT_PRODUCTS = (
    "CFWGlobalAuthority",
    "CFWNativeBridge.framework",
    "CFWProxyAgent.app",
    "com.bill.clashformac.packet-tunnel.systemextension",
)
_CODESIGN_PREFIXES = ("--prepared:", "--validated:")
_CODESIGN_SUFFIXES = (
    ": valid on disk",
    ": satisfies its Designated Requirement",
)
_IDENTITY_LINE = (
    "identity: YKUPL7Z869 / com.bill.clashformac / "
    "com.bill.clashformac.packet-tunnel / com.bill.clashformac.proxy-agent"
)
_PLATFORM_LINE = "platform: arm64 / macOS 15.0+"
_GATEKEEPER_RE = re.compile(
    r"Gatekeeper verified: assessments enabled, "
    r"source=Notarized Developer ID, "
    r"origin-status=(not-reported-by-spctl|reported-by-spctl), "
    r"identity-source=(codesign-leaf-authority|spctl-origin), "
    r"authority=Developer ID Application: .+ \(YKUPL7Z869\)"
)


def _text(value: bytes, label: str) -> str:
    if not isinstance(value, bytes) or len(value) > RELEASE_APP_VERIFIER_OUTPUT_LIMIT:
        raise ReleaseAppVerifierOutputError(f"{label} exceeds its byte contract")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseAppVerifierOutputError(f"{label} is not UTF-8") from error
    if not text.endswith("\n"):
        raise ReleaseAppVerifierOutputError(f"{label} is not newline terminated")
    for character in text:
        category = unicodedata.category(character)
        if character != "\n" and (category.startswith("C") or category in {"Zl", "Zp"}):
            raise ReleaseAppVerifierOutputError(
                f"{label} contains a forbidden control character"
            )
    if "\n\n" in text:
        raise ReleaseAppVerifierOutputError(f"{label} contains an empty line")
    return text


def _app_from_stdout(
    stdout: str,
    *,
    expected_build_number: str,
    expected_app: str | None,
    expected_app_suffix: str | None,
) -> str:
    if (expected_app is None) == (expected_app_suffix is None):
        raise ReleaseAppVerifierOutputError(
            "exactly one expected app identity must be selected"
        )
    if not isinstance(expected_build_number, str) or not expected_build_number.isdigit():
        raise ReleaseAppVerifierOutputError("expected build number is invalid")
    lines = stdout[:-1].split("\n")
    if len(lines) != 15:
        raise ReleaseAppVerifierOutputError(
            "verifier stdout does not match the fixed 15-line success transcript"
        )
    prefix = "release app verified: "
    if not lines[11].startswith(prefix):
        raise ReleaseAppVerifierOutputError(
            "verifier stdout lacks the fixed release-app success line"
        )
    app = lines[11][len(prefix) :]
    if not os.path.isabs(app) or os.path.normpath(app) != app:
        raise ReleaseAppVerifierOutputError("verifier stdout names a non-canonical app")
    if expected_app is not None:
        if (
            not os.path.isabs(expected_app)
            or os.path.normpath(expected_app) != expected_app
            or app != expected_app
        ):
            raise ReleaseAppVerifierOutputError(
                "verifier stdout names an unexpected release app"
            )
    elif (
        not isinstance(expected_app_suffix, str)
        or not expected_app_suffix.startswith("/")
        or os.path.normpath(expected_app_suffix) != expected_app_suffix
        or not app.endswith(expected_app_suffix)
        or len(app) == len(expected_app_suffix)
    ):
        raise ReleaseAppVerifierOutputError(
            "verifier stdout names a non-final candidate path"
        )

    candidate_root = os.path.dirname(os.path.dirname(app))
    native_products = os.path.join(
        candidate_root, "signing-output", "signed-native-products"
    )
    exact_lines = {
        **{
            index: f"artifact manifest verified: {native_products}/{product}"
            for index, product in enumerate(_ARTIFACT_PRODUCTS)
        },
        4: f"candidate bundle verified: {app}",
        5: f"identity: 0.4.0 ({expected_build_number}) / arm64 / macOS 15.0+",
        6: "Mach-O objects: 6",
        8: f"Processing: {app}",
        9: "The validate action worked!",
        11: f"release app verified: {app}",
        12: _IDENTITY_LINE,
        13: _PLATFORM_LINE,
        14: f"build number: {expected_build_number}",
    }
    if any(lines[index] != expected for index, expected in exact_lines.items()):
        raise ReleaseAppVerifierOutputError(
            "verifier stdout contains a missing or altered success assertion"
        )
    if re.fullmatch(
        r"legacy tombstone provenance verified: [0-9a-f]{64}", lines[7]
    ) is None:
        raise ReleaseAppVerifierOutputError(
            "verifier stdout contains an invalid tombstone assertion"
        )
    gatekeeper = _GATEKEEPER_RE.fullmatch(lines[10])
    if gatekeeper is None or (gatekeeper.group(1), gatekeeper.group(2)) not in {
        ("not-reported-by-spctl", "codesign-leaf-authority"),
        ("reported-by-spctl", "spctl-origin"),
    }:
        raise ReleaseAppVerifierOutputError(
            "verifier stdout contains an invalid Gatekeeper assertion"
        )
    return app


def _contained_subject(subject: str, app: str, *, allow_terminal_dot: bool) -> str:
    if allow_terminal_dot and subject.endswith("/."):
        subject = subject[:-2]
    if not subject or not os.path.isabs(subject) or os.path.normpath(subject) != subject:
        raise ReleaseAppVerifierOutputError(
            "verifier stderr contains a non-canonical codesign subject"
        )
    try:
        contained = os.path.commonpath((app, subject)) == app
    except ValueError as error:
        raise ReleaseAppVerifierOutputError(
            "verifier stderr contains an incomparable codesign subject"
        ) from error
    if not contained:
        raise ReleaseAppVerifierOutputError(
            "verifier stderr contains a non-candidate codesign subject"
        )
    return subject


def _expected_codesign_subjects(
    app: str,
) -> tuple[Counter[str], Counter[str], Counter[str]]:
    framework_current = (
        app + "/Contents/Frameworks/CFWNativeBridge.framework/Versions/Current"
    )
    proxy_bundle = app + "/Contents/Library/LoginItems/CFWProxyAgent.app"
    prepared = Counter({framework_current: 3, proxy_bundle: 3})
    prepared_raw = Counter({framework_current + "/.": 3, proxy_bundle: 3})
    results = Counter(
        {
            app: 2,
            app + "/Contents/Library/HelperTools/CFWGlobalAuthority": 2,
            (
                app
                + "/Contents/Library/SystemExtensions/"
                "com.bill.clashformac.packet-tunnel.systemextension"
            ): 1,
            proxy_bundle: 1,
            app + "/Contents/MacOS/clash-for-mac": 1,
            app + "/Contents/Library/HelperTools/cfw-helper-tombstone": 1,
            proxy_bundle + "/Contents/MacOS/CFWProxyAgent": 1,
            (
                app
                + "/Contents/Library/SystemExtensions/"
                "com.bill.clashformac.packet-tunnel.systemextension/"
                "Contents/MacOS/CFWPacketTunnel"
            ): 1,
            (
                app
                + "/Contents/Frameworks/CFWNativeBridge.framework/"
                "Versions/A/CFWNativeBridge"
            ): 1,
        }
    )
    return prepared, prepared_raw, results


def _validate_codesign_stderr(stderr: str, app: str) -> None:
    lines = stderr[:-1].split("\n")
    if len(lines) != 34:
        raise ReleaseAppVerifierOutputError(
            "verifier stderr does not match the fixed 34-line codesign transcript"
        )
    prepared: Counter[str] = Counter()
    prepared_raw: Counter[str] = Counter()
    validated: Counter[str] = Counter()
    validated_raw: Counter[str] = Counter()
    valid_on_disk: Counter[str] = Counter()
    designated_requirement: Counter[str] = Counter()
    for line in lines:
        if line.startswith(_CODESIGN_PREFIXES[0]):
            raw_subject = line[len(_CODESIGN_PREFIXES[0]) :]
            prepared_raw[raw_subject] += 1
            prepared[
                _contained_subject(
                    raw_subject,
                    app,
                    allow_terminal_dot=True,
                )
            ] += 1
        elif line.startswith(_CODESIGN_PREFIXES[1]):
            raw_subject = line[len(_CODESIGN_PREFIXES[1]) :]
            validated_raw[raw_subject] += 1
            validated[
                _contained_subject(
                    raw_subject,
                    app,
                    allow_terminal_dot=True,
                )
            ] += 1
        elif line.endswith(_CODESIGN_SUFFIXES[0]):
            valid_on_disk[
                _contained_subject(
                    line[: -len(_CODESIGN_SUFFIXES[0])],
                    app,
                    allow_terminal_dot=False,
                )
            ] += 1
        elif line.endswith(_CODESIGN_SUFFIXES[1]):
            designated_requirement[
                _contained_subject(
                    line[: -len(_CODESIGN_SUFFIXES[1])],
                    app,
                    allow_terminal_dot=False,
                )
            ] += 1
        else:
            raise ReleaseAppVerifierOutputError(
                "verifier stderr contains an unknown codesign line"
            )
    expected_prepared, expected_prepared_raw, expected_results = (
        _expected_codesign_subjects(app)
    )
    if (
        prepared != expected_prepared
        or validated != expected_prepared
        or prepared_raw != expected_prepared_raw
        or validated_raw != expected_prepared_raw
    ):
        raise ReleaseAppVerifierOutputError(
            "verifier stderr differs from the exact prepared/validated code set"
        )
    if (
        valid_on_disk != expected_results
        or designated_requirement != expected_results
    ):
        raise ReleaseAppVerifierOutputError(
            "verifier stderr differs from the exact codesign result set"
        )


def parse_release_app_verifier_output(
    stdout: bytes,
    stderr: bytes,
    *,
    expected_build_number: str,
    expected_app: str | None = None,
    expected_app_suffix: str | None = None,
) -> ReleaseAppVerifierOutput:
    """Validate and decode one successful release-app verifier transcript."""

    if (
        not isinstance(stdout, bytes)
        or not isinstance(stderr, bytes)
        or len(stdout) + len(stderr) > RELEASE_APP_VERIFIER_OUTPUT_LIMIT
    ):
        raise ReleaseAppVerifierOutputError(
            "verifier transcript exceeds its combined byte contract"
        )
    stdout_text = _text(stdout, "verifier stdout")
    stderr_text = _text(stderr, "verifier stderr")
    app = _app_from_stdout(
        stdout_text,
        expected_build_number=expected_build_number,
        expected_app=expected_app,
        expected_app_suffix=expected_app_suffix,
    )
    _validate_codesign_stderr(stderr_text, app)
    return ReleaseAppVerifierOutput(app=app, stdout=stdout_text, stderr=stderr_text)


__all__ = [
    "RELEASE_APP_VERIFIER_OUTPUT_LIMIT",
    "RELEASE_APP_VERIFIER_TIMEOUT_SECONDS",
    "ReleaseAppVerifierOutput",
    "ReleaseAppVerifierOutputError",
    "parse_release_app_verifier_output",
]
