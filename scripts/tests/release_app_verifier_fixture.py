"""Anonymized fixture matching the complete observed release verifier transcript.

The line order follows the observed post-notarization transcript of the
signed 0.5.0 Host (seven Mach-O objects; the SwiftUI library adds three
prepared/validated pairs and two codesign result pairs). The sealed and
pre-notary stdout shapes drop stapler's two lines and the Gatekeeper line and
end with the script's fixed notarization line instead; stderr is the same.
"""

from __future__ import annotations

import os

from scripts.release_build_identity import ACTIVE_RELEASE_IDENTITY


GA_BUILD = ACTIVE_RELEASE_IDENTITY.ga_build
SEALED_NOTARIZATION_LINE = (
    "notarization: live Apple checks skipped; the caller binds the sealed evidence"
)
PRE_NOTARY_LINE = "notarization: pre-submission identity gate only"


def _structural_lines(app: str, build_number: str) -> list[str]:
    candidate_root = os.path.dirname(os.path.dirname(app))
    native_products = os.path.join(
        candidate_root, "signing-output", "signed-native-products"
    )
    return [
        *(
            f"artifact manifest verified: {native_products}/{product}"
            for product in (
                "CFWGlobalAuthority",
                "CFWNativeBridge.framework",
                "CFWProxyAgent.app",
                "com.bill.clashformac.packet-tunnel.systemextension",
            )
        ),
        f"candidate bundle verified: {app}",
        f"identity: 0.5.0 ({build_number}) / arm64 / macOS 15.0+",
        "Mach-O objects: 7",
        "legacy tombstone provenance verified: " + "a" * 64,
    ]


def verifier_closing_lines(app: str, build_number: str = GA_BUILD) -> list[str]:
    """The four lines the verifier script itself prints after every check."""

    return [
        f"release app verified: {app}",
        (
            "identity: YKUPL7Z869 / com.bill.clashformac / "
            "com.bill.clashformac.packet-tunnel / com.bill.clashformac.proxy-agent"
        ),
        "platform: arm64 / macOS 15.0+",
        f"build number: {build_number}",
    ]


def _encoded(lines: list[str]) -> bytes:
    return ("\n".join(lines) + "\n").encode("utf-8")


def complete_verifier_stdout(app: str, build_number: str = GA_BUILD) -> bytes:
    """The live transcript: stapler validate and Gatekeeper ran."""

    return _encoded(
        [
            *_structural_lines(app, build_number),
            f"Processing: {app}",
            "The validate action worked!",
            (
                "Gatekeeper verified: assessments enabled, "
                "source=Notarized Developer ID, "
                "origin-status=not-reported-by-spctl, "
                "identity-source=codesign-leaf-authority, "
                "authority=Developer ID Application: Release Fixture (YKUPL7Z869)"
            ),
            *verifier_closing_lines(app, build_number),
        ]
    )


def sealed_verifier_stdout(app: str, build_number: str = GA_BUILD) -> bytes:
    """The transcript of `--sealed-notarization`: no live Apple check ran."""

    return _encoded(
        [
            *_structural_lines(app, build_number),
            *verifier_closing_lines(app, build_number),
            SEALED_NOTARIZATION_LINE,
        ]
    )


def pre_notary_verifier_stdout(app: str, build_number: str = GA_BUILD) -> bytes:
    """The transcript of `--pre-notary`, before any ticket exists."""

    return _encoded(
        [
            *_structural_lines(app, build_number),
            *verifier_closing_lines(app, build_number),
            PRE_NOTARY_LINE,
        ]
    )


def complete_verifier_stderr(app: str) -> bytes:
    authority = app + "/Contents/Library/HelperTools/CFWGlobalAuthority"
    proxy_bundle = app + "/Contents/Library/LoginItems/CFWProxyAgent.app"
    framework_current = (
        app + "/Contents/Frameworks/CFWNativeBridge.framework/Versions/Current/."
    )
    extension_bundle = (
        app
        + "/Contents/Library/SystemExtensions/"
        "com.bill.clashformac.packet-tunnel.systemextension"
    )
    ui_library = app + "/Contents/Frameworks/libCFMNativeDashboard.dylib"
    lines = [
        f"{authority}: valid on disk",
        f"{authority}: satisfies its Designated Requirement",
        f"--prepared:{proxy_bundle}",
        f"--validated:{proxy_bundle}",
        f"--prepared:{ui_library}",
        f"--validated:{ui_library}",
        f"--prepared:{framework_current}",
        f"--validated:{framework_current}",
        f"{app}: valid on disk",
        f"{app}: satisfies its Designated Requirement",
        f"{extension_bundle}: valid on disk",
        f"{extension_bundle}: satisfies its Designated Requirement",
        f"{proxy_bundle}: valid on disk",
        f"{proxy_bundle}: satisfies its Designated Requirement",
        f"{ui_library}: valid on disk",
        f"{ui_library}: satisfies its Designated Requirement",
        f"--prepared:{proxy_bundle}",
        f"--validated:{proxy_bundle}",
        f"--prepared:{ui_library}",
        f"--validated:{ui_library}",
        f"--prepared:{framework_current}",
        f"--validated:{framework_current}",
        f"{app}/Contents/MacOS/clash-for-mac: valid on disk",
        (
            f"{app}/Contents/MacOS/clash-for-mac: "
            "satisfies its Designated Requirement"
        ),
        f"{authority}: valid on disk",
        f"{authority}: satisfies its Designated Requirement",
        f"{app}/Contents/Library/HelperTools/cfw-helper-tombstone: valid on disk",
        (
            f"{app}/Contents/Library/HelperTools/cfw-helper-tombstone: "
            "satisfies its Designated Requirement"
        ),
        f"{proxy_bundle}/Contents/MacOS/CFWProxyAgent: valid on disk",
        (
            f"{proxy_bundle}/Contents/MacOS/CFWProxyAgent: "
            "satisfies its Designated Requirement"
        ),
        f"{extension_bundle}/Contents/MacOS/CFWPacketTunnel: valid on disk",
        (
            f"{extension_bundle}/Contents/MacOS/CFWPacketTunnel: "
            "satisfies its Designated Requirement"
        ),
        f"{ui_library}: valid on disk",
        f"{ui_library}: satisfies its Designated Requirement",
        (
            f"{app}/Contents/Frameworks/CFWNativeBridge.framework/Versions/A/"
            "CFWNativeBridge: valid on disk"
        ),
        (
            f"{app}/Contents/Frameworks/CFWNativeBridge.framework/Versions/A/"
            "CFWNativeBridge: satisfies its Designated Requirement"
        ),
        f"--prepared:{ui_library}",
        f"--validated:{ui_library}",
        f"--prepared:{framework_current}",
        f"--validated:{framework_current}",
        f"--prepared:{proxy_bundle}",
        f"--validated:{proxy_bundle}",
        f"{app}: valid on disk",
        f"{app}: satisfies its Designated Requirement",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


__all__ = [
    "PRE_NOTARY_LINE",
    "SEALED_NOTARIZATION_LINE",
    "complete_verifier_stderr",
    "complete_verifier_stdout",
    "pre_notary_verifier_stdout",
    "sealed_verifier_stdout",
    "verifier_closing_lines",
]
