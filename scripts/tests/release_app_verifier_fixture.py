"""Anonymized fixture matching the complete observed release verifier transcript."""

from __future__ import annotations

import os


def complete_verifier_stdout(app: str, build_number: str = "40041") -> bytes:
    candidate_root = os.path.dirname(os.path.dirname(app))
    native_products = os.path.join(
        candidate_root, "signing-output", "signed-native-products"
    )
    lines = [
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
        f"identity: 0.4.0 ({build_number}) / arm64 / macOS 15.0+",
        "Mach-O objects: 6",
        "legacy tombstone provenance verified: " + "a" * 64,
        f"Processing: {app}",
        "The validate action worked!",
        (
            "Gatekeeper verified: assessments enabled, "
            "source=Notarized Developer ID, "
            "origin-status=not-reported-by-spctl, "
            "identity-source=codesign-leaf-authority, "
            "authority=Developer ID Application: Release Fixture (YKUPL7Z869)"
        ),
        f"release app verified: {app}",
        (
            "identity: YKUPL7Z869 / com.bill.clashformac / "
            "com.bill.clashformac.packet-tunnel / com.bill.clashformac.proxy-agent"
        ),
        "platform: arm64 / macOS 15.0+",
        f"build number: {build_number}",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


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
    lines = [
        f"{authority}: valid on disk",
        f"{authority}: satisfies its Designated Requirement",
        f"--prepared:{proxy_bundle}",
        f"--validated:{proxy_bundle}",
        f"--prepared:{framework_current}",
        f"--validated:{framework_current}",
        f"{app}: valid on disk",
        f"{app}: satisfies its Designated Requirement",
        f"{extension_bundle}: valid on disk",
        f"{extension_bundle}: satisfies its Designated Requirement",
        f"{proxy_bundle}: valid on disk",
        f"{proxy_bundle}: satisfies its Designated Requirement",
        f"--prepared:{proxy_bundle}",
        f"--validated:{proxy_bundle}",
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
        (
            f"{app}/Contents/Frameworks/CFWNativeBridge.framework/Versions/A/"
            "CFWNativeBridge: valid on disk"
        ),
        (
            f"{app}/Contents/Frameworks/CFWNativeBridge.framework/Versions/A/"
            "CFWNativeBridge: satisfies its Designated Requirement"
        ),
        f"--prepared:{framework_current}",
        f"--validated:{framework_current}",
        f"--prepared:{proxy_bundle}",
        f"--validated:{proxy_bundle}",
        f"{app}: valid on disk",
        f"{app}: satisfies its Designated Requirement",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


__all__ = ["complete_verifier_stderr", "complete_verifier_stdout"]
