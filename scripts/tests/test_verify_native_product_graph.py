from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from scripts.verify_native_product_graph import (
    AGENT_EMBED,
    AUTHORITY_DESIGNATED_REQUIREMENT,
    AUTHORITY_SIGNING_CRITICAL_BLOCK,
    BRIDGE_EMBED,
    DAEMON_EMBED,
    DAEMON_PLIST_EMBED,
    EXTENSION_EMBED,
    MACH_SERVICES,
    NativeProductGraphError,
    verify_daemon_plist,
    verify_generated_project,
    verify_repository,
    verify_signing_order as _verify_signing_order,
    verify_signing_transaction_boundary,
    verify_tauri_embedding,
    verify_xcodegen_spec,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOMBSTONE_EMBED = "Library/HelperTools/cfw-helper-tombstone"


def _valid_embedding() -> dict[str, str]:
    return {
        BRIDGE_EMBED: "../../target/native-products/CFWNativeBridge.framework",
        DAEMON_EMBED: "../../target/native-products/CFWGlobalAuthority",
        DAEMON_PLIST_EMBED: "../../native/macos/Config/com.bill.clashformac.global-authority.plist",
        AGENT_EMBED: "../../target/native-products/CFWProxyAgent.app",
        EXTENSION_EMBED: "../../target/native-products/com.bill.clashformac.packet-tunnel.systemextension",
        TOMBSTONE_EMBED: (
            "../../target/native-products/CFWLegacyTombstone/cfw-helper-tombstone"
        ),
    }


def _valid_daemon_plist() -> dict[str, object]:
    return {
        "Label": "com.bill.clashformac.global-authority",
        "BundleProgram": f"Contents/{DAEMON_EMBED}",
        "UserName": "root",
        "MachServices": {service: True for service in MACH_SERVICES},
    }


def _valid_manifest() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "teamIdentifier": "YKUPL7Z869",
        "nested": [
            {
                "name": "CFWNativeBridge",
                "destination": f"Contents/{BRIDGE_EMBED}",
            },
            {
                "name": "CFWGlobalAuthority",
                "destination": f"Contents/{DAEMON_EMBED}",
                "launchdPlist": f"Contents/{DAEMON_PLIST_EMBED}",
                "machServices": list(MACH_SERVICES),
            },
            {"name": "CFWProxyAgent", "destination": f"Contents/{AGENT_EMBED}"},
            {"name": "CFWPacketTunnel", "destination": f"Contents/{EXTENSION_EMBED}"},
            {
                "name": "CFWLegacyTombstone",
                "destination": f"Contents/{TOMBSTONE_EMBED}",
            },
        ],
        "outer": {"bundleIdentifier": "com.bill.clashformac", "signedLast": True},
    }


# A minimal transaction-owned helper that signs every nested product before the
# outer app with the frozen certificate fingerprint.
_SIGNING_SCRIPT = "\n".join(
    [
        '[[ $# -eq 1 && "$1" == "--transaction-owned" ]]',
        ': "${CFW_SIGNING_ATTEMPT_WORK:?}"',
        f'bridge="$staged_app/Contents/{BRIDGE_EMBED}"',
        f'authority="$staged_app/Contents/{DAEMON_EMBED}"',
        f'proxy_app="$staged_app/Contents/{AGENT_EMBED}"',
        f'packet_extension="$staged_app/Contents/{EXTENSION_EMBED}"',
        'tombstone="$staged_app/Contents/Library/HelperTools/cfw-helper-tombstone"',
        "readonly authority_designated_requirement="
        + repr(AUTHORITY_DESIGNATED_REQUIREMENT),
        AUTHORITY_SIGNING_CRITICAL_BLOCK,
        '--sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$packet_extension"',
        '--sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$tombstone"',
        '--sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$staged_app"',
    ]
)
_SIGNING_CRITICAL_PREFIX_SHA256 = hashlib.sha256(
    _SIGNING_SCRIPT[: _SIGNING_SCRIPT.index(AUTHORITY_SIGNING_CRITICAL_BLOCK)].encode(
        "utf-8"
    )
).hexdigest()
_SIGNING_CRITICAL_BLOCK_END = (
    _SIGNING_SCRIPT.index(AUTHORITY_SIGNING_CRITICAL_BLOCK)
    + len(AUTHORITY_SIGNING_CRITICAL_BLOCK)
)
_SIGNING_CRITICAL_SUFFIX_SHA256 = hashlib.sha256(
    _SIGNING_SCRIPT[_SIGNING_CRITICAL_BLOCK_END:].encode("utf-8")
).hexdigest()


def verify_signing_order(
    manifest: object, files: dict[str, str], signing_script: str
) -> None:
    _verify_signing_order(
        manifest,
        files,
        signing_script,
        critical_prefix_sha256=_SIGNING_CRITICAL_PREFIX_SHA256,
        critical_suffix_sha256=_SIGNING_CRITICAL_SUFFIX_SHA256,
    )


class RepositoryContractTests(unittest.TestCase):
    def test_current_repository_satisfies_the_contract(self) -> None:
        verify_repository(REPO_ROOT)

    def test_xcodegen_requires_bundle_identifier_wrapper_and_fixed_executable(self) -> None:
        project = (REPO_ROOT / "native/macos/project.yml").read_text(encoding="utf-8")
        with self.assertRaisesRegex(NativeProductGraphError, "wrapper product name"):
            verify_xcodegen_spec(
                project.replace(
                    "PRODUCT_NAME: com.bill.clashformac.packet-tunnel",
                    "PRODUCT_NAME: CFWPacketTunnel",
                )
            )
        with self.assertRaisesRegex(NativeProductGraphError, "executable name"):
            verify_xcodegen_spec(
                project.replace(
                    "EXECUTABLE_NAME: CFWPacketTunnel",
                    "EXECUTABLE_NAME: com.bill.clashformac.packet-tunnel",
                )
            )

    def test_generated_project_requires_canonical_wrapper_and_executable(self) -> None:
        pbx = (REPO_ROOT / "native/macos/CFWNative.xcodeproj/project.pbxproj").read_text(
            encoding="utf-8"
        )
        with self.assertRaisesRegex(NativeProductGraphError, "wrapper product"):
            verify_generated_project(
                pbx.replace(
                    'path = "com.bill.clashformac.packet-tunnel.systemextension";',
                    'path = "CFWPacketTunnel.systemextension";',
                )
            )
        with self.assertRaisesRegex(NativeProductGraphError, "executable name"):
            verify_generated_project(
                pbx.replace(
                    "EXECUTABLE_NAME = CFWPacketTunnel;",
                    "EXECUTABLE_NAME = com.bill.clashformac.packet-tunnel;",
                )
            )

    def test_generated_project_rejects_sandbox_incompatible_header_copy_phase(self) -> None:
        pbx = (REPO_ROOT / "native/macos/CFWNative.xcodeproj/project.pbxproj").read_text(
            encoding="utf-8"
        )
        with self.assertRaisesRegex(NativeProductGraphError, "header boundary"):
            verify_generated_project(
                pbx.replace(
                    "SWIFT_INSTALL_OBJC_HEADER = NO;",
                    "SWIFT_INSTALL_OBJC_HEADER = YES;",
                )
            )
        with self.assertRaisesRegex(NativeProductGraphError, "sandbox-incompatible"):
            verify_generated_project(
                pbx + "\nCopy Swift Objective-C Interface Header\n"
            )

    def test_generated_project_requires_swift_package_access_identity(self) -> None:
        pbx = (REPO_ROOT / "native/macos/CFWNative.xcodeproj/project.pbxproj").read_text(
            encoding="utf-8"
        )
        with self.assertRaisesRegex(NativeProductGraphError, "package-access identity"):
            verify_generated_project(
                pbx.replace(
                    "SWIFT_PACKAGE_NAME = macos;",
                    "SWIFT_PACKAGE_NAME = wrong_package;",
                    1,
                )
            )

    def test_generated_project_rejects_extra_swift_package_access_identity(self) -> None:
        pbx = (REPO_ROOT / "native/macos/CFWNative.xcodeproj/project.pbxproj").read_text(
            encoding="utf-8"
        )
        with self.assertRaisesRegex(NativeProductGraphError, "package-access identity"):
            verify_generated_project(pbx + "\nSWIFT_PACKAGE_NAME = macos;\n")

    def test_generated_project_rejects_package_identity_moved_to_target(self) -> None:
        pbx = (REPO_ROOT / "native/macos/CFWNative.xcodeproj/project.pbxproj").read_text(
            encoding="utf-8"
        )
        mutated = pbx.replace("\t\t\t\tSWIFT_PACKAGE_NAME = macos;\n", "", 1)
        mutated = mutated.replace(
            "\t\t\t\tPRODUCT_MODULE_NAME = CFWSharedProtocol;",
            "\t\t\t\tPRODUCT_MODULE_NAME = CFWSharedProtocol;\n"
            "\t\t\t\tSWIFT_PACKAGE_NAME = macos;",
            1,
        )
        with self.assertRaisesRegex(NativeProductGraphError, "package-access identity"):
            verify_generated_project(mutated)

    def test_generated_project_rejects_wrong_project_identity_with_target_padding(self) -> None:
        pbx = (REPO_ROOT / "native/macos/CFWNative.xcodeproj/project.pbxproj").read_text(
            encoding="utf-8"
        )
        mutated = pbx.replace(
            "SWIFT_PACKAGE_NAME = macos;",
            "SWIFT_PACKAGE_NAME = wrong_package;",
            1,
        )
        mutated = mutated.replace(
            "\t\t\t\tPRODUCT_MODULE_NAME = CFWSharedProtocol;",
            "\t\t\t\tPRODUCT_MODULE_NAME = CFWSharedProtocol;\n"
            "\t\t\t\tSWIFT_PACKAGE_NAME = macos;",
            1,
        )
        with self.assertRaisesRegex(NativeProductGraphError, "package-access identity"):
            verify_generated_project(mutated)


class TauriEmbeddingTests(unittest.TestCase):
    def test_complete_embedding_passes(self) -> None:
        verify_tauri_embedding(_valid_embedding())

    def test_missing_daemon_executable_fails_closed(self) -> None:
        embedding = _valid_embedding()
        del embedding[DAEMON_EMBED]
        with self.assertRaisesRegex(NativeProductGraphError, "daemon executable"):
            verify_tauri_embedding(embedding)

    def test_missing_launchd_plist_fails_closed(self) -> None:
        embedding = _valid_embedding()
        del embedding[DAEMON_PLIST_EMBED]
        with self.assertRaisesRegex(NativeProductGraphError, "launchd daemon plist"):
            verify_tauri_embedding(embedding)

    def test_missing_system_extension_fails_closed(self) -> None:
        embedding = _valid_embedding()
        del embedding[EXTENSION_EMBED]
        with self.assertRaisesRegex(NativeProductGraphError, "system extension"):
            verify_tauri_embedding(embedding)


class DaemonPlistTests(unittest.TestCase):
    def test_valid_daemon_plist_passes(self) -> None:
        verify_daemon_plist(_valid_daemon_plist())

    def test_non_root_daemon_fails_closed(self) -> None:
        plist = _valid_daemon_plist()
        plist["UserName"] = "nobody"
        with self.assertRaisesRegex(NativeProductGraphError, "root"):
            verify_daemon_plist(plist)

    def test_wrong_mach_service_fails_closed(self) -> None:
        plist = _valid_daemon_plist()
        plist["MachServices"] = {"com.example.other": True}
        with self.assertRaisesRegex(NativeProductGraphError, "MachServices"):
            verify_daemon_plist(plist)

    def test_extra_mach_service_fails_closed(self) -> None:
        plist = _valid_daemon_plist()
        plist["MachServices"] = {
            **{service: True for service in MACH_SERVICES},
            "com.example.other": True,
        }
        with self.assertRaisesRegex(NativeProductGraphError, "MachServices"):
            verify_daemon_plist(plist)

    def test_data_plane_launchd_surface_fails_closed(self) -> None:
        for forbidden in ("ProgramArguments", "Sockets", "WatchPaths", "QueueDirectories"):
            with self.subTest(forbidden=forbidden):
                plist = _valid_daemon_plist()
                plist[forbidden] = ["anything"]
                with self.assertRaisesRegex(NativeProductGraphError, "forbidden key"):
                    verify_daemon_plist(plist)

    def test_daemon_program_outside_helper_tools_fails_closed(self) -> None:
        plist = _valid_daemon_plist()
        plist["BundleProgram"] = "Contents/MacOS/CFWGlobalAuthority"
        with self.assertRaisesRegex(NativeProductGraphError, "HelperTools"):
            verify_daemon_plist(plist)


class SigningOrderTests(unittest.TestCase):
    def test_valid_manifest_passes(self) -> None:
        verify_signing_order(_valid_manifest(), _valid_embedding(), _SIGNING_SCRIPT)

    def test_critical_hash_identities_require_strings(self) -> None:
        cases = (
            ("prefix", None, _SIGNING_CRITICAL_SUFFIX_SHA256),
            ("suffix", _SIGNING_CRITICAL_PREFIX_SHA256, None),
        )
        for position, prefix, suffix in cases:
            with self.subTest(position=position):
                with self.assertRaisesRegex(
                    NativeProductGraphError,
                    f"critical-{position} identity is malformed",
                ):
                    _verify_signing_order(
                        _valid_manifest(),
                        _valid_embedding(),
                        _SIGNING_SCRIPT,
                        critical_prefix_sha256=prefix,
                        critical_suffix_sha256=suffix,
                    )

    def test_outer_not_signed_last_fails_closed(self) -> None:
        manifest = copy.deepcopy(_valid_manifest())
        manifest["outer"]["signedLast"] = False
        with self.assertRaisesRegex(NativeProductGraphError, "signed last"):
            verify_signing_order(manifest, _valid_embedding(), _SIGNING_SCRIPT)

    def test_missing_nested_component_fails_closed(self) -> None:
        manifest = copy.deepcopy(_valid_manifest())
        manifest["nested"] = [
            entry
            for entry in manifest["nested"]
            if entry["destination"] != f"Contents/{EXTENSION_EMBED}"
        ]
        with self.assertRaisesRegex(NativeProductGraphError, "missing nested components"):
            verify_signing_order(manifest, _valid_embedding(), _SIGNING_SCRIPT)

    def test_daemon_stage_without_launchd_plist_fails_closed(self) -> None:
        manifest = copy.deepcopy(_valid_manifest())
        for entry in manifest["nested"]:
            if entry["destination"] == f"Contents/{DAEMON_EMBED}":
                del entry["launchdPlist"]
        with self.assertRaisesRegex(NativeProductGraphError, "LaunchDaemons plist"):
            verify_signing_order(manifest, _valid_embedding(), _SIGNING_SCRIPT)

    def test_outer_signed_before_nested_fails_closed(self) -> None:
        outer = '--sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$staged_app"'
        inverted = _SIGNING_SCRIPT.replace(outer, "", 1).replace(
            '--sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$bridge"',
            f'{outer}\n--sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$bridge"',
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "before nested component"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), inverted)

    def test_nested_component_not_embedded_fails_closed(self) -> None:
        embedding = _valid_embedding()
        del embedding[BRIDGE_EMBED]
        with self.assertRaisesRegex(NativeProductGraphError, "not embedded"):
            verify_signing_order(_valid_manifest(), embedding, _SIGNING_SCRIPT)

    def test_signing_script_without_outer_sign_fails_closed(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            '--sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$staged_app"',
            '--verify "$staged_app"',
        )
        with self.assertRaisesRegex(NativeProductGraphError, "outer host app"):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_mutable_identity_name_fails_closed(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            '"$CFW_SIGNING_CERTIFICATE_SHA1"', '"$MACOS_SIGN_IDENTITY"'
        )
        with self.assertRaisesRegex(NativeProductGraphError, "mutable signing identity"):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_designated_requirement_drift_fails_closed(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            AUTHORITY_DESIGNATED_REQUIREMENT,
            AUTHORITY_DESIGNATED_REQUIREMENT.replace(
                "com.bill.clashformac.global-authority", "com.example.other"
            ),
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "exact Global Authority designated requirement"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_designated_requirement_must_be_applied_while_signing(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            '  -r="$authority_designated_requirement" \\\n',
            "",
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "does not apply the exact Global Authority"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_designated_requirement_comparison_cannot_be_removed(self) -> None:
        comparison = (
            '/usr/bin/cmp -s -- "$authority_requirement_expected" '
            '"$authority_requirement_actual" ||\n'
            '  die "Global Authority designated requirement mismatch"'
        )
        script = _SIGNING_SCRIPT.replace(
            comparison,
            "/usr/bin/true",
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "verify the exact Global Authority"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_designated_requirement_verification_must_precede_other_signing(self) -> None:
        proxy_sign = '--sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$proxy_app"'
        authority_sign = '--sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$authority"'
        script = _SIGNING_SCRIPT.replace(proxy_sign + "\n", "", 1).replace(
            authority_sign,
            authority_sign + "\n" + proxy_sign,
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "outside the signed nested-code boundary"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_designated_requirement_root_cannot_escape_attempt_work(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            'readonly authority_requirement_root="$attempt_work/authority-requirement"',
            'readonly authority_requirement_root="/tmp/authority-requirement"',
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "verify the exact Global Authority"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_designated_requirement_outputs_must_remain_distinct(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            '-b "$authority_requirement_expected"',
            '-b "$authority_requirement_actual"',
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "verify the exact Global Authority"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_designated_requirement_path_binding_cannot_be_removed(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            'readonly authority_requirement_text="$authority_requirement_root/signed.txt"\n',
            "",
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "verify the exact Global Authority"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_designated_requirement_root_cannot_be_rebound_after_decoy(self) -> None:
        assignment = (
            'readonly authority_requirement_root='
            '"$attempt_work/authority-requirement"'
        )
        script = _SIGNING_SCRIPT.replace(
            assignment,
            assignment + '\nauthority_requirement_root="/tmp/authority-requirement"',
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "reassigns a readonly Global Authority"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_designated_requirement_expected_cannot_be_rebound_to_actual(self) -> None:
        assignment = (
            'readonly authority_requirement_expected='
            '"$authority_requirement_root/expected.csreq"'
        )
        script = _SIGNING_SCRIPT.replace(
            assignment,
            assignment
            + '\nauthority_requirement_expected="$authority_requirement_actual"',
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "reassigns a readonly Global Authority"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_designated_requirement_file_cleanup_cannot_be_removed(self) -> None:
        cleanup = (
            '/bin/rm -- \\\n'
            '  "$authority_requirement_text" \\\n'
            '  "$authority_requirement_expected" \\\n'
            '  "$authority_requirement_actual" >/dev/null 2>&1 ||\n'
            '  die "cannot remove the Global Authority requirement verification files"'
        )
        script = _SIGNING_SCRIPT.replace(
            cleanup,
            "/usr/bin/true",
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "verify the exact Global Authority"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_designated_requirement_root_cleanup_cannot_be_removed(self) -> None:
        cleanup = (
            '/bin/rmdir "$authority_requirement_root" >/dev/null 2>&1 ||\n'
            '  die "cannot remove the private Global Authority requirement verification root"'
        )
        script = _SIGNING_SCRIPT.replace(cleanup, "/usr/bin/true", 1)
        with self.assertRaisesRegex(
            NativeProductGraphError, "verify the exact Global Authority"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_critical_signing_block_cannot_hide_in_uncalled_function(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            AUTHORITY_SIGNING_CRITICAL_BLOCK,
            "unreachable_signing_block() {\n"
            + AUTHORITY_SIGNING_CRITICAL_BLOCK
            + "\n}",
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "critical-prefix identity differs"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_critical_signing_block_cannot_hide_after_inline_function_body(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            AUTHORITY_SIGNING_CRITICAL_BLOCK,
            "unreachable_signing_block() { :\n"
            + AUTHORITY_SIGNING_CRITICAL_BLOCK
            + "\n}",
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "critical-prefix identity differs"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_critical_signing_block_cannot_hide_in_false_branch(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            AUTHORITY_SIGNING_CRITICAL_BLOCK,
            "if false; then\n" + AUTHORITY_SIGNING_CRITICAL_BLOCK + "\nfi",
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "critical-prefix identity differs"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_critical_signing_block_cannot_hide_in_short_circuit_group(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            AUTHORITY_SIGNING_CRITICAL_BLOCK,
            "false && {\n" + AUTHORITY_SIGNING_CRITICAL_BLOCK + "\n}",
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "critical-prefix identity differs"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_critical_signing_block_cannot_hide_after_inline_group_body(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            AUTHORITY_SIGNING_CRITICAL_BLOCK,
            "false && { :\n" + AUTHORITY_SIGNING_CRITICAL_BLOCK + "\n}",
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "critical-prefix identity differs"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_critical_signing_block_cannot_hide_in_process_substitution(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            AUTHORITY_SIGNING_CRITICAL_BLOCK,
            ": <(\n" + AUTHORITY_SIGNING_CRITICAL_BLOCK + "\n)",
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "critical-prefix identity differs"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_critical_signing_block_cannot_hide_in_coprocess(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            AUTHORITY_SIGNING_CRITICAL_BLOCK,
            "coproc hidden_signing {\n"
            + AUTHORITY_SIGNING_CRITICAL_BLOCK
            + "\n}",
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "critical-prefix identity differs"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_critical_signing_block_cannot_follow_early_exit(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            AUTHORITY_SIGNING_CRITICAL_BLOCK,
            "exit 0\n" + AUTHORITY_SIGNING_CRITICAL_BLOCK,
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "critical-prefix identity differs"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_critical_signing_block_cannot_follow_exec_replacement(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            AUTHORITY_SIGNING_CRITICAL_BLOCK,
            "exec /usr/bin/true\n" + AUTHORITY_SIGNING_CRITICAL_BLOCK,
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "critical-prefix identity differs"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_critical_signing_block_cannot_follow_die_redefinition(self) -> None:
        script = _SIGNING_SCRIPT.replace(
            AUTHORITY_SIGNING_CRITICAL_BLOCK,
            "die() {\n  return 0\n}\n" + AUTHORITY_SIGNING_CRITICAL_BLOCK,
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "critical-prefix identity differs"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)

    def test_critical_signing_block_cannot_be_followed_by_authority_resigning(
        self,
    ) -> None:
        resign = "\n".join(
            (
                "/usr/bin/codesign --force --options runtime --timestamp \\",
                "  -r='designated => true' \\",
                '  -s "$CFW_SIGNING_CERTIFICATE_SHA1" "$authority"',
            )
        )
        script = _SIGNING_SCRIPT.replace(
            AUTHORITY_SIGNING_CRITICAL_BLOCK,
            AUTHORITY_SIGNING_CRITICAL_BLOCK + "\n" + resign,
            1,
        )
        with self.assertRaisesRegex(
            NativeProductGraphError, "critical-suffix identity differs"
        ):
            verify_signing_order(_valid_manifest(), _valid_embedding(), script)


class SigningTransactionBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = "\n".join(
            [
                'candidate_freeze.py" freeze',
                'candidate_freeze.py" verify',
                'signing_attempt_transaction.py"',
            ]
        )
        self.transaction = "\n".join(
            [
                'repository / "scripts/run_ga_signing_attempt.sh"',
                '"--transaction-owned"',
            ]
        )

    def test_frozen_transaction_boundary_passes(self) -> None:
        verify_signing_transaction_boundary(
            self.builder, self.transaction, _SIGNING_SCRIPT
        )

    def test_signing_before_freeze_fails_closed(self) -> None:
        builder = self.builder.replace('candidate_freeze.py" freeze\n', "")
        builder += '\ncandidate_freeze.py" freeze\n'
        with self.assertRaisesRegex(NativeProductGraphError, "freeze"):
            verify_signing_transaction_boundary(
                builder, self.transaction, _SIGNING_SCRIPT
            )

    def test_builder_direct_helper_bypass_fails_closed(self) -> None:
        with self.assertRaisesRegex(NativeProductGraphError, "bypass"):
            verify_signing_transaction_boundary(
                self.builder + "\nrun_ga_signing_attempt.sh",
                self.transaction,
                _SIGNING_SCRIPT,
            )

    def test_helper_without_private_entry_fails_closed(self) -> None:
        helper = _SIGNING_SCRIPT.replace("--transaction-owned", "--public", 1)
        with self.assertRaisesRegex(NativeProductGraphError, "ownership"):
            verify_signing_transaction_boundary(
                self.builder, self.transaction, helper
            )


class FailClosedInputTests(unittest.TestCase):
    def test_missing_repository_input_fails_closed(self) -> None:
        with self.assertRaisesRegex(NativeProductGraphError, "unavailable"):
            verify_repository(Path("/nonexistent/repo/root"))


if __name__ == "__main__":
    unittest.main()
