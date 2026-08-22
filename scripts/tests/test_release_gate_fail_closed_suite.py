"""Integrated fail-closed release-gate suite for task 9.13.

This module consumes the shipped release verifiers as black boxes and drives
them, as a single integrated suite, over hermetic fixtures. It intentionally
does not re-cover the per-verifier unit tests (``test_verify_*.py``,
``test_evidence_manifest.py``, ``test_release_secret_material_blocker.py``);
instead
it fills the integration/example gaps this task names:

* migration/build-boundary scans reject a legacy root data plane, a direct
  ``startVPNTunnel`` payload, private Network Extension access, provider-local
  production authority, and an Authority-error data-plane fallback -- and the
  same fixtures are rejected by the *union* of the build-boundary and
  release-authority gates, so no fixture can enable a legacy/data-plane/fallback
  path (Requirements 1.2, 7.3);
* the release-authority gate is exercised end-to-end over a copied real product
  tree: the shipped tree passes, and a single injected fallback or insecure
  override anywhere in the scanned graph fails closed (Requirements 1.2, 7.3);
* pinned toolchain and patch mismatches are rejected when the real pinned inputs
  are copied and a single tool version or patch byte is changed (Requirement
  5.1);
* evidence promotion negatives are rejected -- over-promotion, a skipped
  predecessor, a masked/skipped probe status, and a lower-level report reused
  for a higher level (Requirements 4.1, 7.5);
* unavailable/skipped probes fail closed across the CI-masking audit, the
  build-boundary scan, and the evidence manifest (Requirement 6.5); and
* path/name-only updater-key blocking blocks release on ``.tauri/cfw-rs.key``
  without ever opening or reading the file (Requirement 8.1).

Every fixture is built in a temporary directory; the real repository is only
ever read, never mutated.

Validates: Requirements 1.2, 4.1, 5.1, 6.5, 7.3, 7.5, 8.1
"""

from __future__ import annotations

import builtins
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.evidence_manifest import (
    EvidenceManifestError,
    validate_evidence_manifest,
)
from scripts.release_secret_material_blocker import (
    SecretMaterialReleaseBlock,
    evaluate_workspace,
    format_response,
)
from scripts.verify_ci_no_masking import CiPolicyError, audit_workflow
from scripts.verify_pinned_build_inputs import PinnedInputError, verify as verify_pinned
from scripts.verify_production_boundary_removal import (
    ProductionBoundaryViolation,
    scan_source,
    verify_repository as verify_boundary,
)
from scripts.verify_release_authority_gate import (
    AuthorityGateContractError,
    reject_insecure_or_fallback,
)
from scripts.verify_release_authority_gate import verify_repository as verify_authority

REPO_ROOT = Path(__file__).resolve().parents[2]

PRODUCTION_SWIFT = "native/macos/Sources/CFWPacketTunnel/PacketTunnelProvider.swift"

# One production data-plane / legacy / fallback construct per named category.
# Each must be rejected by at least one release gate; none may pass both gates.
LEGACY_CONSTRUCTS: dict[str, str] = {
    "legacy root data plane": "SMJobBless(kSMDomainSystemLaunchd, label, auth, &error)\n",
    "direct payload": "let payload = try TunnelStartPayloadCodec.encode(descriptor: d)\n",
    "private API": "let fd = socket.fileDescriptor\n",
    "provider-local acceptance authority": "let s = SandboxConfigurationAcceptanceStore(rootURL: r)\n",
    "provider-local lease authority": "let s = CrossProcessEngineLeaseStore(productionPort: 49_373)\n",
    "insecure authority override": "if allowInsecureAuthority { engine.start() }\n",
    "authority-error data-plane fallback": (
        "do { authority.redeem(ticket) } "
        "catch { engine.start() }\n"
    ),
}


def _rejected_by_any_gate(construct: str) -> bool:
    """True when the build-boundary scan OR the authority-gate fallback scan
    rejects a construct placed in a production Swift file."""
    if scan_source(PRODUCTION_SWIFT, construct):
        return True
    try:
        reject_insecure_or_fallback(construct, PRODUCTION_SWIFT)
    except AuthorityGateContractError:
        return True
    return False


# ---------------------------------------------------------------------------
# 1. Migration / build-boundary scans reject every legacy/data-plane/fallback
#    path, and no fixture can enable one.
# ---------------------------------------------------------------------------
class MigrationBuildBoundaryRejectsLegacyPaths(unittest.TestCase):
    def test_no_fixture_can_enable_a_legacy_data_plane_or_fallback_path(self) -> None:
        # The integrated assertion: for every named construct, the union of the
        # build-boundary gate and the release-authority gate fails closed. There
        # is no fixture that slips a legacy/data-plane/fallback path past both.
        for category, construct in LEGACY_CONSTRUCTS.items():
            with self.subTest(category=category):
                self.assertTrue(
                    _rejected_by_any_gate(construct),
                    f"{category!r} was not rejected by any release gate",
                )

    def test_authority_error_fallback_is_a_gate_rejection_not_a_boundary_hit(self) -> None:
        # The data-plane fallback is a control-flow construct the boundary scan
        # does not model; the authority gate is what closes it. Proving this
        # keeps the two gates from being treated as redundant.
        fallback = LEGACY_CONSTRUCTS["authority-error data-plane fallback"]
        self.assertEqual(scan_source(PRODUCTION_SWIFT, fallback), [])
        with self.assertRaisesRegex(AuthorityGateContractError, "fallback"):
            reject_insecure_or_fallback(fallback, PRODUCTION_SWIFT)

    def test_clean_ticket_only_start_passes_both_gates(self) -> None:
        clean = "let start = TicketOnlyStart(ticket: ticket)\n"
        self.assertEqual(scan_source(PRODUCTION_SWIFT, clean), [])
        # Must not raise.
        reject_insecure_or_fallback(clean, PRODUCTION_SWIFT)


# ---------------------------------------------------------------------------
# 2. Release-authority gate, exercised end-to-end over a copied product tree.
# ---------------------------------------------------------------------------
_AUTHORITY_GATE_INPUTS = (
    "native/macos/project.yml",
    "native/macos/Package.swift",
    "native/macos/CFWNative.xcodeproj/project.pbxproj",
    "scripts/build_native_products.sh",
    "native/macos/Sources/CFWNativeBridge/NativeBridgeABI.swift",
    "native/macos/Sources/CFWNativeBridge/NativeEngineOperations.swift",
    "native/macos/Sources/CFWAppleNetwork/HostBridge.swift",
    "native/macos/Sources/CFWProxyAgent/ProxyAgentExecutable.swift",
    "native/macos/Sources/CFWProxyAgent/ProxyAuthorityOwnership.swift",
    "native/macos/Sources/CFWProxyAgent/ProxyAgentService.swift",
    "native/macos/Sources/CFWPacketTunnel/PacketTunnelProvider.swift",
    "native/macos/Sources/CFWPacketTunnel/TunnelTicketStartCoordinator.swift",
    "native/macos/Sources/CFWSharedProtocol/GlobalAuthorityReleaseGate.swift",
    "apps/cfw-tauri-shell/build.rs",
)


def _copy_authority_gate_tree(destination: Path) -> Path:
    for relative in _AUTHORITY_GATE_INPUTS:
        source = REPO_ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return destination


class AuthorityGateWholeTreeIntegration(unittest.TestCase):
    def test_copied_shipped_tree_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            verify_authority(_copy_authority_gate_tree(Path(tmp)))

    def test_injected_data_plane_fallback_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _copy_authority_gate_tree(Path(tmp))
            provider = root / PRODUCTION_SWIFT
            provider.write_text(
                provider.read_text(encoding="utf-8")
                + "\nfunc cfwInjectedFallback() {\n"
                "  do { authority.redeem(ticket) }\n"
                "  catch { engine.start() }\n"
                "}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AuthorityGateContractError, "fallback"):
                verify_authority(root)

    def test_injected_insecure_override_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _copy_authority_gate_tree(Path(tmp))
            build_rs = root / "apps/cfw-tauri-shell/build.rs"
            build_rs.write_text(
                build_rs.read_text(encoding="utf-8")
                + '\nconst OVERRIDE: &str = "CFW_ALLOW_INSECURE_AUTHORITY";\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AuthorityGateContractError, "insecure"):
                verify_authority(root)


# ---------------------------------------------------------------------------
# 3. Pinned toolchain / patch mismatches are rejected (copied real inputs).
# ---------------------------------------------------------------------------
_PINNED_INPUTS = (
    "scripts/pinned_build_inputs.json",
    "scripts/dependency_pins.env",
    "native/macos/Dependencies.lock.json",
    "scripts/build_libbox.sh",
    "scripts/libbox_source_contract.sh",
    "scripts/libbox_module_cache_contract.bash",
    "scripts/build_native_products.sh",
    "scripts/build_unsigned_candidate.sh",
    "scripts/build_signed_candidate.sh",
    "scripts/gatekeeper_assessment.py",
    "scripts/notarization_transaction.py",
    "scripts/dmg_notarization_transaction.py",
    "scripts/release_artifact_set.py",
    "scripts/repository_source_identity.py",
    "scripts/evidence_manifest.py",
    "scripts/harness/physical_collector_trust_policy.json",
    "scripts/harness/physical_evidence_aggregator.py",
    "scripts/harness/physical_machine_identity.py",
    "scripts/harness/physical_collector_request.py",
    "scripts/harness/raw_artifacts.py",
    "scripts/production_release_evidence.py",
    "scripts/publication/final_candidate.py",
    "scripts/publication/orchestrator.py",
    "scripts/publication/sealed_closure.py",
    "scripts/publication/sealed_manifest.py",
    "scripts/release_capability_inventory.json",
    "scripts/release_capability_inventory.py",
    "scripts/sealed_evidence_manifest.py",
    "scripts/validated_candidate_evidence.py",
    "scripts/verify_remote_release.py",
    "scripts/make_dmg.sh",
    "scripts/make_updater_manifest.sh",
    "scripts/release_publication_gate.sh",
    "scripts/release_workspace_secret_gate.sh",
    "scripts/release_secret_material_blocker.py",
    "scripts/release_toolchain_contract.sh",
    "scripts/updater_signing_launcher.py",
    "scripts/validate_updater_archive.py",
    "CHANGELOG.md",
    "scripts/validate_notary_archive.py",
    "scripts/tauri_host_skeleton.sh",
    "scripts/verify_artifact_manifest.py",
    "scripts/verify_candidate_bundle.py",
    "scripts/verify_candidate_bundle.sh",
    "scripts/verify_release_app.sh",
    "scripts/bootstrap_release_toolchain.sh",
    "scripts/install_pinned_tauri_cli.sh",
    "scripts/tauri_cargo_cache_contract.py",
    "scripts/tauri-cli-2.11.4-spin-0.9.9.patch",
    "scripts/xcodegen-2.46.0-installed-resources.patch",
    "crates/cfw-release-verifier/src/main.rs",
    ".github/workflows/ci.yml",
    "native/macos/patches/sing-box-v1.13.15-security-dependencies.patch",
    "native/macos/patches/sing-box-v1.13.15-raw-packet-tun.patch",
    "native/macos/patches/sing-box-v1.13.15-dns-failover.patch",
    "native/macos/patches/sing-box-v1.13.15-endpoint-conflict.patch",
    # Sources the pinned libbox build tags are bound to: the controller block and
    # the projection that injects it require `with_clash_api` in the artifact.
    "crates/cfw-singbox-config/src/controller.rs",
    "crates/cfw-singbox-config/src/projection.rs",
)
_SECURITY_PATCH = "native/macos/patches/sing-box-v1.13.15-security-dependencies.patch"
_PINS_ENV = "scripts/dependency_pins.env"


def _copy_pinned_tree(destination: Path) -> Path:
    for relative in _PINNED_INPUTS:
        source = REPO_ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    manifest = json.loads(
        (REPO_ROOT / "scripts/pinned_build_inputs.json").read_text(encoding="utf-8")
    )
    runtime_tools = manifest.get("runtimeTools")
    if not isinstance(runtime_tools, dict):
        raise AssertionError("shipped runtime-tool source closure is unavailable")
    for tool_name, tool in runtime_tools.items():
        if not isinstance(tool_name, str) or not isinstance(tool, dict):
            raise AssertionError("shipped runtime-tool entry is malformed")
        source_binding = tool.get("sourceBinding")
        if not isinstance(source_binding, dict):
            raise AssertionError(f"shipped runtime-tool {tool_name} source binding is malformed")
        relative = source_binding.get("path")
        if not isinstance(relative, str):
            raise AssertionError(f"shipped runtime-tool {tool_name} source path is malformed")
        source = REPO_ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    lan_peer = manifest.get("packetLanPeer")
    if not isinstance(lan_peer, dict):
        raise AssertionError("shipped packet LAN peer closure is unavailable")
    lan_source = lan_peer.get("source")
    if not isinstance(lan_source, dict):
        raise AssertionError("shipped packet LAN peer source closure is malformed")
    lan_root = lan_source.get("root")
    lan_files = lan_source.get("files")
    if not isinstance(lan_root, str) or not isinstance(lan_files, list):
        raise AssertionError("shipped packet LAN peer source members are malformed")
    lan_paths: set[str] = set()
    for entry in lan_files:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise AssertionError("shipped packet LAN peer source entry is malformed")
        lan_paths.add(f"{lan_root}/{entry['path']}")
    for contract_name in ("buildScript", "verifyScript", "artifact"):
        contract = lan_peer.get(contract_name)
        if not isinstance(contract, dict) or not isinstance(contract.get("path"), str):
            raise AssertionError(f"shipped packet LAN peer {contract_name} is malformed")
        lan_paths.add(contract["path"])
    for relative in sorted(lan_paths):
        source = REPO_ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    endpoint = manifest.get("packetEvidenceEndpoint")
    source_files = endpoint.get("sourceFiles") if isinstance(endpoint, dict) else None
    if not isinstance(source_files, list) or not source_files:
        raise AssertionError("shipped packet endpoint source closure is unavailable")
    for entry in source_files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise AssertionError("shipped packet endpoint source entry is malformed")
        relative = entry["path"]
        if not isinstance(relative, str):
            raise AssertionError("shipped packet endpoint source path is malformed")
        source = REPO_ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    collector = manifest.get("physicalCollectorModule")
    if not isinstance(collector, dict):
        raise AssertionError("shipped physical collector module binding is unavailable")
    for key in ("goModPath", "goSumPath"):
        relative = collector.get(key)
        if not isinstance(relative, str):
            raise AssertionError(f"shipped physical collector {key} is malformed")
        source = REPO_ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    manifest_paths: set[str] = set()
    for section in ("buildScripts", "artifactBindings"):
        entries = manifest.get(section)
        if not isinstance(entries, dict):
            raise AssertionError(f"shipped pinned-input {section} is malformed")
        if any(not isinstance(relative, str) for relative in entries):
            raise AssertionError(f"shipped pinned-input {section} path is malformed")
        manifest_paths.update(entries)
    for relative in sorted(manifest_paths):
        source = REPO_ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return destination


class PinnedToolchainAndPatchMismatchRejected(unittest.TestCase):
    def test_copied_shipped_pins_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            verify_pinned(_copy_pinned_tree(Path(tmp)))

    def test_drifted_toolchain_version_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _copy_pinned_tree(Path(tmp))
            env_path = root / _PINS_ENV
            env_path.write_text(
                env_path.read_text(encoding="utf-8").replace(
                    "GO_VERSION=1.26.6", "GO_VERSION=1.26.4"
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PinnedInputError, "GO_VERSION"):
                verify_pinned(root)

    def test_tampered_patch_byte_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _copy_pinned_tree(Path(tmp))
            patch_path = root / _SECURITY_PATCH
            patch_path.write_bytes(patch_path.read_bytes() + b"\n# tamper\n")
            with self.assertRaisesRegex(PinnedInputError, "file digest"):
                verify_pinned(root)

    def test_missing_patch_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _copy_pinned_tree(Path(tmp))
            (root / _SECURITY_PATCH).unlink()
            with self.assertRaisesRegex(
                PinnedInputError, "missing, a symlink, or has an unsafe path"
            ):
                verify_pinned(root)

    def test_dropped_engine_start_path_build_tag_fails_closed(self) -> None:
        # An artifact built without `with_clash_api` cannot start the engine at
        # all: the patched tree enables the clash API whenever a platform log
        # writer is installed and the daemon always installs one, so the stub
        # constructor fails every `box.New`. Dropping the tag from the shipped
        # pins must therefore be rejected statically.
        with tempfile.TemporaryDirectory() as tmp:
            root = _copy_pinned_tree(Path(tmp))
            for relative in (_PINS_ENV, "scripts/pinned_build_inputs.json"):
                path = root / relative
                path.write_text(
                    path.read_text(encoding="utf-8").replace(",with_clash_api", ""),
                    encoding="utf-8",
                )
            with self.assertRaisesRegex(PinnedInputError, "with_clash_api"):
                verify_pinned(root)


# ---------------------------------------------------------------------------
# 4. Evidence promotion negatives are rejected.
# ---------------------------------------------------------------------------
_COMMIT = "a" * 40
_TOOLCHAIN = "b" * 64
_SIGNED_APP = "c" * 64
_SHA = "d" * 64


def _report(report_id: str, kind: str, bindings: dict[str, str]) -> dict:
    return {
        "id": report_id,
        "kind": kind,
        "path": f"reports/{report_id}.json",
        "sha256": _SHA,
        "status": "passed",
        "bindings": bindings,
    }


def _evidence_fixture() -> dict:
    source = {"commit": _COMMIT}
    ci = {"commit": _COMMIT, "toolchain_sha256": _TOOLCHAIN}
    return {
        "schema_version": 1,
        "manifest_version": "evidence-manifest-v1",
        "identity": {
            "commit": _COMMIT,
            "toolchain_sha256": _TOOLCHAIN,
            "signed_app_sha256": _SIGNED_APP,
        },
        "reports": [
            _report("source-hash", "source_hash", source),
            _report("boundary", "boundary_scan", source),
            _report("unsigned-artifact", "unsigned_artifact", ci),
            _report("deterministic-test", "deterministic_test", ci),
        ],
        "capabilities": [
            {
                "id": "global-authority",
                "highest_level": "Unsigned_CI_Verified",
                "levels": {
                    "Source_Implemented": {"report_ids": ["source-hash", "boundary"]},
                    "Unsigned_CI_Verified": {
                        "report_ids": ["unsigned-artifact", "deterministic-test"]
                    },
                },
            }
        ],
    }


class EvidencePromotionNegativesRejected(unittest.TestCase):
    def test_baseline_fixture_is_valid(self) -> None:
        result = validate_evidence_manifest(_evidence_fixture())
        self.assertEqual(
            result["capabilities"][0]["highest_level"], "Unsigned_CI_Verified"
        )

    def test_over_promotion_beyond_evidence_fails_closed(self) -> None:
        value = _evidence_fixture()
        value["capabilities"][0]["highest_level"] = "Signed_Installed_Verified"
        with self.assertRaisesRegex(EvidenceManifestError, "highest_level"):
            validate_evidence_manifest(value)

    def test_skipped_predecessor_level_fails_closed(self) -> None:
        value = _evidence_fixture()
        del value["capabilities"][0]["levels"]["Source_Implemented"]
        with self.assertRaisesRegex(EvidenceManifestError, "predecessor"):
            validate_evidence_manifest(value)

    def test_lower_level_report_promoted_to_higher_level_fails_closed(self) -> None:
        value = _evidence_fixture()
        # Reuse Source_Implemented reports to satisfy the CI level.
        value["capabilities"][0]["levels"]["Unsigned_CI_Verified"]["report_ids"] = [
            "source-hash",
            "boundary",
        ]
        with self.assertRaisesRegex(EvidenceManifestError, "Source_Implemented report"):
            validate_evidence_manifest(value)


# ---------------------------------------------------------------------------
# 5. Unavailable / skipped probes fail closed across gates.
# ---------------------------------------------------------------------------
_GOOD_WORKFLOW = """name: CI

jobs:
  build:
    runs-on: macos-26
    timeout-minutes: 60
    steps:
      - uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: "1.97.1"
      - uses: actions/setup-node@v5
        with:
          node-version: "24.18.0"
      - name: Assert toolchain
        run: test "$(xcodebuild -version)" = $'Xcode 26.6\\nBuild version 17F113'
      - name: Check formatting
        run: cargo fmt --all -- --check
      - name: Lint
        run: cargo clippy --locked --workspace -- -D warnings
      - name: Swift lint
        run: swift format lint --recursive --strict native/macos/Sources
"""
_PINS = "\n".join(
    [
        "RUST_VERSION=1.97.1",
        "NODE_VERSION=24.18.0",
        "XCODE_VERSION=26.6",
        "XCODE_BUILD_VERSION=17F113",
    ]
)


class UnavailableProbesFailClosed(unittest.TestCase):
    def _write_ci(self, directory: Path, workflow: str) -> tuple[Path, Path]:
        workflow_path = directory / "ci.yml"
        pins_path = directory / "pins.env"
        workflow_path.write_text(workflow, encoding="utf-8")
        pins_path.write_text(_PINS, encoding="utf-8")
        return workflow_path, pins_path

    def test_masked_ci_command_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            masked = _GOOD_WORKFLOW.replace(
                "run: cargo fmt --all -- --check",
                "run: cargo fmt --all -- --check || true",
            )
            workflow_path, pins_path = self._write_ci(Path(tmp), masked)
            with self.assertRaisesRegex(CiPolicyError, r"\|\| true"):
                audit_workflow(workflow_path, pins_path)

    def test_unavailable_boundary_inputs_fail_closed(self) -> None:
        # An empty candidate tree is an unavailable probe surface: the scan must
        # not report "clean" when its required roots are absent.
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ProductionBoundaryViolation, "unavailable"):
                verify_boundary(Path(tmp))

    def test_skipped_evidence_probe_status_fails_closed(self) -> None:
        for skipped in ("skipped", "masked", "timeout", "failed"):
            with self.subTest(status=skipped):
                value = _evidence_fixture()
                value["reports"][0]["status"] = skipped
                with self.assertRaisesRegex(EvidenceManifestError, "status"):
                    validate_evidence_manifest(value)


# ---------------------------------------------------------------------------
# 6. Path/name-only updater-key blocking on .tauri/cfw-rs.key.
# ---------------------------------------------------------------------------
class _ForbidFileOpen:
    """Any attempt to open a file while active fails the test: the updater-key
    blocker must decide by path and name only, never by reading contents."""

    def __enter__(self) -> "_ForbidFileOpen":
        self._original = builtins.open

        def _forbidden(*args: object, **kwargs: object):
            raise AssertionError(f"updater-key blocker opened a file: {args!r}")

        builtins.open = _forbidden  # type: ignore[assignment]
        return self

    def __exit__(self, *exc: object) -> None:
        builtins.open = self._original  # type: ignore[assignment]


class UpdaterKeyPathNameOnlyBlocking(unittest.TestCase):
    _SECRET = "TOP-SECRET-PRIVATE-KEY-BYTES-DO-NOT-READ"

    def test_tauri_key_blocks_release_without_reading_contents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tauri = root / ".tauri"
            tauri.mkdir()
            key = tauri / "cfw-rs.key"
            key.write_text(self._SECRET, encoding="utf-8")

            with _ForbidFileOpen():
                responses = evaluate_workspace(root)

            self.assertTrue(responses, "release must be blocked when a key is present")
            blocker = next(r for r in responses if r.detected_path == str(key))
            self.assertTrue(blocker.block_release)
            self.assertTrue(blocker.relocation_required)
            # The report identifies the file by path and name only; the secret
            # bytes never appear in the rendered response.
            rendered = format_response(blocker)
            self.assertIn("cfw-rs.key", rendered)
            self.assertNotIn(self._SECRET, rendered)

    def test_clean_workspace_does_not_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("no keys here", encoding="utf-8")
            with _ForbidFileOpen():
                self.assertEqual(evaluate_workspace(root), [])

    def test_unavailable_workspace_root_fails_closed(self) -> None:
        with self.assertRaises(SecretMaterialReleaseBlock):
            evaluate_workspace("/nonexistent/release/workspace/root")


if __name__ == "__main__":
    unittest.main()
