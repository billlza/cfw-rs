from __future__ import annotations

import copy
import hashlib
import unittest
from pathlib import Path

from scripts.publication.common import PublicationError, canonical_json, tree_digest
from scripts.publication.sealed_closure import (
    BLOCKED,
    SEALED,
    _cross_consistent_graph,
    build_sbom_documents,
    build_sealed_closure,
    derive_supply_chain,
    validate_sealed_closure,
)

REPOSITORY = Path(__file__).resolve().parent.parent.parent

# The four design-pinned sing-box patches. The supply-chain test hashes these
# files itself, so the derived patch closure is bound to the patch bytes in the
# repository rather than to the pin table the production code already reads.
PATCH_PATHS = {
    "security": "native/macos/patches/sing-box-v1.13.15-security-dependencies.patch",
    "raw_packet": "native/macos/patches/sing-box-v1.13.15-raw-packet-tun.patch",
    "dns_failover": "native/macos/patches/sing-box-v1.13.15-dns-failover.patch",
    "endpoint_conflict": "native/macos/patches/sing-box-v1.13.15-endpoint-conflict.patch",
}
# Authoritative digest of the raw-packet TUN patch with cleanup ownership retained
# until Close succeeds. Kept as a literal because hashing the file alone would
# still pass if the patch regressed and the pins were recomputed to match.
EXPECTED_RAW_PACKET_PATCH_SHA256 = (
    "3a40130eb30f471bd5ab17cfce289f43e3600bdadcfc1aadab25a68f9703e124"
)
# The combined diff is the full-object-ID digest of the whole working-tree diff
# of the patched sing-box checkout
# (scripts/libbox_source_contract.sh::libbox_combined_diff_sha256), which cannot
# be recomputed from the patch files alone. A pinned literal is therefore the
# only form of this assertion that still fails when a pin drifts.
EXPECTED_COMBINED_DIFF_SHA256 = (
    "1ad890f1e17a9ff9af3369bef3329650b4ac0e0fc4f33a4840c5911f1e6a2a7f"
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _file_sha256(relative: str) -> str:
    path = REPOSITORY / relative
    if not path.is_file():
        raise AssertionError(f"pinned patch file is missing: {relative}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _component(identifier: str, ecosystem: str, license_expression: str = "MIT") -> dict:
    return {
        "id": identifier,
        "name": identifier,
        "version": "1.0.0",
        "ecosystem": ecosystem,
        "scope": "runtime",
        "purl": f"pkg:{ecosystem}/{identifier}@1.0.0",
        "license_expression": license_expression,
        "copyright_text": f"Copyright {identifier} authors",
        "license_files": [
            {"path": f"licenses/{ecosystem}/{identifier}/LICENSE", "sha256": _sha(identifier + "-lic")}
        ],
        "source_path": f"source/{ecosystem}/{identifier}",
        "source_sha256": _sha(identifier + "-src"),
    }


def _build_tool(identifier: str) -> dict:
    return {
        "id": identifier,
        "name": identifier,
        "version": "1.0.0",
        "ecosystem": "toolchain",
        "scope": "toolchain",
        "purl": f"pkg:generic/{identifier}@1.0.0",
        "distribution": "external-build-tool-not-distributed",
        "license_reference": "Apache-2.0",
        "license_evidence": [{"name": "LICENSE", "sha256": _sha(identifier + "-tool-lic")}],
        "identity_metadata_sha256": _sha(identifier + "-meta"),
        "executables": [{"name": "exe-0-tool", "size": 1024, "sha256": _sha(identifier + "-exe")}],
    }


def _sbom_graph() -> dict:
    return {
        "components": [
            _component("application-clash-for-mac", "application", "GPL-3.0-or-later"),
            _component("cargo-serde", "cargo"),
            _component("native-libbox", "native"),
        ],
        "build_tools": [_build_tool("go")],
        "relationships": [
            {"source": "application-clash-for-mac", "target": "cargo-serde", "type": "DEPENDS_ON"},
            {"source": "application-clash-for-mac", "target": "native-libbox", "type": "CONTAINS"},
            {"source": "go", "target": "native-libbox", "type": "BUILD_DEPENDENCY_OF"},
        ],
    }


def _artifact_manifest() -> dict:
    entries = sorted(
        (
            {"path": "artifacts/libbox.xcframework.manifest.json", "sha256": _sha("art-1")},
            {"path": "artifacts/signed-app-manifest.json", "sha256": _sha("art-2")},
        ),
        key=lambda item: item["path"],
    )
    return {"entries": entries, "sha256": tree_digest(entries)}


def _request(**overrides) -> dict:
    request = {
        "product": {"name": "Clash for Mac", "version": "0.4.0", "build_number": "40000"},
        "commit": _sha("commit")[:40],
        "sbom": _sbom_graph(),
        "ccs": {"sha256": _sha("ccs-tree"), "archive_sha256": _sha("ccs-archive")},
        "modification_notice": {"sha256": _sha("modnotice")},
        "third_party_notices": {"sha256": _sha("thirdparty")},
        "artifact_hash_manifest": _artifact_manifest(),
        "signed_app": {"sha256": _sha("signed-app")},
        "xcframework": {"sha256": _sha("xcframework")},
        "vulnerability_reports": [
            {
                "id": "govulncheck-libbox",
                "tool": "govulncheck",
                "tool_version": "v1.6.0",
                "target": "libbox-macos-arm64",
                "sha256": _sha("vuln"),
            }
        ],
    }
    request.update(overrides)
    return request


class DeriveSupplyChainTests(unittest.TestCase):
    def test_binds_repository_toolchain_and_patched_source(self) -> None:
        supply_chain = derive_supply_chain(REPOSITORY)
        self.assertEqual(supply_chain["toolchain_versions"]["rust"], "1.97.1")
        self.assertEqual(supply_chain["toolchain_versions"]["go"], "1.26.6")
        self.assertEqual(
            supply_chain["patched_source"]["upstream_commit"],
            "3708fa18766cda1f11b77f6ed9c7bd61688f17df",
        )
        patched_source = supply_chain["patched_source"]

        # The bound patch closure must be exactly the four patch files that live
        # in this repository, hashed from their bytes here.
        on_disk = {name: _file_sha256(path) for name, path in PATCH_PATHS.items()}
        self.assertEqual(len(patched_source["patch_digests"]), 4)
        self.assertEqual(patched_source["patch_digests"], sorted(on_disk.values()))
        # ...and the raw-packet patch must be the corrected revision, not the
        # truncated-hunk one that silently dropped four test helpers.
        self.assertEqual(on_disk["raw_packet"], EXPECTED_RAW_PACKET_PATCH_SHA256)

        self.assertEqual(
            patched_source["combined_diff_sha256"], EXPECTED_COMBINED_DIFF_SHA256
        )
        # The combined diff must never collapse to a single patch digest.
        self.assertNotIn(
            patched_source["combined_diff_sha256"], patched_source["patch_digests"]
        )
        # A rejected/legacy digest may never be bound as a live patch digest.
        self.assertNotIn(
            patched_source["combined_diff_sha256"],
            patched_source["rejected_patch_digests"],
        )
        self.assertFalse(
            set(patched_source["patch_digests"])
            & set(patched_source["rejected_patch_digests"])
        )

    def test_missing_tool_inputs_fail_closed(self) -> None:
        from scripts.publication import sealed_closure

        original = sealed_closure.pinned.verify_source_contract

        def _raise(_repository):
            raise sealed_closure.pinned.PinnedInputError("dependency_pins.env is missing GO_VERSION")

        sealed_closure.pinned.verify_source_contract = _raise
        try:
            with self.assertRaisesRegex(PublicationError, "pinned supply-chain inputs failed"):
                derive_supply_chain(REPOSITORY)
        finally:
            sealed_closure.pinned.verify_source_contract = original


class SealedClosureRoundTripTests(unittest.TestCase):
    def test_full_inputs_produce_sealed_closure(self) -> None:
        closure = build_sealed_closure(REPOSITORY, _request(), fixture=True)
        self.assertEqual(closure["status"], SEALED)
        self.assertEqual(closure["blocked_inputs"], [])
        validate_sealed_closure(REPOSITORY, closure, fixture=True, require_sealed=True)

    def test_missing_physical_inputs_block_and_cannot_be_promoted(self) -> None:
        for missing in ("signed_app", "xcframework", "vulnerability_reports"):
            closure = build_sealed_closure(REPOSITORY, _request(**{missing: None}), fixture=True)
            self.assertEqual(closure["status"], BLOCKED)
            self.assertIn(missing, closure["blocked_inputs"])
            # A blocked closure still validates structurally...
            validate_sealed_closure(REPOSITORY, closure, fixture=True)
            # ...but can never be promoted to sealed.
            with self.assertRaisesRegex(PublicationError, "environment-gated"):
                validate_sealed_closure(REPOSITORY, closure, fixture=True, require_sealed=True)

    def test_fixture_mode_mismatch_is_rejected(self) -> None:
        closure = build_sealed_closure(REPOSITORY, _request(), fixture=True)
        with self.assertRaisesRegex(PublicationError, "fixture mode mismatch"):
            validate_sealed_closure(REPOSITORY, closure, fixture=False)


class SealedClosureRejectionTests(unittest.TestCase):
    def _base(self) -> dict:
        return build_sealed_closure(REPOSITORY, _request(), fixture=True)

    def test_schema_version_rejects_float_and_bool(self) -> None:
        for invalid in (1.0, True):
            with self.subTest(invalid=invalid):
                closure = self._base()
                closure["schema_version"] = invalid
                with self.assertRaisesRegex(PublicationError, "unsupported schema/document"):
                    validate_sealed_closure(REPOSITORY, closure, fixture=True)

    def test_unreviewed_license_node_rejected(self) -> None:
        graph = _sbom_graph()
        graph["components"][1]["license_expression"] = "NOASSERTION"
        with self.assertRaises(PublicationError):
            build_sealed_closure(REPOSITORY, _request(sbom=graph), fixture=True)

    def test_spdx_hash_mismatch_rejected(self) -> None:
        closure = self._base()
        closure["sbom"]["spdx_sha256"] = _sha("tampered")
        closure["closure_sha256"] = hashlib.sha256(
            canonical_json({k: v for k, v in closure.items() if k != "closure_sha256"})
        ).hexdigest()
        with self.assertRaisesRegex(PublicationError, "SBOM digests"):
            validate_sealed_closure(REPOSITORY, closure, fixture=True)

    def test_artifact_hash_manifest_mismatch_rejected(self) -> None:
        request = _request()
        request["artifact_hash_manifest"]["sha256"] = _sha("wrong")
        with self.assertRaisesRegex(PublicationError, "artifact hash manifest digest"):
            build_sealed_closure(REPOSITORY, request, fixture=True)

    def test_tampered_supply_chain_rejected(self) -> None:
        closure = self._base()
        closure["supply_chain"]["patched_source"]["combined_diff_sha256"] = _sha("evil")
        closure["closure_sha256"] = hashlib.sha256(
            canonical_json({k: v for k, v in closure.items() if k != "closure_sha256"})
        ).hexdigest()
        with self.assertRaisesRegex(PublicationError, "supply chain does not bind"):
            validate_sealed_closure(REPOSITORY, closure, fixture=True)

    def test_inconsistent_package_graph_rejected(self) -> None:
        graph = _sbom_graph()
        graph["relationships"].append(
            {"source": "cargo-serde", "target": "absent-component", "type": "DEPENDS_ON"}
        )
        with self.assertRaises(PublicationError):
            build_sealed_closure(REPOSITORY, _request(sbom=graph), fixture=True)

    def test_missing_source_input_rejected(self) -> None:
        request = _request()
        request["ccs"] = {"sha256": _sha("only-tree")}  # missing archive_sha256
        with self.assertRaises(PublicationError):
            build_sealed_closure(REPOSITORY, request, fixture=True)

    def test_vulnerability_report_wrong_tool_rejected(self) -> None:
        request = _request()
        request["vulnerability_reports"][0]["tool"] = "cargo-audit"
        with self.assertRaisesRegex(PublicationError, "not a govulncheck report"):
            build_sealed_closure(REPOSITORY, request, fixture=True)

    def test_vulnerability_report_missing_libbox_target_rejected(self) -> None:
        request = _request()
        request["vulnerability_reports"][0]["target"] = "some-other-target"
        with self.assertRaisesRegex(PublicationError, "libbox scan target"):
            build_sealed_closure(REPOSITORY, request, fixture=True)

    def test_closure_digest_tamper_rejected(self) -> None:
        closure = self._base()
        closure["commit"] = _sha("different-commit")[:40]
        with self.assertRaisesRegex(PublicationError, "content digest mismatch"):
            validate_sealed_closure(REPOSITORY, closure, fixture=True)

    def test_blocked_input_set_must_be_consistent(self) -> None:
        closure = self._base()
        closure["blocked_inputs"] = ["signed_app"]
        closure["closure_sha256"] = hashlib.sha256(
            canonical_json({k: v for k, v in closure.items() if k != "closure_sha256"})
        ).hexdigest()
        with self.assertRaisesRegex(PublicationError, "blocked-input set is inconsistent"):
            validate_sealed_closure(REPOSITORY, closure, fixture=True)


class CrossConsistentGraphTests(unittest.TestCase):
    def test_dependency_graph_must_cover_every_component(self) -> None:
        product = {"name": "Clash for Mac", "version": "0.4.0", "build_number": "40000"}
        graph = _sbom_graph()
        from scripts.publication.sealed_closure import _sbom_graph as normalize

        normalized = normalize(graph)
        documents = build_sbom_documents(product, normalized)
        # Corrupt the CycloneDX dependency graph so it no longer covers a node.
        broken = copy.deepcopy(documents["cyclonedx"])
        broken["dependencies"] = broken["dependencies"][:-1]
        with self.assertRaises(PublicationError):
            _cross_consistent_graph(documents["spdx"], broken)


if __name__ == "__main__":
    unittest.main()
