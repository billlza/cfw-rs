from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.evidence_manifest import (
    EvidenceManifestError,
    load_evidence_manifest,
    validate_evidence_manifest,
)


COMMIT = "a" * 40
TOOLCHAIN = "b" * 64
SIGNED_APP = "c" * 64


def _report(report_id: str, kind: str, bindings: dict[str, str], sha: str) -> dict:
    return {
        "id": report_id,
        "kind": kind,
        "path": f"reports/{report_id}.json",
        "sha256": sha,
        "status": "passed",
        "bindings": bindings,
    }


def fixture() -> dict:
    source_bindings = {"commit": COMMIT}
    ci_bindings = {"commit": COMMIT, "toolchain_sha256": TOOLCHAIN}
    signed_bindings = {
        "commit": COMMIT,
        "toolchain_sha256": TOOLCHAIN,
        "signed_app_sha256": SIGNED_APP,
    }
    sha = "d" * 64
    reports = [
        _report("source-hash", "source_hash", source_bindings, sha),
        _report("boundary", "boundary_scan", source_bindings, sha),
        _report("unsigned-artifact", "unsigned_artifact", ci_bindings, sha),
        _report("deterministic-test", "deterministic_test", ci_bindings, sha),
        _report("signed-identity", "signed_identity", signed_bindings, sha),
        _report("physical-machine", "physical_machine", signed_bindings, sha),
        _report("notarization", "notarization", signed_bindings, sha),
        _report("publication", "publication", signed_bindings, sha),
        _report("sbom", "sbom", signed_bindings, sha),
    ]
    return {
        "schema_version": 1,
        "manifest_version": "evidence-manifest-v1",
        "identity": {
            "commit": COMMIT,
            "toolchain_sha256": TOOLCHAIN,
            "signed_app_sha256": SIGNED_APP,
        },
        "reports": reports,
        "capabilities": [
            {
                "id": "global-authority",
                "highest_level": "Sealed_Release_Evidence",
                "levels": {
                    "Source_Implemented": {"report_ids": ["source-hash", "boundary"]},
                    "Unsigned_CI_Verified": {
                        "report_ids": ["unsigned-artifact", "deterministic-test"]
                    },
                    "Signed_Installed_Verified": {
                        "report_ids": ["signed-identity", "physical-machine"]
                    },
                    "Sealed_Release_Evidence": {
                        "report_ids": ["notarization", "publication", "sbom"]
                    },
                },
            },
            {
                "id": "source-only-capability",
                "highest_level": "Source_Implemented",
                "levels": {
                    "Source_Implemented": {"report_ids": ["source-hash", "boundary"]}
                },
            },
        ],
    }


class EvidenceManifestValidTests(unittest.TestCase):
    def test_complete_manifest_assigns_correct_highest_levels(self) -> None:
        result = validate_evidence_manifest(fixture())
        achieved = {cap["id"]: cap["highest_level"] for cap in result["capabilities"]}
        self.assertEqual(
            achieved,
            {
                "global-authority": "Sealed_Release_Evidence",
                "source-only-capability": "Source_Implemented",
            },
        )

    def test_intermediate_highest_level_is_accepted(self) -> None:
        value = copy.deepcopy(fixture())
        cap = value["capabilities"][0]
        del cap["levels"]["Signed_Installed_Verified"]
        del cap["levels"]["Sealed_Release_Evidence"]
        cap["highest_level"] = "Unsigned_CI_Verified"
        # Drop now-unused higher-level reports so nothing is left unbound.
        value["reports"] = [
            report
            for report in value["reports"]
            if report["id"]
            not in {"signed-identity", "physical-machine", "notarization", "publication", "sbom"}
        ]
        result = validate_evidence_manifest(value)
        self.assertEqual(result["capabilities"][0]["highest_level"], "Unsigned_CI_Verified")


class EvidenceManifestRejectionTests(unittest.TestCase):
    def test_missing_predecessor_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        cap = value["capabilities"][0]
        del cap["levels"]["Unsigned_CI_Verified"]
        with self.assertRaisesRegex(EvidenceManifestError, "predecessor"):
            validate_evidence_manifest(value)

    def test_over_promotion_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        cap = value["capabilities"][1]
        cap["highest_level"] = "Signed_Installed_Verified"
        with self.assertRaisesRegex(EvidenceManifestError, "highest_level"):
            validate_evidence_manifest(value)

    def test_source_report_cannot_satisfy_installed_level(self) -> None:
        value = copy.deepcopy(fixture())
        cap = value["capabilities"][0]
        cap["levels"]["Signed_Installed_Verified"]["report_ids"] = ["source-hash", "boundary"]
        with self.assertRaisesRegex(EvidenceManifestError, "Source_Implemented report"):
            validate_evidence_manifest(value)

    def test_masked_status_fails_closed(self) -> None:
        for masked in ("skipped", "masked", "timeout", "failed", "|| true", "passed_with_warnings"):
            value = copy.deepcopy(fixture())
            value["reports"][0]["status"] = masked
            with self.assertRaisesRegex(EvidenceManifestError, "status"):
                validate_evidence_manifest(value)

    def test_stale_binding_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["reports"][2]["bindings"]["commit"] = "e" * 40
        with self.assertRaisesRegex(EvidenceManifestError, "does not match the manifest identity"):
            validate_evidence_manifest(value)

    def test_foreign_signed_app_binding_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["reports"][4]["bindings"]["signed_app_sha256"] = "f" * 64
        with self.assertRaisesRegex(EvidenceManifestError, "does not match the manifest identity"):
            validate_evidence_manifest(value)

    def test_missing_referenced_report_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["capabilities"][0]["levels"]["Source_Implemented"]["report_ids"] = ["ghost"]
        with self.assertRaisesRegex(EvidenceManifestError, "missing raw report"):
            validate_evidence_manifest(value)

    def test_skipped_required_kind_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        # Reference only one of the two required Source_Implemented kinds.
        value["capabilities"][0]["levels"]["Source_Implemented"]["report_ids"] = ["source-hash"]
        value["capabilities"][1]["levels"]["Source_Implemented"]["report_ids"] = ["source-hash"]
        value["reports"] = [r for r in value["reports"] if r["id"] != "boundary"]
        with self.assertRaisesRegex(EvidenceManifestError, "skips required evidence kinds"):
            validate_evidence_manifest(value)

    def test_unknown_field_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["extra"] = True
        with self.assertRaisesRegex(EvidenceManifestError, "unknown fields"):
            validate_evidence_manifest(value)

    def test_unknown_report_kind_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["reports"][0]["kind"] = "made_up"
        with self.assertRaisesRegex(EvidenceManifestError, "unknown report kind"):
            validate_evidence_manifest(value)

    def test_unknown_level_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["capabilities"][1]["levels"]["Imaginary_Level"] = {"report_ids": ["source-hash"]}
        with self.assertRaisesRegex(EvidenceManifestError, "unknown levels"):
            validate_evidence_manifest(value)

    def test_duplicate_report_id_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["reports"].append(copy.deepcopy(value["reports"][0]))
        with self.assertRaisesRegex(EvidenceManifestError, "duplicate report id"):
            validate_evidence_manifest(value)

    def test_unbound_report_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["reports"].append(
            _report("dangling", "source_hash", {"commit": COMMIT}, "d" * 64)
        )
        with self.assertRaisesRegex(EvidenceManifestError, "unbound reports"):
            validate_evidence_manifest(value)

    def test_wrong_manifest_version_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["manifest_version"] = "evidence-manifest-v2"
        with self.assertRaisesRegex(EvidenceManifestError, "manifest_version"):
            validate_evidence_manifest(value)


class EvidenceManifestLoaderTests(unittest.TestCase):
    def _write(self, directory: Path, name: str, payload) -> Path:
        path = directory / name
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8")
        else:
            path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            manifest = self._write(
                directory,
                "manifest.json",
                '{"schema_version": 1, "schema_version": 1, "manifest_version": '
                '"evidence-manifest-v1", "identity": {}, "reports": [], "capabilities": []}',
            )
            with self.assertRaisesRegex(EvidenceManifestError, "duplicate field"):
                load_evidence_manifest(manifest)

    def test_content_addressed_reports_verified_against_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            reports_root = directory / "root"
            (reports_root / "reports").mkdir(parents=True)
            value = fixture()
            # Materialize each raw report and bind its real SHA-256.
            for report in value["reports"]:
                raw_path = reports_root / report["path"]
                body = f"raw-{report['id']}".encode("utf-8")
                raw_path.write_bytes(body)
                report["sha256"] = hashlib.sha256(body).hexdigest()
            manifest = self._write(directory, "manifest.json", value)
            result = load_evidence_manifest(manifest, reports_root=reports_root)
            self.assertEqual(len(result["capabilities"]), 2)

    def test_missing_raw_report_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            reports_root = directory / "root"
            reports_root.mkdir()
            manifest = self._write(directory, "manifest.json", fixture())
            with self.assertRaisesRegex(EvidenceManifestError, "missing or is a symlink"):
                load_evidence_manifest(manifest, reports_root=reports_root)

    def test_content_hash_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            reports_root = directory / "root"
            (reports_root / "reports").mkdir(parents=True)
            value = fixture()
            for report in value["reports"]:
                (reports_root / report["path"]).write_bytes(b"tampered")
            manifest = self._write(directory, "manifest.json", value)
            with self.assertRaisesRegex(EvidenceManifestError, "content hash"):
                load_evidence_manifest(manifest, reports_root=reports_root)


if __name__ == "__main__":
    unittest.main()
