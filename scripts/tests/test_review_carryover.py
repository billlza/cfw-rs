from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from scripts.publication.common import PublicationError
from scripts.publication.review_carryover import (
    APPROVAL,
    COMPARISON,
    DECISIONS,
    PENDING,
    REVIEWED,
    CarryoverRefused,
    Release,
    closure_difference,
    compare,
    record_decisions,
    record_legal_review,
    shipped_decisions,
)

VERSION = "0.5.0"
PRODUCT = {"name": "Clash for Mac", "version": VERSION}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(path: Path, data: bytes | str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = data.encode() if isinstance(data, str) else data
    path.write_bytes(payload)
    return sha256(payload)


def write_json(path: Path, value: object) -> str:
    return write(path, json.dumps(value, sort_keys=True))


class Answers:
    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.answers.pop(0)


class CarryoverFixture(unittest.TestCase):
    """A shipped release with one manual decision and a candidate that keeps it."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.shipped = Release(VERSION, "90001", self.root / "shipped-artifact", self.root / "shipped-review")
        self.candidate = Release(VERSION, "90002", self.root / "candidate-artifact", self.root / "candidate-review")
        self.candidate.review.mkdir()
        self.shipped.review.mkdir()
        self.license_text = "MIT License\n\nPermission is hereby granted ...\n"
        for release in (self.shipped, self.candidate):
            write(release.artifact / "scripts/dependency_pins.env", "NODE_VERSION=26.8.2\nGO_VERSION=1.27.2\n")
            write(release.artifact / "src/gizmo/LICENSE", self.license_text)
            write(release.artifact / "src/auto/LICENSE", "Apache License 2.0\n")
        write(self.root / "executor/scripts/publication/license_resolution.py", "# resolver\n")
        self.ship()

    def component(self, release: Release, *, status: str, expression: str, supports: bool) -> dict:
        path = release.artifact / "src/gizmo/LICENSE"
        item = {"path": str(path), "sha256": sha256(path.read_bytes())}
        if supports:
            item["supports"] = ["MIT"]
        return {
            "id": "go:gizmo:1",
            "name": "gizmo",
            "version": "1.0",
            "purl": "pkg:golang/example.com/gizmo@1.0",
            "copyright_text": "NOASSERTION",
            "source_override": None,
            "source_evidence": {"path": str(release.artifact / "src/gizmo")},
            "license_resolution": {
                "status": status,
                "expression": expression,
                "method": "human-legal-review" if status == "manual-reviewed" else "none",
                "reason": "approved" if status == "manual-reviewed" else "no automatic conclusion",
                "metadata": None,
                "files": [item],
            },
        }

    def automatic(self, release: Release) -> dict:
        path = release.artifact / "src/auto/LICENSE"
        return {
            "id": "go:auto:1",
            "name": "auto",
            "version": "2.0",
            "purl": "pkg:golang/example.com/auto@2.0",
            "copyright_text": "NOASSERTION",
            "source_override": None,
            "source_evidence": {"path": str(release.artifact / "src/auto")},
            "license_resolution": {
                "status": "automatic",
                "expression": "Apache-2.0",
                "method": "automatic",
                "reason": "license file",
                "metadata": None,
                "files": [{"path": str(path), "sha256": sha256(path.read_bytes()), "supports": ["Apache-2.0"]}],
            },
        }

    def closure(self, release: Release, components: list[dict]) -> dict:
        return {
            "product": {"build_number": release.build, **PRODUCT},
            "fixture": False,
            "components": [
                {
                    "id": item["id"],
                    "name": item["name"],
                    "version": item["version"],
                    "license_expression": item["license_resolution"]["expression"],
                    "license_files": [{"sha256": entry["sha256"]} for entry in item["license_resolution"]["files"]],
                }
                for item in components
            ],
            "build_tools": [],
            "corresponding_source": {"sha256": "1" * 64, "total_file_bytes": 10},
        }

    def ship(self) -> None:
        """Write the shipped release's approved records, as the driver leaves them."""

        shipped = self.shipped
        reviewed = {"schema_version": 1, "product": PRODUCT, "components": [
            self.component(shipped, status="manual-reviewed", expression="MIT", supports=True),
            self.automatic(shipped),
        ]}
        reviewed_sha = write_json(shipped.review / REVIEWED, reviewed)
        comparison_sha = write_json(shipped.review / COMPARISON, {"document": "comparison"})
        closure_sha = write_json(shipped.stage_inputs / "publication/machine-closure.json",
                                 self.closure(shipped, reviewed["components"]))
        legal = {
            "decision": "approved",
            "closure_sha256": closure_sha,
            "license_texts_reviewed": True,
            "source_scope_reviewed": True,
            "notes": f"reviewed input {reviewed_sha}; comparison {comparison_sha}",
        }
        legal_sha = write_json(shipped.stage_inputs / "legal-review.json", legal)
        write_json(shipped.stage_inputs / "publication/legal-review.json", legal)
        write_json(shipped.review / APPROVAL, {
            "approved_closure_sha256": closure_sha,
            "review_sha256": legal_sha,
            "reviewed_components_sha256": reviewed_sha,
        })

    def template(self, expression: str = "") -> None:
        write_json(self.candidate.stage_inputs / "component-review.json", {
            "schema_version": 1,
            "product": PRODUCT,
            "components": [
                self.component(self.candidate, status="manual-required", expression=expression, supports=False),
                self.automatic(self.candidate),
            ],
        })

    def compare(self) -> dict:
        return compare(self.shipped, self.candidate, self.root / "executor", self.root / "tooling")


class ReuseTests(CarryoverFixture):
    def test_an_unchanged_manual_decision_carries_over_with_its_bindings(self) -> None:
        self.template()
        summary = self.compare()
        self.assertEqual(summary["review_kind"], "complete")
        self.assertEqual(summary["reused_decisions"], ["gizmo"])
        reviewed = json.loads((self.candidate.review / REVIEWED).read_text())
        gizmo = next(item for item in reviewed["components"] if item["name"] == "gizmo")
        self.assertEqual(gizmo["license_resolution"]["status"], "manual-reviewed")
        self.assertEqual(gizmo["license_resolution"]["expression"], "MIT")
        self.assertEqual(gizmo["license_resolution"]["files"][0]["supports"], ["MIT"])
        self.assertIn("approved 90001 closure", gizmo["license_resolution"]["reason"])
        self.assertFalse(os.path.lexists(self.candidate.review / PENDING))

    def test_the_shipped_build_caches_need_not_be_retained(self) -> None:
        self.template()
        shutil.rmtree(self.shipped.artifact / "src")
        self.assertEqual(self.compare()["review_kind"], "complete")

    def test_changed_license_bytes_need_a_new_human_decision(self) -> None:
        write(self.candidate.artifact / "src/gizmo/LICENSE", self.license_text + "Extra clause.\n")
        self.template()
        summary = self.compare()
        self.assertEqual(summary["review_kind"], "pending")
        self.assertEqual(summary["pending_human_decisions"][0]["reasons"], ["license file set or bytes changed"])
        self.assertFalse(os.path.lexists(self.candidate.review / REVIEWED))
        answers = Answers("Ziang Li", "MIT", "all", "Same MIT grant with an added clause", "yes")
        record = record_decisions(self.candidate, answers, lambda line: None)
        reviewed = json.loads((self.candidate.review / REVIEWED).read_bytes())
        gizmo = next(item for item in reviewed["components"] if item["name"] == "gizmo")
        self.assertEqual(gizmo["license_resolution"]["files"][0]["supports"], ["MIT"])
        self.assertIn("new human license decision", gizmo["license_resolution"]["reason"])
        self.assertEqual(record["reviewed_components_sha256"], sha256((self.candidate.review / REVIEWED).read_bytes()))
        self.assertTrue((self.candidate.review / DECISIONS).is_file())

    def test_an_unconfirmed_decision_writes_nothing(self) -> None:
        write(self.candidate.artifact / "src/gizmo/LICENSE", self.license_text + "Extra clause.\n")
        self.template()
        self.compare()
        with self.assertRaisesRegex(CarryoverRefused, "not confirmed"):
            record_decisions(self.candidate, Answers("Ziang Li", "MIT", "all", "Reviewed", "no"), lambda line: None)
        self.assertFalse(os.path.lexists(self.candidate.review / REVIEWED))
        self.assertFalse(os.path.lexists(self.candidate.review / DECISIONS))

    def test_a_shipped_approval_that_does_not_bind_its_closure_is_refused(self) -> None:
        approval = json.loads((self.shipped.review / APPROVAL).read_text())
        approval["approved_closure_sha256"] = "0" * 64
        write_json(self.shipped.review / APPROVAL, approval)
        self.template()
        with self.assertRaisesRegex(CarryoverRefused, "does not bind its closure"):
            self.compare()
        self.assertEqual(list(self.candidate.review.iterdir()), [])

    def test_a_shipped_decision_absent_from_its_approved_closure_is_refused(self) -> None:
        closure_path = self.shipped.stage_inputs / "publication/machine-closure.json"
        closure = json.loads(closure_path.read_text())
        closure["components"] = [item for item in closure["components"] if item["name"] != "gizmo"]
        closure_sha = write_json(closure_path, closure)
        approval = json.loads((self.shipped.review / APPROVAL).read_text())
        legal = json.loads((self.shipped.stage_inputs / "legal-review.json").read_text())
        legal["closure_sha256"] = closure_sha
        approval.update(approved_closure_sha256=closure_sha,
                        review_sha256=write_json(self.shipped.stage_inputs / "legal-review.json", legal))
        write_json(self.shipped.stage_inputs / "publication/legal-review.json", legal)
        write_json(self.shipped.review / APPROVAL, approval)
        with self.assertRaisesRegex(CarryoverRefused, "absent from the approved closure"):
            shipped_decisions(self.shipped)

    def test_legacy_build_suffixed_records_are_found(self) -> None:
        for name in (APPROVAL, COMPARISON):
            source = self.shipped.review / name
            source.rename(self.shipped.review / name.replace(".json", "-90001.json"))
        (self.shipped.review / REVIEWED).rename(self.shipped.review / "component-review-reused-90001.json")
        self.assertEqual(shipped_decisions(self.shipped).release, self.shipped)


class LegalReviewTests(CarryoverFixture):
    def setUp(self) -> None:
        super().setUp()
        self.template()
        self.compare()
        reviewed = json.loads((self.candidate.review / REVIEWED).read_bytes())
        self.draft = self.candidate.stage_inputs / "machine-closure.draft.json"
        self.draft_sha = write_json(self.draft, self.closure(self.candidate, reviewed["components"]))

    def test_the_approval_binds_the_exact_closure_and_passes_the_release_validator(self) -> None:
        answers = Answers(self.draft_sha, "yes", "yes", "Ziang Li", "")
        approval = record_legal_review(self.shipped, self.candidate, answers, lambda line: None)
        review_path = self.candidate.stage_inputs / "legal-review.json"
        self.assertEqual(approval["approved_closure_sha256"], self.draft_sha)
        self.assertEqual(approval["review_sha256"], sha256(review_path.read_bytes()))
        review = json.loads(review_path.read_text())
        self.assertIn(approval["reviewed_components_sha256"], review["notes"])
        self.assertIn(approval["component_comparison_sha256"], review["notes"])
        # After finalize the candidate is itself a verifiable shipped release.
        (self.candidate.stage_inputs / "publication").mkdir()
        shutil.copyfile(self.draft, self.candidate.stage_inputs / "publication/machine-closure.json")
        shutil.copyfile(review_path, self.candidate.stage_inputs / "publication/legal-review.json")
        self.assertEqual(shipped_decisions(self.candidate).closure_sha256, self.draft_sha)

    def test_a_wrong_digest_or_a_missing_confirmation_writes_nothing(self) -> None:
        for answers in (Answers("0" * 64), Answers(self.draft_sha, "yes", "no")):
            with self.assertRaises(CarryoverRefused):
                record_legal_review(self.shipped, self.candidate, answers, lambda line: None)
            self.assertFalse(os.path.lexists(self.candidate.stage_inputs / "legal-review.json"))
            self.assertFalse(os.path.lexists(self.candidate.review / APPROVAL))

    def test_a_fixture_reviewer_identity_is_refused_by_the_release_validator(self) -> None:
        with self.assertRaisesRegex(PublicationError, "fixture reviewer"):
            record_legal_review(self.shipped, self.candidate, Answers(self.draft_sha, "yes", "yes", "test owner", ""),
                                lambda line: None)
        self.assertFalse(os.path.lexists(self.candidate.stage_inputs / "legal-review.json"))
        self.assertFalse(os.path.lexists(self.candidate.stage_inputs / ".legal-review.json.pending"))
        self.assertFalse(os.path.lexists(self.candidate.review / APPROVAL))

    def test_the_closure_difference_flags_a_license_change(self) -> None:
        closure = json.loads(self.draft.read_text())
        closure["components"][0]["license_expression"] = "Apache-2.0"
        write_json(self.draft, closure)
        lines = closure_difference(self.shipped, self.draft)
        self.assertTrue(any("LICENSE CHANGED" in line for line in lines))
        self.assertEqual(lines[-1], "review flags: 1")


if __name__ == "__main__":
    unittest.main()
