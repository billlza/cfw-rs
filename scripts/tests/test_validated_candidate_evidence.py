from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.candidate_artifact_binding import (
    RELEASE_TREE_METADATA,
    toolchain_manifest_metadata,
)
from scripts.hash_artifact import build_manifest
from scripts.publication import ci_lanes
from scripts.publication.artifact_preparation import _artifact_sources
from scripts.publication.common import PublicationError
from scripts.tests.test_release_runtime_evidence import fixture as runtime_fixture
from scripts.validated_candidate_evidence import (
    ValidatedCandidateError,
    validate_candidate_review,
)


COMMIT = "a" * 40
SOURCE = "b" * 64


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


class ValidatedCandidateEvidenceTests(unittest.TestCase):
    def make_review(self, repository: Path) -> Path:
        base = repository / "target/candidates/0.4.0/validation/40000"
        signed = base / "signed"
        evidence = base / "evidence"
        review_root = repository / "target/candidates/0.4.0/review"
        app = signed / "Clash for Mac.app"
        app.mkdir(parents=True)
        (app / "Contents").mkdir()
        (app / "Contents/fixture.bin").write_bytes(b"signed-candidate")
        evidence.mkdir()
        review_root.mkdir()

        trees = {
            key: hashlib.sha256(key.encode("utf-8")).hexdigest()
            for key in RELEASE_TREE_METADATA
        }
        identity = {
            "document": ci_lanes.TOOLCHAIN_BINDING_KIND,
            "fixture": True,
            "release_tree_sha256": trees,
        }
        toolchain_sha256 = ci_lanes.toolchain_sha256(identity)
        toolchain_metadata = toolchain_manifest_metadata(toolchain_sha256, identity)
        binding = evidence / "toolchain-binding.json"
        write_json(binding, identity)

        ci_document = {
            "schema_version": 2,
            "document": "unsigned-ci-lanes-v2",
            "release_source_sha256": SOURCE,
            "toolchain_sha256": toolchain_sha256,
            "lanes": [
                {
                    "id": lane.identifier,
                    "command": lane.command,
                    "status": "passed",
                    "exit_code": 0,
                    "log_sha256": hashlib.sha256(lane.identifier.encode()).hexdigest(),
                    "commit": COMMIT,
                    "release_source_sha256": SOURCE,
                    "toolchain_sha256": toolchain_sha256,
                }
                for lane in ci_lanes.LANES
            ],
        }
        ci_evidence = evidence / "unsigned-ci-lanes.json"
        write_json(ci_evidence, ci_document)

        app_manifest = signed / "Clash for Mac.app.manifest.json"
        metadata = {
            "artifactKind": "notarized-validation-candidate-v1",
            "architecture": "arm64",
            "buildNumber": "40000",
            "deploymentTarget": "15.0",
            "releaseSourceSha256": SOURCE,
            "repositoryCommit": COMMIT,
            **toolchain_metadata,
            "teamID": "YKUPL7Z869",
            "version": "0.4.0",
        }
        write_json(app_manifest, build_manifest(app, metadata))

        notary = signed / "notarization.json"
        write_json(notary, {"status": "Accepted", "id": "request-id"})
        runtime = evidence / "runtime-recovery.json"
        runtime_document = runtime_fixture()
        runtime_document["app_manifest_sha256"] = digest(app_manifest)
        write_json(runtime, runtime_document)
        review = review_root / "validated-candidate.json"
        write_json(
            review,
            {
                "schema_version": 1,
                "decision": "approved",
                "reviewer": "Release Reviewer",
                "reviewed_at": "2026-07-22T00:00:00Z",
                "product": {"version": "0.4.0", "build_number": "40000"},
                "candidate": {
                    "app_manifest_path": (
                        "target/candidates/0.4.0/validation/40000/signed/"
                        "Clash for Mac.app.manifest.json"
                    ),
                    "app_manifest_sha256": digest(app_manifest),
                    "ci_evidence_path": (
                        "target/candidates/0.4.0/validation/40000/evidence/"
                        "unsigned-ci-lanes.json"
                    ),
                    "ci_evidence_sha256": digest(ci_evidence),
                    "notarization_result_path": (
                        "target/candidates/0.4.0/validation/40000/signed/notarization.json"
                    ),
                    "notarization_result_sha256": digest(notary),
                    "runtime_evidence_path": (
                        "target/candidates/0.4.0/validation/40000/evidence/"
                        "runtime-recovery.json"
                    ),
                    "runtime_evidence_sha256": digest(runtime),
                    "toolchain_binding_path": (
                        "target/candidates/0.4.0/validation/40000/evidence/"
                        "toolchain-binding.json"
                    ),
                    "toolchain_binding_sha256": digest(binding),
                },
            },
        )
        return review

    @staticmethod
    def source_identity() -> dict[str, str]:
        return {"repositoryCommit": COMMIT, "releaseSourceSha256": SOURCE}

    def refresh_review_digests(self, repository: Path, review: Path) -> None:
        document = json.loads(review.read_text(encoding="utf-8"))
        candidate = document["candidate"]
        app_manifest = repository / candidate["app_manifest_path"]
        runtime = repository / candidate["runtime_evidence_path"]
        runtime_document = json.loads(runtime.read_text(encoding="utf-8"))
        runtime_document["app_manifest_sha256"] = digest(app_manifest)
        write_json(runtime, runtime_document)
        for path_key, digest_key in (
            ("app_manifest_path", "app_manifest_sha256"),
            ("ci_evidence_path", "ci_evidence_sha256"),
            ("notarization_result_path", "notarization_result_sha256"),
            ("runtime_evidence_path", "runtime_evidence_sha256"),
            ("toolchain_binding_path", "toolchain_binding_sha256"),
        ):
            candidate[digest_key] = digest(repository / candidate[path_key])
        write_json(review, document)

    def validate(self, repository: Path, review: Path, final: str = "40001"):
        return validate_candidate_review(
            repository,
            review,
            final,
            expected_source_identity=self.source_identity(),
        )

    def make_final_app(self, repository: Path) -> Path:
        root = repository / "target/candidates/0.4.0/signed"
        app = root / "Clash for Mac.app"
        app.mkdir(parents=True)
        (app / "Contents").mkdir()
        (app / "Contents/fixture.bin").write_bytes(b"final-signed-app")
        candidate_manifest = (
            repository
            / "target/candidates/0.4.0/validation/40000/signed/"
            "Clash for Mac.app.manifest.json"
        )
        candidate_metadata = json.loads(
            candidate_manifest.read_text(encoding="utf-8")
        )["metadata"]
        metadata = {
            **candidate_metadata,
            "artifactKind": "notarized-release-v1",
            "buildNumber": "40001",
        }
        write_json(root / "Clash for Mac.app.manifest.json", build_manifest(app, metadata))
        write_json(root / "notarization.json", {"status": "Accepted", "id": "final-id"})
        archive = root / "Clash.for.Mac_0.4.0_40001_notary.zip"
        archive.write_bytes(b"notary-submission")
        submission_metadata = {
            **metadata,
            "artifactKind": "notarization-submission-v1",
        }
        write_json(
            root / "Clash.for.Mac_0.4.0_40001_notary.zip.manifest.json",
            build_manifest(archive, submission_metadata),
        )
        return app

    def test_final_build_must_be_newer_and_all_evidence_is_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            review = self.make_review(repository)
            result = self.validate(repository, review)
            self.assertEqual(result["product"]["build_number"], "40000")

    def test_same_final_build_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            review = self.make_review(repository)
            with self.assertRaisesRegex(ValueError, "strictly greater"):
                self.validate(repository, review, "40000")

    def test_review_schema_version_rejects_float_and_bool(self) -> None:
        for invalid in (1.0, True):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as directory:
                repository = Path(directory)
                review = self.make_review(repository)
                document = json.loads(review.read_text(encoding="utf-8"))
                document["schema_version"] = invalid
                write_json(review, document)
                with self.assertRaisesRegex(
                    ValidatedCandidateError,
                    "explicitly approved",
                ):
                    self.validate(repository, review)

    def test_runtime_evidence_tamper_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            review = self.make_review(repository)
            runtime = (
                repository
                / "target/candidates/0.4.0/validation/40000/evidence/runtime-recovery.json"
            )
            runtime.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValidatedCandidateError, "digest"):
                self.validate(repository, review)

    def test_actual_app_tamper_fails_even_when_manifest_and_review_are_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            review = self.make_review(repository)
            app_file = (
                repository
                / "target/candidates/0.4.0/validation/40000/signed/"
                "Clash for Mac.app/Contents/fixture.bin"
            )
            app_file.write_bytes(b"tampered-after-review")
            with self.assertRaisesRegex(ValidatedCandidateError, "actual app tree"):
                self.validate(repository, review)

    def test_source_toolchain_and_constituent_mismatches_fail_closed(self) -> None:
        for field in (
            "releaseSourceSha256",
            "repositoryCommit",
            "toolchainSha256",
            "nodeToolchainTreeSha256",
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                repository = Path(directory)
                review = self.make_review(repository)
                app_manifest = (
                    repository
                    / "target/candidates/0.4.0/validation/40000/signed/"
                    "Clash for Mac.app.manifest.json"
                )
                document = json.loads(app_manifest.read_text(encoding="utf-8"))
                document["metadata"][field] = (
                    "c" * 40 if field == "repositoryCommit" else "c" * 64
                )
                write_json(app_manifest, document)
                self.refresh_review_digests(repository, review)
                with self.assertRaisesRegex(ValidatedCandidateError, "metadata"):
                    self.validate(repository, review)

    def test_ci_toolchain_mismatch_and_nonpassing_lane_fail_closed(self) -> None:
        for defect in ("source", "toolchain", "lane"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                repository = Path(directory)
                review = self.make_review(repository)
                ci_path = (
                    repository
                    / "target/candidates/0.4.0/validation/40000/evidence/"
                    "unsigned-ci-lanes.json"
                )
                document = json.loads(ci_path.read_text(encoding="utf-8"))
                if defect == "source":
                    document["release_source_sha256"] = "d" * 64
                    for lane in document["lanes"]:
                        lane["release_source_sha256"] = "d" * 64
                elif defect == "toolchain":
                    document["toolchain_sha256"] = "d" * 64
                    for lane in document["lanes"]:
                        lane["toolchain_sha256"] = "d" * 64
                else:
                    document["lanes"][0]["status"] = "failed"
                    document["lanes"][0]["exit_code"] = 1
                write_json(ci_path, document)
                self.refresh_review_digests(repository, review)
                expected = {
                    "source": "release source",
                    "toolchain": "digest",
                    "lane": "non-passing",
                }[defect]
                with self.assertRaisesRegex(ValidatedCandidateError, expected):
                    self.validate(repository, review)

    def test_toolchain_binding_constituent_tamper_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            review = self.make_review(repository)
            binding = (
                repository
                / "target/candidates/0.4.0/validation/40000/evidence/"
                "toolchain-binding.json"
            )
            document = json.loads(binding.read_text(encoding="utf-8"))
            document["release_tree_sha256"]["node"] = "f" * 64
            write_json(binding, document)
            self.refresh_review_digests(repository, review)
            with self.assertRaisesRegex(ValidatedCandidateError, "digest"):
                self.validate(repository, review)

    def test_publication_preparation_reverifies_actual_final_app_and_preserves_ci_inputs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            self.make_review(repository)
            app = self.make_final_app(repository)
            release_environment = dict(os.environ)
            with mock.patch(
                "scripts.publication.artifact_preparation.current_identity",
                return_value=self.source_identity(),
            ):
                sources = _artifact_sources(
                    repository,
                    repository / "target/candidates/0.4.0/release-build/40001/native-products",
                    app,
                    "40001",
                    release_environment,
                )
            self.assertIn("validated-candidate-unsigned-ci", sources)
            self.assertIn("validated-candidate-toolchain-binding", sources)
            self.assertTrue(
                {
                    "final-candidate-binding",
                    "sealed-evidence-manifest",
                    "physical-evidence-aggregate",
                    "physical-evidence-private-archive",
                }.isdisjoint(sources),
                "private physical/release-operations manifests must not enter the public bundle",
            )
            self.assertTrue(
                {
                    "final-candidate.json",
                    "physical-evidence.json",
                    "sealed-evidence-manifest.json",
                }.isdisjoint(source.name for source in sources.values()),
                "private release-input filenames must not enter the public bundle",
            )

    def test_publication_preparation_rejects_final_app_tree_or_binding_tamper(self) -> None:
        for defect in ("tree", "metadata"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                repository = Path(directory)
                self.make_review(repository)
                app = self.make_final_app(repository)
                release_environment = dict(os.environ)
                if defect == "tree":
                    (app / "Contents/fixture.bin").write_bytes(b"final-app-tamper")
                else:
                    manifest = app.parent / "Clash for Mac.app.manifest.json"
                    document = json.loads(manifest.read_text(encoding="utf-8"))
                    document["metadata"]["toolchainSha256"] = "e" * 64
                    write_json(manifest, document)
                with mock.patch(
                    "scripts.publication.artifact_preparation.current_identity",
                    return_value=self.source_identity(),
                ), self.assertRaisesRegex(PublicationError, "binding"):
                    _artifact_sources(
                        repository,
                        repository
                        / "target/candidates/0.4.0/release-build/40001/native-products",
                        app,
                        "40001",
                        release_environment,
                    )


if __name__ == "__main__":
    unittest.main()
