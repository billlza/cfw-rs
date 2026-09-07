#!/usr/bin/env python3
"""Static fail-closed contract for the production physical receipt signer.

The collector is intentionally a separate Cloud Run/KMS trust boundary. These
tests do not execute cloud operations. They keep the checked-in implementation
from drifting into a caller-selected signing oracle, silently retrying an
ambiguous signature, or deploying with mutable/root container inputs.

The suite deliberately fails when ``tools/physical-collector`` is absent or
partial. A fixture, comment in another directory, or the offline receipt
verifier cannot substitute for the production gateway implementation.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
COLLECTOR = REPOSITORY / "tools/physical-collector"

REQUIRED_FILES = (
    ".dockerignore",
    "go.mod",
    "go.sum",
    "Dockerfile",
    "cloudbuild.yaml",
    "main.go",
    "source_digest.sh",
)
REQUIRED_INTERNAL_MODULES = (
    "config",
    "contract",
    "ledger",
    "server",
    "signing",
)
REQUIRED_ENVIRONMENT = frozenset(
    {
        "CFW_COLLECTOR_ROLE",
        "CFW_PRODUCTION_RECEIPTS_ENABLED",
        "GOOGLE_CLOUD_PROJECT",
        "CFW_FIRESTORE_DATABASE",
        "CFW_KMS_KEY_VERSION",
        "CFW_TRUST_POLICY_SHA256",
        "CFW_COLLECTOR_VERSION",
        "CFW_COLLECTOR_SOURCE_SHA256",
        "CFW_COLLECTOR_EXECUTABLE_SHA256",
        "CFW_KMS_PUBLIC_KEY_SHA256",
        "CFW_KMS_PUBLIC_KEY_DER_BASE64",
        "PORT",
    }
)
AUTHORITY_FIELDS = (
    "KMSKeyVersion",
    "TrustPolicySHA256",
    "CollectorVersion",
    "CollectorSourceSHA256",
    "CollectorExecutableSHA256",
)
INBOUND_JSON_FIELDS = {
    "Candidate": frozenset(
        {
            "version",
            "build_number",
            "app_manifest_sha256",
            "signed_app_tree_sha256",
            "artifact_hash_manifest_sha256",
            "built_at",
        }
    ),
    "RunIntent": frozenset(
        {
            "os",
            "macos_version",
            "macos_build",
            "machine_sha256",
            "clean_install",
            "run_id",
        }
    ),
    "NonceRequest": frozenset({"schema_version", "candidate", "run"}),
    "ReceiptRun": frozenset(
        {
            "os",
            "macos_version",
            "macos_build",
            "machine_sha256",
            "clean_install",
            "captured_at",
            "completed_at",
            "run_id",
            "run_nonce",
        }
    ),
    "Descriptor": frozenset({"kind", "path", "size", "sha256"}),
    "ReportBinding": frozenset(
        {
            "harness",
            "tool_version",
            "captured_at",
            "completed_at",
            "signed_at",
            "descriptor",
        }
    ),
    "RawArtifactBinding": frozenset({"harness", "subject", "descriptor"}),
    "ReceiptRequest": frozenset(
        {"schema_version", "candidate", "run", "reports", "raw_artifacts"}
    ),
}
FORBIDDEN_AUTHORITY_JSON_FIELDS = frozenset(
    {
        "algorithm",
        "digest",
        "digest_crc32c",
        "key_version",
        "kms_algorithm",
        "kms_key_version",
        "policy_path",
        "policy_sha256",
        "signing_digest",
        "trust_policy_sha256",
    }
)
LEDGER_STATES = frozenset({"ISSUED", "SIGNING", "COMMITTED", "ABANDONED"})
SHA256_IMAGE = re.compile(
    r"@sha256:[0-9a-f]{64}(?:\s+AS\s+[A-Za-z0-9_.-]+)?$", re.I
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _struct_json_fields(source: str, name: str) -> frozenset[str]:
    match = re.search(
        rf"(?ms)^type\s+{re.escape(name)}\s+struct\s*\{{(?P<body>.*?)^\}}",
        source,
    )
    if match is None:
        raise AssertionError(f"missing exact inbound request struct {name}")
    return frozenset(
        re.findall(r'`json:"([^",]+)(?:,[^"]*)?"`', match.group("body"))
    )


class PhysicalCollectorCloudContractTests(unittest.TestCase):
    """Source-level release boundary for the Cloud signing gateway."""

    @classmethod
    def setUpClass(cls) -> None:
        missing: list[str] = []
        if not COLLECTOR.is_dir() or COLLECTOR.is_symlink():
            missing.append("tools/physical-collector/")
        else:
            for relative in REQUIRED_FILES:
                path = COLLECTOR / relative
                if not path.is_file() or path.is_symlink():
                    missing.append(f"tools/physical-collector/{relative}")
            for module in REQUIRED_INTERNAL_MODULES:
                module_root = COLLECTOR / "internal" / module
                production_go = tuple(
                    path
                    for path in module_root.glob("*.go")
                    if path.is_file()
                    and not path.is_symlink()
                    and not path.name.endswith("_test.go")
                )
                if not production_go:
                    missing.append(f"tools/physical-collector/internal/{module}/*.go")
        if missing:
            raise AssertionError(
                "physical collector cloud contract is unavailable or incomplete; missing "
                + ", ".join(sorted(missing))
            )

        cls.production_go = tuple(
            path
            for path in sorted(COLLECTOR.rglob("*.go"))
            if not path.name.endswith("_test.go")
        )
        if not cls.production_go:
            raise AssertionError("physical collector has no production Go source")
        cls.go_source = "\n".join(
            f"// FILE: {path.relative_to(COLLECTOR)}\n{_read(path)}"
            for path in cls.production_go
        )

    def module_source(self, module: str) -> str:
        paths = sorted((COLLECTOR / "internal" / module).glob("*.go"))
        return "\n".join(
            _read(path) for path in paths if not path.name.endswith("_test.go")
        )

    def test_tree_has_explicit_module_boundaries_and_no_symlinks(self) -> None:
        for path in COLLECTOR.rglob("*"):
            self.assertFalse(
                path.is_symlink(), f"collector source tree contains symlink: {path}"
            )
        self.assertIn("package main", _read(COLLECTOR / "main.go"))
        internal_main = [
            path.relative_to(COLLECTOR).as_posix()
            for path in self.production_go
            if path != COLLECTOR / "main.go"
            and re.search(r"(?m)^package\s+main\s*$", _read(path))
        ]
        self.assertEqual(
            [], internal_main, f"internal modules must not be package main: {internal_main}"
        )

    def test_cloud_dependencies_are_versioned_without_local_replacements(self) -> None:
        go_mod = _read(COLLECTOR / "go.mod")
        go_sum = _read(COLLECTOR / "go.sum")
        self.assertIn("cloud.google.com/go/firestore", go_mod)
        self.assertIn("cloud.google.com/go/kms", go_mod)
        self.assertNotRegex(go_mod, r"(?m)^\s*replace\s+")
        self.assertNotIn(" latest", go_mod)
        self.assertTrue(go_sum.strip(), "go.sum must bind the collector dependency graph")

    def test_configuration_is_exact_explicit_and_defaults_production_off(self) -> None:
        source = self.module_source("config")
        for name in sorted(REQUIRED_ENVIRONMENT):
            self.assertIn(f'"{name}"', source, f"missing exact environment input {name}")
        configured_environment = frozenset(
            re.findall(
                r'"((?:CFW_[A-Z0-9_]+|GOOGLE_CLOUD_PROJECT|PORT))"', source
            )
        )
        self.assertEqual(
            REQUIRED_ENVIRONMENT,
            configured_environment,
            "collector environment surface must be explicit and reviewable",
        )
        self.assertIn('"nonce-issuer"', source)
        self.assertIn('"receipt-signer"', source)
        self.assertNotIn(
            "strconv.ParseBool", source, "broad boolean spellings weaken the release switch"
        )
        self.assertRegex(
            source,
            r'loadBool\(\s*"CFW_PRODUCTION_RECEIPTS_ENABLED"\s*,\s*false\s*\)',
        )
        load_bool = source[source.find("func loadBool") :]
        self.assertIn("os.LookupEnv(name)", load_bool)
        self.assertIn('case "true":', load_bool)
        self.assertIn('case "false":', load_bool)
        self.assertNotIn(
            "CFW_KMS_ALGORITHM", source, "PS256 must not be environment-selectable"
        )

    def test_request_surface_cannot_select_signing_authority(self) -> None:
        server = self.module_source("server")
        request_types = _read(COLLECTOR / "internal/contract/types.go")
        for name, expected_fields in INBOUND_JSON_FIELDS.items():
            actual_fields = _struct_json_fields(request_types, name)
            self.assertEqual(
                expected_fields,
                actual_fields,
                f"inbound schema drifted for {name}; signing authority must stay server-owned",
            )
            self.assertTrue(
                actual_fields.isdisjoint(FORBIDDEN_AUTHORITY_JSON_FIELDS),
                f"inbound {name} accepts caller-selected signing authority",
            )
        self.assertIn("var body contract.NonceRequest", server)
        self.assertIn("var body contract.ReceiptRequest", server)
        self.assertIn('request.URL.RawQuery != ""', server)
        self.assertIn("return contract.DecodeExact(body, target)", server)
        self.assertNotRegex(
            server, r"(?i)URL\.Query\(\).*?(?:key|algorithm|policy|digest)"
        )
        self.assertNotRegex(
            server, r"(?i)Header\.Get\([^\n]*(?:key|algorithm|policy|digest)"
        )

        validation = (
            self.module_source("contract") + "\n" + self.module_source("signing")
        )
        for field in AUTHORITY_FIELDS:
            self.assertIn(
                field, validation, f"receipt validation does not bind config.{field}"
            )
        self.assertIn(
            '"PS256"', validation, "collector receipt algorithm is not fixed to PS256"
        )
        self.assertIn(
            "sha256.Sum256", validation, "signing digest is not derived from receipt bytes"
        )
        self.assertRegex(
            server,
            r"contract\.BuildReceiptPayload\(\s*body\s*,\s*"
            r"service\.config\.Binding\(\)\s*,\s*signedAt\s*\)",
        )
        self.assertIn("contract.CanonicalJSON(payload)", server)
        self.assertIn("service.signer.Sign(request.Context(), payloadBytes)", server)

    def test_decoder_and_canonical_boundary_fail_closed(self) -> None:
        contract = self.module_source("contract")
        self.assertIn("DisallowUnknownFields", contract)
        self.assertRegex(
            contract,
            r"(?s)(?:io\.EOF|Decode\(&struct\{\}\{\}\)).*trailing|"
            r"trailing.*(?:io\.EOF|Decode)",
        )
        self.assertIn("json.NewEncoder", contract)
        self.assertIn("SetEscapeHTML(false)", contract)
        self.assertIn("appendCanonical", contract)
        request_types = _read(COLLECTOR / "internal/contract/types.go")
        self.assertNotIn("map[string]interface{}", request_types)
        self.assertNotIn("map[string]any", request_types)
        self.assertNotIn("interface{}", request_types)
        self.assertNotRegex(request_types, r"\b(?:any|json\.RawMessage)\b")
        self.assertNotIn("UnmarshalJSON", contract)

    def test_kms_integrity_and_local_pss_verification_are_mandatory(self) -> None:
        source = self.module_source("signing")
        required_tokens = (
            "crc32.Castagnoli",
            "DigestCrc32C",
            "VerifiedDigestCrc32C",
            "SignatureCrc32C",
            "ProtectionLevel_HSM",
            "rsa.VerifyPSS",
            "rsa.PSSSaltLengthEqualsHash",
            "crypto.SHA256",
        )
        for token in required_tokens:
            self.assertIn(token, source, f"KMS integrity contract omits {token}")
        self.assertRegex(
            source, r"(?s)response\.Name\s*!=\s*[^\n]*(?:KMSKeyVersion|keyVersion)"
        )
        self.assertRegex(source, r"crc32\.Checksum\([^\n]*Signature")
        self.assertIn("x509.ParsePKIXPublicKey", self.module_source("config"))
        self.assertRegex(
            source,
            r"(?s)gax\.WithRetry\(\s*func\(\)\s+gax\.Retryer\s*\{\s*return\s+nil\s*\}\s*\)",
        )
        self.assertEqual(
            1,
            source.count(".AsymmetricSign("),
            "production source must have one auditable KMS sign call site",
        )

    def test_firestore_ledger_is_transactional_and_has_no_resign_path(self) -> None:
        ledger = self.module_source("ledger")
        signer = self.module_source("signing")
        server = self.module_source("server")
        for state in sorted(LEDGER_STATES):
            self.assertIn(f'"{state}"', ledger, f"ledger omits terminal/state {state}")
        self.assertIn('"physical_receipt_nonces_v1"', ledger)
        self.assertIn("RunTransaction", ledger)
        claim_start = ledger.index("func (store *Firestore) Claim")
        commit_start = ledger.index("func (store *Firestore) Commit")
        abandon_start = ledger.index("func (store *Firestore) Abandon")
        decode_start = ledger.index("func decodeDocument")
        claim = ledger[claim_start:commit_start]
        commit = ledger[commit_start:abandon_start]
        abandon = ledger[abandon_start:decode_start]
        self.assertIn("current.Status != StatusIssued", claim)
        self.assertIn('{Path: "status", Value: StatusSigning}', claim)
        for transition, terminal in (
            (commit, "StatusCommitted"),
            (abandon, "StatusAbandoned"),
        ):
            self.assertIn("current.Status != StatusSigning", transition)
            self.assertIn("current.PayloadSHA256 !=", transition)
            self.assertIn("current.AttemptID !=", transition)
            self.assertIn(f'{{Path: "status", Value: {terminal}}}', transition)
        claim_call = server.index("service.ledger.Claim(")
        sign_call = server.index("service.signer.Sign(", claim_call)
        commit_call = server.index("service.ledger.Commit(", sign_call)
        success_response = server.index("contract.ReceiptResponse{", commit_call)
        self.assertLess(claim_call, sign_call)
        self.assertLess(sign_call, commit_call)
        self.assertLess(commit_call, success_response)
        combined = (ledger + "\n" + signer).lower()
        self.assertIn("automatic re-sign", combined)
        self.assertIn("forbidden", combined)
        for retry_marker in (
            "retryablehttp",
            "backoff.retry",
            "for attempt :=",
        ):
            self.assertNotIn(
                retry_marker, combined, f"automatic KMS retry path found: {retry_marker}"
            )

    def test_container_is_digest_pinned_nonroot_and_exec_form(self) -> None:
        dockerfile = _read(COLLECTOR / "Dockerfile")
        lines = [line.strip() for line in dockerfile.splitlines() if line.strip()]
        from_lines = [line for line in lines if line.upper().startswith("FROM ")]
        self.assertTrue(from_lines, "Dockerfile has no FROM instruction")
        for line in from_lines:
            image = re.sub(r"^FROM\s+(?:--platform=\S+\s+)?", "", line, flags=re.I)
            self.assertRegex(image, SHA256_IMAGE, f"mutable Docker base image: {line}")
        stage_starts = tuple(re.finditer(r"(?mi)^FROM\s+", dockerfile))
        self.assertTrue(stage_starts, "Dockerfile has no parseable build stage")
        final_stage = dockerfile[stage_starts[-1].start() :]
        self.assertRegex(
            final_stage,
            r"(?mi)^USER\s+(?:nonroot(?::nonroot)?|65532(?::65532)?)\s*$",
        )
        self.assertNotRegex(final_stage, r"(?mi)^USER\s+(?:root|0(?::0)?)\s*$")
        self.assertRegex(
            final_stage,
            r'(?mi)^ENTRYPOINT\s*\[\s*"[^\"]+"(?:\s*,\s*"[^\"]+")*\s*\]\s*$',
        )
        self.assertNotRegex(dockerfile, r"(?i)(?:latest|:main|:master)(?:\s|@|$)")
        self.assertNotRegex(
            dockerfile,
            r"(?i)COPY\s+[^\n]*(?:service[-_]?account|credentials|\.p8|\.pem|private[-_]?key)",
        )

    def test_source_closure_and_cloud_build_are_digest_bound(self) -> None:
        source_digest = _read(COLLECTOR / "source_digest.sh")
        cloud_build = _read(COLLECTOR / "cloudbuild.yaml")
        docker_ignore = frozenset(
            line.strip()
            for line in _read(COLLECTOR / ".dockerignore").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )

        self.assertTrue((COLLECTOR / "source_digest.sh").stat().st_mode & 0o111)
        self.assertIn("set -euo pipefail", source_digest)
        self.assertIn("find . -type l -print -quit", source_digest)
        self.assertIn("LC_ALL=C sort", source_digest)
        self.assertIn("cfw-physical-collector-source-v1", source_digest)
        self.assertIn("sha256_stdin <\"$manifest\"", source_digest)
        self.assertRegex(
            source_digest,
            r"\^\[A-Za-z0-9\._/-\]\+\$",
        )
        self.assertNotIn("|| true", source_digest)
        self.assertNotIn("set +e", source_digest)

        self.assertEqual(
            frozenset({".git", ".collector-source-sha256", "physical-collector"}),
            docker_ignore,
            "Docker context exclusions must remain minimal and explicit",
        )
        builder_images = re.findall(r"(?m)^\s+name:\s+(\S+)\s*$", cloud_build)
        self.assertTrue(builder_images, "Cloud Build has no pinned builder images")
        for builder_image in builder_images:
            self.assertRegex(
                builder_image,
                r"@sha256:[0-9a-f]{64}$",
                f"Cloud Build uses a mutable builder image: {builder_image}",
            )
        self.assertIn('actual="$(./source_digest.sh)"', cloud_build)
        self.assertIn(
            '[[ ! "${_EXPECTED_SOURCE_SHA256}" =~ ^[0-9a-f]{64}$ ]]',
            cloud_build,
        )
        self.assertIn('[[ "$actual" != "${_EXPECTED_SOURCE_SHA256}" ]]', cloud_build)
        self.assertIn("_EXPECTED_SOURCE_SHA256: REQUIRED", cloud_build)
        self.assertIn("com.bill.clashformac.collector-source-sha256", cloud_build)
        self.assertIn("physical-collector:${BUILD_ID}", cloud_build)
        self.assertRegex(cloud_build, r"(?ms)^\s+- id: test\s+.*?\s+- test\s+\s+- \./\.\.\.")
        self.assertRegex(cloud_build, r"(?ms)^\s+- id: vet\s+.*?\s+- vet\s+\s+- \./\.\.\.")
        self.assertNotRegex(cloud_build, r"(?i)gcloud\s+run\s+deploy|--image(?:=|\s)")
        self.assertNotRegex(cloud_build, r"(?i)(?:latest|:main|:master)(?:\s|@|$)")

    def test_runtime_uses_service_identity_not_static_credentials(self) -> None:
        all_text = self.go_source + "\n" + _read(COLLECTOR / "Dockerfile")
        self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", all_text)
        self.assertNotRegex(all_text, r"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----")
        self.assertNotRegex(all_text, r'"private_key"\s*:')


if __name__ == "__main__":
    unittest.main()
