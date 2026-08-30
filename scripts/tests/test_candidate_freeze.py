"""Focused tests for the durable pre-sign GA candidate freeze boundary."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import candidate_freeze
from scripts import release_signing_plan
from scripts import release_signing_preflight
from scripts.release_build_identity import RETIRED_GA_WORKSPACE_PATHS
from scripts.verify_release_build_allocations import (
    IMMUTABLE_RETIRED_PREFIX,
    POLICY_SUPERSEDED_ALLOCATION,
    RETIRED_GA_ALLOCATIONS,
)


SOURCE_IDENTITY = {
    "repositoryCommit": "a" * 40,
    "releaseSourceSha256": "b" * 64,
}
TOOLCHAIN = {
    "cargoWorkspaceSourcesTreeSha256": "0" * 64,
    "goModuleCacheTreeSha256": "1" * 64,
    "goToolchainTreeSha256": "2" * 64,
    "goToolsTreeSha256": "3" * 64,
    "nodeToolchainTreeSha256": "4" * 64,
    "tauriToolchainTreeSha256": "5" * 64,
    "toolchainSha256": "6" * 64,
    "uiDependenciesTreeSha256": "7" * 64,
    "xcodegenToolchainTreeSha256": "8" * 64,
}


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


class CandidateFreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name).resolve()
        self.preflight = (
            self.repository / "target/candidates/0.4.0/ga-preflight/40038"
        )
        self.final = self.repository / "target/candidates/0.4.0/ga/40038"
        (self.repository / "docs/release").mkdir(parents=True)
        allocations = [
            {"build": build, "role": role, "status": status}
            for build, role, status in (
                *IMMUTABLE_RETIRED_PREFIX,
                POLICY_SUPERSEDED_ALLOCATION,
                *RETIRED_GA_ALLOCATIONS,
                ("40038", "ga", "active_ga"),
            )
        ]
        (self.repository / "docs/release/build-allocations-v040.json").write_bytes(
            _canonical_json(
                {
                    "active_ga": "40038",
                    "allocations": allocations,
                    "document": "cfm-release-build-allocation-v2",
                    "product_version": "0.4.0",
                }
            )
        )
        app = self.preflight / "pre-sign/Clash for Mac.app/Contents/MacOS"
        app.mkdir(parents=True)
        (app / "clash-for-mac").write_bytes(b"unsigned-host")
        native = self.preflight / "native-products"
        native.mkdir()
        (native / "CFWGlobalAuthority").write_bytes(b"unsigned-native")
        profiles = self.preflight / "profiles"
        profiles.mkdir(mode=0o700)
        (profiles / "host.provisionprofile").write_bytes(b"host-profile")
        (profiles / "proxy-agent.provisionprofile").write_bytes(b"proxy-profile")
        (profiles / "packet-tunnel.provisionprofile").write_bytes(b"packet-profile")
        (profiles / "host.plist").write_bytes(b"host-plist")
        (profiles / "proxy-agent.plist").write_bytes(b"proxy-plist")
        (profiles / "packet-tunnel.plist").write_bytes(b"packet-plist")
        (profiles / "signing-identities.txt").write_bytes(b"signing-identities")
        possession = profiles / "updater-key-possession"
        possession.mkdir(mode=0o700)
        for name in (
            "challenge.json",
            "challenge.json.sig",
            "embedded-pubkey-verification.json",
            "release-verifier-binding.json",
            "proof.json",
        ):
            path = possession / name
            path.write_bytes(f"fixture-{name}".encode("ascii"))
            path.chmod(0o600)
        custody_home = self.repository / "custody-home"
        custody_home.mkdir(mode=0o700)
        library = custody_home / "Library"
        library.mkdir(mode=0o700)
        application_support = library / "Application Support"
        application_support.mkdir(mode=0o700)
        release = application_support / "Clash for Mac Release"
        release.mkdir(mode=0o700)
        updater = release / "Updater"
        updater.mkdir(mode=0o700)
        updater_key = custody_home / release_signing_preflight.PRIVATE_KEY_RELATIVE
        updater_key.write_bytes(b"encrypted-updater-key")
        updater_key.chmod(0o600)
        self.updater_key = updater_key
        keychains = custody_home / release_signing_preflight.LOGIN_KEYCHAIN_RELATIVE.parent
        keychains.mkdir(mode=0o755)
        login_keychain = custody_home / release_signing_preflight.LOGIN_KEYCHAIN_RELATIVE
        login_keychain.write_bytes(b"login-keychain")
        login_keychain.chmod(0o644)
        self.login_keychain = login_keychain

        def metadata(path: Path) -> dict[str, object]:
            return release_signing_preflight.FileMetadata.from_stat(
                path, path.lstat()
            ).as_manifest()

        def directory_identity(path: Path) -> dict[str, object]:
            return release_signing_preflight.DirectoryIdentity.from_metadata(
                release_signing_preflight.FileMetadata.from_stat(path, path.lstat())
            ).as_manifest()

        certificate_sha256 = "A" * 64
        now = datetime.now(timezone.utc)
        profile_specs = {
            "host": (
                profiles / "host.provisionprofile",
                release_signing_preflight.HOST_BUNDLE_ID,
                "11111111-1111-4111-8111-111111111111",
            ),
            "packet-tunnel": (
                profiles / "packet-tunnel.provisionprofile",
                release_signing_preflight.PACKET_TUNNEL_BUNDLE_ID,
                "22222222-2222-4222-8222-222222222222",
            ),
            "proxy-agent": (
                profiles / "proxy-agent.provisionprofile",
                release_signing_preflight.PROXY_AGENT_BUNDLE_ID,
                "33333333-3333-4333-8333-333333333333",
            ),
        }
        profile_manifest = {}
        for role, (path, bundle_id, profile_uuid) in profile_specs.items():
            profile_manifest[role] = {
                "authorizedCertificateSha256": [certificate_sha256],
                "bundleId": bundle_id,
                "creation": (now - timedelta(days=1)).isoformat().replace(
                    "+00:00", "Z"
                ),
                "expiration": (now + timedelta(days=365)).isoformat().replace(
                    "+00:00", "Z"
                ),
                "fileSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "fileSize": path.stat().st_size,
                "name": f"fixture {role}",
                "path": str(path),
                "role": role,
                "selectedCertificateSha256": certificate_sha256,
                "uuid": profile_uuid,
            }
        signing_preflight_manifest = {
            "document": release_signing_preflight.DOCUMENT,
            "identity": {
                "certificateSha1": "B" * 40,
                "certificateSha256": certificate_sha256,
                "name": (
                    "Developer ID Application: Release Fixture "
                    f"({release_signing_preflight.TEAM_ID})"
                ),
            },
            "notary": {
                "historyProbe": "passed",
                "profile": release_signing_preflight.NOTARY_PROFILE,
            },
            "profiles": profile_manifest,
            "schemaVersion": release_signing_preflight.SCHEMA_VERSION,
            "teamId": release_signing_preflight.TEAM_ID,
            "updater": {
                "credentialAncestors": [
                    directory_identity(path)
                    for path in (
                        custody_home,
                        library,
                        application_support,
                        release,
                        updater,
                    )
                ],
                "custodyPolicy": release_signing_preflight.UPDATER_CUSTODY_POLICY,
                "key": {
                    "aclPolicy": "deny-only",
                    "file": metadata(updater_key),
                },
                "passwordKeychain": {
                    "account": release_signing_preflight.KEYCHAIN_ACCOUNT,
                    "directoryPolicy": {
                        "aclPolicy": "deny-only",
                        "allowedModes": ["0700", "0755"],
                        "ownerUid": os.geteuid(),
                        "path": str(keychains),
                        "type": "directory",
                    },
                    "filePolicy": {
                        "aclPolicy": "deny-only",
                        "allowedModes": ["0600", "0644"],
                        "hardLinks": 1,
                        "maximumSize": 512 * 1024 * 1024,
                        "minimumSize": 1,
                        "ownerUid": os.geteuid(),
                        "path": str(login_keychain),
                        "type": "regular",
                    },
                    "service": release_signing_preflight.KEYCHAIN_SERVICE,
                    "synchronizable": False,
                },
            },
            "validatedAt": now.isoformat().replace("+00:00", "Z"),
        }
        signing_preflight_path = profiles / "signing-preflight.json"
        signing_preflight_path.write_bytes(
            release_signing_preflight.canonical_manifest(signing_preflight_manifest)
        )
        signing_preflight_path.chmod(0o600)
        self.signing_preflight_path = signing_preflight_path
        entitlements = self.preflight / "entitlements"
        entitlements.mkdir(mode=0o700)
        (entitlements / "Host.release.xcent").write_bytes(b"host-entitlements")
        (entitlements / "ProxyAgent.release.xcent").write_bytes(b"proxy-entitlements")
        (entitlements / "PacketTunnel.release.xcent").write_bytes(b"packet-entitlements")
        (entitlements / "GlobalAuthority.entitlements").write_bytes(b"authority")
        signing_order = self.repository / release_signing_plan.SOURCE_PLAN_RELATIVE
        signing_order.parent.mkdir(parents=True)
        signing_order.write_text(
            json.dumps(
                {
                    "description": "fixed",
                    "nested": [{"name": str(index)} for index in range(5)],
                    "outer": {"signedLast": True},
                    "schemaVersion": 1,
                    "teamIdentifier": "YKUPL7Z869",
                }
            ),
            encoding="utf-8",
        )
        (entitlements / "signing-order.json").write_bytes(signing_order.read_bytes())
        (self.preflight / "product-input.json").write_bytes(
            _canonical_json(
                {
                    "document": "cfm-ga-product-input-v1",
                    "product": {"build_number": "40038", "version": "0.4.0"},
                    "schema_version": 1,
                    "source": {
                        "release_source_sha256": "b" * 64,
                        "repository_commit": "a" * 40,
                    },
                    "toolchain": TOOLCHAIN,
                }
            )
        )
        release_signing_plan.create_plan(self.repository, self.preflight)
        self.source_patch = patch.object(
            candidate_freeze,
            "_read_source_identity",
            return_value=dict(SOURCE_IDENTITY),
        )
        self.source_patch.start()
        self.updater_possession_patch = patch.object(
            candidate_freeze,
            "verify_possession_proof",
            side_effect=lambda _repository, root: SimpleNamespace(
                embedded_public_key_sha256="c" * 64,
                proof_path=root / "profiles/updater-key-possession/proof.json",
                proof_sha256="9" * 64,
                root=root / "profiles/updater-key-possession",
                tauri_config_sha256="d" * 64,
            ),
        )
        self.updater_possession_patch.start()
        self.live_custody_patch = patch.object(
            candidate_freeze,
            "verify_live_custody_metadata",
            return_value=signing_preflight_manifest,
        )
        self.live_custody_patch.start()

    def tearDown(self) -> None:
        self.live_custody_patch.stop()
        self.updater_possession_patch.stop()
        self.source_patch.stop()
        self.temporary.cleanup()

    def freeze(self) -> candidate_freeze.FrozenCandidate:
        return candidate_freeze.freeze_candidate(self.repository)

    def test_freeze_publishes_fixed_root_and_complete_canonical_intent(self) -> None:
        receipt = self.freeze()

        self.assertEqual(receipt.root, self.final)
        self.assertEqual(receipt.build_number, "40038")
        self.assertFalse(receipt.recovered)
        self.assertFalse(self.preflight.exists())
        self.assertTrue((self.final / "candidate-freeze/intent.json").is_file())
        raw = (self.final / "candidate-freeze/intent.json").read_bytes()
        intent = json.loads(raw)
        self.assertEqual(raw, _canonical_json(intent))
        self.assertEqual(set(intent), candidate_freeze._INTENT_FIELDS)
        self.assertEqual(intent["repository_commit"], "a" * 40)
        self.assertEqual(intent["release_source_sha256"], "b" * 64)
        self.assertEqual(intent["consumption_state"], "candidate_frozen_consumed")
        semantic_product_input = {
            "document_sha256": intent["product_input_document_sha256"],
            "entitlements_tree_sha256": intent["entitlements_tree_sha256"],
            "profiles_tree_sha256": intent["profiles_tree_sha256"],
        }
        self.assertEqual(
            intent["product_input_sha256"],
            hashlib.sha256(_canonical_json(semantic_product_input)).hexdigest(),
        )
        for field in (
            "allocation_ledger_sha256",
            "entitlements_tree_sha256",
            "native_products_tree_sha256",
            "pre_sign_app_tree_sha256",
            "pre_sign_tree_sha256",
            "product_input_document_sha256",
            "product_input_sha256",
            "profiles_tree_sha256",
            "signing_preflight_sha256",
            "signing_plan_sha256",
            "updater_embedded_public_key_sha256",
            "updater_key_possession_proof_sha256",
            "updater_tauri_config_sha256",
        ):
            self.assertRegex(intent[field], r"\A[0-9a-f]{64}\Z")
        verified = candidate_freeze.verify_frozen_candidate(self.repository)
        self.assertEqual(verified.intent_sha256, receipt.intent_sha256)

    def test_two_freezers_have_exactly_one_success(self) -> None:
        def invoke() -> tuple[str, str]:
            try:
                result = self.freeze()
            except candidate_freeze.CandidateFreezeError as error:
                return "error", error.code
            return "success", result.intent_sha256

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _index: invoke(), range(2)))

        self.assertEqual(sum(kind == "success" for kind, _value in outcomes), 1)
        self.assertEqual(sum(kind == "error" for kind, _value in outcomes), 1)
        self.assertTrue(self.final.is_dir())
        self.assertFalse(self.preflight.exists())

    def test_retired_workspace_paths_are_rejected_without_consuming_ga(self) -> None:
        for relative in RETIRED_GA_WORKSPACE_PATHS:
            with self.subTest(relative=relative):
                path = self.repository.joinpath(*relative.parts)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"retired\n")
                try:
                    with self.assertRaisesRegex(
                        candidate_freeze.CandidateFreezeError,
                        "retired",
                    ) as raised:
                        self.freeze()
                    self.assertEqual(
                        raised.exception.code,
                        "workspace_path_precondition_failed",
                    )
                    self.assertFalse(raised.exception.consumed)
                    self.assertFalse(
                        (self.preflight / "candidate-freeze/intent.json").exists()
                    )
                finally:
                    path.unlink()

    def test_retired_path_race_is_rejected_immediately_before_intent(self) -> None:
        retired = self.repository.joinpath(*RETIRED_GA_WORKSPACE_PATHS[0].parts)
        real_ensure_destination_parent = candidate_freeze._ensure_destination_parent

        def ensure_then_publish_retired_path(final_root: Path) -> None:
            real_ensure_destination_parent(final_root)
            retired.symlink_to("missing-raced-retired-path")

        with (
            patch.object(
                candidate_freeze,
                "_ensure_destination_parent",
                side_effect=ensure_then_publish_retired_path,
            ),
            patch.object(
                candidate_freeze,
                "_create_intent",
                side_effect=AssertionError("intent creation must not be reached"),
            ) as create_intent,
            self.assertRaisesRegex(
                candidate_freeze.CandidateFreezeError,
                "retired",
            ) as raised,
        ):
            self.freeze()

        self.assertEqual(
            raised.exception.code,
            "workspace_path_precondition_failed",
        )
        self.assertFalse(raised.exception.consumed)
        create_intent.assert_not_called()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_fresh_retry_never_resumes_consumed_intent(self) -> None:
        with patch.object(
            candidate_freeze,
            "_rename_exclusive",
            side_effect=OSError(errno.EIO, "injected rename failure"),
        ):
            with self.assertRaises(candidate_freeze.CandidateFreezeOutcomeUnknown):
                self.freeze()

        self.assertTrue((self.preflight / "candidate-freeze/intent.json").is_file())
        with self.assertRaises(candidate_freeze.CandidateAlreadyConsumed):
            self.freeze()

        recovered = candidate_freeze.recover_candidate(self.repository)
        self.assertTrue(recovered.recovered)
        self.assertTrue(self.final.is_dir())

    def test_rename_reply_loss_requires_exact_recovery(self) -> None:
        real_rename = candidate_freeze._rename_exclusive

        def rename_then_lose_reply(source: Path, destination: Path) -> None:
            real_rename(source, destination)
            raise OSError(errno.EIO, "injected reply loss")

        with patch.object(
            candidate_freeze, "_rename_exclusive", side_effect=rename_then_lose_reply
        ):
            with self.assertRaises(candidate_freeze.CandidateFreezeOutcomeUnknown) as raised:
                self.freeze()

        self.assertTrue(raised.exception.consumed)
        self.assertEqual(raised.exception.state, "quarantined_outcome_unknown")
        self.assertTrue(self.final.is_dir())
        recovered = candidate_freeze.recover_candidate(self.repository)
        self.assertTrue(recovered.recovered)

    def test_parent_fsync_failure_after_rename_requires_recovery(self) -> None:
        with patch.object(
            candidate_freeze,
            "_sync_publish_parents",
            side_effect=candidate_freeze.CandidateFreezeError(
                "injected_fsync_failure", "injected parent fsync failure"
            ),
        ):
            with self.assertRaises(candidate_freeze.CandidateFreezeOutcomeUnknown):
                self.freeze()

        self.assertTrue(self.final.is_dir())
        self.assertTrue(candidate_freeze.recover_candidate(self.repository).recovered)

    def test_intent_directory_fsync_failure_consumes_and_recovers_exactly(self) -> None:
        real_sync_directory = candidate_freeze._sync_directory

        def fail_claim_directory(path: Path) -> None:
            if path.name == "candidate-freeze":
                raise candidate_freeze.CandidateFreezeError(
                    "injected_fsync_failure", "injected intent-directory fsync failure"
                )
            real_sync_directory(path)

        with patch.object(
            candidate_freeze,
            "_sync_directory",
            side_effect=fail_claim_directory,
        ):
            with self.assertRaises(candidate_freeze.CandidateFreezeOutcomeUnknown):
                self.freeze()

        self.assertTrue((self.preflight / "candidate-freeze/intent.json").is_file())
        self.assertTrue(candidate_freeze.recover_candidate(self.repository).recovered)

    def test_partial_intent_write_is_consumed_and_cannot_be_relabelled(self) -> None:
        def partial_write(descriptor: int, data: bytes) -> None:
            os.write(descriptor, data[: len(data) // 2])
            raise OSError(errno.EIO, "injected partial intent write")

        with patch.object(candidate_freeze, "_write_all", side_effect=partial_write):
            with self.assertRaises(candidate_freeze.CandidateFreezeOutcomeUnknown):
                self.freeze()

        self.assertTrue((self.preflight / "candidate-freeze/intent.json").is_file())
        with self.assertRaises(candidate_freeze.CandidateFreezeQuarantined):
            candidate_freeze.recover_candidate(self.repository)

    def test_recovery_rejects_source_identity_drift(self) -> None:
        with patch.object(
            candidate_freeze,
            "_rename_exclusive",
            side_effect=OSError(errno.EIO, "injected rename failure"),
        ):
            with self.assertRaises(candidate_freeze.CandidateFreezeOutcomeUnknown):
                self.freeze()

        with patch.object(
            candidate_freeze,
            "_read_source_identity",
            return_value={
                "repositoryCommit": "d" * 40,
                "releaseSourceSha256": "e" * 64,
            },
        ):
            with self.assertRaises(candidate_freeze.CandidateFreezeQuarantined):
                candidate_freeze.recover_candidate(self.repository)

    def test_recovery_rejects_product_input_drift(self) -> None:
        with patch.object(
            candidate_freeze,
            "_rename_exclusive",
            side_effect=OSError(errno.EIO, "injected rename failure"),
        ):
            with self.assertRaises(candidate_freeze.CandidateFreezeOutcomeUnknown):
                self.freeze()

        (self.preflight / "product-input.json").write_bytes(
            _canonical_json(
                {
                    "document": "cfm-ga-product-input-v1",
                    "product": {"build_number": "40038", "version": "0.4.0"},
                    "schema_version": 1,
                    "source": {
                        "release_source_sha256": "b" * 64,
                        "repository_commit": "a" * 40,
                    },
                    "toolchain": {**TOOLCHAIN, "toolchainSha256": "f" * 64},
                }
            )
        )
        with self.assertRaises(candidate_freeze.CandidateFreezeQuarantined):
            candidate_freeze.recover_candidate(self.repository)

    def test_unknown_intent_field_is_quarantined(self) -> None:
        self.freeze()
        path = self.final / "candidate-freeze/intent.json"
        value = json.loads(path.read_bytes())
        value["unexpected"] = "f" * 64
        path.write_bytes(_canonical_json(value))

        with self.assertRaises(candidate_freeze.CandidateFreezeQuarantined):
            candidate_freeze.verify_frozen_candidate(self.repository)

    def test_duplicate_json_key_is_rejected_before_consumption(self) -> None:
        (self.preflight / "product-input.json").write_bytes(
            b'{"document":"one","document":"two"}\n'
        )

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "repeats key"
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_product_input_unknown_key_is_rejected_before_consumption(self) -> None:
        path = self.preflight / "product-input.json"
        value = json.loads(path.read_bytes())
        value["unexpected"] = "forbidden"
        path.write_bytes(_canonical_json(value))

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "missing or unknown fields"
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_product_input_requires_all_nine_toolchain_digests(self) -> None:
        path = self.preflight / "product-input.json"
        value = json.loads(path.read_bytes())
        del value["toolchain"]["uiDependenciesTreeSha256"]
        path.write_bytes(_canonical_json(value))

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "missing or unknown fields"
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_product_input_source_must_equal_clean_repository(self) -> None:
        path = self.preflight / "product-input.json"
        value = json.loads(path.read_bytes())
        value["source"]["repository_commit"] = "d" * 40
        path.write_bytes(_canonical_json(value))

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "differs from the clean repository"
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_signing_plan_order_must_close_over_component_digests(self) -> None:
        path = self.preflight / "signing-plan.json"
        value = json.loads(path.read_bytes())
        value["order"] = ["host"]
        path.write_bytes(_canonical_json(value))

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "fixed inside-out order"
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_allocation_ledger_unknown_field_is_rejected(self) -> None:
        path = self.repository / "docs/release/build-allocations-v040.json"
        value = json.loads(path.read_bytes())
        value["unexpected"] = True
        path.write_bytes(_canonical_json(value))

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "allocation ledger"
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_noncanonical_json_is_rejected_before_consumption(self) -> None:
        (self.preflight / "signing-plan.json").write_text(
            '{ "document": "candidate-signing-plan-v1" }\n', encoding="utf-8"
        )

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "not canonical JSON"
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_nonfinite_json_constant_is_rejected_before_consumption(self) -> None:
        (self.preflight / "signing-plan.json").write_bytes(
            b'{"components":{"host":NaN},"document":"cfm-ga-signing-plan-v1",'
            b'"order":["host"],"product":{"build_number":"40038",'
            b'"version":"0.4.0"},"schema_version":1}\n'
        )

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "non-finite constant"
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_unknown_candidate_root_entry_is_rejected(self) -> None:
        (self.preflight / "unbound-cache").mkdir()

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "fixed freeze layout"
        ):
            self.freeze()

    def test_missing_or_forged_signing_preflight_does_not_consume_ga(self) -> None:
        original = self.signing_preflight_path.read_bytes()
        self.signing_preflight_path.unlink()
        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "signing preflight"
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

        self.signing_preflight_path.write_bytes(original)
        self.signing_preflight_path.chmod(0o600)
        forged = json.loads(original)
        forged["notary"]["historyProbe"] = "failed"
        self.signing_preflight_path.write_bytes(_canonical_json(forged))
        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "signing preflight"
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_copied_profile_or_updater_custody_failure_does_not_consume_ga(self) -> None:
        host_profile = self.preflight / "profiles/host.provisionprofile"
        host_profile.write_bytes(b"different-host-profile")
        with self.assertRaises(candidate_freeze.CandidateFreezeError):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

        host_profile.write_bytes(b"host-profile")
        with patch.object(
            candidate_freeze,
            "verify_live_custody_metadata",
            side_effect=release_signing_preflight.SigningPreflightError(
                "updater private key changed after preflight"
            ),
        ):
            with self.assertRaisesRegex(
                candidate_freeze.CandidateFreezeError, "updater custody"
            ) as raised:
                self.freeze()
        self.assertEqual(raised.exception.code, "signing_custody_readiness_invalid")
        self.assertFalse(raised.exception.consumed)
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_frozen_reopen_is_independent_of_live_external_readiness(self) -> None:
        frozen = self.freeze()

        with (
            patch.object(
                candidate_freeze,
                "verify_live_custody_metadata",
                side_effect=AssertionError(
                    "frozen verification touched the live Keychain"
                ),
            ),
            patch.object(
                candidate_freeze,
                "verify_live_profile_validity",
                side_effect=AssertionError(
                    "frozen verification touched live profile readiness"
                ),
            ),
        ):
            reopened = candidate_freeze.verify_frozen_candidate(self.repository)

        self.assertEqual(reopened.intent_sha256, frozen.intent_sha256)

    def test_live_profile_failure_does_not_consume_ga(self) -> None:
        with patch.object(
            candidate_freeze,
            "verify_live_profile_validity",
            side_effect=release_signing_preflight.SigningPreflightError(
                "host provisioning profile is outside its live signing window"
            ),
        ):
            with self.assertRaisesRegex(
                candidate_freeze.CandidateFreezeError,
                "not currently signable",
            ) as raised:
                self.freeze()

        self.assertEqual(raised.exception.code, "signing_profile_readiness_invalid")
        self.assertFalse(raised.exception.consumed)
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_updater_possession_failure_does_not_consume_ga(self) -> None:
        with patch.object(
            candidate_freeze,
            "verify_possession_proof",
            side_effect=candidate_freeze.UpdaterKeyPossessionError(
                "fixture possession failure"
            ),
        ):
            with self.assertRaisesRegex(
                candidate_freeze.CandidateFreezeError,
                "live updater-key possession proof",
            ):
                self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_signing_material_directories_reject_unbound_entries(self) -> None:
        (self.preflight / "profiles/.updater-key-possession.crashed").mkdir()

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError,
            "fixed private layout",
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_symlink_is_rejected_before_consumption(self) -> None:
        app = self.preflight / "pre-sign/Clash for Mac.app"
        os.symlink("Contents", app / "Alias")

        with self.assertRaisesRegex(candidate_freeze.CandidateFreezeError, "symlink"):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_fixed_post_freeze_outputs_do_not_rewrite_frozen_inputs(self) -> None:
        self.freeze()
        for name in (
            "signing-output",
            "transactions",
            "signed",
            "stage-inputs",
            "prepackage",
            "packages",
            "ga-acceptance",
            "publication",
        ):
            (self.final / name).mkdir()

        receipt = candidate_freeze.verify_frozen_candidate(self.repository)

        self.assertEqual(receipt.root, self.final)
        (self.final / "unclassified-output").mkdir()
        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "cannot be reopened exactly"
        ):
            candidate_freeze.verify_frozen_candidate(self.repository)

    def test_post_freeze_output_symlink_is_rejected(self) -> None:
        self.freeze()
        os.symlink("pre-sign", self.final / "stage-inputs")

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "cannot be reopened exactly"
        ):
            candidate_freeze.verify_frozen_candidate(self.repository)

    def test_exact_native_bridge_framework_symlinks_are_frozen(self) -> None:
        for framework in (
            self.preflight
            / "pre-sign/Clash for Mac.app/Contents/Frameworks/CFWNativeBridge.framework",
            self.preflight / "native-products/CFWNativeBridge.framework",
        ):
            version = framework / "Versions/A"
            (version / "Resources").mkdir(parents=True)
            (version / "Headers").mkdir()
            (version / "Modules").mkdir()
            (version / "CFWNativeBridge").write_bytes(b"unsigned-framework")
            os.symlink("A", framework / "Versions/Current")
            os.symlink(
                "Versions/Current/CFWNativeBridge", framework / "CFWNativeBridge"
            )
            os.symlink("Versions/Current/Resources", framework / "Resources")
            os.symlink("Versions/Current/Headers", framework / "Headers")
            os.symlink("Versions/Current/Modules", framework / "Modules")

        frozen = self.freeze()

        self.assertEqual(frozen.root, self.final)
        candidate_freeze.verify_frozen_candidate(self.repository)

    def test_framework_symlink_target_drift_is_rejected_before_consumption(self) -> None:
        framework = (
            self.preflight
            / "pre-sign/Clash for Mac.app/Contents/Frameworks/CFWNativeBridge.framework"
        )
        framework.mkdir(parents=True)
        os.symlink("/tmp/escape", framework / "Resources")

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "fixed layout"
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_framework_shaped_symlink_outside_product_tree_is_rejected(self) -> None:
        framework = self.preflight / "profiles/CFWNativeBridge.framework"
        framework.mkdir()
        os.symlink("Versions/Current/Resources", framework / "Resources")

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "fixed private layout"
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_hardlink_is_rejected_before_consumption(self) -> None:
        native = self.preflight / "native-products"
        os.link(native / "CFWGlobalAuthority", native / "CFWGlobalAuthority-copy")

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "hard-linked file"
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_special_file_is_rejected_before_consumption(self) -> None:
        os.mkfifo(self.preflight / "profiles/untrusted.fifo")

        with self.assertRaisesRegex(
            candidate_freeze.CandidateFreezeError, "fixed private layout"
        ):
            self.freeze()
        self.assertFalse((self.preflight / "candidate-freeze/intent.json").exists())

    def test_intent_and_tree_files_and_directories_receive_stable_barriers(self) -> None:
        real_sync = candidate_freeze.full_fsync
        observed_types: list[int] = []

        def observe(descriptor: int) -> None:
            observed_types.append(stat.S_IFMT(os.fstat(descriptor).st_mode))
            real_sync(descriptor)

        with patch.object(candidate_freeze, "_stable_sync", side_effect=observe):
            self.freeze()

        self.assertIn(stat.S_IFREG, observed_types)
        self.assertIn(stat.S_IFDIR, observed_types)

    def test_fresh_freeze_refuses_existing_frozen_candidate(self) -> None:
        self.freeze()

        with self.assertRaises(candidate_freeze.CandidateAlreadyConsumed):
            self.freeze()

    def test_operational_updater_reopen_cause_remains_typed(self) -> None:
        self.freeze()

        def unavailable(_repository: Path, _root: Path) -> object:
            raise candidate_freeze.UpdaterKeyPossessionOperationalError("timeout")

        with self.assertRaises(candidate_freeze.CandidateFreezeError) as caught:
            candidate_freeze.verify_frozen_candidate(
                self.repository,
                possession_verifier=unavailable,
            )
        self.assertEqual(caught.exception.code, "updater_verifier_unavailable")
        self.assertTrue(caught.exception.consumed)

    def test_generic_updater_reopen_failure_stays_quarantined(self) -> None:
        self.freeze()

        def invalid(_repository: Path, _root: Path) -> object:
            raise candidate_freeze.UpdaterKeyPossessionError(
                "injected semantic proof mismatch"
            )

        with self.assertRaises(
            candidate_freeze.CandidateFreezeQuarantined
        ) as caught:
            candidate_freeze.verify_frozen_candidate(
                self.repository,
                possession_verifier=invalid,
            )
        self.assertEqual(caught.exception.code, "candidate_freeze_quarantined")

    def test_default_possession_verifier_is_resolved_at_call_time(self) -> None:
        self.freeze()
        with patch.object(
            candidate_freeze,
            "verify_possession_proof",
            side_effect=candidate_freeze.UpdaterKeyPossessionOperationalError(
                "start"
            ),
        ) as verifier, self.assertRaises(
            candidate_freeze.CandidateFreezeError
        ) as caught:
            candidate_freeze.verify_frozen_candidate(self.repository)
        verifier.assert_called_once_with(self.repository, self.final)
        self.assertEqual(caught.exception.code, "updater_verifier_unavailable")


if __name__ == "__main__":
    unittest.main()
