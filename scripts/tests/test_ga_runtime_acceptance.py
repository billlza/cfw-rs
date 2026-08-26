from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from typing import Any
import unittest
from unittest.mock import patch

from scripts.ga_runtime_acceptance import (
    ACCEPTANCE_RELATIVE,
    CHECKS,
    CHECK_DOCUMENT,
    COLLECTION_RELATIVE,
    COLLECTION_DOCUMENT,
    COLLECTION_EVENT_DOCUMENT,
    COLLECTION_SUCCESS_STEPS,
    COMMAND_DOCUMENT,
    DOCUMENT,
    FROM_BUILD,
    GARuntimeAcceptanceError,
    GACollectionRecoveryRequired,
    HIGH_RISK_PROBES,
    OFF_PROOF_COMMAND,
    PCAP_FILES,
    PROCESS_OBSERVATION_COMMAND,
    ProductionCollectorRuntime,
    PRODUCT_VERSION,
    RAW_FILE_NAMES,
    RAW_ROOT_RELATIVE,
    SCHEMA_VERSION,
    SECRET_POLICY,
    SHUTDOWN_APPLE_EVENT,
    TO_BUILD,
    TRAFFIC_CHECKS,
    TRAFFIC_POLICY,
    _confirm_snapshot,
    _arguments,
    _derive_capture_token,
    _fixed_paths,
    collect_ga_runtime_acceptance,
    recover_ga_runtime_collection,
    seal_ga_runtime_acceptance,
    self_check,
    validate_ga_runtime_acceptance,
)
from scripts.harness.packet_evidence import packet_capture_filter_argv
from scripts.physical_capture.packet_host import (
    PacketCaptureDisposition,
    PacketHostError,
    PacketHostReceipt,
    PacketHostSnapshot,
)
from scripts.publication.common import PublicationError, canonical_json, sha256_bytes
from scripts.publication.durable_file import DurabilityOutcomeUnknown
from scripts.tests.physical_evidence_fixture import pcap_bytes


DIGESTS = {
    "dmg_gatekeeper_sha256": "1" * 64,
    "dmg_set_seal_sha256": "2" * 64,
    "dmg_sha256": "3" * 64,
    "install_journal_sha256": "4" * 64,
    "service_journal_tree_sha256": "5" * 64,
}
APP_TREE = "6" * 64
SESSION_ID = "12345678-1234-4234-8234-123456789abc"
CHALLENGE = base64.urlsafe_b64encode(b"C" * 32).decode("ascii").rstrip("=")
REPOSITORY = Path(__file__).resolve().parent.parent.parent


def prepackage_stage_verifier(_repository: Path) -> dict[str, object]:
    return {}


def command(
    argv: list[str],
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    started_at: str = "2026-07-27T11:59:59Z",
    finished_at: str = "2026-07-27T12:00:06Z",
) -> dict[str, object]:
    return {
        "argv": argv,
        "document": COMMAND_DOCUMENT,
        "exit_code": exit_code,
        "finished_at": finished_at,
        "schema_version": SCHEMA_VERSION,
        "started_at": started_at,
        "stderr": stderr,
        "stdout": stdout,
    }


def check(check_id: str, **fields: object) -> dict[str, object]:
    return {
        "check_id": check_id,
        "collection": {"challenge": CHALLENGE, "session_id": SESSION_ID},
        "document": CHECK_DOCUMENT,
        "schema_version": SCHEMA_VERSION,
        **fields,
    }


def host_observation(case_id: str, *, stop_cleanup: bool = False) -> dict[str, Any]:
    baseline = {
        "config_digest": "a" * 64,
        "desired_mode": "tunnel",
        "generation": 10,
        "ipv6_enabled": True,
        "owner": "packet_tunnel_system_extension",
        "phase": "tunnel_active",
        "ready": True,
    }
    test = (
        {
            "config_digest": None,
            "desired_mode": "off",
            "generation": 11,
            "ipv6_enabled": False,
            "owner": None,
            "phase": "off",
            "ready": False,
        }
        if stop_cleanup
        else {
            "config_digest": "b" * 64,
            "desired_mode": "tunnel",
            "generation": 11,
            "ipv6_enabled": True,
            "owner": "packet_tunnel_system_extension",
            "phase": "tunnel_active",
            "ready": True,
        }
    )
    restore = {**baseline, "generation": 12}
    return {
        "baseline": baseline,
        "baseline_observation_sequence": 20,
        "candidate_observation_sequence": 21,
        "case_id": case_id,
        "document": "cfw-packet-host-completed-v5",
        "restore": restore,
        "restore_observation_sequence": 22,
        "schema_version": 5,
        "sequence": 8,
        "session_id": hashlib.sha256(f"host:{case_id}".encode("ascii")).hexdigest(),
        "test": test,
        "test_observation_sequence": 21,
    }


def typed_host_receipt(case_id: str, *, stop_cleanup: bool = False) -> PacketHostReceipt:
    document = host_observation(case_id, stop_cleanup=stop_cleanup)

    def snapshot(name: str) -> PacketHostSnapshot:
        value = document[name]
        return PacketHostSnapshot(
            config_digest=value["config_digest"],
            desired_mode=value["desired_mode"],
            generation=value["generation"],
            ipv6_enabled=value["ipv6_enabled"],
            owner=value["owner"],
            phase=value["phase"],
            ready=value["ready"],
        )

    return PacketHostReceipt(
        baseline=snapshot("baseline"),
        baseline_observation_sequence=document["baseline_observation_sequence"],
        candidate_observation_sequence=document["candidate_observation_sequence"],
        case_id=case_id,
        restore=snapshot("restore"),
        restore_observation_sequence=document["restore_observation_sequence"],
        session_id=document["session_id"],
        test=snapshot("test"),
        test_observation_sequence=document["test_observation_sequence"],
    )


def off_proof_output() -> str:
    return canonical_json(
        {
            "action": "prove_off",
            "document": "cfw-current-service-maintenance-v2",
            "engine_status": "off",
            "global_authority": "enabled",
            "off_proof_profile": "current_engine_v6_authority_v1_1",
            "proxy_agent": "enabled",
        }
    ).decode("utf-8")


def guard() -> dict[str, object]:
    return {
        "cfw_processes": [
            {
                "binary_sha256": "7" * 64,
                "path": (
                    "/Applications/Clash for Windows.app/Contents/MacOS/"
                    "Clash for Windows"
                ),
                "pid": 111,
                "started_at": "Mon Jul 27 11:00:00 2026",
                "uid": 501,
            },
            {
                "binary_sha256": "8" * 64,
                "path": (
                    "/Applications/Clash for Windows.app/Contents/Resources/static/"
                    "files/darwin/x64/clash-darwin"
                ),
                "pid": 112,
                "started_at": "Mon Jul 27 11:00:01 2026",
                "uid": 0,
            },
        ],
        "dns_sha256": "9" * 64,
        "proxy_sha256": "a" * 64,
        "routes_ipv4_sha256": "b" * 64,
        "routes_ipv6_sha256": "c" * 64,
        "tun_sha256": "d" * 64,
    }


def process_table(*, running: bool) -> str:
    lines = [
        (
            "111 501 Mon Jul 27 11:00:00 2026 "
            "/Applications/Clash for Windows.app/Contents/MacOS/Clash for Windows"
        ),
        (
            "112 0 Mon Jul 27 11:00:01 2026 "
            "/Applications/Clash for Windows.app/Contents/Resources/static/files/"
            "darwin/x64/clash-darwin"
        ),
    ]
    if running:
        lines.append(
            "200 501 Mon Jul 27 11:59:58 2026 "
            "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac"
        )
    return "\n".join(lines) + "\n"


def system_extension_output() -> str:
    return (
        "1 extension(s)\n"
        "--- com.apple.system_extension.network_extension\n"
        "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
        "*\t*\tYKUPL7Z869\tcom.bill.clashformac.packet-tunnel "
        "(0.4.0/40034)\tCFWPacketTunnel\t[activated enabled]\n"
    )


class RuntimeFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name).resolve()
        self.acceptance, self.raw_root = _fixed_paths(self.repository)
        self.acceptance.parent.mkdir(parents=True)
        self.acceptance.parent.chmod(0o700)
        self.raw_root.mkdir(mode=0o700)
        self.expected = {
            "checks": CHECKS,
            "document": DOCUMENT,
            **DIGESTS,
            "from_build": FROM_BUILD,
            "product_version": PRODUCT_VERSION,
            "to_build": TO_BUILD,
        }
        self.documents: dict[str, dict[str, object]] = {}
        self.pcaps: dict[str, bytes] = {}
        self._build()
        self.write_all()
        self.write_collection_receipt()

    def cleanup(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _traffic_tokens(check_id: str) -> dict[str, str]:
        return {
            stage: _derive_capture_token(CHALLENGE, check_id, stage)
            for stage in ("start", "target", "end")
        }

    def _traffic(self, check_id: str) -> dict[str, object]:
        policy = TRAFFIC_POLICY[check_id]
        tokens = self._traffic_tokens(check_id)
        pcap_name = f"{check_id.replace('_', '-')}.pcap"
        capture = pcap_bytes(
            start_marker=tokens["start"].encode("ascii"),
            token=tokens["target"].encode("ascii"),
            end_marker=tokens["end"].encode("ascii"),
            include_token=True,
            protocol=policy["protocol"],
            family="ipv4",
            local_address="198.18.64.1",
            remote_address=policy["remote_address"],
            local_port=41000,
            remote_port=policy["remote_port"],
            link_type=1,
        )
        self.pcaps[pcap_name] = capture
        sender_commands = []
        stage_times = {
            "start": ("2026-07-27T11:59:59.500000Z", "2026-07-27T12:00:00.500000Z"),
            "target": ("2026-07-27T12:00:00.500000Z", "2026-07-27T12:00:01.500000Z"),
            "end": ("2026-07-27T12:00:04.500000Z", "2026-07-27T12:00:05.500000Z"),
        }
        for stage in ("start", "target", "end"):
            token = tokens[stage]
            sender_result = {
                "bytes_submitted": len(token),
                "case_id": policy["case_id"],
                "dns_result": None,
                "document": "cfw-packet-send-stage-result-v2",
                "local_address": "198.18.64.1",
                "local_port": 41000,
                "remote_address": policy["remote_address"],
                "remote_port": policy["remote_port"],
                "schema_version": 2,
                "stage": stage,
                "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
                "transport": policy["protocol"],
            }
            if policy["protocol"] == "dns":
                sender_result.update(
                    {
                        "dns_result": {
                            "query": {
                                "addresses": ["192.0.2.1"],
                                "name": f"{token}.evidence.test",
                                "token_sha256": hashlib.sha256(
                                    token.encode("ascii")
                                ).hexdigest(),
                            },
                            "requested_type": "A",
                            "resolver_role": "primary",
                            "trigger": "getaddrinfo",
                        },
                        "local_address": None,
                        "local_port": None,
                        "remote_address": None,
                        "remote_port": None,
                        "transport": "resolver",
                    }
                )
            argv = [
                os.sys.executable,
                "-I",
                "-S",
                "-B",
                "-W",
                "error",
                "scripts/physical_capture/packet_sender.py",
                "--case",
                policy["case_id"],
                "--stage",
                stage,
                "--protocol",
                policy["protocol"],
                "--family",
                "ipv4",
            ]
            if policy["protocol"] != "dns":
                argv.extend(
                    [
                        "--local-address",
                        "198.18.64.1",
                        "--local-port",
                        "0",
                        "--remote-address",
                        policy["remote_address"],
                        "--remote-port",
                        str(policy["remote_port"]),
                    ]
                )
            argv.extend(
                [
                    "--resolver-role",
                    "primary" if policy["protocol"] == "dns" else "none",
                    "--token",
                    token,
                    "--quic-version",
                    "0",
                    "--absence-window-ms",
                    "0",
                ]
            )
            sender_commands.append(
                command(
                    argv,
                    stdout=canonical_json(sender_result).decode("utf-8"),
                    started_at=stage_times[stage][0],
                    finished_at=stage_times[stage][1],
                )
            )
        capture_filter = packet_capture_filter_argv(
            case_id=policy["case_id"],
            tokens=(tokens["start"], tokens["target"], tokens["end"]),
        )
        return check(
            check_id,
            capture={
                "kind": "packet-pcap",
                "path": pcap_name,
                "sha256": sha256_bytes(capture),
                "size": len(capture),
            },
            capture_command=command(
                [
                    "/usr/sbin/tcpdump",
                    "-U",
                    "-n",
                    "-i",
                    "en0",
                    "-c",
                    str(policy["expected_records"]),
                    "-w",
                    "-",
                    *capture_filter,
                ],
                stderr=f"{policy['expected_records']} packets captured\n",
            ),
            endpoint={
                "family": "ipv4",
                "interface_name": "en0",
                "link_type": 1,
                "local_address": "198.18.64.1",
                "remote_address": policy["remote_address"],
                "remote_port": policy["remote_port"],
            },
            host_observation=host_observation(policy["case_id"]),
            observation_ms=5000,
            protocol=policy["protocol"],
            send_commands=sender_commands,
            tokens=tokens,
        )

    def _build(self) -> None:
        bindings = copy.deepcopy(DIGESTS)
        self.documents["exact-dmg-install.json"] = check(
            "exact_dmg_install",
            bindings=bindings,
            commands={
                "dmg_gatekeeper": command(
                    [
                        "/usr/sbin/spctl",
                        "--assess",
                        "--type",
                        "open",
                        "--context",
                        "context:primary-signature",
                        "-vv",
                        (
                            "target/candidates/0.4.0/ga/40034/packages/dmg/v0.4.0/"
                            "Clash.for.Mac_0.4.0_arm64.dmg"
                        ),
                    ],
                    stderr="accepted\nsource=Notarized Developer ID\n",
                ),
                "dmg_set_verify": command(
                    [
                        os.sys.executable,
                        "scripts/release_artifact_set_cli.py",
                        "verify-dmg",
                        "--directory",
                        "target/candidates/0.4.0/ga/40034/packages/dmg/v0.4.0",
                        "--version",
                        "0.4.0",
                        "--repository",
                        ".",
                    ],
                    stdout=(
                        "DMG release set verified: target/candidates/0.4.0/ga/40034/"
                        "packages/dmg/v0.4.0\n"
                    ),
                ),
            },
            dmg_contained_app_tree_sha256=APP_TREE,
            installed_app_tree_sha256=APP_TREE,
        )
        self.documents["launch.json"] = check(
            "launch",
            launch_command=command(
                ["/usr/bin/open", "-a", "/Applications/Clash for Mac.app"]
            ),
            process_observation=command(
                ["/bin/ps", "-axo", "pid=,uid=,lstart=,comm="],
                stdout=process_table(running=True),
            ),
        )
        uid = os.geteuid()
        self.documents["service-registration.json"] = check(
            "service_registration",
            commands={
                "global_authority": command(
                    [
                        "/bin/launchctl",
                        "print",
                        "system/com.bill.clashformac.global-authority",
                    ],
                    stdout=(
                        "state = running\n"
                        "program = /Applications/Clash for Mac.app/Contents/Library/"
                        "HelperTools/CFWGlobalAuthority\n"
                    ),
                ),
                "proxy_agent": command(
                    [
                        "/bin/launchctl",
                        "print",
                        f"gui/{uid}/com.bill.clashformac.proxy-agent",
                    ],
                    stdout=(
                        "state = running\n"
                        "program = /Applications/Clash for Mac.app/Contents/Library/"
                        "LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent\n"
                    ),
                ),
            },
        )
        self.documents["system-extension.json"] = check(
            "system_extension",
            command=command(
                ["/usr/bin/systemextensionsctl", "list"],
                stdout=system_extension_output(),
            ),
        )
        rejection_receipts = []
        for _probe_id, argv, exit_code, expected_stderr in HIGH_RISK_PROBES:
            rejection_receipts.append(
                command(
                    list(argv),
                    stderr=expected_stderr,
                    exit_code=exit_code,
                )
            )
        self.documents["high-risk-rejections.json"] = check(
            "high_risk_rejections", observations=rejection_receipts
        )
        state = guard()
        self.documents["shutdown-restore.json"] = check(
            "shutdown_restore",
            after_guard=copy.deepcopy(state),
            before_guard=copy.deepcopy(state),
            host_process_observation=command(
                list(PROCESS_OBSERVATION_COMMAND),
                stdout=process_table(running=False),
                started_at="2026-07-27T12:00:07Z",
                finished_at="2026-07-27T12:00:08Z",
            ),
            off_proof_command=command(
                list(OFF_PROOF_COMMAND),
                stdout=off_proof_output(),
                started_at="2026-07-27T12:00:08Z",
                finished_at="2026-07-27T12:00:09Z",
            ),
            process_observation=command(
                list(PROCESS_OBSERVATION_COMMAND),
                stdout=process_table(running=False),
                started_at="2026-07-27T12:00:09Z",
                finished_at="2026-07-27T12:00:10Z",
            ),
            shutdown_command=command(
                list(SHUTDOWN_APPLE_EVENT),
                started_at="2026-07-27T12:00:06Z",
                finished_at="2026-07-27T12:00:07Z",
            ),
            stop_restore_observation=host_observation(
                "stop-cleanup", stop_cleanup=True
            ),
        )
        self.documents["legacy-cfw-preserved.json"] = check(
            "legacy_cfw_preserved",
            after_guard=copy.deepcopy(state),
            before_guard=copy.deepcopy(state),
            install_journal_sha256=DIGESTS["install_journal_sha256"],
            service_journal_tree_sha256=DIGESTS["service_journal_tree_sha256"],
        )
        for check_id in TRAFFIC_CHECKS:
            self.documents[f"{check_id.replace('_', '-')}.json"] = self._traffic(
                check_id
            )
        self.documents["network-extension.json"] = check(
            "network_extension",
            traffic_bindings={
                check_id: {
                    "case_id": TRAFFIC_POLICY[check_id]["case_id"],
                    "host_observation_sha256": sha256_bytes(
                        canonical_json(
                            self.documents[f"{check_id.replace('_', '-')}.json"][
                                "host_observation"
                            ]
                        )
                    ),
                }
                for check_id in TRAFFIC_CHECKS
            },
        )

    def _raw_bytes_without_scan(self) -> dict[str, bytes]:
        result = {
            name: canonical_json(value)
            for name, value in self.documents.items()
            if name != "credential-leak-scan.json"
        }
        result.update(self.pcaps)
        return result

    def rebuild_scan(self) -> None:
        corpus = []
        for name, data in sorted(self._raw_bytes_without_scan().items()):
            corpus.append(
                {"path": name, "sha256": sha256_bytes(data), "size": len(data)}
            )
        self.documents["credential-leak-scan.json"] = check(
            "credential_leak_scan",
            corpus=corpus,
            pattern_policy=SECRET_POLICY,
        )

    def write_all(self) -> None:
        self.rebuild_scan()
        for name in RAW_FILE_NAMES:
            data = (
                self.pcaps[name]
                if name in PCAP_FILES
                else canonical_json(self.documents[name])
            )
            path = self.raw_root / name
            path.write_bytes(data)
            path.chmod(0o600)

    def write_collection_receipt(self) -> None:
        root = self.repository.joinpath(*COLLECTION_RELATIVE.parts)
        root.mkdir(mode=0o700)
        intent = {
            "collection": {"challenge": CHALLENGE, "session_id": SESSION_ID},
            "document": COLLECTION_DOCUMENT,
            "package_bindings": {
                key: DIGESTS[key]
                for key in (
                    "dmg_gatekeeper_sha256",
                    "dmg_set_seal_sha256",
                    "dmg_sha256",
                )
            },
            "product": {
                "from_build": FROM_BUILD,
                "to_build": TO_BUILD,
                "version": PRODUCT_VERSION,
            },
            "schema_version": SCHEMA_VERSION,
        }
        intent_path = root / "intent.json"
        intent_path.write_bytes(canonical_json(intent))
        intent_path.chmod(0o600)
        pairs = [
            (phase, step)
            for step in COLLECTION_SUCCESS_STEPS
            for phase in ("started", "completed")
        ]
        pairs.append(("raw_published", "collection"))
        for index, (phase, step) in enumerate(pairs):
            event = {
                "collection": {"challenge": CHALLENGE, "session_id": SESSION_ID},
                "command_sha256": None,
                "document": COLLECTION_EVENT_DOCUMENT,
                "phase": phase,
                "schema_version": SCHEMA_VERSION,
                "sequence": index,
                "step": step,
            }
            path = root / f"event-{index:03d}.json"
            path.write_bytes(canonical_json(event))
            path.chmod(0o600)

    def rewrite_json(self, name: str) -> None:
        path = self.raw_root / name
        path.write_bytes(canonical_json(self.documents[name]))
        path.chmod(0o600)

    def remove_unsealed_raw_tree(self) -> None:
        for name in sorted(os.listdir(self.raw_root)):
            (self.raw_root / name).unlink()
        self.raw_root.rmdir()
        collection = self.repository.joinpath(*COLLECTION_RELATIVE.parts)
        for name in sorted(os.listdir(collection)):
            (collection / name).unlink()
        collection.rmdir()

    def seal(self) -> dict[str, dict[str, str]]:
        with patch(
            "scripts.ga_runtime_acceptance._installed_candidate_tree",
            return_value=APP_TREE,
        ), patch(
            "scripts.ga_runtime_acceptance._dmg_contained_candidate_tree",
            return_value=APP_TREE,
        ), patch(
            "scripts.ga_runtime_acceptance._installed_guard_baseline",
            return_value=guard(),
        ):
            return seal_ga_runtime_acceptance(
                repository=self.repository,
                expected=self.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )

    def validate(self) -> dict[str, dict[str, str]]:
        with patch(
            "scripts.ga_runtime_acceptance._installed_candidate_tree",
            return_value=APP_TREE,
        ), patch(
            "scripts.ga_runtime_acceptance._dmg_contained_candidate_tree",
            return_value=APP_TREE,
        ), patch(
            "scripts.ga_runtime_acceptance._installed_guard_baseline",
            return_value=guard(),
        ):
            return validate_ga_runtime_acceptance(
                repository=self.repository,
                acceptance_path=self.acceptance,
                raw_evidence_root=self.raw_root,
                expected=self.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )


class GARuntimeAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RuntimeFixture()
        self.addCleanup(self.fixture.cleanup)

    def test_contract_has_fixed_paths_and_twelve_raw_derived_checks(self) -> None:
        self_check()
        self.assertEqual((PRODUCT_VERSION, FROM_BUILD, TO_BUILD), ("0.4.0", "40019", "40034"))
        self.assertEqual(len(CHECKS), 12)
        self.assertEqual(len(RAW_FILE_NAMES), 15)
        self.assertEqual(
            ACCEPTANCE_RELATIVE,
            Path(
                "target/candidates/0.4.0/ga/40034/stage-inputs/ga-acceptance/"
                "runtime-acceptance.json"
            ),
        )
        self.assertEqual(
            RAW_ROOT_RELATIVE,
            Path(
                "target/candidates/0.4.0/ga/40034/stage-inputs/ga-acceptance/"
                "runtime-evidence"
            ),
        )

    def test_complete_raw_evidence_seals_and_reopens_exact_records(self) -> None:
        result = self.fixture.seal()
        self.assertEqual(result, self.fixture.validate())
        self.assertEqual(result["adapter"]["path"], ACCEPTANCE_RELATIVE.as_posix())
        adapter = json.loads(self.fixture.acceptance.read_text(encoding="utf-8"))
        self.assertEqual([entry["id"] for entry in adapter["checks"]], list(CHECKS))
        self.assertNotIn("passed", self.fixture.acceptance.read_text(encoding="utf-8"))

    def test_adapter_rename_reply_loss_is_outcome_unknown_and_recoverable(self) -> None:
        from scripts.publication.durable_file import promote_private_pending

        def promote_then_lose_reply(pending: Path, destination: Path) -> None:
            promote_private_pending(pending, destination)
            raise DurabilityOutcomeUnknown("simulated adapter rename reply loss")

        with patch(
            "scripts.ga_runtime_acceptance.promote_private_pending",
            side_effect=promote_then_lose_reply,
        ), self.assertRaises(DurabilityOutcomeUnknown):
            self.fixture.seal()
        self.assertTrue(self.fixture.acceptance.is_file())
        self.assertEqual(self.fixture.seal(), self.fixture.validate())

    def test_missing_or_unexpected_raw_file_fails_closed(self) -> None:
        (self.fixture.raw_root / "launch.json").unlink()
        with self.assertRaisesRegex(Exception, "missing or unexpected file set"):
            self.fixture.seal()

    def test_tampered_adapter_cannot_be_reused(self) -> None:
        self.fixture.seal()
        document = json.loads(self.fixture.acceptance.read_text(encoding="utf-8"))
        document["product_version"] = "0.4.1"
        self.fixture.acceptance.write_bytes(canonical_json(document))
        self.fixture.acceptance.chmod(0o600)
        with self.assertRaisesRegex(Exception, "differs from reopened raw evidence"):
            self.fixture.validate()

    def test_tampered_collection_receipt_invalidates_the_adapter(self) -> None:
        self.fixture.seal()
        collection = self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts)
        event = collection / "event-000.json"
        document = json.loads(event.read_text(encoding="utf-8"))
        document["phase"] = "forged-completed"
        event.write_bytes(canonical_json(document))
        event.chmod(0o600)
        with self.assertRaisesRegex(Exception, "fixed command registry"):
            self.fixture.validate()

    def test_duplicate_json_key_is_rejected(self) -> None:
        path = self.fixture.raw_root / "launch.json"
        path.write_bytes(
            b'{"check_id":"launch","check_id":"launch","document":"x"}\n'
        )
        path.chmod(0o600)
        with self.assertRaisesRegex(Exception, "repeats JSON field"):
            self.fixture.seal()

    def test_symlink_and_hardlink_evidence_are_rejected(self) -> None:
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                fixture = RuntimeFixture()
                try:
                    source = fixture.raw_root / "launch.json"
                    target = fixture.acceptance.parent / "launch-original.json"
                    source.rename(target)
                    if kind == "symlink":
                        source.symlink_to(Path("..") / target.name)
                    else:
                        os.link(target, source)
                    with self.assertRaisesRegex(Exception, "single-link 0600 file"):
                        fixture.seal()
                finally:
                    fixture.cleanup()

    def test_local_all_passed_summary_cannot_satisfy_a_check(self) -> None:
        self.fixture.documents["launch.json"] = {
            "checks": {name: "passed" for name in CHECKS},
            "document": DOCUMENT,
            "schema_version": 1,
        }
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "unexpected field set"):
            self.fixture.seal()

    def test_partial_traffic_without_target_token_is_rejected(self) -> None:
        check_id = "udp_traffic"
        name = "udp-traffic.pcap"
        document = self.fixture.documents["udp-traffic.json"]
        tokens = document["tokens"]
        policy = TRAFFIC_POLICY[check_id]
        capture = pcap_bytes(
            start_marker=tokens["start"].encode("ascii"),
            token=tokens["target"].encode("ascii"),
            end_marker=tokens["end"].encode("ascii"),
            include_token=False,
            protocol="udp",
            family="ipv4",
            local_address="198.18.64.1",
            remote_address=policy["remote_address"],
            local_port=41000,
            remote_port=policy["remote_port"],
            link_type=1,
        )
        self.fixture.pcaps[name] = capture
        document["capture"] = {
            "kind": "packet-pcap",
            "path": name,
            "sha256": sha256_bytes(capture),
            "size": len(capture),
        }
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "do not prove the required traffic"):
            self.fixture.seal()

    def test_traffic_requires_authenticated_candidate_tunnel_state(self) -> None:
        traffic = self.fixture.documents["tcp-traffic.json"]
        traffic["host_observation"]["test"]["owner"] = "proxy_agent"
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "ready Packet Tunnel observation"):
            self.fixture.seal()

    def test_network_extension_binding_cannot_forge_a_passed_summary(self) -> None:
        network = self.fixture.documents["network-extension.json"]
        network["traffic_bindings"] = {"all_passed": True}
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "unexpected field set"):
            self.fixture.seal()

    def test_packet_host_session_cannot_be_replayed_across_checks(self) -> None:
        tcp = self.fixture.documents["tcp-traffic.json"]["host_observation"]
        udp = self.fixture.documents["udp-traffic.json"]["host_observation"]
        udp["session_id"] = tcp["session_id"]
        network = self.fixture.documents["network-extension.json"]
        network["traffic_bindings"]["udp_traffic"][
            "host_observation_sha256"
        ] = sha256_bytes(canonical_json(udp))
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "reuse an authenticated Packet Host session"):
            self.fixture.seal()

    def test_credential_scan_fails_without_echoing_secret(self) -> None:
        secret = "-----BEGIN PRIVATE KEY-----fixture-private-material"
        launch = self.fixture.documents["launch.json"]
        launch["process_observation"]["stderr"] = secret
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "credential-like material") as captured:
            self.fixture.seal()
        self.assertNotIn(secret, str(captured.exception))

    def test_output_bound_is_enforced(self) -> None:
        launch = self.fixture.documents["launch.json"]
        launch["process_observation"]["stderr"] = "x" * (256 * 1024 + 1)
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "bounded UTF-8 command output"):
            self.fixture.seal()

    def test_before_after_cfw_state_drift_is_rejected(self) -> None:
        shutdown = self.fixture.documents["shutdown-restore.json"]
        shutdown["after_guard"]["proxy_sha256"] = "e" * 64
        legacy = self.fixture.documents["legacy-cfw-preserved.json"]
        legacy["after_guard"] = copy.deepcopy(shutdown["after_guard"])
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "restore the exact pre-run CFW state"):
            self.fixture.seal()

    def test_shutdown_allows_recommissioned_service_process_only_with_off_proof(self) -> None:
        shutdown = self.fixture.documents["shutdown-restore.json"]
        shutdown["process_observation"]["stdout"] += (
            "201 501 Mon Jul 27 12:00:07 2026 "
            "/Applications/Clash for Mac.app/Contents/Library/LoginItems/"
            "CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent\n"
        )
        self.fixture.write_all()
        self.fixture.seal()
        shutdown["off_proof_command"]["stdout"] = ""
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "did not prove the candidate globally Off"):
            self.fixture.seal()

    def test_package_or_journal_binding_drift_is_rejected(self) -> None:
        self.fixture.expected["dmg_sha256"] = "f" * 64
        with self.assertRaisesRegex(Exception, "different package or journal"):
            self.fixture.seal()

    def test_dmg_contained_app_tree_cannot_be_self_assigned_from_install(self) -> None:
        with patch(
            "scripts.ga_runtime_acceptance._installed_candidate_tree",
            return_value=APP_TREE,
        ), patch(
            "scripts.ga_runtime_acceptance._dmg_contained_candidate_tree",
            return_value="f" * 64,
        ), patch(
            "scripts.ga_runtime_acceptance._installed_guard_baseline",
            return_value=guard(),
        ), self.assertRaisesRegex(Exception, "DMG-contained app and installed"):
            seal_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )

    def test_toctou_replacement_after_validation_is_rejected(self) -> None:
        self.fixture.seal()
        original = _confirm_snapshot

        def replace_then_confirm(root: Path, snapshots: object) -> None:
            path = root / "launch.json"
            data = path.read_bytes()
            replacement = root / ".launch-replacement"
            replacement.write_bytes(data)
            replacement.chmod(0o600)
            replacement.replace(path)
            original(root, snapshots)

        with patch(
            "scripts.ga_runtime_acceptance._confirm_snapshot",
            side_effect=replace_then_confirm,
        ), self.assertRaisesRegex(Exception, "changed during verification"):
            self.fixture.validate()


class FakeCollectorRuntime:
    def __init__(self, fixture: RuntimeFixture, *, fail_launch: bool = False) -> None:
        self.fixture = fixture
        self.fail_launch = fail_launch
        self.calls: list[tuple[list[str], int]] = []
        documents = fixture.documents
        self.receipts: dict[tuple[str, ...], list[dict[str, object]]] = {}

        def add(receipt: dict[str, object]) -> None:
            self.receipts.setdefault(tuple(receipt["argv"]), []).append(
                copy.deepcopy(receipt)
            )

        install_commands = documents["exact-dmg-install.json"]["commands"]
        add(install_commands["dmg_gatekeeper"])
        add(install_commands["dmg_set_verify"])
        add(documents["launch.json"]["launch_command"])
        add(documents["launch.json"]["process_observation"])
        services = documents["service-registration.json"]["commands"]
        add(services["proxy_agent"])
        add(services["global_authority"])
        add(documents["system-extension.json"]["command"])
        for receipt in documents["high-risk-rejections.json"]["observations"]:
            add(receipt)
        add(documents["shutdown-restore.json"]["shutdown_command"])
        add(documents["shutdown-restore.json"]["host_process_observation"])
        add(documents["shutdown-restore.json"]["off_proof_command"])
        add(documents["shutdown-restore.json"]["process_observation"])
        self.guards = [guard(), guard()]

    def run(self, argv: list[str], *, timeout: int = 900) -> dict[str, object]:
        self.calls.append((list(argv), timeout))
        if self.fail_launch and argv[:2] == ["/usr/bin/open", "-a"]:
            raise GARuntimeAcceptanceError("simulated launch failure")
        queue = self.receipts.get(tuple(argv))
        if not queue:
            raise AssertionError(f"unexpected collector command: {argv}")
        return queue.pop(0)

    def capture_guard(self) -> dict[str, object]:
        if not self.guards:
            raise AssertionError("unexpected extra CFW guard capture")
        return copy.deepcopy(self.guards.pop(0))

    def capture_traffic(
        self, check_id: str, tokens: dict[str, str]
    ) -> tuple[dict[str, object], bytes]:
        document = self.fixture.documents[f"{check_id.replace('_', '-')}.json"]
        self.assert_tokens(tokens, document["tokens"])
        return (
            {
                "capture_command": copy.deepcopy(document["capture_command"]),
                "endpoint": copy.deepcopy(document["endpoint"]),
                "host_observation": copy.deepcopy(document["host_observation"]),
                "observation_ms": document["observation_ms"],
                "send_commands": copy.deepcopy(document["send_commands"]),
            },
            self.fixture.pcaps[f"{check_id.replace('_', '-')}.pcap"],
        )

    def capture_stop_restore(self) -> dict[str, object]:
        return copy.deepcopy(
            self.fixture.documents["shutdown-restore.json"][
                "stop_restore_observation"
            ]
        )

    def await_host_absence(self, *, timeout: int) -> dict[str, object]:
        return self.run(list(PROCESS_OBSERVATION_COMMAND), timeout=timeout)

    @staticmethod
    def assert_tokens(observed: dict[str, str], expected: object) -> None:
        if observed != expected:
            raise AssertionError("collector traffic tokens differ from the session challenge")


class GARuntimeCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RuntimeFixture()
        self.fixture.remove_unsealed_raw_tree()
        self.addCleanup(self.fixture.cleanup)

    def _patch_evidence_sources(self):
        return (
            patch(
                "scripts.ga_runtime_acceptance._installed_candidate_tree",
                return_value=APP_TREE,
            ),
            patch(
                "scripts.ga_runtime_acceptance._dmg_contained_candidate_tree",
                return_value=APP_TREE,
            ),
            patch(
                "scripts.ga_runtime_acceptance._installed_guard_baseline",
                return_value=guard(),
            ),
        )

    def test_production_capture_is_inside_authenticated_host_test_stage(self) -> None:
        runtime = object.__new__(ProductionCollectorRuntime)
        tokens = RuntimeFixture._traffic_tokens("tcp_traffic")
        expected_capture = b"pcap-bytes"
        expected_traffic = {
            "capture_command": {},
            "endpoint": {},
            "observation_ms": 5000,
            "send_commands": [],
        }
        order: list[str] = []

        def transaction(*, case_id, begin_capture, exercise_test, finish_capture):
            self.assertEqual(case_id, "tcp-ipv4")
            order.append("host-begin")
            begin_capture(object())
            order.append("host-test")
            exercise_test(object())
            order.append("host-restore")
            finish_capture(object())
            return typed_host_receipt("tcp-ipv4")

        with patch.object(
            runtime,
            "_capture_traffic_bytes",
            return_value=(copy.deepcopy(expected_traffic), expected_capture),
        ) as capture_bytes, patch(
            "scripts.ga_runtime_acceptance.run_fixed_host_transaction",
            side_effect=transaction,
        ):
            traffic, capture = runtime.capture_traffic("tcp_traffic", tokens)
        self.assertEqual(order, ["host-begin", "host-test", "host-restore"])
        capture_bytes.assert_called_once_with("tcp_traffic", tokens)
        self.assertEqual(capture, expected_capture)
        self.assertEqual(traffic["host_observation"]["case_id"], "tcp-ipv4")

    def test_operator_approval_wait_expires_fail_closed(self) -> None:
        unavailable = PacketHostError("tunnel_unavailable", "Tunnel is not ready")

        def complete(_stage: object) -> PacketCaptureDisposition:
            return PacketCaptureDisposition.COMPLETE

        with patch(
            "scripts.ga_runtime_acceptance.run_fixed_host_transaction",
            side_effect=unavailable,
        ), patch(
            "scripts.ga_runtime_acceptance.time.monotonic",
            side_effect=(0.0, 601.0),
        ), self.assertRaisesRegex(Exception, "Tunnel is not ready"):
            ProductionCollectorRuntime._run_packet_host_transaction(
                case_id="tcp-ipv4",
                begin_capture=complete,
                exercise_test=complete,
                finish_capture=complete,
            )

    def test_collect_owns_fixed_commands_tokens_raw_bytes_and_atomic_publication(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2]:
            result = collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=runtime,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )
        self.assertEqual(result["adapter"]["path"], ACCEPTANCE_RELATIVE.as_posix())
        self.assertEqual(set(os.listdir(self.fixture.raw_root)), set(RAW_FILE_NAMES))
        commands = [argv for argv, _timeout in runtime.calls]
        self.assertIn(["/usr/bin/open", "-a", "/Applications/Clash for Mac.app"], commands)
        self.assertIn(["/usr/bin/systemextensionsctl", "list"], commands)
        self.assertNotIn("CFWLifecycleProbe", repr(commands))
        self.assertTrue(
            all(
                argv[0]
                == "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac"
                and list(argv) in commands
                for _probe_id, argv, _exit_code, _stderr in HIGH_RISK_PROBES
            )
        )
        self.assertTrue(all("run_current_service_transaction.sh" not in argv for argv in commands))
        self.assertTrue(all("run_dormant_app_install.sh" not in argv for argv in commands))
        self.assertEqual(runtime.guards, [])

    def test_cli_exposes_fixed_collect_and_recover_without_input_paths(self) -> None:
        self.assertEqual(_arguments(["collect"]).command, "collect")
        self.assertEqual(_arguments(["recover"]).command, "recover")
        with patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit):
            _arguments(["collect", "--input", "/tmp/untrusted"])
        with patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit):
            _arguments(["seal"])
        runner = REPOSITORY / "scripts/run_ga_runtime_acceptance.sh"
        source = runner.read_text(encoding="utf-8")
        self.assertTrue(os.access(runner, os.X_OK))
        self.assertIn("cfw_seal_release_tool_environment production", source)
        self.assertIn("cfw_run_release_python_script", source)
        self.assertIn('"$repo_root/scripts/ga_runtime_acceptance_cli.py"', source)

    def test_collect_refuses_to_start_before_authoritative_journals_close(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        with self.assertRaisesRegex(PublicationError, "expected bindings"):
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected={},
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=runtime,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )
        self.assertFalse(
            self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts).exists()
        )
        self.assertEqual(runtime.calls, [])

    def test_runtime_failure_requires_only_fixed_cleanup_recovery(self) -> None:
        failing = FakeCollectorRuntime(self.fixture, fail_launch=True)
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
            GACollectionRecoveryRequired
        ):
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=failing,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )
        recovery = FakeCollectorRuntime(self.fixture)
        # A failed open has no dashboard to quit; recovery observes absence,
        # proves global Off through the signed Host, then checks the final guard.
        process_receipt = copy.deepcopy(
            self.fixture.documents["shutdown-restore.json"]["process_observation"]
        )
        recovery.receipts = {
            tuple(PROCESS_OBSERVATION_COMMAND): [
                copy.deepcopy(process_receipt),
                copy.deepcopy(process_receipt),
                copy.deepcopy(process_receipt),
            ],
            tuple(OFF_PROOF_COMMAND): [
                copy.deepcopy(
                    self.fixture.documents["shutdown-restore.json"]["off_proof_command"]
                )
            ],
        }
        recovery.guards = [guard()]
        with patch(
            "scripts.ga_runtime_acceptance._installed_guard_baseline",
            return_value=guard(),
        ):
            archived = recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertTrue(archived.is_dir())
        recovered_commands = [argv for argv, _timeout in recovery.calls]
        self.assertEqual(
            recovered_commands,
            [
                list(PROCESS_OBSERVATION_COMMAND),
                list(PROCESS_OBSERVATION_COMMAND),
                list(OFF_PROOF_COMMAND),
                list(PROCESS_OBSERVATION_COMMAND),
            ],
        )

    def test_recovery_uses_normal_quit_when_the_installed_host_is_running(self) -> None:
        failing = FakeCollectorRuntime(self.fixture)
        system_command = self.fixture.documents["system-extension.json"]["command"]
        failing.receipts[tuple(system_command["argv"])] = []
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
            GACollectionRecoveryRequired
        ):
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=failing,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )

        recovery = FakeCollectorRuntime(self.fixture)
        shutdown = self.fixture.documents["shutdown-restore.json"]
        recovery.receipts = {
            tuple(PROCESS_OBSERVATION_COMMAND): [
                copy.deepcopy(self.fixture.documents["launch.json"]["process_observation"]),
                copy.deepcopy(shutdown["host_process_observation"]),
                copy.deepcopy(shutdown["process_observation"]),
            ],
            tuple(SHUTDOWN_APPLE_EVENT): [copy.deepcopy(shutdown["shutdown_command"])],
            tuple(OFF_PROOF_COMMAND): [copy.deepcopy(shutdown["off_proof_command"])],
        }
        recovery.guards = [guard()]
        with patch(
            "scripts.ga_runtime_acceptance._installed_guard_baseline",
            return_value=guard(),
        ):
            archived = recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertTrue(archived.is_dir())
        self.assertEqual(
            [argv for argv, _timeout in recovery.calls],
            [
                list(PROCESS_OBSERVATION_COMMAND),
                list(SHUTDOWN_APPLE_EVENT),
                list(PROCESS_OBSERVATION_COMMAND),
                list(OFF_PROOF_COMMAND),
                list(PROCESS_OBSERVATION_COMMAND),
            ],
        )


if __name__ == "__main__":
    unittest.main()
