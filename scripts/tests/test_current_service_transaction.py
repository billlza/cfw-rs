from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import current_service_transaction as service
from scripts import dormant_app_install as install


PREVIOUS = install.AppIdentity("0.4.0", "40019", "a" * 64)
CANDIDATE = install.CandidateIdentity(
    app=install.AppIdentity("0.4.0", "40022", "b" * 64),
    manifest_sha256="c" * 64,
    repository_commit="d" * 40,
    release_source_sha256="e" * 64,
)


def guard(*, proxy: str = "1" * 64) -> dict[str, object]:
    return {
        "cfw_processes": [
            {
                "binary_sha256": "2" * 64,
                "path": (
                    "/Applications/Clash for Windows.app/Contents/MacOS/"
                    "Clash for Windows"
                ),
                "pid": 100,
                "started_at": "Thu Jul 23 15:20:55 2026",
                "uid": os.geteuid(),
            },
            {
                "binary_sha256": "3" * 64,
                "path": (
                    "/Applications/Clash for Windows.app/Contents/Resources/"
                    "static/files/darwin/x64/clash-darwin"
                ),
                "pid": 101,
                "started_at": "Thu Jul 23 15:21:03 2026",
                "uid": 0,
            },
        ],
        "dns_sha256": "4" * 64,
        "proxy_sha256": proxy,
        "routes_ipv4_sha256": "5" * 64,
        "routes_ipv6_sha256": "6" * 64,
        "tun_sha256": "7" * 64,
    }


def registered_job(
    domain: str, *, program: str, build: str, signing_identifier: str, pid: int
) -> str:
    return "\n".join(
        (
            f"{domain} = {{",
            "\tmanaged_by = com.apple.xpc.ServiceManagement",
            "\tstate = running",
            f"\tprogram identifier = {program} (mode: 2)",
            "\tparent bundle identifier = com.bill.clashformac",
            f"\tparent bundle version = {build}",
            f"\tpid = {pid}",
            f'\t"signing-identifier" => "{signing_identifier}"',
            '\t"team-identifier" => "YKUPL7Z869"',
            "}",
            "",
        )
    )


def service_processes(*, extra: tuple[str, ...] = ()) -> str:
    lines = [
        (
            "648 501 Sun Aug 23 04:00:00 2026 "
            "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"
        ),
        (
            "6805 501 Sun Aug 23 04:01:00 2026 "
            "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent"
        ),
        (
            "6806 0 Sun Aug 23 04:01:00 2026 "
            "Contents/Library/HelperTools/CFWGlobalAuthority"
        ),
        *extra,
    ]
    return "\n".join(lines) + "\n"


class FakeRuntime:
    def __init__(self) -> None:
        self.runner = lambda arguments: (_ for _ in ()).throw(AssertionError(arguments))
        self.guards = [guard()]

    def capture_guard(self) -> dict[str, object]:
        if len(self.guards) > 1:
            return self.guards.pop(0)
        return self.guards[0]


class ServiceFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        repository = root / "repository"
        candidate = repository / "candidate" / install.TARGET_NAME
        target = root / "Applications" / install.TARGET_NAME
        candidate.mkdir(parents=True)
        target.mkdir(parents=True)
        self.paths = service.ServicePaths(
            install_paths=install.InstallPaths(
                repository=repository,
                candidate_app=candidate,
                candidate_manifest=candidate.parent / f"{install.TARGET_NAME}.manifest.json",
                target_parent=target.parent,
                operator_repository=repository,
            ),
            transaction_parent=target.parent,
        )
        self.runtime = FakeRuntime()
        self.transaction = service.CurrentServiceTransaction(self.paths, self.runtime)

    def cleanup(self) -> None:
        self.temporary.cleanup()


class ServiceEventStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = ServiceFixture()

    def tearDown(self) -> None:
        self.fixture.cleanup()

    def test_final_generation_uses_independent_fixed_service_journals(self) -> None:
        paths = service.ServicePaths.production("final")

        self.assertEqual(paths.install_paths.profile.build_number, "40023")
        self.assertEqual(
            paths.install_paths.profile.previous_build_number,
            "40022",
        )
        self.assertEqual(
            paths.transaction_directory.name,
            ".com.bill.clashformac.final-service-transaction-v1",
        )
        self.assertNotEqual(
            paths.transaction_directory.name,
            service.TRANSACTION_DIRECTORY,
        )

    def test_append_only_lineage_round_trips_every_phase(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, events = store.create(CANDIDATE, PREVIOUS, guard())
                for phase, action in zip(
                    service.PHASES[1:], service.ACTIONS[1:], strict=True
                ):
                    events.append(
                        store.append(
                            events,
                            phase=phase,
                            action=action,
                            guard=guard(),
                        )
                    )
                loaded = store.load()
        self.assertIsNotNone(loaded)
        loaded_intent, loaded_events = loaded or ({}, [])
        self.assertEqual(loaded_intent, intent)
        self.assertEqual(
            [event["phase"] for event in loaded_events], list(service.PHASES)
        )

    def test_initial_pending_directory_is_recovered_atomically(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, events = store.create(CANDIDATE, PREVIOUS, guard())
                os.rename(
                    self.fixture.paths.transaction_directory,
                    self.fixture.paths.pending_directory,
                )
                loaded = store.load()
        self.assertEqual(loaded, (intent, events))
        self.assertTrue(self.fixture.paths.transaction_directory.is_dir())
        self.assertFalse(self.fixture.paths.pending_directory.exists())

    def test_complete_pending_event_is_published_on_recovery(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                _intent, events = store.create(CANDIDATE, PREVIOUS, guard())
                with patch.object(
                    service.ServiceEventStore,
                    "_publish_pending_event",
                    side_effect=RuntimeError("simulated crash before rename"),
                ):
                    with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                        store.append(
                            events,
                            phase="proxy_unregistered",
                            action="unregister-proxy-agent",
                            guard=guard(),
                        )
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                loaded = store.load()
        self.assertEqual((loaded or ({}, [{}]))[1][-1]["phase"], "proxy_unregistered")
        self.assertFalse(
            (
                self.fixture.paths.transaction_directory
                / ".event-00000001.json.pending"
            ).exists()
        )

    def test_partial_pending_event_is_discarded_for_idempotent_replay(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                _intent, _events = store.create(CANDIDATE, PREVIOUS, guard())
        pending = (
            self.fixture.paths.transaction_directory
            / ".event-00000001.json.pending"
        )
        pending.write_bytes(b'{"partial"')
        pending.chmod(0o600)
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                loaded = store.load()
        self.assertEqual((loaded or ({}, [{}]))[1][-1]["phase"], "prepared")
        self.assertFalse(pending.exists())

    def test_pending_event_must_be_resynced_before_recovery_publication(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                _intent, events = store.create(CANDIDATE, PREVIOUS, guard())
                with patch.object(
                    service.ServiceEventStore,
                    "_publish_pending_event",
                    side_effect=RuntimeError("simulated crash before rename"),
                ):
                    with self.assertRaises(RuntimeError):
                        store.append(
                            events,
                            phase="proxy_unregistered",
                            action="unregister-proxy-agent",
                            guard=guard(),
                        )
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked(), patch.object(
                service.os, "fsync", side_effect=OSError("injected fsync failure")
            ):
                with self.assertRaisesRegex(OSError, "injected fsync failure"):
                    store.load()
        pending = (
            self.fixture.paths.transaction_directory
            / ".event-00000001.json.pending"
        )
        self.assertTrue(pending.is_file())
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                loaded = store.load()
        self.assertEqual((loaded or ({}, [{}]))[1][-1]["phase"], "proxy_unregistered")
        self.assertFalse(pending.exists())

    def test_incomplete_initial_pending_transaction_is_safely_rebuilt(self) -> None:
        pending = self.fixture.paths.pending_directory
        pending.mkdir(mode=0o700)
        intent = pending / service.INTENT_NAME
        intent.write_bytes(b'{"partial"')
        intent.chmod(0o600)
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                self.assertIsNone(store.load())
                rebuilt_intent, rebuilt_events = store.create(
                    CANDIDATE, PREVIOUS, guard()
                )
        self.assertEqual(rebuilt_intent["candidate"], CANDIDATE.document())
        self.assertEqual(rebuilt_events[-1]["phase"], "prepared")
        self.assertFalse(self.fixture.paths.pending_directory.exists())

    def test_unsafe_initial_pending_inventory_is_never_deleted(self) -> None:
        pending = self.fixture.paths.pending_directory
        pending.mkdir(mode=0o700)
        unexpected = pending / "unexpected"
        unexpected.write_text("do not delete\n", encoding="utf-8")
        unexpected.chmod(0o600)
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked(), self.assertRaises(install.InstallError) as captured:
                store.load()
        self.assertEqual(captured.exception.code, "service_journal_unsafe")
        self.assertTrue(unexpected.is_file())

    def test_intent_replacement_and_wrong_phase_action_fail_closed(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                _intent, events = store.create(CANDIDATE, PREVIOUS, guard())
                with self.assertRaises(install.InstallError) as action_error:
                    store.append(
                        events,
                        phase="proxy_unregistered",
                        action="register-proxy-agent",
                        guard=guard(),
                    )
        self.assertEqual(action_error.exception.code, "service_journal_invalid")
        intent_path = self.fixture.paths.transaction_directory / service.INTENT_NAME
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        intent["transaction_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        intent_path.write_bytes(install._canonical_json(intent))
        with service.ServiceEventStore(self.fixture.paths) as store:
            with self.assertRaises(install.InstallError) as intent_error:
                store.load()
        self.assertEqual(intent_error.exception.code, "service_journal_invalid")

    def test_excess_event_inventory_is_a_typed_failure(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                _intent, events = store.create(CANDIDATE, PREVIOUS, guard())
                for phase, action in zip(
                    service.PHASES[1:], service.ACTIONS[1:], strict=True
                ):
                    events.append(
                        store.append(
                            events, phase=phase, action=action, guard=guard()
                        )
                    )
        final = self.fixture.paths.transaction_directory / "event-00000006.json"
        extra = self.fixture.paths.transaction_directory / "event-00000007.json"
        extra.write_bytes(final.read_bytes())
        extra.chmod(0o600)
        with service.ServiceEventStore(self.fixture.paths) as store:
            with self.assertRaises(install.InstallError) as captured:
                store.load()
        self.assertEqual(captured.exception.code, "service_journal_invalid")

    def test_event_gap_tamper_and_guard_drift_fail_closed(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                _intent, events = store.create(CANDIDATE, PREVIOUS, guard())
                events.append(
                    store.append(
                        events,
                        phase="proxy_unregistered",
                        action="unregister-proxy-agent",
                        guard=guard(),
                    )
                )
        event = self.fixture.paths.transaction_directory / "event-00000001.json"
        value = json.loads(event.read_text(encoding="utf-8"))
        value["guard_after"]["proxy_sha256"] = "9" * 64
        event.write_bytes(install._canonical_json(value))
        with service.ServiceEventStore(self.fixture.paths) as store:
            with self.assertRaises(install.InstallError) as captured:
                store.load()
        self.assertEqual(captured.exception.code, "service_journal_invalid")

    def test_append_rejects_guard_drift_between_individually_stable_events(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                _intent, events = store.create(CANDIDATE, PREVIOUS, guard())
                with self.assertRaises(install.InstallError) as captured:
                    store.append(
                        events,
                        phase="proxy_unregistered",
                        action="unregister-proxy-agent",
                        guard=guard(proxy="9" * 64),
                    )
        self.assertEqual(captured.exception.code, "service_journal_invalid")
        self.assertFalse(
            (
                self.fixture.paths.transaction_directory
                / "event-00000001.json"
            ).exists()
        )

    def test_concurrent_transaction_lock_is_rejected(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as first:
            with first.locked():
                with service.ServiceEventStore(self.fixture.paths) as second:
                    with self.assertRaises(install.InstallError) as captured:
                        with second.locked():
                            pass
        self.assertEqual(captured.exception.code, "maintenance_busy")

    def test_decommissioned_journal_is_the_exact_installer_authorization(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                _intent, events = store.create(CANDIDATE, PREVIOUS, guard())
                for phase, action in (
                    ("proxy_unregistered", "unregister-proxy-agent"),
                    ("authority_unregistered", "unregister-global-authority"),
                    ("decommissioned", "verify-dormant"),
                ):
                    events.append(
                        store.append(
                            events,
                            phase=phase,
                            action=action,
                            guard=guard(),
                        )
                    )

        install.require_decommissioned_service_transaction(
            self.fixture.paths.install_paths,
            CANDIDATE,
            PREVIOUS,
            guard(),
        )

        transaction_directory = self.fixture.paths.transaction_directory
        before_inode = transaction_directory.stat().st_ino
        before_documents = {
            path.name: path.read_bytes()
            for path in transaction_directory.iterdir()
        }
        with self.assertRaises(install.InstallError) as guard_error:
            install.require_decommissioned_service_transaction(
                self.fixture.paths.install_paths,
                CANDIDATE,
                PREVIOUS,
                guard(proxy="8" * 64),
            )
        self.assertEqual(guard_error.exception.code, "cfw_guard_changed")
        self.assertEqual(transaction_directory.stat().st_ino, before_inode)
        self.assertEqual(
            {
                path.name: path.read_bytes()
                for path in transaction_directory.iterdir()
            },
            before_documents,
        )

        intent_path = self.fixture.paths.transaction_directory / service.INTENT_NAME
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        intent["previous"]["tree_sha256"] = "9" * 64
        intent_path.write_bytes(install._canonical_json(intent))
        with self.assertRaises(install.InstallError) as captured:
            install.require_decommissioned_service_transaction(
                self.fixture.paths.install_paths,
                CANDIDATE,
                PREVIOUS,
                guard(),
            )
        self.assertEqual(
            captured.exception.code,
            "service_decommission_evidence_invalid",
        )


class RegisteredServiceObservationTests(unittest.TestCase):
    @staticmethod
    def runtime(process_output: str) -> service.ServiceRuntime:
        proxy_domain = service.PROXY_DOMAIN_TEMPLATE.format(uid=501)

        def runner(arguments: tuple[str, ...]) -> install.CommandResult:
            if arguments == ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="):
                return install.CommandResult(0, process_output, "")
            if arguments == ("/bin/launchctl", "print", proxy_domain):
                return install.CommandResult(
                    0,
                    registered_job(
                        proxy_domain,
                        program=service.PROXY_PROGRAM,
                        build="40019",
                        signing_identifier="com.bill.clashformac.proxy-agent",
                        pid=6805,
                    ),
                    "",
                )
            if arguments == ("/bin/launchctl", "print", service.AUTHORITY_DOMAIN):
                return install.CommandResult(
                    0,
                    registered_job(
                        service.AUTHORITY_DOMAIN,
                        program=service.AUTHORITY_PROGRAM,
                        build="40019",
                        signing_identifier="com.bill.clashformac.global-authority",
                        pid=6806,
                    ),
                    "",
                )
            raise AssertionError(arguments)

        return service.ServiceRuntime(runner=runner)

    def test_relative_ps_comm_is_bound_through_absolute_proc_pidpath(self) -> None:
        paths = {
            6805: (
                "/Applications/Clash for Mac.app/Contents/Library/LoginItems/"
                "CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent"
            ),
            6806: (
                "/Applications/Clash for Mac.app/Contents/Library/HelperTools/"
                "CFWGlobalAuthority"
            ),
        }
        with patch.object(
            service, "_absolute_process_path", side_effect=lambda pid: paths[pid]
        ):
            service._require_registered_services(
                self.runtime(service_processes()), parent_build="40019", uid=501
            )

    def test_wrong_absolute_helper_path_fails_closed(self) -> None:
        with patch.object(
            service,
            "_absolute_process_path",
            return_value="/tmp/Clash for Mac.app/Contents/Library/HelperTools/CFWGlobalAuthority",
        ):
            with self.assertRaises(install.InstallError) as captured:
                service._require_registered_services(
                    self.runtime(service_processes()), parent_build="40019", uid=501
                )
        self.assertEqual(captured.exception.code, "service_process_identity_invalid")

    def test_other_gui_session_and_extra_helper_fail_before_mutation(self) -> None:
        other_login = (
            "7000 502 Sun Aug 23 04:02:00 2026 "
            "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"
        )
        with self.assertRaises(install.InstallError) as session_error:
            service._require_registered_services(
                self.runtime(service_processes(extra=(other_login,))),
                parent_build="40019",
                uid=501,
            )
        self.assertEqual(session_error.exception.code, "service_multi_user_session")

        extra_helper = (
            "7001 501 Sun Aug 23 04:02:00 2026 "
            "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent"
        )
        with patch.object(
            service,
            "_absolute_process_path",
            return_value=(
                "/Applications/Clash for Mac.app/Contents/Library/LoginItems/"
                "CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent"
            ),
        ):
            with self.assertRaises(install.InstallError) as helper_error:
                service._require_registered_services(
                    self.runtime(service_processes(extra=(extra_helper,))),
                    parent_build="40019",
                    uid=501,
                )
        self.assertEqual(helper_error.exception.code, "service_process_identity_invalid")


class CurrentServiceTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = ServiceFixture()

    def tearDown(self) -> None:
        self.fixture.cleanup()

    @staticmethod
    def receipt(action: str) -> dict[str, object]:
        pairs = {
            "unregister-proxy-agent": ("not_registered", "enabled"),
            "unregister-global-authority": ("not_registered", "not_registered"),
            "register-global-authority": ("not_registered", "enabled"),
            "register-proxy-agent": ("enabled", "enabled"),
            "prove-off": ("enabled", "enabled"),
        }
        proxy, authority = pairs[action]
        return {
            "action": action.replace("-", "_"),
            "document": "cfw-current-service-maintenance-v1",
            "engine_status": "off",
            "global_authority": authority,
            "proxy_agent": proxy,
        }

    def test_decommission_orders_proxy_before_authority_and_preserves_tombstone(self) -> None:
        actions: list[str] = []

        def run_action(_runtime, _executable, action):
            actions.append(action)
            return self.receipt(action)

        with (
            patch.object(
                self.fixture.transaction,
                "preflight",
                return_value=(CANDIDATE, PREVIOUS, guard()),
            ),
            patch.object(
                self.fixture.transaction,
                "_identity_pair",
                return_value=(CANDIDATE, PREVIOUS),
            ),
            patch.object(service, "_service_receipt", side_effect=run_action),
            patch.object(service, "_wait_for_service_absence"),
            patch.object(install, "require_cfm_dormant"),
        ):
            result = self.fixture.transaction.decommission()

        self.assertEqual(
            actions,
            ["unregister-proxy-agent", "unregister-global-authority"],
        )
        self.assertEqual(result["event"]["phase"], "decommissioned")
        self.assertNotIn("helper", " ".join(actions))

    def test_crash_before_event_is_recovered_by_idempotent_same_action(self) -> None:
        attempts = 0

        def wait_then_crash(*_arguments, **_keywords):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("simulated interruption")

        with (
            patch.object(
                self.fixture.transaction,
                "preflight",
                return_value=(CANDIDATE, PREVIOUS, guard()),
            ),
            patch.object(
                self.fixture.transaction,
                "_identity_pair",
                return_value=(CANDIDATE, PREVIOUS),
            ),
            patch.object(
                service,
                "_service_receipt",
                side_effect=lambda _runtime, _executable, action: self.receipt(action),
            ),
            patch.object(service, "_wait_for_service_absence", side_effect=wait_then_crash),
            patch.object(install, "require_cfm_dormant"),
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                self.fixture.transaction.decommission()
            with service.ServiceEventStore(self.fixture.paths) as store:
                loaded = store.load()
            self.assertEqual((loaded or ({}, [{}]))[1][-1]["phase"], "prepared")
            result = self.fixture.transaction.decommission()

        self.assertEqual(result["event"]["phase"], "decommissioned")
        self.assertGreaterEqual(attempts, 3)

    def test_cfw_guard_drift_blocks_event_publication_and_next_mutation(self) -> None:
        self.fixture.runtime.guards = [guard(), guard(), guard(proxy="9" * 64)]
        with (
            patch.object(
                self.fixture.transaction,
                "preflight",
                return_value=(CANDIDATE, PREVIOUS, guard()),
            ),
            patch.object(
                service,
                "_service_receipt",
                side_effect=lambda _runtime, _executable, action: self.receipt(action),
            ),
            patch.object(service, "_wait_for_service_absence"),
            patch.object(install, "require_cfm_dormant"),
        ):
            with self.assertRaises(install.InstallError) as captured:
                self.fixture.transaction.decommission()
        self.assertEqual(captured.exception.code, "cfw_guard_changed")
        with service.ServiceEventStore(self.fixture.paths) as store:
            loaded = store.load()
        self.assertEqual((loaded or ({}, [{}]))[1][-1]["phase"], "prepared")

    def test_preexisting_guard_drift_blocks_before_any_service_mutation(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                store.create(CANDIDATE, PREVIOUS, guard())
        self.fixture.runtime.guards = [guard(proxy="9" * 64)]
        with (
            patch.object(
                self.fixture.transaction,
                "_identity_pair",
                return_value=(CANDIDATE, PREVIOUS),
            ),
            patch.object(service, "_service_receipt") as receipt,
        ):
            with self.assertRaises(install.InstallError) as captured:
                self.fixture.transaction.decommission()
        self.assertEqual(captured.exception.code, "cfw_guard_changed")
        receipt.assert_not_called()
        with service.ServiceEventStore(self.fixture.paths) as store:
            loaded = store.load()
        self.assertEqual((loaded or ({}, [{}]))[1][-1]["phase"], "prepared")

    def test_recommission_orders_authority_before_proxy_then_reproves_off(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                _intent, events = store.create(CANDIDATE, PREVIOUS, guard())
                for phase, action in (
                    ("proxy_unregistered", "unregister-proxy-agent"),
                    ("authority_unregistered", "unregister-global-authority"),
                    ("decommissioned", "verify-dormant"),
                ):
                    events.append(
                        store.append(
                            events,
                            phase=phase,
                            action=action,
                            guard=guard(),
                        )
                    )
        actions: list[str] = []

        def run_action(_runtime, _executable, action):
            actions.append(action)
            return self.receipt(action)

        with (
            patch.object(self.fixture.transaction, "_candidate", return_value=CANDIDATE),
            patch.object(
                self.fixture.transaction,
                "_require_installed_candidate",
                return_value=CANDIDATE.app,
            ),
            patch.object(service, "_service_receipt", side_effect=run_action),
            patch.object(service, "_require_registered_services"),
            patch.object(service, "_require_tombstone_and_no_system_extension"),
        ):
            result = self.fixture.transaction.recommission()

        self.assertEqual(
            actions,
            ["register-global-authority", "register-proxy-agent", "prove-off"],
        )
        self.assertEqual(result["event"]["phase"], "recommissioned")

    def test_installed_candidate_evidence_also_binds_previous_application(self) -> None:
        installation = {
            "phase": "installed",
            "candidate": CANDIDATE.document(),
            "previous": {
                **PREVIOUS.document(),
                "tree_sha256": "9" * 64,
            },
        }
        with (
            patch.object(
                install,
                "read_app_identity",
                return_value=CANDIDATE.app,
            ),
            patch.object(install, "verify_dormant_bundle"),
            patch.object(
                install.JournalStore,
                "load",
                return_value=installation,
            ),
        ):
            with self.assertRaises(install.InstallError) as captured:
                self.fixture.transaction._require_installed_candidate(
                    {
                        "candidate": CANDIDATE.document(),
                        "previous": PREVIOUS.document(),
                    }
                )

        self.assertEqual(
            captured.exception.code,
            "service_install_evidence_invalid",
        )


if __name__ == "__main__":
    unittest.main()
