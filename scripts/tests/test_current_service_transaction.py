from __future__ import annotations

from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import current_service_transaction as service
from scripts import dormant_app_install as install
from scripts import ga_acceptance_environment as ga_environment


PREVIOUS = install.AppIdentity(
    "0.4.0", "40019", install.INSTALLED_40019_PREDECESSOR.tree_sha256
)
# The profile bound to that recorded predecessor: this is what every reader of
# a transaction retaining the 40019 predecessor resolves to, so the tests
# speak the same vocabulary the production path selects.
BOUND = install.BoundInstallProfile.recorded(install.GA_INSTALL_PROFILE, PREVIOUS)
CANDIDATE = install.CandidateIdentity(
    app=install.AppIdentity("0.4.0", "40044", "b" * 64),
    manifest_sha256="c" * 64,
    repository_commit="d" * 40,
    release_source_sha256="e" * 64,
)
# The installed 40043 with its real frozen tree identity: the production
# predecessor of this build, which selects the current service vocabulary.
INSTALLED_PREVIOUS = install.AppIdentity(
    "0.4.0", "40043", install.INSTALLED_40043_PREDECESSOR.tree_sha256
)
GA_ENVIRONMENT = {
    "architecture": "arm64",
    "boot_environment_sha256": "9" * 64,
    "document": ga_environment.DOCUMENT,
    "hardware_model": "Mac16,1",
    "machine_sha256": "8" * 64,
    "macos_build_version": "26A5388g",
    "macos_product_version": "27.0",
    "physical_nonvirtualized": True,
    "schema_version": ga_environment.SCHEMA_VERSION,
}


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
        self.observe_environment = lambda: dict(GA_ENVIRONMENT)

    def capture_guard(self) -> dict[str, object]:
        if len(self.guards) > 1:
            return self.guards.pop(0)
        return self.guards[0]


class ServiceFixture:
    def __init__(
        self,
        profile: install.InstallProfile = install.GA_INSTALL_PROFILE,
    ) -> None:
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
                profile=profile,
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

    def test_ga_service_transaction_is_fixed_to_the_ga_build(self) -> None:
        paths = service.ServicePaths.production()

        self.assertEqual(paths.install_paths.profile, install.GA_INSTALL_PROFILE)
        self.assertEqual(paths.install_paths.profile.build_number, "40044")
        # The predecessor is observed and bound, never declared on the profile.
        self.assertFalse(hasattr(paths.install_paths.profile, "previous_build_number"))
        self.assertEqual(
            dict(install.SUPPORTED_PREDECESSORS),
            {
                "40019": install.INSTALLED_40019_PREDECESSOR,
                "40041": install.INSTALLED_40041_PREDECESSOR,
                "40043": install.INSTALLED_40043_PREDECESSOR,
            },
        )
        self.assertEqual(
            paths.transaction_directory.name,
            ".com.bill.clashformac.service-transaction-v3",
        )
        self.assertEqual(
            paths.transaction_directory.name,
            service.TRANSACTION_DIRECTORY,
        )
        self.assertEqual(
            BOUND.service_actions[1:3],
            (
                "unregister-installed-40019-proxy-agent",
                "unregister-installed-40019-global-authority",
            ),
        )
        self.assertEqual(
            BOUND.predecessor.off_proof_profile,
            install.INSTALLED_40019_OFF_PROOF_PROFILE,
        )

    def test_service_intent_binds_one_private_ga_environment(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, _events = store.create(
                    CANDIDATE,
                    PREVIOUS,
                    guard(),
                    GA_ENVIRONMENT,
                )
        self.assertEqual(
            intent["ga_environment_sha256"],
            ga_environment.environment_sha256(GA_ENVIRONMENT),
        )
        environment_path = (
            self.fixture.paths.transaction_directory / service.ENVIRONMENT_NAME
        )
        self.assertEqual(
            environment_path.read_bytes(),
            ga_environment.canonical_json(GA_ENVIRONMENT),
        )
        self.assertNotIn("io_platform_uuid", environment_path.read_text())
        self.assertNotIn("volume_uuid", environment_path.read_text())

    def test_service_journal_rejects_environment_document_drift(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
        changed = dict(GA_ENVIRONMENT)
        changed["macos_build_version"] = "26A5389a"
        environment_path = (
            self.fixture.paths.transaction_directory / service.ENVIRONMENT_NAME
        )
        environment_path.write_bytes(ga_environment.canonical_json(changed))
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked(), self.assertRaises(install.InstallError) as captured:
                store.load()
        self.assertEqual(captured.exception.code, "service_journal_invalid")

    def test_service_mutation_boundary_rejects_current_environment_drift(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, _events = store.create(
                    CANDIDATE,
                    PREVIOUS,
                    guard(),
                    GA_ENVIRONMENT,
                )
        changed = dict(GA_ENVIRONMENT)
        changed["boot_environment_sha256"] = "7" * 64
        self.fixture.runtime.observe_environment = lambda: changed
        with self.assertRaises(install.InstallError) as captured:
            self.fixture.transaction._require_environment(intent)
        self.assertEqual(captured.exception.code, "service_environment_drift")

    def test_pre_environment_service_schema_is_rejected(self) -> None:
        legacy = {
            "candidate": CANDIDATE.document(),
            "document": "cfw-current-service-transaction-v2",
            "off_proof_profile": install.INSTALLED_40019_OFF_PROOF_PROFILE,
            "previous": PREVIOUS.document(),
            "schema_version": 2,
            "transaction_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        }
        with self.assertRaises(install.InstallError) as captured:
            service.validate_intent(legacy)
        self.assertEqual(captured.exception.code, "service_journal_invalid")

        boolean_schema = {
            "candidate": CANDIDATE.document(),
            "document": service.DOCUMENT,
            "ga_environment_sha256": ga_environment.environment_sha256(
                GA_ENVIRONMENT
            ),
            "off_proof_profile": install.INSTALLED_40019_OFF_PROOF_PROFILE,
            "previous": PREVIOUS.document(),
            "schema_version": True,
            "transaction_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        }
        with self.assertRaises(install.InstallError) as captured:
            service.validate_intent(boolean_schema)
        self.assertEqual(captured.exception.code, "service_journal_invalid")

    def test_service_event_rejects_boolean_schema_and_sequence(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, events = store.create(
                    CANDIDATE,
                    PREVIOUS,
                    guard(),
                    GA_ENVIRONMENT,
                )
                event = store.append(
                    events,
                    intent=intent,
                    phase=service.PHASES[1],
                    action=BOUND.service_actions[1],
                    guard=guard(),
                )
        for field in ("schema_version", "sequence"):
            malformed = dict(event)
            malformed[field] = True
            with self.subTest(field=field), self.assertRaises(install.InstallError):
                service.validate_event(
                    malformed,
                    expected_sequence=1,
                    previous_event_sha256=event["previous_event_sha256"],
                    expected_guard=event["guard_before"],
                    intent_sha256=event["intent_sha256"],
                    expected_actions=frozenset({event["action"]}),
                    expected_off_proof_profiles=frozenset(
                        {event["off_proof_profile"]}
                    ),
                )

    def test_service_json_recursion_is_a_stable_journal_error(self) -> None:
        deeply_nested = (
            "{\"nested\":" * 10_000 + "0" + "}" * 10_000
        ).encode("ascii")
        with self.assertRaises(install.InstallError) as captured:
            service._strict_json_bytes(deeply_nested, "deep service fixture")
        self.assertEqual(captured.exception.code, "service_journal_invalid")

        with patch.object(
            service,
            "_canonical_json",
            side_effect=RecursionError("fixture canonical recursion"),
        ), self.assertRaises(install.InstallError) as captured:
            service._strict_json_bytes(b"{}\n", "deep service fixture")
        self.assertEqual(captured.exception.code, "service_journal_invalid")

        for token in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(token=token), self.assertRaises(
                install.InstallError
            ) as captured:
                service._strict_json_bytes(
                    b'{"value":' + token + b"}\n",
                    "non-finite service fixture",
                )
            self.assertEqual(captured.exception.code, "service_journal_invalid")

    def test_retired_v2_service_namespace_is_never_reused_or_removed(self) -> None:
        for name in service.RETIRED_TRANSACTION_NAMES:
            with self.subTest(name=name):
                fixture = ServiceFixture()
                self.addCleanup(fixture.cleanup)
                legacy = fixture.paths.transaction_parent / name
                if name.endswith(".lock"):
                    legacy.write_text("historical\n", encoding="utf-8")
                else:
                    legacy.mkdir()
                with service.ServiceEventStore(fixture.paths) as store:
                    with self.assertRaises(install.InstallError) as captured:
                        with store.locked():
                            store.create(
                                CANDIDATE,
                                PREVIOUS,
                                guard(),
                                GA_ENVIRONMENT,
                            )
                self.assertEqual(
                    captured.exception.code,
                    "service_retired_journal_present",
                )
                self.assertTrue(os.path.lexists(legacy))
                self.assertFalse(fixture.paths.pending_directory.exists())
                self.assertFalse(fixture.paths.transaction_directory.exists())
                self.assertFalse(
                    (fixture.paths.transaction_parent / fixture.paths.lock_name).exists()
                )

    def test_retired_namespace_race_is_rejected_inside_maintenance_lock(
        self,
    ) -> None:
        retired = (
            self.fixture.paths.transaction_parent
            / service.RETIRED_TRANSACTION_NAMES[0]
        )
        real_maintenance_lock = install.exclusive_release_maintenance_lock

        @contextmanager
        def create_retired_name_after_lock(
            target_parent: Path,
            *,
            require_existing: bool = False,
        ):
            with real_maintenance_lock(
                target_parent,
                require_existing=require_existing,
            ):
                retired.write_bytes(b"historical\n")
                yield

        with patch.object(
            install,
            "exclusive_release_maintenance_lock",
            new=create_retired_name_after_lock,
        ):
            with service.ServiceEventStore(self.fixture.paths) as store:
                with self.assertRaises(install.InstallError) as captured:
                    with store.locked():
                        self.fail("retired namespace race was accepted")
        self.assertEqual(
            captured.exception.code,
            "service_retired_journal_present",
        )
        self.assertTrue(retired.is_file())
        self.assertFalse(self.fixture.paths.pending_directory.exists())
        self.assertFalse(self.fixture.paths.transaction_directory.exists())
        self.assertFalse(
            (
                self.fixture.paths.transaction_parent
                / self.fixture.paths.lock_name
            ).exists()
        )

    def test_unobservable_retired_namespace_is_typed_not_absent(self) -> None:
        retired_name = service.RETIRED_TRANSACTION_NAMES[0]
        real_stat = os.stat
        with service.ServiceEventStore(self.fixture.paths) as store:

            def deny_retired_name(
                name: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                if (
                    name == retired_name
                    and kwargs.get("dir_fd") == store.parent_fd
                    and kwargs.get("follow_symlinks") is False
                ):
                    raise PermissionError("fixture retired namespace denial")
                return real_stat(name, *args, **kwargs)

            with patch.object(
                service.os,
                "stat",
                side_effect=deny_retired_name,
            ), self.assertRaises(install.InstallError) as captured:
                with store.locked():
                    self.fail("unobservable retired namespace was accepted")
        self.assertEqual(
            captured.exception.code,
            "service_retired_journal_unavailable",
        )
        self.assertFalse(
            (
                self.fixture.paths.transaction_parent
                / self.fixture.paths.lock_name
            ).exists()
        )

    def test_retired_final_cli_and_wrapper_are_explicitly_rejected(self) -> None:
        with (
            patch.object(
                sys,
                "argv",
                ["current_service_transaction.py", "--preflight", "--final"],
            ),
            patch("sys.stderr", new_callable=io.StringIO) as stderr,
            patch.object(service, "_transaction") as transaction,
            self.assertRaises(SystemExit) as captured,
        ):
            service.main()
        self.assertEqual(captured.exception.code, 2)
        self.assertIn("--final is retired", stderr.getvalue())
        transaction.assert_not_called()

        repository = Path(__file__).resolve().parents[2]
        completed = subprocess.run(
            (
                "/bin/bash",
                str(repository / "scripts/run_current_service_transaction.sh"),
                "--preflight",
                "--final",
            ),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertIn("--final is retired", completed.stderr)

    def test_no_current_profile_can_accept_retired_40030_as_previous(self) -> None:
        retired_previous = install.AppIdentity("0.4.0", "40030", "f" * 64)
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                with self.assertRaises(install.InstallError) as captured:
                    store.create(CANDIDATE, retired_previous, guard(), GA_ENVIRONMENT)
        # A retired build was never a supported predecessor, so no vocabulary
        # exists to write the transaction in; that is the precise reason.
        self.assertEqual(captured.exception.code, "predecessor_unsupported")
        self.assertFalse(self.fixture.paths.transaction_directory.exists())
        self.assertTrue(self.fixture.paths.pending_directory.exists())

    def test_append_only_lineage_round_trips_every_phase(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                for phase, action in zip(
                    service.PHASES[1:], service.INSTALLED_40019_ACTIONS[1:], strict=True
                ):
                    events.append(
                        store.append(
                            events,
                            intent=intent,
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
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                os.rename(
                    self.fixture.paths.transaction_directory,
                    self.fixture.paths.pending_directory,
                )
                loaded = store.load()
                self.assertEqual(loaded, (intent, events))

    def test_authority_recovery_profile_is_preserved_as_exact_event_evidence(
        self,
    ) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                events.append(
                    store.append(
                        events,
                        intent=intent,
                        phase="proxy_unregistered",
                        action="unregister-installed-40019-proxy-agent",
                        guard=guard(),
                    )
                )
                store.prepare_authority_recovery(intent, events, guard())
                events.append(
                    store.append(
                        events,
                        intent=intent,
                        phase="authority_unregistered",
                        action=install.INSTALLED_40019_RECOVERY_ACTION,
                        guard=guard(),
                        off_proof_profile=(
                            install.INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE
                        ),
                    )
                )
                loaded = store.load()

        self.assertEqual(loaded, (intent, events))
        self.assertEqual(
            events[-1]["off_proof_profile"],
            install.INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE,
        )
        self.assertTrue(self.fixture.paths.transaction_directory.is_dir())
        self.assertFalse(self.fixture.paths.pending_directory.exists())

    def test_complete_pending_authority_recovery_intent_is_published_on_load(
        self,
    ) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                events.append(
                    store.append(
                        events,
                        intent=intent,
                        phase="proxy_unregistered",
                        action="unregister-installed-40019-proxy-agent",
                        guard=guard(),
                    )
                )
                with patch.object(
                    service.ServiceEventStore,
                    "_publish_pending_event",
                    side_effect=RuntimeError("simulated crash before marker rename"),
                ):
                    with self.assertRaisesRegex(RuntimeError, "marker rename"):
                        store.prepare_authority_recovery(intent, events, guard())

        pending = (
            self.fixture.paths.transaction_directory
            / install.AUTHORITY_RECOVERY_PENDING_INTENT_NAME
        )
        published = (
            self.fixture.paths.transaction_directory
            / install.AUTHORITY_RECOVERY_INTENT_NAME
        )
        self.assertTrue(pending.is_file())
        self.assertFalse(published.exists())
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                self.assertEqual(store.load(), (intent, events))
                self.assertTrue(
                    store.authority_recovery_prepared(intent, events)
                )
        self.assertFalse(pending.exists())
        self.assertTrue(published.is_file())

    def test_incomplete_pending_authority_recovery_intent_is_discarded(
        self,
    ) -> None:
        for payload in (b"", b"{"):
            with self.subTest(payload=payload):
                fixture = ServiceFixture()
                try:
                    with service.ServiceEventStore(fixture.paths) as store:
                        with store.locked():
                            intent, events = store.create(
                                CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT
                            )
                            events.append(
                                store.append(
                                    events,
                                    intent=intent,
                                    phase="proxy_unregistered",
                                    action=(
                                        "unregister-installed-40019-proxy-agent"
                                    ),
                                    guard=guard(),
                                )
                            )
                    pending = (
                        fixture.paths.transaction_directory
                        / install.AUTHORITY_RECOVERY_PENDING_INTENT_NAME
                    )
                    pending.write_bytes(payload)
                    pending.chmod(0o600)
                    with service.ServiceEventStore(fixture.paths) as store:
                        with store.locked():
                            self.assertEqual(store.load(), (intent, events))
                            self.assertFalse(
                                store.authority_recovery_prepared(intent, events)
                            )
                    self.assertFalse(pending.exists())
                finally:
                    fixture.cleanup()

    def test_invalid_published_authority_recovery_intent_is_never_deleted(
        self,
    ) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                events.append(
                    store.append(
                        events,
                        intent=intent,
                        phase="proxy_unregistered",
                        action="unregister-installed-40019-proxy-agent",
                        guard=guard(),
                    )
                )
                store.prepare_authority_recovery(intent, events, guard())
        published = (
            self.fixture.paths.transaction_directory
            / install.AUTHORITY_RECOVERY_INTENT_NAME
        )
        published.write_bytes(b"{}\n")
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                with self.assertRaises(install.InstallError) as captured:
                    store.load()
        self.assertEqual(captured.exception.code, "service_journal_invalid")
        self.assertEqual(published.read_bytes(), b"{}\n")

    def test_recovery_marker_cannot_authorize_a_legacy_authority_event(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                events.append(
                    store.append(
                        events,
                        intent=intent,
                        phase="proxy_unregistered",
                        action="unregister-installed-40019-proxy-agent",
                        guard=guard(),
                    )
                )
                store.prepare_authority_recovery(intent, events, guard())
        contradictory = {
            "action": "unregister-installed-40019-global-authority",
            "document": service.DOCUMENT,
            "guard_after": guard(),
            "guard_before": guard(),
            "intent_sha256": events[0]["intent_sha256"],
            "off_proof_profile": install.INSTALLED_40019_OFF_PROOF_PROFILE,
            "phase": "authority_unregistered",
            "previous_event_sha256": service._sha256(
                service._canonical_json(events[1])
            ),
            "schema_version": service.SCHEMA_VERSION,
            "sequence": 2,
        }
        path = self.fixture.paths.transaction_directory / "event-00000002.json"
        path.write_bytes(service._canonical_json(contradictory))
        path.chmod(0o600)

        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                with self.assertRaises(install.InstallError) as captured:
                    store.load()
        self.assertEqual(captured.exception.code, "service_journal_invalid")

    def test_non_scalar_event_proof_profile_is_a_stable_journal_error(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                with self.assertRaises(install.InstallError) as captured:
                    store.append(
                        events,
                        intent=intent,
                        phase="proxy_unregistered",
                        action="unregister-installed-40019-proxy-agent",
                        guard=guard(),
                        off_proof_profile=[
                            install.INSTALLED_40019_OFF_PROOF_PROFILE
                        ],
                    )
        self.assertEqual(captured.exception.code, "service_journal_invalid")

    def test_complete_pending_event_is_published_on_recovery(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                with patch.object(
                    service.ServiceEventStore,
                    "_publish_pending_event",
                    side_effect=RuntimeError("simulated crash before rename"),
                ):
                    with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                        store.append(
                            events,
                            intent=intent,
                            phase="proxy_unregistered",
                            action="unregister-installed-40019-proxy-agent",
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
                _intent, _events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
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
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                with patch.object(
                    service.ServiceEventStore,
                    "_publish_pending_event",
                    side_effect=RuntimeError("simulated crash before rename"),
                ):
                    with self.assertRaises(RuntimeError):
                        store.append(
                            events,
                            intent=intent,
                            phase="proxy_unregistered",
                            action="unregister-installed-40019-proxy-agent",
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
                    CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT
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
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                with self.assertRaises(install.InstallError) as action_error:
                    store.append(
                        events,
                        intent=intent,
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

    def test_append_binds_its_contract_to_the_journals_own_intent(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                foreign = dict(intent)
                foreign["transaction_id"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
                with self.assertRaises(install.InstallError) as raised:
                    store.append(
                        events,
                        intent=foreign,
                        phase=service.PHASES[1],
                        action=BOUND.service_actions[1],
                        guard=guard(),
                    )
        self.assertEqual(raised.exception.code, "service_journal_invalid")
        with service.ServiceEventStore(self.fixture.paths) as store:
            loaded = store.load()
        self.assertEqual(len((loaded or ({}, []))[1]), 1)

    def test_tampered_intent_predecessor_is_rejected_by_its_own_identity(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
        intent_path = self.fixture.paths.transaction_directory / service.INTENT_NAME
        original = json.loads(intent_path.read_text(encoding="utf-8"))
        for previous, code in (
            ({**original["previous"], "build_number": "40030"}, "predecessor_unsupported"),
            ({**original["previous"], "tree_sha256": "f" * 64}, "predecessor_identity_mismatch"),
        ):
            with self.subTest(code=code):
                tampered = dict(original)
                tampered["previous"] = previous
                intent_path.write_bytes(install._canonical_json(tampered))
                with service.ServiceEventStore(self.fixture.paths) as store:
                    with self.assertRaises(install.InstallError) as raised:
                        store.load()
                self.assertEqual(raised.exception.code, code)
                self.assertTrue(intent_path.is_file())

    def test_excess_event_inventory_is_a_typed_failure(self) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                for phase, action in zip(
                    service.PHASES[1:], service.INSTALLED_40019_ACTIONS[1:], strict=True
                ):
                    events.append(
                        store.append(
                            events, intent=intent, phase=phase, action=action, guard=guard()
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
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                events.append(
                    store.append(
                        events,
                        intent=intent,
                        phase="proxy_unregistered",
                        action="unregister-installed-40019-proxy-agent",
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
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                with self.assertRaises(install.InstallError) as captured:
                    store.append(
                        events,
                        intent=intent,
                        phase="proxy_unregistered",
                        action="unregister-installed-40019-proxy-agent",
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
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                for phase, action in (
                    (
                        "proxy_unregistered",
                        "unregister-installed-40019-proxy-agent",
                    ),
                    (
                        "authority_unregistered",
                        install.INSTALLED_40019_RECOVERY_ACTION,
                    ),
                    ("decommissioned", "verify-dormant"),
                ):
                    if action == install.INSTALLED_40019_RECOVERY_ACTION:
                        store.prepare_authority_recovery(
                            intent, events, guard()
                        )
                    events.append(
                        store.append(
                            events,
                            intent=intent,
                            phase=phase,
                            action=action,
                            guard=guard(),
                            off_proof_profile=(
                                install.INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE
                                if action == install.INSTALLED_40019_RECOVERY_ACTION
                                else None
                            ),
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
        retired = (
            self.fixture.paths.transaction_parent
            / service.RETIRED_TRANSACTION_NAMES[0]
        )
        retired.write_bytes(b"historical\n")
        with self.assertRaises(install.InstallError) as retired_error:
            install.require_decommissioned_service_transaction(
                self.fixture.paths.install_paths,
                CANDIDATE,
                PREVIOUS,
                guard(),
            )
        self.assertEqual(
            retired_error.exception.code,
            "service_retired_journal_present",
        )
        retired.unlink()

        real_stat = os.stat

        def deny_retired_name(
            name: object,
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            if (
                name == service.RETIRED_TRANSACTION_NAMES[0]
                and kwargs.get("follow_symlinks") is False
            ):
                raise PermissionError("fixture retired namespace denial")
            return real_stat(name, *args, **kwargs)

        with patch.object(
            install.os,
            "stat",
            side_effect=deny_retired_name,
        ), self.assertRaises(install.InstallError) as unavailable_error:
            install.require_decommissioned_service_transaction(
                self.fixture.paths.install_paths,
                CANDIDATE,
                PREVIOUS,
                guard(),
            )
        self.assertEqual(
            unavailable_error.exception.code,
            "service_retired_journal_unavailable",
        )
        self.assertEqual(transaction_directory.stat().st_ino, before_inode)
        self.assertEqual(
            {
                path.name: path.read_bytes()
                for path in transaction_directory.iterdir()
            },
            before_documents,
        )

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

        return service.ServiceRuntime(
            runner=runner,
            observe_environment=lambda: dict(GA_ENVIRONMENT),
        )

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
        if action == "status":
            return {
                "action": "status",
                "document": install.SERVICE_MAINTENANCE_DOCUMENT,
                "engine_status": None,
                "global_authority": "enabled",
                "off_proof_profile": None,
                "proxy_agent": "not_registered",
            }
        pairs = {
            "unregister-installed-40019-proxy-agent": (
                "not_registered",
                "enabled",
            ),
            "unregister-installed-40019-global-authority": (
                "not_registered",
                "not_registered",
            ),
            install.INSTALLED_40019_RECOVERY_ACTION: (
                "not_registered",
                "not_registered",
            ),
            "unregister-proxy-agent": ("not_registered", "enabled"),
            "unregister-global-authority": ("not_registered", "not_registered"),
            "register-global-authority": ("not_registered", "enabled"),
            "register-proxy-agent": ("enabled", "enabled"),
            "prove-off": ("enabled", "enabled"),
        }
        proxy, authority = pairs[action]
        return {
            "action": action.replace("-", "_"),
            "document": install.SERVICE_MAINTENANCE_DOCUMENT,
            "engine_status": "off",
            "global_authority": authority,
            "off_proof_profile": (
                install.INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE
                if action == install.INSTALLED_40019_RECOVERY_ACTION
                else (
                    install.INSTALLED_40019_OFF_PROOF_PROFILE
                    if "installed-40019" in action
                    else install.CURRENT_OFF_PROOF_PROFILE
                )
            ),
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
            [
                "unregister-installed-40019-proxy-agent",
                "status",
                "unregister-installed-40019-global-authority",
            ],
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

    def test_recovery_intent_survives_current_authority_action_interruption(
        self,
    ) -> None:
        with service.ServiceEventStore(self.fixture.paths) as store:
            with store.locked():
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                events.append(
                    store.append(
                        events,
                        intent=intent,
                        phase="proxy_unregistered",
                        action="unregister-installed-40019-proxy-agent",
                        guard=guard(),
                    )
                )

        actions: list[str] = []
        recovery_attempts = 0

        def run_action(_runtime, _executable, action):
            nonlocal recovery_attempts
            actions.append(action)
            if action == "status":
                receipt = self.receipt(action)
                return {
                    **receipt,
                    "global_authority": (
                        "not_registered"
                        if recovery_attempts == 0
                        else "enabled"
                    ),
                }
            if action == install.INSTALLED_40019_RECOVERY_ACTION:
                recovery_attempts += 1
                if recovery_attempts == 1:
                    raise RuntimeError("simulated interruption after current register")
            return self.receipt(action)

        with (
            patch.object(
                self.fixture.transaction,
                "_identity_pair",
                return_value=(CANDIDATE, PREVIOUS),
            ),
            patch.object(service, "_service_receipt", side_effect=run_action),
            patch.object(service, "_wait_for_service_absence"),
            patch.object(install, "require_cfm_dormant"),
        ):
            with self.assertRaisesRegex(RuntimeError, "current register"):
                self.fixture.transaction.decommission()
            marker = (
                self.fixture.paths.transaction_directory
                / install.AUTHORITY_RECOVERY_INTENT_NAME
            )
            self.assertTrue(marker.is_file())
            with service.ServiceEventStore(self.fixture.paths) as store:
                loaded = store.load()
            self.assertEqual((loaded or ({}, [{}]))[1][-1]["phase"], "proxy_unregistered")
            result = self.fixture.transaction.decommission()

        self.assertEqual(result["event"]["phase"], "decommissioned")
        self.assertEqual(
            actions,
            [
                "status",
                install.INSTALLED_40019_RECOVERY_ACTION,
                "status",
                install.INSTALLED_40019_RECOVERY_ACTION,
            ],
        )

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
                store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
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
                intent, events = store.create(CANDIDATE, PREVIOUS, guard(), GA_ENVIRONMENT)
                for phase, action in (
                    (
                        "proxy_unregistered",
                        "unregister-installed-40019-proxy-agent",
                    ),
                    (
                        "authority_unregistered",
                        "unregister-installed-40019-global-authority",
                    ),
                    ("decommissioned", "verify-dormant"),
                ):
                    events.append(
                        store.append(
                            events,
                            intent=intent,
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

    def test_identity_pair_admits_only_a_supported_newer_installed_application(
        self,
    ) -> None:
        target = self.fixture.paths.install_paths.target_app
        rejected = (
            (CANDIDATE, install.AppIdentity("0.4.0", "40030", "a" * 64), "predecessor_unsupported"),
            (CANDIDATE, install.AppIdentity("0.4.0", "40019", "f" * 64), "predecessor_identity_mismatch"),
            # The GA build itself is never a predecessor.
            (CANDIDATE, install.AppIdentity("0.4.0", "40044", "a" * 64), "predecessor_unsupported"),
            (CANDIDATE, install.AppIdentity("0.4.0", "40043", "a" * 64), "predecessor_identity_mismatch"),
            (CANDIDATE, install.AppIdentity("0.3.5", "40019", PREVIOUS.tree_sha256), "install_identity_mismatch"),
            (
                install.CandidateIdentity(
                    app=install.AppIdentity("0.4.0", "40040", "b" * 64),
                    manifest_sha256="c" * 64,
                    repository_commit="d" * 40,
                    release_source_sha256="e" * 64,
                ),
                PREVIOUS,
                "service_identity_mismatch",
            ),
        )
        for candidate, observed, code in rejected:
            with self.subTest(code=code):
                with (
                    patch.object(self.fixture.transaction, "_candidate", return_value=candidate),
                    patch.object(install, "read_app_identity", return_value=observed),
                    patch.object(install, "verify_dormant_bundle"),
                ):
                    with self.assertRaises(install.InstallError) as raised:
                        self.fixture.transaction._identity_pair()
                self.assertEqual(raised.exception.code, code)
        with (
            patch.object(self.fixture.transaction, "_candidate", return_value=CANDIDATE),
            patch.object(install, "read_app_identity", return_value=PREVIOUS),
            patch.object(install, "verify_dormant_bundle"),
        ):
            self.assertEqual(self.fixture.transaction._identity_pair(), (CANDIDATE, PREVIOUS))
        with (
            patch.object(self.fixture.transaction, "_candidate", return_value=CANDIDATE),
            patch.object(install, "read_app_identity", return_value=INSTALLED_PREVIOUS),
            patch.object(install, "verify_dormant_bundle"),
        ):
            self.assertEqual(
                self.fixture.transaction._identity_pair(), (CANDIDATE, INSTALLED_PREVIOUS)
            )
        # An absent or non-directory target is decided before any identity read.
        shutil.rmtree(target)
        for prepare, code in (
            (lambda: None, "previous_app_absent"),
            (lambda: target.symlink_to(target.parent), "app_identity_invalid"),
        ):
            with self.subTest(code=code):
                prepare()
                with (
                    patch.object(self.fixture.transaction, "_candidate", return_value=CANDIDATE),
                    patch.object(install, "read_app_identity") as read_identity,
                ):
                    with self.assertRaises(install.InstallError) as raised:
                        self.fixture.transaction._identity_pair()
                self.assertEqual(raised.exception.code, code)
                read_identity.assert_not_called()

    def test_preflight_proves_off_in_the_observed_predecessors_vocabulary(self) -> None:
        successor = ServiceFixture()
        self.addCleanup(successor.cleanup)
        historical = ServiceFixture()
        self.addCleanup(historical.cleanup)
        cases = (
            (self.fixture, CANDIDATE, PREVIOUS, "prove-installed-40019-off", install.INSTALLED_40019_OFF_PROOF_PROFILE),
            (
                historical,
                CANDIDATE,
                install.AppIdentity("0.4.0", "40041", install.INSTALLED_40041_PREDECESSOR.tree_sha256),
                "prove-off",
                install.CURRENT_OFF_PROOF_PROFILE,
            ),
            (successor, CANDIDATE, INSTALLED_PREVIOUS, "prove-off", install.CURRENT_OFF_PROOF_PROFILE),
        )
        for fixture, candidate, previous, prove_off, profile in cases:
            with self.subTest(previous=previous.build_number, prove_off=prove_off):
                actions: list[str] = []

                def run_action(_runtime, _executable, action, *, profile=profile):
                    actions.append(action)
                    return {
                        "action": action.replace("-", "_"),
                        "document": install.SERVICE_MAINTENANCE_DOCUMENT,
                        "engine_status": None if action == "status" else "off",
                        "global_authority": "enabled",
                        "off_proof_profile": None if action == "status" else profile,
                        "proxy_agent": "enabled",
                    }

                with (
                    patch.object(fixture.transaction, "_identity_pair", return_value=(candidate, previous)),
                    patch.object(service, "_service_receipt", side_effect=run_action),
                    patch.object(service, "_require_registered_services"),
                    patch.object(service, "_require_tombstone_and_no_system_extension"),
                    patch.object(install, "require_single_interactive_local_user"),
                ):
                    result = fixture.transaction.preflight()
                self.assertEqual(actions, ["status", prove_off])
                self.assertEqual(result[:2], (candidate, previous))

    def test_current_predecessor_decommission_speaks_only_the_current_vocabulary(
        self,
    ) -> None:
        fixture = ServiceFixture()
        self.addCleanup(fixture.cleanup)
        actions: list[str] = []

        def run_action(_runtime, _executable, action):
            actions.append(action)
            return self.receipt(action)

        with (
            patch.object(
                fixture.transaction,
                "preflight",
                return_value=(CANDIDATE, INSTALLED_PREVIOUS, guard()),
            ),
            patch.object(
                fixture.transaction,
                "_identity_pair",
                return_value=(CANDIDATE, INSTALLED_PREVIOUS),
            ),
            patch.object(service, "_service_receipt", side_effect=run_action),
            patch.object(service, "_wait_for_service_absence"),
            patch.object(install, "require_cfm_dormant"),
        ):
            result = fixture.transaction.decommission()

        # No 40019 action, no status probe, no recovery branch.
        self.assertEqual(actions, ["unregister-proxy-agent", "unregister-global-authority"])
        self.assertEqual(result["event"]["phase"], "decommissioned")
        with service.ServiceEventStore(fixture.paths) as store:
            loaded = store.load()
        self.assertIsNotNone(loaded)
        intent, events = loaded or ({}, [])
        self.assertEqual(intent["previous"], INSTALLED_PREVIOUS.document())
        self.assertEqual(intent["off_proof_profile"], install.CURRENT_OFF_PROOF_PROFILE)
        self.assertEqual(
            [event["action"] for event in events],
            ["prepare", "unregister-proxy-agent", "unregister-global-authority", "verify-dormant"],
        )
        self.assertEqual(
            {event["off_proof_profile"] for event in events},
            {install.CURRENT_OFF_PROOF_PROFILE},
        )
        # A recovery intent has no meaning for this predecessor: it cannot be
        # prepared, and one placed by hand is rejected on load and left as is.
        with service.ServiceEventStore(fixture.paths) as store:
            with store.locked():
                with self.assertRaises(install.InstallError) as prepared:
                    store.prepare_authority_recovery(intent, events, guard())
        self.assertEqual(prepared.exception.code, "service_journal_invalid")
        marker = fixture.paths.transaction_directory / install.AUTHORITY_RECOVERY_INTENT_NAME
        marker.write_bytes(b"{}\n")
        marker.chmod(0o600)
        with service.ServiceEventStore(fixture.paths) as store:
            with self.assertRaises(install.InstallError) as loaded_error:
                store.load()
        self.assertEqual(loaded_error.exception.code, "service_journal_invalid")
        self.assertEqual(marker.read_bytes(), b"{}\n")
        # The same holds for an unpublished (pending) marker next to a journal
        # that has only its prepare event: load must not treat it as this
        # transaction's own interrupted recovery and discard it.
        marker.unlink()
        pending = ServiceFixture()
        self.addCleanup(pending.cleanup)
        with service.ServiceEventStore(pending.paths) as store:
            with store.locked():
                store.create(CANDIDATE, INSTALLED_PREVIOUS, guard(), GA_ENVIRONMENT)
        pending_marker = (
            pending.paths.transaction_directory
            / install.AUTHORITY_RECOVERY_PENDING_INTENT_NAME
        )
        pending_marker.write_bytes(b"{}\n")
        pending_marker.chmod(0o600)
        with service.ServiceEventStore(pending.paths) as store:
            with self.assertRaises(install.InstallError) as pending_error:
                store.load()
        self.assertEqual(pending_error.exception.code, "service_journal_invalid")
        self.assertEqual(pending_marker.read_bytes(), b"{}\n")

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
                "terminal_snapshot",
                return_value=install.TerminalInstallJournalSnapshot(
                    document=installation,
                    data=b"{}\n",
                    metadata=os.stat(self.fixture.paths.install_paths.target_app),
                ),
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

    def test_installed_candidate_consumes_only_a_terminal_install_snapshot(self) -> None:
        installation = {
            "phase": "installed",
            "candidate": CANDIDATE.document(),
            "previous": PREVIOUS.document(),
            "ga_environment_sha256": ga_environment.environment_sha256(
                GA_ENVIRONMENT
            ),
        }
        snapshot = install.TerminalInstallJournalSnapshot(
            document=installation,
            data=b"{}\n",
            metadata=os.stat(self.fixture.paths.install_paths.target_app),
        )
        intent = {
            "candidate": CANDIDATE.document(),
            "previous": PREVIOUS.document(),
            "ga_environment_sha256": installation["ga_environment_sha256"],
        }
        with (
            patch.object(install, "read_app_identity", return_value=CANDIDATE.app),
            patch.object(install, "verify_dormant_bundle"),
            patch.object(
                install.JournalStore,
                "terminal_snapshot",
                return_value=snapshot,
            ) as terminal_snapshot,
            patch.object(
                install.JournalStore,
                "load",
                side_effect=AssertionError("service evidence must not publish pending state"),
            ) as load,
        ):
            self.assertEqual(
                self.fixture.transaction._require_installed_candidate(intent),
                CANDIDATE.app,
            )

        terminal_snapshot.assert_called_once_with()
        load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
