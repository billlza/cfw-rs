from __future__ import annotations

import copy
import json
import os
import unittest
from unittest.mock import patch

from scripts import current_service_transaction as service
from scripts import dormant_app_install as install
from test_current_service_transaction import CANDIDATE, GA_ENVIRONMENT, ServiceFixture, guard
from test_ga_acceptance_journal_export import JournalExportFixture, ENVIRONMENT, guard as export_guard


class DNSContinuationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = ServiceFixture()
        self.paths = self.fixture.paths
        self.transaction = self.fixture.transaction
        self.previous = install.AppIdentity(
            "0.4.0", "40070", install.INSTALLED_40070_PREDECESSOR.tree_sha256
        )
        self.old = guard()
        self.new = {**self.old, "dns_sha256": "a" * 64}
        with service.ServiceEventStore(self.paths) as store, store.locked():
            self.intent, self.events = store.create(CANDIDATE, self.previous, self.old, GA_ENVIRONMENT)
            for sequence, action in enumerate(
                ("unregister-proxy-agent", "unregister-global-authority", "verify-dormant"), 1
            ):
                self.events.append(store.append(
                    self.events, intent=self.intent, phase=service.PHASES[sequence],
                    action=action, guard=self.old,
                ))
        self.directory = self.paths.transaction_directory
        self.original = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        self.record = self.directory / install.SERVICE_DNS_CONTINUATION_NAME

    def tearDown(self) -> None:
        self.fixture.cleanup()

    def create_continuation(self, observations=None, *, proof_error=None) -> None:
        self.fixture.runtime.guards = observations or [self.new]
        with patch.object(self.transaction, "_identity_pair", return_value=(CANDIDATE, self.previous)), \
             patch.object(install, "require_single_interactive_local_user") as user, \
             patch.object(install, "require_cfm_dormant", side_effect=proof_error) as dormant:
            self.transaction.continue_after_dns_change()
            user.assert_called_once()
            dormant.assert_called_once()

    def assert_original_preserved(self) -> None:
        for name, data in self.original.items():
            self.assertEqual((self.directory / name).read_bytes(), data)

    def test_no_continuation_keeps_the_original_strict_guard(self) -> None:
        with self.assertRaises(install.InstallError) as error:
            install.require_decommissioned_service_transaction(
                self.paths.install_paths, CANDIDATE, self.previous, self.new
            )
        self.assertEqual(error.exception.code, "cfw_guard_changed")

    def test_explicit_continuation_preserves_old_events_and_admits_new_guard(self) -> None:
        self.create_continuation()
        self.assert_original_preserved()
        self.assertEqual(install.require_decommissioned_service_transaction(
            self.paths.install_paths, CANDIDATE, self.previous, self.new
        ), GA_ENVIRONMENT)
        original_record = self.record.read_bytes()
        self.create_continuation()
        self.assertEqual(self.record.read_bytes(), original_record)

    def test_recommission_and_export_validate_both_guard_segments(self) -> None:
        self.create_continuation()
        with service.ServiceEventStore(self.paths) as store, store.locked():
            intent, events = store.load()
            for sequence, action in enumerate(
                ("register-global-authority", "register-proxy-agent", "prove-off"), 4
            ):
                events.append(store.append(events, intent=intent, phase=service.PHASES[sequence], action=action, guard=self.new))
            snapshot = store.terminal_snapshot()
        files = {item.name: item.data for item in snapshot.files}
        self.assertIn(install.SERVICE_DNS_CONTINUATION_NAME, files)
        _environment, _intent, events = service.validate_terminal_snapshot_files(files)
        self.assertTrue(all(event["guard_before"] == self.old for event in events[:4]))
        self.assertTrue(all(event["guard_before"] == self.new for event in events[4:]))
        self.assert_original_preserved()

    def test_other_changes_and_missing_cfw_are_rejected(self) -> None:
        for key in ("proxy_sha256", "routes_ipv4_sha256", "routes_ipv6_sha256", "tun_sha256", "cfw_processes"):
            changed = copy.deepcopy(self.new)
            if key == "cfw_processes":
                changed[key] = []
            else:
                changed[key] = "f" * 64
            with self.subTest(field=key), self.assertRaises(install.InstallError):
                self.create_continuation([changed])
            self.assertFalse(self.record.exists())
            self.assert_original_preserved()

    def test_unstable_current_guard_or_failed_dormancy_proof_writes_nothing(self) -> None:
        different = {**self.new, "dns_sha256": "f" * 64}
        with self.assertRaises(install.InstallError):
            self.create_continuation([self.new, different])
        with self.assertRaises(install.InstallError):
            self.create_continuation(proof_error=install.InstallError("not_dormant", "proof failed"))
        self.assertFalse(self.record.exists())
        self.assert_original_preserved()

    def test_installation_or_nonterminal_teardown_cannot_be_rebased(self) -> None:
        for name in (self.paths.install_paths.journal_name, self.paths.install_paths.journal_pending_name):
            marker = self.paths.transaction_parent / name
            marker.write_bytes(b"existing")
            try:
                with self.assertRaises(install.InstallError) as error:
                    self.create_continuation()
                self.assertEqual(error.exception.code, "service_dns_continuation_ineligible")
                self.assertEqual(marker.read_bytes(), b"existing")
            finally:
                marker.unlink()
        self.assertFalse(self.record.exists())
        (self.directory / "event-00000003.json").unlink()
        with self.assertRaises(install.InstallError) as error:
            self.create_continuation()
        self.assertEqual(error.exception.code, "service_dns_continuation_ineligible")
        self.assertFalse(self.record.exists())

    def test_changed_application_identity_cannot_create_continuation(self) -> None:
        self.fixture.runtime.guards = [self.new]
        foreign = install.AppIdentity("0.4.0", "40070", "f" * 64)
        with patch.object(self.transaction, "_identity_pair", return_value=(CANDIDATE, foreign)), self.assertRaises(install.InstallError) as error:
            self.transaction.continue_after_dns_change()
        self.assertEqual(error.exception.code, "service_identity_drift")
        self.assertFalse(self.record.exists())

    def test_wrong_lineage_and_non_dns_changes_in_record_are_rejected(self) -> None:
        self.create_continuation()
        original = json.loads(self.record.read_text())
        mutations = []
        for key in ("intent_sha256", "decommissioned_event_sha256"):
            mutations.append({**original, key: "f" * 64})
        mutations.extend([
            {**original, "transaction_id": "foreign"},
            {**original, "guard_after": self.old},
            {**original, "guard_after": {**self.new, "tun_sha256": "f" * 64}},
            {**original, "unexpected": True},
        ])
        for value in mutations:
            self.record.write_bytes(install._canonical_json(value))
            with self.assertRaises(install.InstallError):
                install.require_decommissioned_service_transaction(self.paths.install_paths, CANDIDATE, self.previous, self.new)
            with service.ServiceEventStore(self.paths) as store, store.locked(), self.assertRaises(install.InstallError):
                store.load()
        self.assert_original_preserved()

    def test_complete_pending_publication_can_resume_but_partial_bytes_are_retained(self) -> None:
        with patch.object(service.ServiceEventStore, "_publish_pending_event", side_effect=OSError("publication interrupted")):
            with self.assertRaises(OSError):
                self.create_continuation()
        pending = self.directory / install.SERVICE_DNS_CONTINUATION_PENDING
        self.assertTrue(pending.exists())
        with service.ServiceEventStore(self.paths) as store, store.locked():
            intent, events = store.load()
            self.assertEqual(store.effective_guard(intent, events), self.new)
        self.assertFalse(pending.exists())
        self.assert_original_preserved()
        self.record.rename(pending)
        pending.write_bytes(b"{")
        with service.ServiceEventStore(self.paths) as store, store.locked(), self.assertRaises(install.InstallError):
            store.load()
        self.assertEqual(pending.read_bytes(), b"{")
        self.assertFalse(self.record.exists())

    def test_acceptance_export_retains_the_dns_gap_record(self) -> None:
        class ContinuedExport(JournalExportFixture):
            def _write_service_journal(self):
                before = export_guard()
                after = {**before, "dns_sha256": "a" * 64}
                with service.ServiceEventStore(self.service_paths) as store, store.locked():
                    intent, events = store.create(CANDIDATE, self.previous, before, ENVIRONMENT)
                    bound = install.BoundInstallProfile.recorded(install.GA_INSTALL_PROFILE, self.previous)
                    for sequence in range(1, len(service.PHASES)):
                        if sequence == 4:
                            value = {
                                "document": "cfm-service-dns-observation-continuation-v1",
                                "schema_version": 1,
                                "transaction_id": intent["transaction_id"],
                                "intent_sha256": service._sha256(service._canonical_json(intent)),
                                "decommissioned_event_sha256": service._sha256(service._canonical_json(events[3])),
                                "guard_before": before, "guard_after": after,
                            }
                            install.validate_service_dns_continuation(value, intent, events)
                            descriptor = store._open_transaction_directory()
                            try:
                                store._write_new(descriptor, install.SERVICE_DNS_CONTINUATION_NAME, value)
                            finally:
                                os.close(descriptor)
                        events.append(store.append(
                            events, intent=intent, phase=service.PHASES[sequence],
                            action=bound.service_actions[sequence], guard=before if sequence < 4 else after,
                        ))

            def install_document(self):
                document = super().install_document()
                current = {**export_guard(), "dns_sha256": "a" * 64}
                document["guards"] = [{"before": current, "after": current, "operation": "install"}]
                return document

        fixture = ContinuedExport()
        try:
            original = (fixture.service_paths.transaction_directory / install.SERVICE_DNS_CONTINUATION_NAME).read_bytes()
            fixture.export()
            fixture.verify()
            copies = list(fixture.repository.rglob(install.SERVICE_DNS_CONTINUATION_NAME))
            self.assertEqual(len(copies), 1)
            self.assertEqual(copies[0].read_bytes(), original)
        finally:
            fixture.cleanup()


if __name__ == "__main__":
    unittest.main()
