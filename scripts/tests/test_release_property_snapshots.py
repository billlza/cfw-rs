#!/usr/bin/env python3
"""Regression tests for strict release-property snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from scripts.publication.common import PublicationError
from scripts.tests.release_property_snapshots import (
    PhysicalSnapshotInput,
    StrictReleasePropertySnapshots,
)


@dataclass(frozen=True)
class _Policy:
    policy_sha256: str
    trust_domain: str = "registered"


@dataclass(frozen=True)
class _AlternatePolicy:
    policy_sha256: str
    trust_domain: str = "registered"


class ReleasePropertySnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name).resolve()
        self.addCleanup(self._temporary.cleanup)

    def _source_only(
        self,
        derive,
        consumer: SimpleNamespace,
    ) -> StrictReleasePropertySnapshots:
        return StrictReleasePropertySnapshots(
            repository=self.root,
            source_deriver=derive,
            source_consumers=((consumer, "derive"),),
        )

    def test_source_snapshot_is_real_at_entry_and_exit_and_returns_deep_copies(
        self,
    ) -> None:
        calls = 0
        state = {"value": ["pinned"]}

        def derive(repository: Path) -> dict:
            nonlocal calls
            self.assertEqual(repository, self.root)
            calls += 1
            return {"source": list(state["value"])}

        consumer = SimpleNamespace(derive=derive)
        snapshots = self._source_only(derive, consumer)
        self.assertEqual(calls, 1)
        with snapshots:
            first = consumer.derive(self.root)
            first["source"].append("seed-mutation")
            self.assertEqual(consumer.derive(self.root), {"source": ["pinned"]})
            self.assertEqual(calls, 1)
        self.assertEqual(calls, 2)

    def test_unregistered_source_key_raises_assertion_not_publication_error(self) -> None:
        other_temporary = tempfile.TemporaryDirectory()
        self.addCleanup(other_temporary.cleanup)
        other = Path(other_temporary.name).resolve()

        def derive(_repository: Path) -> dict:
            return {"source": "pinned"}

        consumer = SimpleNamespace(derive=derive)
        with self._source_only(derive, consumer):
            with self.assertRaises(AssertionError) as captured:
                consumer.derive(other)
        self.assertNotIsInstance(captured.exception, PublicationError)

    def test_source_exit_revalidation_detects_drift(self) -> None:
        state = {"source": 1}

        def derive(_repository: Path) -> dict:
            return dict(state)

        consumer = SimpleNamespace(derive=derive)
        with self.assertRaisesRegex(
            AssertionError, "source property snapshot changed"
        ):
            with self._source_only(derive, consumer):
                # ``dict.__eq__`` considers 1 and True equal. Canonical bytes
                # must retain their distinct JSON scalar types.
                state["source"] = True

    def test_patch_point_is_rechecked_immediately_before_entry(self) -> None:
        def derive(_repository: Path) -> dict:
            return {"source": "pinned"}

        consumer = SimpleNamespace(derive=derive)
        snapshots = self._source_only(derive, consumer)
        consumer.derive = lambda _repository: {"source": "substituted"}
        with self.assertRaisesRegex(
            AssertionError, "consumer differs from the real dependency"
        ):
            snapshots.__enter__()

    def test_physical_snapshot_uses_strict_key_and_returns_deep_copies(self) -> None:
        policy = _Policy("a" * 64)
        descriptor = {
            "kind": "physical-aggregate",
            "path": "fixture/aggregate.json",
            "size": 1,
            "sha256": "b" * 64,
        }
        calls = 0

        def source(_repository: Path) -> dict:
            return {"source": "pinned"}

        def load(
            observed: object,
            *,
            evidence_root: Path,
            trust_policy: object,
            fixture: bool,
        ) -> dict:
            nonlocal calls
            self.assertEqual(observed, descriptor)
            self.assertEqual(evidence_root, self.root)
            self.assertIs(trust_policy, policy)
            self.assertIs(fixture, True)
            calls += 1
            return {"runs": ["macos15", "current-macos"]}

        source_consumer = SimpleNamespace(derive=source)
        physical_consumer = SimpleNamespace(load=load)
        snapshots = StrictReleasePropertySnapshots(
            repository=self.root,
            source_deriver=source,
            source_consumers=((source_consumer, "derive"),),
            physical_loader=load,
            physical_consumers=((physical_consumer, "load"),),
            physical_inputs=(
                PhysicalSnapshotInput(
                    descriptor=descriptor,
                    evidence_root=self.root,
                    trust_policy=policy,
                ),
            ),
        )
        self.assertEqual(calls, 1)
        with snapshots:
            first = physical_consumer.load(
                descriptor,
                evidence_root=self.root,
                trust_policy=policy,
                fixture=True,
            )
            first["runs"].append("seed-mutation")
            self.assertEqual(
                physical_consumer.load(
                    descriptor,
                    evidence_root=self.root,
                    trust_policy=policy,
                    fixture=True,
                ),
                {"runs": ["macos15", "current-macos"]},
            )
            self.assertEqual(calls, 1)
        self.assertEqual(calls, 2)

    def test_unregistered_physical_key_cannot_be_counted_as_domain_rejection(
        self,
    ) -> None:
        policy = _Policy("c" * 64)
        descriptor = {
            "kind": "physical-aggregate",
            "path": "fixture/aggregate.json",
            "size": 1,
            "sha256": "d" * 64,
        }

        def source(_repository: Path) -> dict:
            return {"source": "pinned"}

        def load(_descriptor: object, **_kwargs) -> dict:
            return {"runs": []}

        source_consumer = SimpleNamespace(derive=source)
        physical_consumer = SimpleNamespace(load=load)
        snapshots = StrictReleasePropertySnapshots(
            repository=self.root,
            source_deriver=source,
            source_consumers=((source_consumer, "derive"),),
            physical_loader=load,
            physical_consumers=((physical_consumer, "load"),),
            physical_inputs=(
                PhysicalSnapshotInput(
                    descriptor=descriptor,
                    evidence_root=self.root,
                    trust_policy=policy,
                ),
            ),
        )
        with snapshots:
            with self.assertRaises(AssertionError) as captured:
                physical_consumer.load(
                    {**descriptor, "sha256": "e" * 64},
                    evidence_root=self.root,
                    trust_policy=policy,
                    fixture=True,
                )
        self.assertNotIsInstance(captured.exception, PublicationError)

    def test_physical_key_binds_complete_policy_not_only_its_sha256(self) -> None:
        descriptor = {
            "kind": "physical-aggregate",
            "path": "fixture/aggregate.json",
            "size": 1,
            "sha256": "2" * 64,
        }
        registered = _Policy("3" * 64, trust_domain="registered")
        substitutions = (
            _Policy("3" * 64, trust_domain="substituted"),
            _AlternatePolicy("3" * 64, trust_domain="registered"),
        )

        def source(_repository: Path) -> dict:
            return {"source": "pinned"}

        def load(_descriptor: object, **_kwargs) -> dict:
            return {"runs": []}

        source_consumer = SimpleNamespace(derive=source)
        physical_consumer = SimpleNamespace(load=load)
        snapshots = StrictReleasePropertySnapshots(
            repository=self.root,
            source_deriver=source,
            source_consumers=((source_consumer, "derive"),),
            physical_loader=load,
            physical_consumers=((physical_consumer, "load"),),
            physical_inputs=(
                PhysicalSnapshotInput(
                    descriptor=descriptor,
                    evidence_root=self.root,
                    trust_policy=registered,
                ),
            ),
        )
        with snapshots:
            for substituted in substitutions:
                with self.subTest(policy_type=type(substituted).__name__):
                    with self.assertRaises(AssertionError):
                        physical_consumer.load(
                            descriptor,
                            evidence_root=self.root,
                            trust_policy=substituted,
                            fixture=True,
                        )

    def test_noncanonical_descriptor_error_is_converted_to_fixture_assertion(
        self,
    ) -> None:
        policy = _Policy("4" * 64)
        descriptor = {
            "kind": "physical-aggregate",
            "path": "fixture/aggregate.json",
            "size": 1,
            "sha256": "5" * 64,
        }

        def source(_repository: Path) -> dict:
            return {"source": "pinned"}

        def load(_descriptor: object, **_kwargs) -> dict:
            return {"runs": []}

        source_consumer = SimpleNamespace(derive=source)
        physical_consumer = SimpleNamespace(load=load)
        snapshots = StrictReleasePropertySnapshots(
            repository=self.root,
            source_deriver=source,
            source_consumers=((source_consumer, "derive"),),
            physical_loader=load,
            physical_consumers=((physical_consumer, "load"),),
            physical_inputs=(
                PhysicalSnapshotInput(
                    descriptor=descriptor,
                    evidence_root=self.root,
                    trust_policy=policy,
                ),
            ),
        )
        with snapshots:
            with self.assertRaises(AssertionError) as captured:
                physical_consumer.load(
                    {**descriptor, "invalid": object()},
                    evidence_root=self.root,
                    trust_policy=policy,
                    fixture=True,
                )
        self.assertNotIsInstance(captured.exception, PublicationError)

    def test_intentional_physical_defect_can_use_explicit_uncached_scope(self) -> None:
        policy = _Policy("6" * 64)
        descriptor = {
            "kind": "physical-aggregate",
            "path": "fixture/aggregate.json",
            "size": 1,
            "sha256": "7" * 64,
        }
        calls: list[str] = []

        def source(_repository: Path) -> dict:
            return {"source": "pinned"}

        def load(observed: object, **_kwargs) -> dict:
            assert isinstance(observed, dict)
            calls.append(observed["sha256"])
            return {"sha256": observed["sha256"]}

        source_consumer = SimpleNamespace(derive=source)
        physical_consumer = SimpleNamespace(load=load)
        snapshots = StrictReleasePropertySnapshots(
            repository=self.root,
            source_deriver=source,
            source_consumers=((source_consumer, "derive"),),
            physical_loader=load,
            physical_consumers=((physical_consumer, "load"),),
            physical_inputs=(
                PhysicalSnapshotInput(
                    descriptor=descriptor,
                    evidence_root=self.root,
                    trust_policy=policy,
                ),
            ),
        )
        unknown = {**descriptor, "sha256": "8" * 64}
        with snapshots:
            with self.assertRaises(AssertionError):
                physical_consumer.load(
                    unknown,
                    evidence_root=self.root,
                    trust_policy=policy,
                    fixture=True,
                )
            with snapshots.uncached_physical_validation():
                self.assertEqual(
                    physical_consumer.load(
                        unknown,
                        evidence_root=self.root,
                        trust_policy=policy,
                        fixture=True,
                    ),
                    {"sha256": "8" * 64},
                )
        self.assertEqual(calls, ["7" * 64, "8" * 64, "7" * 64])

    def test_physical_exit_revalidation_detects_drift(self) -> None:
        policy = _Policy("f" * 64)
        descriptor = {
            "kind": "physical-aggregate",
            "path": "fixture/aggregate.json",
            "size": 1,
            "sha256": "1" * 64,
        }
        state = {"revision": 1}

        def source(_repository: Path) -> dict:
            return {"source": "pinned"}

        def load(_descriptor: object, **_kwargs) -> dict:
            return dict(state)

        source_consumer = SimpleNamespace(derive=source)
        physical_consumer = SimpleNamespace(load=load)
        snapshots = StrictReleasePropertySnapshots(
            repository=self.root,
            source_deriver=source,
            source_consumers=((source_consumer, "derive"),),
            physical_loader=load,
            physical_consumers=((physical_consumer, "load"),),
            physical_inputs=(
                PhysicalSnapshotInput(
                    descriptor=descriptor,
                    evidence_root=self.root,
                    trust_policy=policy,
                ),
            ),
        )
        with self.assertRaisesRegex(
            AssertionError, "physical property snapshot changed"
        ):
            with snapshots:
                state["revision"] = True


if __name__ == "__main__":
    unittest.main()
