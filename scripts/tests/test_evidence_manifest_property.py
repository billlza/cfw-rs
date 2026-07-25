#!/usr/bin/env python3
"""Property-based test for Evidence_Manifest evidence-level closure.

Property 11: Evidence levels cannot be promoted without closure.

    For all evidence manifests, a capability is accepted at a level only if
    every required predecessor, exact artifact/environment binding, digest,
    command result, and level-specific evidence is present and valid; source
    or unsigned evidence alone can never satisfy signed-installed or
    sealed-release status, and any skipped/masked/unbound item rejects the
    manifest.

**Validates: Requirements 4.1, 6.5, 7.5**

This test treats ``scripts.evidence_manifest.validate_evidence_manifest`` as a
black box (its public API). The generator is deterministic: it uses the stdlib
``random`` module seeded with fixed integers so any failure reproduces exactly.
``hypothesis`` is intentionally not required; when it is unavailable we drive at
least 100 hand-generated manifests per property. On failure the test prints the
reproducing seed and the minimal offending manifest.
"""

from __future__ import annotations

import copy
import json
import random
import unittest

from scripts.evidence_manifest import (
    EvidenceManifestError,
    validate_evidence_manifest,
)

# --- Black-box description of the four evidence levels ----------------------
# Kept independent of the validator internals so the test exercises the public
# contract rather than mirroring the implementation.
LEVELS = (
    ("Source_Implemented", ("source_hash", "boundary_scan"), ("commit",)),
    (
        "Unsigned_CI_Verified",
        ("unsigned_artifact", "deterministic_test"),
        ("commit", "toolchain_sha256"),
    ),
    (
        "Signed_Installed_Verified",
        ("signed_identity", "physical_machine"),
        ("commit", "toolchain_sha256", "signed_app_sha256"),
    ),
    (
        "Sealed_Release_Evidence",
        ("notarization", "publication", "sbom"),
        ("commit", "toolchain_sha256", "signed_app_sha256"),
    ),
)
LEVEL_NAMES = tuple(name for name, _kinds, _bindings in LEVELS)
# Optional extra kinds a level accepts beyond its required set.
OPTIONAL_KINDS = {"Signed_Installed_Verified": ("packet_evidence",)}
MASKED_STATUSES = (
    "skipped",
    "masked",
    "timeout",
    "failed",
    "|| true",
    "passed_with_warnings",
    "",
    "PASSED",
)

# Number of generated manifests per property (>= 100 as mandated by Req 7.2).
ACCEPT_CASES = 160
REJECT_CASES = 240


def _hex(rng: random.Random, length: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(length))


def _fresh_identity(rng: random.Random) -> dict[str, str]:
    return {
        "commit": _hex(rng, 40),
        "toolchain_sha256": _hex(rng, 64),
        "signed_app_sha256": _hex(rng, 64),
    }


def build_manifest(rng: random.Random, forced_target: int | None = None):
    """Build a fully-closed, valid manifest and its expected highest levels.

    Returns ``(manifest, expected_levels)`` where ``expected_levels`` maps each
    capability id to the level name it should validate at.
    """
    identity = _fresh_identity(rng)
    reports: list[dict] = []
    capabilities: list[dict] = []
    expected: dict[str, str] = {}
    num_caps = 1 if forced_target is not None else rng.randint(1, 3)
    for cap_index in range(num_caps):
        target = forced_target if forced_target is not None else rng.randint(0, 3)
        cap_id = f"cap-{cap_index}"
        levels: dict[str, dict] = {}
        for level_index in range(target + 1):
            level_name, required_kinds, binding_keys = LEVELS[level_index]
            kind_list = list(required_kinds)
            for optional in OPTIONAL_KINDS.get(level_name, ()):  # sometimes add extras
                if rng.random() < 0.5:
                    kind_list.append(optional)
            report_ids: list[str] = []
            for kind in kind_list:
                report_id = f"{cap_id}-{level_name}-{kind}"
                reports.append(
                    {
                        "id": report_id,
                        "kind": kind,
                        "path": f"reports/{report_id}.json",
                        "sha256": _hex(rng, 64),
                        "status": "passed",
                        "bindings": {key: identity[key] for key in binding_keys},
                    }
                )
                report_ids.append(report_id)
            levels[level_name] = {"report_ids": report_ids}
        capabilities.append(
            {"id": cap_id, "highest_level": LEVEL_NAMES[target], "levels": levels}
        )
        expected[cap_id] = LEVEL_NAMES[target]
    manifest = {
        "schema_version": 1,
        "manifest_version": "evidence-manifest-v1",
        "identity": identity,
        "reports": reports,
        "capabilities": capabilities,
    }
    return manifest, expected


# --- Mutators: each returns a rejected manifest + a label, or None ----------
# Every mutator applies exactly one defect so the resulting manifest MUST be
# rejected (fail-closed). None means the mutator does not apply to this base.


def _find_cap_with_depth(manifest, min_depth):
    for cap in manifest["capabilities"]:
        if len(cap["levels"]) >= min_depth:
            return cap
    return None


def mutate_missing_predecessor(manifest, rng):
    cap = _find_cap_with_depth(manifest, 2)
    if cap is None:
        return None
    present = [name for name in LEVEL_NAMES if name in cap["levels"]]
    # Drop a non-top level so the declared levels are no longer a prefix while
    # the highest_level stays put.
    victim = rng.choice(present[:-1])
    del cap["levels"][victim]
    return manifest, f"missing-predecessor:{cap['id']}:{victim}"


def mutate_over_promotion(manifest, rng):
    candidates = [
        cap
        for cap in manifest["capabilities"]
        if LEVEL_NAMES.index(cap["highest_level"]) < 3
    ]
    if not candidates:
        return None
    cap = rng.choice(candidates)
    current = LEVEL_NAMES.index(cap["highest_level"])
    higher = rng.randint(current + 1, 3)
    cap["highest_level"] = LEVEL_NAMES[higher]
    return manifest, f"over-promotion:{cap['id']}->{LEVEL_NAMES[higher]}"


def mutate_stale_binding(manifest, rng):
    report = rng.choice(manifest["reports"])
    key = rng.choice(list(report["bindings"]))
    length = 40 if key == "commit" else 64
    stale = _hex(rng, length)
    while stale == report["bindings"][key]:
        stale = _hex(rng, length)
    report["bindings"][key] = stale
    return manifest, f"stale-binding:{report['id']}:{key}"


def mutate_masked_status(manifest, rng):
    report = rng.choice(manifest["reports"])
    report["status"] = rng.choice(MASKED_STATUSES)
    return manifest, f"masked-status:{report['id']}:{report['status']!r}"


def mutate_skipped_required_kind(manifest, rng):
    # Remove one required-kind report reference from a level that has >= 2
    # required kinds so a required kind is skipped.
    cap = rng.choice(manifest["capabilities"])
    level_name = rng.choice(list(cap["levels"]))
    required = dict((n, k) for n, k, _b in LEVELS)[level_name]
    ids = cap["levels"][level_name]["report_ids"]
    by_id = {r["id"]: r for r in manifest["reports"]}
    # find a referenced report whose kind is required
    victims = [rid for rid in ids if by_id[rid]["kind"] in required]
    if len(victims) < 1 or len(ids) < 2:
        return None
    victim = rng.choice(victims)
    ids.remove(victim)
    # also drop the raw report so an unbound-report defect does not mask this
    manifest["reports"] = [r for r in manifest["reports"] if r["id"] != victim]
    # if some other capability referenced it, this base is unsuitable
    for other in manifest["capabilities"]:
        for lvl in other["levels"].values():
            if victim in lvl["report_ids"]:
                return None
    return manifest, f"skipped-kind:{cap['id']}:{level_name}"


def mutate_unbound_report(manifest, rng):
    identity = manifest["identity"]
    dangling = {
        "id": "dangling-unbound",
        "kind": "source_hash",
        "path": "reports/dangling-unbound.json",
        "sha256": _hex(rng, 64),
        "status": "passed",
        "bindings": {"commit": identity["commit"]},
    }
    manifest["reports"].append(dangling)
    return manifest, "unbound-report"


def mutate_duplicate_report_id(manifest, rng):
    manifest["reports"].append(copy.deepcopy(rng.choice(manifest["reports"])))
    return manifest, "duplicate-report-id"


def mutate_malformed(manifest, rng):
    choice = rng.randint(0, 5)
    if choice == 0:
        manifest["extra_field"] = True
        return manifest, "malformed:unknown-field"
    if choice == 1:
        rng.choice(manifest["reports"])["kind"] = "totally_made_up"
        return manifest, "malformed:unknown-kind"
    if choice == 2:
        cap = rng.choice(manifest["capabilities"])
        cap["levels"]["Imaginary_Level"] = {"report_ids": []}
        return manifest, "malformed:unknown-level"
    if choice == 3:
        manifest["manifest_version"] = "evidence-manifest-v2"
        return manifest, "malformed:manifest-version"
    if choice == 4:
        manifest["identity"]["commit"] = "not-a-valid-commit"
        return manifest, "malformed:bad-identity-commit"
    manifest["reports"][0]["sha256"] = "xyz"
    return manifest, "malformed:bad-sha256"


MUTATORS = (
    mutate_missing_predecessor,
    mutate_over_promotion,
    mutate_stale_binding,
    mutate_masked_status,
    mutate_skipped_required_kind,
    mutate_unbound_report,
    mutate_duplicate_report_id,
    mutate_malformed,
)


def _dump(manifest) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True)


class EvidenceLevelClosureProperty(unittest.TestCase):
    def test_complete_manifest_validates_with_correct_highest_level(self) -> None:
        """A fully-closed manifest validates and reports the exact levels."""
        level_hits = {name: 0 for name in LEVEL_NAMES}
        cases = 0
        # Force one manifest per level first so every level is exercised.
        forced = [(1_000 + i, i % 4) for i in range(4)]
        seeds = forced + [(seed, None) for seed in range(ACCEPT_CASES)]
        for seed, forced_target in seeds:
            rng = random.Random(seed)
            manifest, expected = build_manifest(rng, forced_target)
            try:
                result = validate_evidence_manifest(copy.deepcopy(manifest))
            except EvidenceManifestError as error:  # a valid manifest was rejected
                self.fail(
                    "fully-closed manifest was wrongly rejected\n"
                    f"seed={seed} forced_target={forced_target}\n"
                    f"error={error}\nmanifest=\n{_dump(manifest)}"
                )
            achieved = {cap["id"]: cap["highest_level"] for cap in result["capabilities"]}
            if achieved != expected:
                self.fail(
                    "fully-closed manifest validated at the wrong level\n"
                    f"seed={seed} expected={expected} achieved={achieved}\n"
                    f"manifest=\n{_dump(manifest)}"
                )
            for name in expected.values():
                level_hits[name] += 1
            cases += 1
        self.assertGreaterEqual(cases, 100, "must run at least 100 accept cases")
        for name, hits in level_hits.items():
            self.assertGreater(hits, 0, f"level {name} was never exercised")

    def test_incomplete_manifest_is_rejected(self) -> None:
        """Every missing/stale/masked/skipped/malformed/unbound defect fails closed."""
        mutator_hits = {m.__name__: 0 for m in MUTATORS}
        cases = 0
        seed = 0
        while cases < REJECT_CASES:
            rng = random.Random(50_000 + seed)
            seed += 1
            # rotate mutators for even coverage
            mutator = MUTATORS[cases % len(MUTATORS)]
            base, _expected = build_manifest(rng)
            outcome = mutator(copy.deepcopy(base), rng)
            if outcome is None:
                continue
            mutated, label = outcome
            # Sanity: the mutation must actually change the document.
            if mutated == base and label != "malformed:bad-sha256":
                continue
            try:
                validate_evidence_manifest(copy.deepcopy(mutated))
            except EvidenceManifestError:
                mutator_hits[mutator.__name__] += 1
                cases += 1
                continue
            # Reaching here means an invalid manifest was wrongly accepted.
            self.fail(
                "over-promotion / incomplete manifest was wrongly ACCEPTED\n"
                f"seed={50_000 + seed - 1} defect={label}\n"
                f"manifest=\n{_dump(mutated)}"
            )
        self.assertGreaterEqual(cases, 100, "must run at least 100 reject cases")
        for name, hits in mutator_hits.items():
            self.assertGreater(hits, 0, f"defect class {name} was never exercised")

    def test_source_evidence_cannot_satisfy_higher_levels(self) -> None:
        """Source/unsigned reports can never be promoted to installed/sealed."""
        for seed in range(60):
            rng = random.Random(90_000 + seed)
            manifest, _expected = build_manifest(rng, forced_target=3)
            cap = manifest["capabilities"][0]
            by_id = {r["id"]: r for r in manifest["reports"]}
            # Point the Signed_Installed_Verified level at Source_Implemented reports.
            source_ids = cap["levels"]["Source_Implemented"]["report_ids"]
            cap["levels"]["Signed_Installed_Verified"]["report_ids"] = list(source_ids)
            with self.assertRaises(EvidenceManifestError):
                validate_evidence_manifest(copy.deepcopy(manifest))
            del by_id  # unused guard


if __name__ == "__main__":
    unittest.main()
