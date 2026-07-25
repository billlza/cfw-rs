#!/usr/bin/env python3
"""Property-based fail-closed test for the sealed source/license/SBOM closure.

This exercises ``publication.sealed_closure`` as a black box (Task 12.1,
Requirements 4.1, 5.1, 6.5). It is deterministic: the stdlib ``random`` module
is seeded with fixed integers so any failure reproduces exactly. ``hypothesis``
is intentionally not required; at least 100 generated closures are validated per
property and, on failure, the reproducing seed and offending document are
printed.

Two properties are checked:

* round trip - every fully specified reviewed closure builds and validates, and
  a closure missing any physical/signed input is environment-gated to
  ``blocked`` and can never be promoted to ``sealed``;
* fail closed - every single-defect mutation (unreviewed license node, tampered
  SBOM/artifact/supply-chain digest, inconsistent package graph, or corrupted
  content digest) is rejected.
"""

from __future__ import annotations

import copy
import hashlib
import json
import random
import unittest
from pathlib import Path

from scripts.publication.common import PublicationError, canonical_json
from scripts.publication.sealed_closure import (
    BLOCKED,
    SEALED,
    build_sealed_closure,
    validate_sealed_closure,
)

REPOSITORY = Path(__file__).resolve().parent.parent.parent
ACCEPT_CASES = 120
REJECT_CASES = 160

ECOSYSTEMS = ("cargo", "npm", "go", "swift", "native")
LICENSES = ("MIT", "Apache-2.0", "GPL-3.0-or-later", "BSD-3-Clause", "ISC", "MPL-2.0")
PHYSICAL = ("signed_app", "xcframework", "vulnerability_reports")


def _sha(rng: random.Random) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(64))


def _component(rng: random.Random, index: int) -> dict:
    ecosystem = rng.choice(ECOSYSTEMS)
    identifier = f"{ecosystem}-pkg-{index}"
    return {
        "id": identifier,
        "name": identifier,
        "version": f"{rng.randint(0, 9)}.{rng.randint(0, 20)}.{rng.randint(0, 99)}",
        "ecosystem": ecosystem,
        "scope": "runtime",
        "purl": f"pkg:{ecosystem}/{identifier}@1.0.0",
        "license_expression": rng.choice(LICENSES),
        "copyright_text": f"Copyright {identifier} authors",
        "license_files": [
            {"path": f"licenses/{ecosystem}/{identifier}/LICENSE", "sha256": _sha(rng)}
        ],
        "source_path": f"source/{ecosystem}/{identifier}",
        "source_sha256": _sha(rng),
    }


def _build_tool(rng: random.Random, index: int) -> dict:
    identifier = f"tool-{index}"
    return {
        "id": identifier,
        "name": identifier,
        "version": "1.0.0",
        "ecosystem": "toolchain",
        "scope": "toolchain",
        "purl": f"pkg:generic/{identifier}@1.0.0",
        "distribution": "external-build-tool-not-distributed",
        "license_reference": rng.choice(LICENSES),
        "license_evidence": [{"name": "LICENSE", "sha256": _sha(rng)}],
        "identity_metadata_sha256": _sha(rng),
        "executables": [{"name": "exe-0", "size": rng.randint(1, 4096), "sha256": _sha(rng)}],
    }


def _artifact_manifest(rng: random.Random) -> dict:
    from scripts.publication.common import tree_digest

    count = rng.randint(1, 4)
    entries = sorted(
        ({"path": f"artifacts/item-{i}.json", "sha256": _sha(rng)} for i in range(count)),
        key=lambda item: item["path"],
    )
    return {"entries": entries, "sha256": tree_digest(entries)}


def _request(rng: random.Random, drop_physical: str | None = None) -> dict:
    components = [_component(rng, i) for i in range(rng.randint(1, 4))]
    # validate_components requires a canonical (id-sorted, unique) inventory.
    unique: dict[str, dict] = {component["id"]: component for component in components}
    components = sorted(unique.values(), key=lambda item: item["id"])
    # Guarantee a canonical relationship that references real components.
    relationships = []
    if len(components) >= 2:
        pair = sorted((components[0]["id"], components[1]["id"]))
        relationships.append({"source": pair[0], "target": pair[1], "type": "DEPENDS_ON"})
    request = {
        "product": {"name": "Clash for Mac", "version": "0.4.0", "build_number": "40000"},
        "commit": _sha(rng)[:40],
        "sbom": {
            "components": components,
            "build_tools": [_build_tool(rng, 0)],
            "relationships": relationships,
        },
        "ccs": {"sha256": _sha(rng), "archive_sha256": _sha(rng)},
        "modification_notice": {"sha256": _sha(rng)},
        "third_party_notices": {"sha256": _sha(rng)},
        "artifact_hash_manifest": _artifact_manifest(rng),
        "signed_app": {"sha256": _sha(rng)},
        "xcframework": {"sha256": _sha(rng)},
        "vulnerability_reports": [
            {
                "id": "govulncheck-libbox",
                "tool": "govulncheck",
                "tool_version": "v1.6.0",
                "target": "libbox-macos-arm64",
                "sha256": _sha(rng),
            }
        ],
    }
    if drop_physical is not None:
        request[drop_physical] = None
    return request


def _reseal(closure: dict) -> dict:
    body = {k: v for k, v in closure.items() if k != "closure_sha256"}
    closure["closure_sha256"] = hashlib.sha256(canonical_json(body)).hexdigest()
    return closure


def _dump(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, default=str)


# --- Mutators: each applies exactly one defect that MUST be rejected ---------


def mutate_unreviewed_license(closure, rng):
    closure["sbom"]["components"][0]["license_expression"] = "NOASSERTION"
    return _reseal(closure), "unreviewed-license"


def mutate_spdx_digest(closure, rng):
    closure["sbom"]["spdx_sha256"] = _sha(rng)
    return _reseal(closure), "spdx-digest"


def mutate_cyclonedx_digest(closure, rng):
    closure["sbom"]["cyclonedx_sha256"] = _sha(rng)
    return _reseal(closure), "cyclonedx-digest"


def mutate_artifact_digest(closure, rng):
    closure["artifact_hash_manifest"]["sha256"] = _sha(rng)
    return _reseal(closure), "artifact-digest"


def mutate_supply_chain(closure, rng):
    closure["supply_chain"]["patched_source"]["combined_diff_sha256"] = _sha(rng)
    return _reseal(closure), "supply-chain"


def mutate_content_digest(closure, rng):
    closure["closure_sha256"] = _sha(rng)
    return closure, "content-digest"


def mutate_relationship_absent(closure, rng):
    closure["sbom"]["relationships"].append(
        {"source": closure["sbom"]["components"][0]["id"], "target": "ghost", "type": "DEPENDS_ON"}
    )
    return _reseal(closure), "graph-inconsistent"


MUTATORS = (
    mutate_unreviewed_license,
    mutate_spdx_digest,
    mutate_cyclonedx_digest,
    mutate_artifact_digest,
    mutate_supply_chain,
    mutate_content_digest,
    mutate_relationship_absent,
)


class SealedClosureRoundTripProperty(unittest.TestCase):
    def test_full_closures_build_and_validate(self) -> None:
        blocked_hits = {name: 0 for name in PHYSICAL}
        sealed_hits = 0
        cases = 0
        for seed in range(ACCEPT_CASES):
            rng = random.Random(1_000 + seed)
            drop = rng.choice((None, *PHYSICAL))
            request = _request(rng, drop)
            try:
                closure = build_sealed_closure(REPOSITORY, request, fixture=True)
                validate_sealed_closure(REPOSITORY, closure, fixture=True)
            except PublicationError as error:
                self.fail(
                    f"valid closure was rejected\nseed={1000 + seed} drop={drop}\n"
                    f"error={error}\nrequest=\n{_dump(request)}"
                )
            if drop is None:
                self.assertEqual(closure["status"], SEALED)
                validate_sealed_closure(REPOSITORY, closure, fixture=True, require_sealed=True)
                sealed_hits += 1
            else:
                self.assertEqual(closure["status"], BLOCKED)
                self.assertIn(drop, closure["blocked_inputs"])
                blocked_hits[drop] += 1
                with self.assertRaises(PublicationError):
                    validate_sealed_closure(REPOSITORY, closure, fixture=True, require_sealed=True)
            cases += 1
        self.assertGreaterEqual(cases, 100, "must run at least 100 accept cases")
        self.assertGreater(sealed_hits, 0, "sealed status was never exercised")
        for name, hits in blocked_hits.items():
            self.assertGreater(hits, 0, f"blocked input {name} was never exercised")


class SealedClosureFailClosedProperty(unittest.TestCase):
    def test_single_defect_closures_are_rejected(self) -> None:
        mutator_hits = {m.__name__: 0 for m in MUTATORS}
        cases = 0
        seed = 0
        while cases < REJECT_CASES:
            rng = random.Random(50_000 + seed)
            seed += 1
            mutator = MUTATORS[cases % len(MUTATORS)]
            base = build_sealed_closure(REPOSITORY, _request(rng), fixture=True)
            mutated, label = mutator(copy.deepcopy(base), rng)
            if mutated == base:
                continue
            try:
                validate_sealed_closure(REPOSITORY, mutated, fixture=True)
            except PublicationError:
                mutator_hits[mutator.__name__] += 1
                cases += 1
                continue
            self.fail(
                "a single-defect sealed closure was wrongly ACCEPTED\n"
                f"seed={50_000 + seed - 1} defect={label}\nclosure=\n{_dump(mutated)}"
            )
        self.assertGreaterEqual(cases, 100, "must run at least 100 reject cases")
        for name, hits in mutator_hits.items():
            self.assertGreater(hits, 0, f"defect class {name} was never exercised")


if __name__ == "__main__":
    unittest.main()
