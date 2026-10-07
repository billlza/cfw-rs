# 0.5.0 release identity

This document records how the 0.5.0 line obtained its releasable identity under
the existing single-GA policy
([`ga-assurance-policy-v040.md`](ga-assurance-policy-v040.md)) and the
forward-only lifecycle
([`candidate-identity-lifecycle.md`](candidate-identity-lifecycle.md)).
On 2026-10-07 ordering 1 below was chosen; the allocation in §2 and the
tooling delta in §3 are applied on the branch. 40073 is retired in
[`ga-build-40073-retirement.md`](ga-build-40073-retirement.md) and the
v0.4.0 ledger is closed. The last signed preview, 50025, stays recorded as
`SIGNED_PREVIEW_BUILD` only as the retained predecessor of the 50025 → 50026
migration evidence; `verify_version_contract.py` checks the one release identity
(its `--preview` selector and the preview build chain were removed on 2026-10-07).

## 1. Decision required first

The 0.4.0 GA identity 40073 was frozen on 2026-09-20 and never published; the
last public release is v0.3.5 (2026-07-21). The 0.5.0 line carries every 0.4.0
change plus the in-app update installer and the corrections of previews
50001–50025. Two orderings are possible:

1. **Publish 0.5.0 as the next release (recommended).** 40073 is retired as
   `retired_unbuilt_policy_superseded`-style history (a new terminal status is
   needed for "superseded by the next product version", see §3), and the
   migration gate for 0.5.0 covers v0.3.5 → 0.5.0 only, which is the only
   installed base that exists. The 0.4 worktree's installer changes are kept as
   history, not released.
2. **Publish 0.4.0 first, then 0.5.0.** Requires finishing the 0.4 line's own
   installer round, running the complete 0.4.0 GA matrix for 40073's successor
   (40073 itself was retired by the 2026-10-05 decision), and then repeating
   the whole matrix for 0.5.0 including a 0.4.0 → 0.5.0 migration run.

Everything below assumes ordering 1; ordering 2 only changes the migration
predecessor in §4.

## 2. Draft ledger `build-allocations-v050.json`

The verifier requires canonical JSON, an ordered gap-free build history from
the first recorded build to the last, exactly one `active_ga` record with role
`ga`, and a fixed immutable prefix. For 0.5.0 the recorded history starts at
50001. The 25 previews are consumed validation lineages; none may be relabelled
or reused. The first GA allocation is therefore 50026.

```json
{
  "active_ga": "50026",
  "allocations": [
    {"build": "50001", "role": "validation", "status": "retired_preview_before_signing"},
    {"build": "50002", "role": "validation", "status": "retired_preview_before_signing"},
    {"build": "50003", "role": "validation", "status": "retired_preview_before_signing"},
    {"build": "50004", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50005", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50006", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50007", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50008", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50009", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50010", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50011", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50012", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50013", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50014", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50015", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50016", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50017", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50018", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50019", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50020", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50021", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50022", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50023", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50024", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50025", "role": "validation", "status": "retired_preview_installed_superseded"},
    {"build": "50026", "role": "ga", "status": "active_ga"}
  ],
  "document": "cfm-release-build-allocation-v2",
  "product_version": "0.5.0"
}
```

The per-preview statuses must be taken from the retained evidence under
`target/050-completion/` and `docs/planning/0.5.0-implementation-status.md`
before the ledger is committed; the two statuses above are the only two
outcomes the previews had (not signed, or signed/notarized/installed and then
superseded by the next preview). 50025 is the currently installed preview.

## 3. Tooling delta before the ledger can exist

- `scripts/release_build_identity.py`: `PRODUCT_VERSION` becomes `0.5.0` and
  the active release identity becomes 50026; `SIGNED_PREVIEW_BUILD` stays only
  as the retained predecessor record (the `--preview` selector was removed).
- `scripts/verify_release_build_allocations.py`: ledger path and the three
  frozen tables (`IMMUTABLE_RETIRED_PREFIX`, `POLICY_SUPERSEDED_ALLOCATION`,
  `RETIRED_GA_ALLOCATIONS`) are v0.4.0 constants. They need a per-version
  table keyed by `PRODUCT_VERSION`, two new terminal statuses
  (`retired_preview_before_signing`, `retired_preview_installed_superseded`),
  and the 0.5.0 immutable prefix (50001–50025). The v0.4.0 ledger keeps its
  verifier table unchanged and gains one terminal status for 40073,
  `retired_superseded_by_next_product_version`.
- `scripts/candidate_freeze.py`: `LEDGER_RELATIVE_PATH` follows the version.
- `scripts/pinned_build_inputs.json` and `verify_pinned_build_inputs.py`:
  the new ledger is a pinned input; re-derive the bindings from the committed
  tree (`REQUIRED_ARTIFACT_BINDINGS_SHA256`,
  `REQUIRED_ARTIFACT_SOURCE_DIGESTS_SHA256`).
- `scripts/tests/test_candidate_freeze.py`,
  `test_release_build_identity.py` and the allocation verifier tests gain the
  0.5.0 cases; the "future build" constant in those tests moves past 50026.
- `CHANGELOG.md`: `## 0.5.0 - Unreleased` becomes `## 0.5.0 — <date>` in the
  release commit, dated by that commit, before candidate freeze: the frozen
  file is published as `MODIFICATIONS.md` and cannot change afterwards. The
  0.4.0 section stays as history under ordering 1.

## 4. GA evidence still owed for 0.5.0 (see RELEASE.md §1–§7)

Sealed networked inputs and the offline libbox build exist for the preview
lock; the quality gates pass on the branch head. Still owed, in order:
native data-plane evidence on the physical Apple Silicon Mac in the two
source-pinned clean OS environments with the packet-evidence endpoint;
inside-out signing and notarization of the GA identity; DMG, updater
archive, minisign signature and `latest.json`; GPL corresponding source,
SBOM and the human legal review; GA acceptance on the macOS 15 baseline
with the v0.3.5 → 0.5.0 migration, real TCP/UDP/DNS traffic, shutdown and
restoration proofs, the legacy-process non-mutation proof and the high-risk
rejection set; then publication. The branch `feat/liquid-glass-dialogs` is a
fast-forward of `main` (246 commits ahead, nothing behind).
