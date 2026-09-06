# Release candidate identity lifecycle

## Authority and scope

This document defines the cross-version design rules for allocating and
consuming application build numbers. It prevents source checks, CI retries,
documentation work, and evidence collection from being mistaken for new
application candidates.

This document defines lifecycle semantics only. It does not allocate,
activate, retire, or authorize any concrete build. Concrete current build state
is authoritative only when the versioned allocation ledger validates against
the release source constants. Version-specific policy may narrow the selected
GA build, but it must not weaken these no-reuse and provenance rules. Examples
in this document use symbolic identifiers and are non-normative.

A `CFBundleVersion` is a public, monotonic application-candidate identity and
ordering field. It is not a credential, authenticator, nonce, signature,
freshness proof, revocation mechanism, or retry counter. A higher build number
does not repair unsafe bytes, a compromised key, invalid evidence, or an
ambiguous external transaction.

## Build-number allocation and consumption

The rules below are the required design checkpoint before any release changes
an allocation ledger, freezes a candidate, or proposes a successor build.

## Identity vocabulary

Each kind of work has its own identity. They must not substitute for one
another.

| Identity | What it names | May advance without a new app build? |
| --- | --- | --- |
| `build_number` | One application-candidate lineage and its monotonic bundle identity | No, once consumed it remains bound to that lineage |
| `product_input_sha256` | The source, configuration, dependencies, and build inputs that determine application bytes | Yes before candidate freeze; after consumption, a change requires a new build |
| `candidate_source_identity` | The immutable source commit and product-input identity used to produce the frozen app | Never relabelled after freeze |
| `evidence_policy_identity` | The current evidence tooling, policy, and documentation commit used to validate the candidate | Yes, if the historical candidate product-input closure is reopened and remains identical |
| `attempt_id` | A local source, build, package, or evidence attempt | Yes; it is the normal retry identity |
| `ci_run_id` | One hosted CI run for one exact commit | Yes; failed or superseded runs remain history |
| `notary_submission_id` | One recoverable Apple notarization transaction | Only through recovery of the same known transaction; it is not replaced silently |
| `package_seal_sha256` | One immutable DMG or updater envelope around the frozen app | Yes; an envelope attempt is not a new application candidate |
| `publication_id` | One immutable external release/upload transaction | Only through recovery or a new explicit publication transaction |

`candidate_source_identity` and `evidence_policy_identity` are deliberately
separate. An evidence-only fix must not rewrite the source provenance recorded
inside an already frozen application. The evidence layer instead records its
own commit and attempt, then proves that the candidate commit and the current
evidence commit derive the same `product_input_sha256`.

The product-input closure is source-owned, complete, and versioned. It is not a
caller-selected include/exclude list. A new or unclassified release path fails
closed until the source policy classifies it as either product input or
evidence-policy input. Moving a path between those classes is itself a reviewed
product-input policy change and cannot be used to relabel an existing
candidate.

## Lifecycle state machine

The lifecycle is monotonic and forward-only:

```text
reserved_unconsumed
  -> active_ga_unconsumed
  -> candidate_frozen_consumed
  -> accepted
  -> published

reserved_unconsumed | active_ga_unconsumed
  -> retired_unbuilt

candidate_frozen_consumed | accepted
  -> retired_consumed
```

- `reserved_unconsumed` means the number is recorded but no production
  candidate lineage has been frozen. Source, CI, test, tooling, documentation,
  and read-only preflight failures do not leave this state.
- `active_ga_unconsumed` means the number is the only selected GA target. It is
  still unconsumed and may survive any number of pre-candidate attempts.
- `candidate_frozen_consumed` means an exclusive, durable candidate-freeze
  transaction has permanently bound the number to one verified application
  lineage and `product_input_sha256`.
- `accepted` means the exact frozen candidate and its fixed package envelopes
  passed the required GA acceptance. It is still immutable.
- `published` means official distribution has exposed the immutable release.
  It may be referenced or re-downloaded, never replaced.
- `retired_unbuilt` preserves a reserved but unmaterialized number as history.
  It is not evidence that a candidate existed, and it is never reused.
- `retired_consumed` preserves a consumed candidate that may no longer proceed.
  Its bytes, receipts, failures, and external identifiers remain immutable.

`consumed` does not mean that every later failure requires another build. It
means only that the build number cannot be rebound to different application or
application/nested-code signature bytes. Evidence queries, physical capture,
legal review, packaging, and recoverable external operations may use new
append-only attempt identities against the same exact frozen lineage.

## Consumption boundary

The normal consumption boundary is an exclusive `candidate-freeze`
transaction. All read-only source, dependency, toolchain, CI, signing-profile,
entitlement, credential-availability, and host preflights must pass first. The
transaction then durably records at least:

- the build number;
- `candidate_source_identity` and `product_input_sha256`;
- the complete pre-sign application tree and manifest identities;
- the fixed nested-product identities;
- the allocation-ledger identity; and
- an append-only consumption intent committed and directory-fsynced before the
  first signing mutation or externally observable candidate action.

The complete unsigned pre-sign application tree, including all nested native
products, must exist and pass its fixed structural verification before this
intent commits. No nested product or Host Developer ID signing command may run
before that durable boundary. After it commits, signing may only advance the
recorded lineage; it may not substitute a rebuilt unsigned tree.

Partial directories, compiler scratch data, failed unsigned builds, and other
unfrozen temporary output do not consume a build. Once the durable intent is
committed, a crash does not restore the number to an unconsumed state.

If an implementation fails to establish the normal freeze boundary, the first
action that may expose or mutate a production candidate also consumes the
number. This includes starting Developer ID signing, installation or service
mutation, notarization submission, collector or reviewer handoff, and upload
or publication. Consumption is based on the first possible side effect, not on
eventual success.

If the system cannot prove whether freeze, signing, installation, submission,
or publication began, it records lifecycle state
`quarantined_outcome_unknown`, treats the build as
consumed and quarantined, and reconciles the original transaction. It must not
assume the number is unused or hide an ambiguous side effect by allocating a
new number. Existing attempt schemas may retain their established
`outcome-unknown` wire value; implementations must map it explicitly and must
not silently accept both spellings for the same schema field.

## Consumption decision table

| Event | Consume the selected app build? | Required identity/action |
| --- | --- | --- |
| Source, dependency, lint, unit, build-script, documentation, or verifier failure before freeze | No | Append a source/CI attempt; keep the same active unconsumed build |
| Tool bootstrap or read-only environment/preflight failure before freeze | No | Append a preflight attempt; fix the boundary; do not allocate a companion build |
| Incomplete or failed temporary app construction before durable freeze | No | Retain preflight inputs and partial products; clean only the owned temporary Cargo runtime; preserve the failed tree before starting another attempt |
| Durable candidate-freeze intent commits | Yes | Bind the build permanently to the recorded product inputs and pre-sign tree |
| First signing mutation may have started without a proven freeze | Yes | Quarantine or recover the exact lineage; never reuse the number for different bytes |
| Notarization wait, info, log, or ticket query for a known submission | Already consumed; no new build | Recover the same submission ID and exact archive |
| Evidence, legal, SBOM, or physical capture failure with unchanged frozen app and nested-code signature bytes | Already consumed; no new build | Append a new evidence attempt bound to the same candidate |
| DMG or updater staging failure with unchanged frozen app and no external exposure | Already consumed; no new app build | Append a package attempt; preserve previous attempt history |
| Product source, dependencies, entitlements, profiles, app bytes, or application/nested-code signature bytes must change after consumption | Yes; retire and allocate a successor | Preserve the old lineage and build a new candidate from new product inputs |
| External transaction outcome cannot be uniquely recovered | Already consumed; quarantine | Record `quarantined_outcome_unknown`; do not fresh-submit or overwrite an official path |
| Assurance work after GA publication | No new GA build | Reference the immutable GA manifest; never rebuild, re-sign, or relabel it |

## Design and review workflow

Before proposing or changing a build number, the author and reviewer must
answer these questions in order:

1. Has a complete application tree been frozen by the durable
   `candidate-freeze` transaction?
2. May signing, installation, notarization, collection, review handoff, or
   publication already have started?
3. Is the failure confined to source checks, hosted CI, documentation, tests,
   tool bootstrap, a read-only preflight, packaging, or evidence collection?
4. Do the frozen product inputs, application tree, entitlements, profiles, and
   application/nested-code signature bytes remain exactly unchanged?
5. Can the original external transaction be recovered using its existing
   append-only identity?
6. Does a newer evidence-policy commit reopen the historical candidate commit
   and prove the same `product_input_sha256`?
7. Are the failure, attempt identity, consumption state, and any external
   action IDs durably recorded without overwriting earlier history?

The decision is then mechanical:

- If questions 1 and 2 are both no, keep the same unconsumed build and use a
  new attempt or CI run identity.
- If the build is consumed and questions 4 through 6 establish the same exact
  candidate and a recoverable operation, keep the build and rerun or recover
  only the affected evidence/envelope transaction.
- If product or application/nested-code signature bytes must change, or a
  unique signed lineage cannot be proven, retire the consumed build and
  allocate one successor.
- If an external outcome is ambiguous, quarantine and reconcile it. A build
  bump is not a recovery mechanism.

An evidence journal's capacity is an operation resource bound, not a candidate
retirement condition. Recovery must reserve enough space for its complete
success or failure path before changing retained evidence. An exhausted journal
remains readable; it must not append a record that invalidates its own history.

The allocation ledger reserves numbers and prevents reuse. Runtime consumption
belongs in a candidate directory outside the source tree as an exclusive,
append-only claim or transaction. Updating a checked-in allocation status
after a side effect must not rewrite the candidate's own source provenance.

## Required failure examples

- A hosted runner rejects a legitimate Python owner/mode layout, a temporary
  directory check fails, or lint/tests fail before candidate freeze: append a
  new CI run; keep `<ga_build>` unconsumed. Do not allocate `<ga_build + 1>`.
- A source-gate schema or attempt journal is corrected before candidate freeze:
  preserve failed attempts and rerun under a new attempt ID. Do not treat an
  old pre-candidate retirement as the forward policy.
- Evidence tooling or documentation changes after freeze while
  `product_input_sha256` and candidate bytes remain identical: retain the
  original `candidate_source_identity`, bind the new
  `evidence_policy_identity`, and rerun only affected evidence.
- A physical GA run discovers a product defect that requires code changes:
  retire the consumed build and allocate a successor. The old build must not be
  rebuilt with the fix.
- `codesign` may have started and the unique signed tree cannot be proven:
  quarantine or retire the build. Do not use forced re-signing to create a
  second set of bytes under the same build number.
- A notarization submit reply is lost: recover the same submission from its
  durable intent and known history. Do not fresh-submit while the outcome is
  ambiguous.
- An updater metadata or local DMG staging attempt fails before external
  exposure: use a new package attempt around the same exact application tree.
  Do not change `CFBundleVersion`.
- A package has been submitted or uploaded at an official location: never
  overwrite or relabel it. Recover the original transaction or create a new
  explicit package/publication identity; if app bytes change, use a new build.
- A signing or publication key is compromised: rotate or revoke the trust
  material and rebuild under a successor when application or nested-code
  signature bytes must change. Package-envelope signatures and seals retain
  their separate immutable package-attempt identity. A larger build number
  alone provides no security.
- Assurance qualification after publication references the immutable GA seal.
  It must not rebuild, re-sign, relabel, or replace the GA application.

## Version-specific application

The current v0.4.0 mapping and the ordinary-GA versus assurance boundary are
defined in [`ga-assurance-policy-v040.md`](ga-assurance-policy-v040.md). The
authoritative concrete allocation state is
[`build-allocations-v040.json`](build-allocations-v040.json), interpreted by
the corresponding source verifier. Historical retirement documents remain
facts about earlier workflows; they do not override this forward-only design
rule.
