# v0.4.0 GA and assurance policy calibration

Status: **accepted policy; implementation pending**.

This decision corrects the release-policy boundary for v0.4.0. It does not by
itself authorize a build, package, upload, or release. Until the implementation
migration is complete, the current executable gates remain authoritative and
v0.4.0 remains blocked.

## One releasable application identity

Build 40031 will be the only application identity signed, notarized, installed,
accepted, and published for the v0.4.0 GA. The DMG and updater archive will be
two distribution envelopes around the exact same 40031 application tree, not
separate application candidates.

Build 40030 will not be built, signed, submitted to Apple, installed, or used as
a substitute for 40031 evidence. After the executable policy migration, it will
be recorded as `retired_unbuilt_policy_superseded` and 40031 will become the
single `active_ga` build. The allocation file is intentionally unchanged until
the code and schema migration lands, so documentation cannot get ahead of the
enforced policy.

No further build pair may be allocated for a source, CI, documentation, test,
verifier, or preflight failure that occurs before an application candidate is
materialized. Such failures use an append-only attempt or CI-run identity.
Historical retired builds remain retired; this policy is forward-only.

A build number becomes consumed when a complete application candidate is
materialized and frozen, Developer ID signing starts, the candidate is
installed, a notarization submission starts, or another externally observable
candidate action occurs. Evidence-only changes that do not alter the frozen
application bytes require the affected evidence to be rerun, not a new
`CFBundleVersion`.

## Build-number allocation and consumption

The cross-version lifecycle and design-review rules are normative in
[`candidate-identity-lifecycle.md`](candidate-identity-lifecycle.md#build-number-allocation-and-consumption). In
particular, `CFBundleVersion` is an application-candidate identity, not a retry
counter. Source gates, hosted CI, documentation, tests, verifier changes, tool
bootstrap, and read-only preflights before candidate freeze use attempt or run
identities and do not consume the selected GA build.

The migrated implementation must durably commit an exclusive
`candidate-freeze` consumption intent before the first Developer ID signing
mutation or other externally observable candidate action. If it cannot prove
whether freeze, signing, installation, submission, or publication began, it
must record lifecycle state `quarantined_outcome_unknown` and treat the build
as consumed and quarantined. Existing versioned attempt schemas retain their
explicit `outcome-unknown` wire value; the migration must map it deliberately.
It must not assume the number is unused or allocate another number to hide an
ambiguous side effect.

Consumption binds the number permanently to one candidate lineage; it does not
mean that every later evidence failure needs a new build. The same exact frozen
and signed application may be queried, packaged, or re-evidenced under new
append-only attempt identities. A successor build is required only when
product inputs, application bytes, entitlements, profiles, or application or
nested-code signature bytes must change, or when the unique signed lineage
cannot be safely recovered. DMG/updater envelope signatures and seals use their
own package-attempt identity and do not by themselves change `CFBundleVersion`.

Candidate provenance and evidence provenance must remain distinct. An
evidence-only policy/tooling commit may advance only after it reopens the
candidate source commit and proves the same product-input digest. It records a
new evidence-policy identity and must never rewrite or relabel the candidate's
original source identity.

## GA-required gates

Every GA-required gate is explicit and fail closed. The GA manifest must bind:

- one clean repository commit, product-input identity, and exact-head hosted CI
  result with successful build, test, lint, and dependency-policy lanes;
- the arm64 application and nested products, inside-out Developer ID signing,
  the expected Team and bundle identities, reviewed provisioning profiles,
  entitlements, Hardened Runtime, and secure timestamps;
- application notarization, stapling, `stapler validate`, and Gatekeeper
  enabled/accepted evidence;
- GPL corresponding source, a minimum shipped-component SBOM, required licenses
  and notices, unresolved-license blockers, and the release-file digests needed
  to reproduce the shipped source obligation;
- the signed and notarized DMG seal, plus an updater archive, updater signature,
  manifest, official URL, and exact application-tree binding when updater
  publication is enabled;
- an exact-DMG install and 40019-to-40031 migration on a fixed Apple Silicon
  GA environment, including launch, service registration, System Extension and
  Network Extension approval, and real TCP, UDP, and DNS traffic;
- shutdown and restoration of Network Extension, proxy, DNS, and route state;
- proof that the protected legacy CFW process, its port 7890 ownership, and its
  proxy/network state were not stopped or mutated;
- a fixed high-risk rejection set covering wrong Team or bundle/role identity,
  wrong user or session, replayed or expired start authorization, and malformed
  or over-limit messages; and
- proof that credentials do not enter logs, configuration, journals, or
  evidence, and that ambiguous cleanup is reported as Failed or Quarantined
  rather than Off.

The complete GA acceptance must run on one fixed Apple Silicon environment.
The preferred baseline is the lowest supported macOS 15 environment. A light
install, launch, traffic, and shutdown smoke on the newest supported macOS
remains recommended, but does not inherit the full assurance matrix.

## Assurance-only qualification

The following evidence remains valuable but will not block an ordinary GA:

- a second full clean-OS environment on the same physical machine;
- the complete dual-OS lifecycle, packet, performance, and adversarial matrix;
- three hours of observed soak per OS and the fixed 72, 265, and related raw
  subject counts;
- the complete 32-case adversarial and 13-case packet suites;
- Cloud KMS HSM signing, Firestore replay ledgers, Binary Authorization,
  collector provenance, and long-retention audit custody;
- fixed pixel evidence and the 99 capability-report bindings; and
- the complete research-grade outer evidence seal.

Missing assurance evidence must be recorded as incomplete or not run. It must
never be represented as passed, and the release must not claim assurance
qualification without it. A product defect discovered by an assurance run is
handled by the defect policy; unavailable research infrastructure alone is not
a GA product failure.

## Three-stage release order

The implementation must expose three closed stages without skip flags or
fallback success:

1. `prepackage` verifies the exact 40031 application, source and CI identity,
   signing, notarization, Gatekeeper result, and license/source closure. Only a
   passing prepackage manifest may create the candidate DMG and updater sets.
2. `ga-acceptance` freezes and binds the DMG and updater set seals, then installs
   the exact DMG and records all required GA runtime and migration evidence.
3. `publication` binds the prepackage manifest, exact package sets, and passing
   GA acceptance before producing a distribution seal or authorizing upload.

An assurance manifest may reference the immutable GA manifest. It must not
rebuild, re-sign, relabel, or replace the GA application.

## Closed status model

The migrated schema will use fixed classifications and states:

```text
GateClass       = ga_required | assurance_only
GateStatus      = not_run | passed | failed | blocked
GAStatus        = eligible | blocked
AssuranceStatus = qualified | incomplete | failed
```

`GAStatus` is `eligible` only when every fixed `ga_required` gate is `passed`.
Missing, unknown, malformed, `not_run`, or `blocked` GA evidence blocks the
release. `AssuranceStatus` is `qualified` only when every fixed
`assurance_only` gate is `passed`; otherwise it remains incomplete or failed.
No optional field, exception handler, compatibility wrapper, or command-line
override may turn missing evidence into success.

## Required implementation migration

The next release-policy change must land as one reviewed migration that:

1. replaces the validation/final pair with one enforced `ga_build=40031`;
2. removes the 40030 build, notarization, installation, and review path;
3. performs the existing guarded 40019-to-40031 migration directly;
4. splits prepackage authorization from final publication authorization;
5. binds exact-DMG acceptance and updater-set identity before upload;
6. extracts the shared GA artifact core from the current final-candidate graph;
7. makes the existing full physical aggregate and sealed evidence graph an
   assurance extension that references the GA manifest;
8. rejects old production schemas rather than adding a compatibility fallback;
   and
9. updates build-allocation, publication, boundary, source-identity,
   documentation, and negative-order tests together.

Until all nine items and their fail-closed tests pass, neither this decision nor
the legacy high-assurance gate may be cited as ordinary GA authorization.
