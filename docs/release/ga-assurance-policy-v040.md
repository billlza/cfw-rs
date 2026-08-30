# v0.4.0 GA and assurance policy calibration

Status: **accepted executable policy; GA evidence pending**.

This decision corrects the release-policy boundary for v0.4.0. The executable
gates implement it, but the document by itself does not authorize a build,
package, upload, or release. v0.4.0 remains blocked until the exact source,
hosted CI, signing, notarization, package, installation, and GA-runtime evidence
passes for the single candidate below.

## One releasable application identity

Build 40038 is the only application identity signed, notarized, installed,
accepted, and published for the v0.4.0 GA. The DMG and updater archive will be
two distribution envelopes around the exact same 40038 application tree, not
separate application candidates.

Build 40030 must not be built, signed, submitted to Apple, installed, or used as
a substitute for 40038 evidence. It is recorded as
`retired_unbuilt_policy_superseded`; 40038 is the single `active_ga` build.

Build 40031 completed candidate freeze and began one private signing attempt,
but no canonical signed output or notarization submission was produced. It is
permanently recorded as
`retired_after_candidate_freeze_before_canonical_signing_output`; its frozen
root and failed attempt remain immutable under
[`ga-build-40031-retirement.md`](ga-build-40031-retirement.md). Build 40031
must not be rebuilt, resumed, promoted, installed, or substituted for 40038.

Build 40032 also completed candidate freeze and began one private signing
attempt. Five nested products were signed, but the fixed verifier rejected the
private transaction root before Host signing because its inner and outer path
contracts differed. No canonical signed output or notarization submission was
produced. Build 40032 is permanently recorded with the same consumed status;
its frozen root and failed attempt remain immutable under
[`ga-build-40032-retirement.md`](ga-build-40032-retirement.md). It must not be
resumed, rebuilt, promoted, installed, or substituted for 40038.

Build 40033 completed candidate freeze and began one private signing attempt.
Five nested products were signed, but the private helper's `umask 077` caused
bundle `CodeResources` files created by `codesign` to use mode `0600`; the
distribution-mode verifier rejected the staged application before Host
signing. No canonical signed output or notarization submission was produced.
Build 40033 is permanently recorded with the same consumed status; its frozen
root and failed attempt remain immutable under
[`ga-build-40033-retirement.md`](ga-build-40033-retirement.md). It must not be
resumed, rebuilt, promoted, installed, or substituted for 40038.

Build 40034 completed candidate freeze and one private signing attempt. Its
five nested roles and outer Host were correctly Developer ID signed, but the
post-sign Tombstone verifier's exact metadata schema omitted the two mandatory
pre-sign lineage fields. The fail-closed verifier rejected the attempt before
canonical output or notarization. Build 40034 is permanently recorded with the
same consumed status; its frozen root and failed attempt remain immutable under
[`ga-build-40034-retirement.md`](ga-build-40034-retirement.md). It must not be
resumed, rebuilt, promoted, installed, or substituted for 40038.

Build 40035 completed candidate freeze and entered one private signing attempt.
The attempt terminated with `signed_output_verification_failed` during complete
private signed-output verification, before canonical output or notarization.
The durable journal does not identify a narrower failing substage. Build 40035
is permanently recorded with the same consumed status; its frozen root and
failed attempt remain immutable under
[`ga-build-40035-retirement.md`](ga-build-40035-retirement.md). It must not be
resumed, rebuilt, promoted, installed, or substituted for 40038.

Build 40036 completed candidate freeze, canonical Developer ID signing, Apple
notarization, stapling, and Gatekeeper assessment. Publication preparation then
exposed verifier and code-closure contract defects whose correction changes the
tracked release-source identity bound into the frozen product input. Build
40036 is permanently recorded as `retired_after_notarization_before_install`;
its signed lineage and receipts remain immutable under
[`ga-build-40036-retirement.md`](ga-build-40036-retirement.md). It must not be
resumed, rebuilt, installed, packaged, promoted, or substituted for 40038.

Build 40037 completed candidate freeze and one private signing attempt. The
signing helper returned success and a complete transformation receipt was
durably present, but a later mandatory read-only verification replay failed
before publish-ready, canonical output, or notarization. Later read-only
replays passed without recovering the exact historical nested cause. The
frozen implementation recorded a terminal failure with no recovery transition,
so build 40037 is permanently recorded as
`retired_after_candidate_freeze_before_canonical_signing_output`; its immutable
history is retained under
[`ga-build-40037-retirement.md`](ga-build-40037-retirement.md). It must not be
resumed, rebuilt, signed again, promoted, installed, or substituted for 40038.

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

A future signing attempt may use an explicit `verification_blocked` state only
after the signing helper returned success, a complete transformation receipt
and exact private-work inventory are durably present, and no canonical output
or notarization transaction exists. Recovery must reopen and verify those exact
bytes without invoking the signing helper or receipt creator again. This rule
is forward-only and cannot reinterpret build 40037's terminal journal.

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
- an exact-DMG install and 40019-to-40038 migration on a fixed Apple Silicon
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

The ordinary-GA environment binding is private release evidence. Before the
first service mutation, the transaction records one canonical document that
contains only the domain-separated machine and APFS boot-environment digests,
the physical Apple hardware model, `arm64`, and the exact macOS product/build
versions. Raw IOPlatformUUID, APFS volume UUID, and volume-group UUID values
must never enter a journal, log, adapter, stage seal, or upload asset. The
service intent, dormant-install journal, runtime collection, every raw-derived
check, and the runtime adapter bind the same environment-document digest.
Machine, system-volume, or macOS-build drift fails closed before the next
mutation and again after restoration.

This contract fixes the machine and system environment, not one boot session.
A reboot needed for System Extension or Network Extension approval is allowed
only when the machine digest, APFS boot-environment digest, and exact macOS
version/build remain unchanged. The completed service and install journals are
then copied without modifying their source into one private, atomically
published `migration-journals` container before runtime collection. A partial,
pending, foreign-environment, or mixed-candidate export cannot authorize GA
acceptance.

The fixed container path is
`target/candidates/0.4.0/ga/40038/stage-inputs/ga-acceptance/migration-journals`.
It contains exactly the private `dormant-install.json`, the complete
`service-transaction` directory, `export-intent.json`, and
`export-receipt.json`. The sole environment document is
`service-transaction/environment.json`; a second root-level environment file
is forbidden. The producer schemas are `cfw-current-service-transaction-v3`,
`cfw-dormant-app-install-v2`, and `cfm-ga-environment-identity-v1`. The export
transaction uses `cfm-ga-journal-export-intent-v1` and
`cfm-ga-journal-export-receipt-v1`. GA runtime evidence uses
`cfm-ga-runtime-acceptance-v2`, `cfm-ga-runtime-check-v2`,
`cfm-ga-command-observation-v2`, `cfm-ga-runtime-collection-intent-v2`, and
`cfm-ga-runtime-collection-event-v2`. The prepackage stage remains
`cfm-ga-prepackage-seal-v1`; the acceptance and publication stages use
`cfm-ga-acceptance-seal-v2` and `cfm-ga-publication-seal-v2`.
Older service/runtime/stage markers cannot be accepted as compatible evidence.

The mandatory order is service recommission, journal `--export`, journal
`--verify`, runtime `collect`, runtime `verify`, and GA-acceptance sealing.
Journal `--recover` is admitted only after a recovery-required or
outcome-unknown export and must be followed by `--verify`; it is never a normal
step. Export and recovery must reopen byte-identical source journals under the
same environment binding and must never modify producer journals or replace an
already published container. The producer maintenance, service, and install
lock files must already exist as owned `0600` files; the read-only exporter
never creates a missing coordination lock. Verification holds the fixed
`stage-inputs` directory identity continuously while it opens and validates
the descendant acceptance container, so a directory rebind cannot combine two
different snapshots.

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

1. `prepackage` verifies the exact 40038 application, source and CI identity,
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

## Executable migration invariants

The release-policy implementation must preserve all of these invariants:

1. replaces the validation/final pair with one enforced `ga_build=40038`;
2. keeps build 40030 unbuilt; builds 40031/40032/40033/40034/40035 consumed and
   failed; build 40036 consumed, notarized, then retired before install; and
   build 40037 consumed and retired after private signed-work verification but
   before canonical output or notarization; all remain permanently outside
   every active notarization, installation, and review path;
3. performs the existing guarded 40019-to-40038 migration directly;
4. splits prepackage authorization from final publication authorization;
5. binds exact-DMG acceptance and updater-set identity before upload;
6. extracts the shared GA artifact core from the current final-candidate graph;
7. makes the existing full physical aggregate and sealed evidence graph an
   assurance extension that references the GA manifest;
8. rejects old production schemas rather than adding a compatibility fallback;
   and
9. updates build-allocation, publication, boundary, source-identity,
   documentation, and negative-order tests together.

All nine items and their fail-closed tests are required together. Even when the
source implementation passes, ordinary GA authorization exists only after the
immutable 40038 prepackage, GA-acceptance, and publication stages have each
reopened and accepted their real inputs. The assurance extension cannot replace
a missing GA stage.
