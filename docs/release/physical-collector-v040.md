# v0.4.0 physical collector provisioning record

This record binds the v0.4.0 production collector trust root and its external
control plane. It does not grant `Signed_Installed_Verified`, replace the
same-machine two-clean-OS requirement, or authorize validation build 40022.

## Source and image binding

- Collector contract: `physical-collector-v1`, receipt v3, PS256.
- Reviewed source-closure SHA-256:
  `67fa401401dfe1ffca670cbea62eff5f74e581dcc9161847a371968b6f5176a2`.
- Cloud Build ID: `ce844089-08be-4b00-ac89-a3177ccaf482` in
  `asia-east1`; source-closure verification, `go test ./...`, `go vet ./...`,
  image build and push all completed successfully under the dedicated builder
  service account.
- Immutable OCI image:
  `asia-east1-docker.pkg.dev/cfw-release-evidence-20260730/physical-evidence-control/physical-collector@sha256:d4fa73f55dead6e806844a2c1bdbb445b55d83b9603444d3e591ffd1f418c230`.
- On-demand scan:
  `projects/cfw-release-evidence-20260730/locations/asia/scans/fb3004c0-5908-4725-b725-87c07f0a18f8`;
  the result contained no vulnerability occurrences.
- Current activated trust-policy v3 SHA-256:
  `e95c2710371b3ba6f6899cb24fcbdc42038869934b1c89ddca651bd910601355`.

The first lifecycle-v4 candidate had source closure `9a640285...`, Cloud Build
`071c7484-471f-4ea8-a997-8a364dbe5df1`, image `af2048c3...`, scan
`d7f3ba5f-6464-43a7-9b41-d15f50694733`, deployment occurrence
`c6318119-cb07-4c63-bcae-3299983f2ecc`, and candidate policy
`ecbc6a17...`. It was never enabled: the authenticated `/healthz` probe was
intercepted by Cloud Run with HTTP 404 because Cloud Run reserves paths ending
in `z`. Both production roles remained disabled while the source replaced that
route with `/health`, added its regression test, and went through a fresh
build, scan, deployment attestation, policy generation, and deployment. The
failed candidate and its immutable evidence remain historical and do not
authorize collection.

The preceding lifecycle-v3 source closure `efe0e7a1...`, image `6b78b06d...`,
Cloud Build `66ec6a46-723f-4075-8f80-a4c4c635b3a7`, scan
`28c9f7de-8d15-40de-8cfa-226c71c7e51e`, and trust policy `907e7f11...` also
remain historical. They are not accepted by the current source-pinned client.

The original source closure `2439c826...`, image `0fb9e228...`, build
`0ca20d11-...`, scan `b3bd8346-...`, and trust-policy v2 digest
`f7a3e459...` remain historical activation evidence; none is accepted by the
current source-pinned client.

The build pushes a tag only as an upload handle. Binary Authorization and Cloud
Run use the immutable digest above; no service is deployed from a mutable tag.

## Receipt-signing HSM key

- Key version:
  `projects/cfw-release-evidence-20260730/locations/asia-east1/keyRings/physical-evidence/cryptoKeys/collector-receipts-v040/cryptoKeyVersions/1`.
- Algorithm and protection: `RSA_SIGN_PSS_3072_SHA256`, Cloud HSM.
- DER SubjectPublicKeyInfo SHA-256:
  `863babb36d4f8f57ade95d8fce2cee57b2bbdd4f7688f85097ec29f3bbbb555a`.
- Raw `CAVIUM_V2_COMPRESSED` attestation SHA-256:
  `1c7b7535900239b917b867b059ce33fd0b4fc676bd412bae5f54dadf1a766d79`.
- The Google verification script was pinned to upstream commit
  `fe585b8dad2cec3746c37c43d2b955e8d9979103`; script SHA-256
  `f9b1b393b6ee982545d3a4d943484242fae4381652bfe4765a769c014ad76dbb`.
  In Google Cloud Shell it built both the manufacturer and owner certificate
  chains and reported that the attestation was verified.
- Marvell `parse_v2.py` SHA-256 is
  `e82612c32b478446fe2e467c82c6ed22129aff7dc759f9a96a182f380a0dca27`;
  `verify_pubkey.py` SHA-256 is
  `0fdcec97b837e8e1bb468c2469fc4983399491f27202f67268db25f9911089a1`.
  The parsed private-key attributes were `0x0162=00` (not extractable),
  `0x0163=01` (generated locally), `0x0164=01` (never extractable), and
  `0x0165=01` (always sensitive). The resource-name SHA-256
  `539f286833008bd6264858f48470b6477f756e8dbf6f93015354023c633e4fe0`
  matched both key-ID records, and the exported public key matched the
  attestation.

The receipt runtime identity has only the custom
`cloudkms.cryptoKeyVersions.useToSign` permission on this dedicated CryptoKey.
Cloud KMS evaluates that permission against the parent CryptoKey even when the
request names a complete key version; therefore a `resource.name` condition for
the version would always deny the real call. The runtime configuration and
source-pinned policy both require version 1, the key has no other version, and
the runtime identity cannot create or administer key versions. Rotation must
use a newly reviewed key and policy update rather than silently adding a
version under the existing grant.

## Deployment authorization

- Artifact Analysis note and Binary Authorization attestor:
  `physical-collector-v040`.
- Deployment attestation occurrence:
  `projects/cfw-release-evidence-20260730/occurrences/ecc18ee8-244a-48fe-ace9-2983145f90e4`.
- The occurrence was PAE-encoded, signed by the separate Cloud HSM ECDSA P-256
  key `collector-deploy-attestor-v040/cryptoKeyVersions/1`, and validated during
  creation. All temporary signing, occurrence-write, attestor-verifier and
  impersonation grants were removed afterward.
- Occurrences `c6318119-cb07-4c63-bcae-3299983f2ecc` for the rejected
  lifecycle-v4 health candidate and `44cdf0f1-8477-4602-b5da-034b972ff01d`
  for the lifecycle-v3 dependency refresh remain immutable historical
  evidence; neither authorizes the current image.
- The project Binary Authorization policy is
  `REQUIRE_ATTESTATION` with `ENFORCED_BLOCK_AND_AUDIT_LOG` and no application
  image exemption. The effective organization policy allows only the `default`
  Binary Authorization policy for Cloud Run.

## Runtime and replay ledger

- Nonce issuer: `physical-nonce-issuer-v040`, active revision
  `physical-nonce-issuer-v040-enabled-20260822151852`, runtime identity
  `physical-nonce-issuer@cfw-release-evidence-20260730.iam.gserviceaccount.com`.
- Receipt signer: `physical-receipt-signer-v040`, active revision
  `physical-receipt-signer-v040-enabled-20260822151852`, runtime identity
  `physical-receipt-signer@cfw-release-evidence-20260730.iam.gserviceaccount.com`.
- Both services are private Cloud Run services in `asia-east1`, use the exact
  image digest, enforce Binary Authorization, scale from zero to at most one
  instance, and use no service-account key file.
- Firestore database `physical-release-ledger` uses Native mode, pessimistic
  concurrency, delete protection and point-in-time recovery. The runtime state
  machine is `ISSUED -> SIGNING -> COMMITTED/ABANDONED`.
- A denied KMS preflight produced a terminal `ABANDONED` record and did not
  retry. After the IAM resource-projection correction, a fresh preflight
  produced `COMMITTED`, key version 1 and signature SHA-256
  `d8fe752553e72191fc144cdd599e16411fbfd41c74fcc5bcd17beb005f392090`.
  Independent local OpenSSL verification accepted the RSA-PSS signature with a
  32-byte salt over `cfw-physical-collector-kms-preflight-v1`.
- Source pin commit `852cfd9` was deployed to both services with production
  receipt handling enabled and trust-policy SHA-256
  `f7a3e459384537c5b74ac8766dc6e2874a1dce95342e7be288d1ce5989b2ad61`.
  Both production routes remained private and returned HTTP 403 to
  unauthenticated requests. Activation issued no production nonce or receipt
  and did not start validation build 40002.
- The 2026-08-22 lifecycle-v4 activation produced one disabled-state and one
  enabled-state `COMMITTED` preflight, with signature SHA-256 values
  `81be5f922136821aef83d93837bc6cb7e56f0a652bf6e8df0c7e1456c5de8e84`
  and `0a2982a0fb9417d12b0ded6151156964bda1fd16ae0b2546617fca407ca2a0af`.
  Both independently verified as RSA-PSS/SHA-256 with a 32-byte salt over the
  fixed challenge and were read back as unique committed Firestore records.

## Single-machine policy transition

The single-machine evidence profile was first activated in trust-policy schema
v3 with SHA-256
`ed8538dbf11f49555a917617b3f20911801364c4853b05f9704fec99729293d0`.
Its `evidence_profile` authorizes only aggregate schema v5,
`physical-evidence-aggregator-v5-single-machine`, the two pinned OS/build
lanes, one-machine/two-clean-OS topology, distinct sealed boot environments,
the fixed machine/boot identity schemes, and a 3-hour-per-OS internal-release
soak. That policy digest and the following revisions are retained as historical
activation evidence.

The transition was activated on 2026-08-01 through a fail-closed maintenance
window: the receipt signer was disabled first, then the nonce issuer; both were
changed to the exact v3 policy digest while disabled; a fresh fixed-challenge
KMS preflight was independently verified with the checked-in RSA public key;
then signer and issuer were re-enabled in that order. Those revisions were:

- receipt signer `physical-receipt-signer-v040-00005-2tl`;
- nonce issuer `physical-nonce-issuer-v040-00005-dct`.

Both served 100 percent of traffic from the then-current immutable image
digest, retained Binary Authorization `default`, and reported
`CFW_PRODUCTION_RECEIPTS_ENABLED=true` with the exact v3 policy hash. The
activation preflight issued at `2026-08-01T07:12:34Z` reached `COMMITTED` with
signature SHA-256
`c01738abbc65051f9efa9e77817846c0d5ef65c360dfbb7d07c5fcf7a955d60c`.
A subsequent fixed-challenge preflight issued and committed at
`2026-08-01T07:13:07Z` with signature SHA-256
`2394e39dc01c8388f206d8c8a942c3cc3458e5b8bfe6c865204e91b9b77241b2`.
Both were `kms-ledger-preflight-v1` records; neither created a production nonce
or receipt.
Authenticated malformed nonce/receipt documents returned HTTP 400, proving
that both enabled schema gates were reached without issuing a production nonce
or receipt. Anonymous requests returned the platform's HTTP 404 privacy
response. The original v2 hash and revision IDs above remain historical
evidence and are not rewritten as v5 activation.

## Dependency security refresh activation

On 2026-08-02 the collector dependency closure was rebuilt after upgrading
`google.golang.org/grpc` to `1.82.1` and `golang.org/x/text` to `0.39.0`.
Local `go test`, race detection, `go vet`, and `govulncheck` reported no
reachable vulnerability. Cloud Build
`66ec6a46-723f-4075-8f80-a4c4c635b3a7` independently rechecked source closure
`efe0e7a16d67406aff50bb3439e59d4fad1c9dbb6f06ab7437a7d6b84ce44545`,
tests, and vet before producing image digest
`6b78b06d7640568099d815b3c3485c3a00bc92eac1972721ce8be01384dde759`.
The Asia on-demand scan returned an empty vulnerability occurrence list, and
Cloud HSM deploy-attestor version 1 created and validated Binary Authorization
occurrence `44cdf0f1-8477-4602-b5da-034b972ff01d`. All temporary token-creator,
KMS signer, occurrence-writer, note-attacher, and attestor-verifier grants were
removed and their resource policies were read back afterward.

Activation used a fail-closed maintenance window. The receipt signer was first
set to `CFW_PRODUCTION_RECEIPTS_ENABLED=false` and its newly ready revision was
required to be the sole 100-percent traffic target. The nonce issuer was then
disabled and verified in the same way. While both production routes were
disabled, the signer and issuer were moved to the exact immutable image,
trust-policy, source, and executable binding. Each new revision was required to
preserve its role-specific service account, Binary Authorization `default`,
private invocation policy, gen2 runtime, resource limits, scaling, timeout, and
reviewed concurrency. Authenticated health checks then proved process startup.
The signer fixed empty-body KMS preflight was committed and independently
verified locally. Only after those checks passed was the signer enabled and
verified, followed by the issuer. Authenticated malformed and anonymous probes
were completed before the source-pinned endpoint policy was updated to the
final revisions. No valid nonce or receipt request was sent during activation.
The disabled-state and enabled-state signature SHA-256 values were
`5313e17e17b63140c205ba8a3bb3578c1b3a3309b3241496959a7097ae472b69`
and `82cdc2f5e8bdab9b9e8ecd20d2a199a185120985eaf85d824cf5a9e133870a3b`.
Both verified as RSA-PSS/SHA-256 with a 32-byte salt over the fixed challenge.
They created only committed `kms-ledger-preflight-v1` records.

The fixed-challenge preflight proves only that the configured signer can create,
claim, sign, and commit a `kms-ledger-preflight-v1` record with the pinned HSM
key. Its RSA-PSS signature covers only
`cfw-physical-collector-kms-preflight-v1`; it does not independently bind the
serving image, trust-policy/source/executable environment, runtime service
account, Binary Authorization setting, traffic, scaling, or concurrency. Those
properties require a separate exact Cloud Run service, revision, IAM, and
traffic description gate. The issuer has no non-production route that exercises
its Firestore create path, so activation intentionally makes no claim of a live
issuer-ledger write without a production nonce.

That dependency refresh ended with receipt signer
`physical-receipt-signer-v040-00008-gh7` and nonce issuer
`physical-nonce-issuer-v040-00008-b58`. Each has one 100-percent traffic target,
used that refresh's immutable digest and exact configured policy SHA-256
`907e7f11c9510eb541537a077290c43cf2121b5047d777339a4c1f3debf9bec3`,
retained Binary Authorization `default`, its role-specific service account,
gen2, 512 MiB/1 CPU, zero minimum and one maximum instance. Signer concurrency
was 1 and issuer concurrency was its reviewed value 8. Authenticated malformed
documents returned HTTP 400 from the enabled schema gates; anonymous requests
were denied by Cloud Run with HTTP 403. No production nonce or receipt was
created during that refresh. The lifecycle-v4 activation below supersedes
those revisions and bindings.

## Lifecycle-v4 collector activation

The lifecycle-v4 source was activated on 2026-08-22 through a fail-closed
maintenance window. The signer was first moved to
`physical-receipt-signer-v040-disabled-20260822151852`, then the issuer to
`physical-nonce-issuer-v040-disabled-20260822151852`; each was Ready, the sole
100-percent traffic target, retained its old internally consistent binding, and
returned authenticated HTTP 503 from its production route. The rejected first
candidate reached only signer revision
`physical-receipt-signer-v040-prepared-20260822151852`; its external health
failure stopped the transaction before the issuer was updated or either role
was enabled.

With both roles still closed, the final source/image/policy binding was deployed
to `physical-receipt-signer-v040-prepared-health-20260822151852` and
`physical-nonce-issuer-v040-prepared-health-20260822151852`. Each revision was
required to be Ready and the sole traffic target, preserve Binary Authorization
`default`, private invocation IAM, its role-specific service account, gen2,
512 MiB/1 CPU, zero-to-one scaling, 30-second timeout, and concurrency 1 for
the signer or 8 for the issuer. Authenticated `GET /health` returned HTTP 200
from both containers, while their production routes still returned HTTP 503.

The disabled-state fixed-challenge preflight committed at
`2026-08-22T15:44:29Z` with signature SHA-256
`81be5f922136821aef83d93837bc6cb7e56f0a652bf6e8df0c7e1456c5de8e84`.
The signer was then enabled as
`physical-receipt-signer-v040-enabled-20260822151852`; only after its exact
configuration, health, authenticated HTTP 400 schema gate, anonymous HTTP 403
gate, and a fresh enabled-state preflight passed was the issuer enabled as
`physical-nonce-issuer-v040-enabled-20260822151852`. The second preflight
committed at `2026-08-22T15:47:32Z` with signature SHA-256
`0a2982a0fb9417d12b0ded6151156964bda1fd16ae0b2546617fca407ca2a0af`.
Both signatures independently verified with the checked-in RSA-3072 key as
RSA-PSS/SHA-256 with a 32-byte salt. A bounded Firestore read over the whole
maintenance interval returned exactly those two committed preflight records
and no production nonce or receipt record.

The final services use source closure `67fa4014...`, image digest
`d4fa73f5...`, trust-policy SHA-256 `e95c2710...`, and the final revisions above.
All temporary deploy-attestor token-creator, KMS signer, note-attacher,
occurrence-writer, and attestor-verifier grants were removed and read back to
their empty baseline before deployment. The project Binary Authorization policy
remained `REQUIRE_ATTESTATION` with `ENFORCED_BLOCK_AND_AUDIT_LOG`; the HSM keys,
service IAM, and protected Firestore configuration did not drift.

Rollback is forward-only and fail closed. Traffic must never be routed directly
to `physical-receipt-signer-v040-00005-2tl`,
`physical-nonce-issuer-v040-00005-dct`, or any other historical revision whose
immutable configuration has production receipt handling enabled. If any image,
environment, readiness, preflight, traffic, IAM, or probe check fails, the
operator must first create or retain a signer revision with production handling
disabled and verify it as the sole 100-percent latest traffic target, then do
the same for the issuer. The endpoint policy remains pinned to the last accepted
production revisions so clients fail before send. An image or policy rollback
must itself use fresh production-disabled revisions with internally matching
image/source/executable/policy bindings and must pass the complete deployment,
preflight, and source-pin review before either service can be re-enabled. If the
disabled traffic state cannot be proven, revoke the dedicated client's signer
invoker grant first, then the issuer grant, and quarantine all involved
revisions and audit records. Ambiguous KMS, ledger, or HTTP outcomes are never
automatically retried.

## Local invocation identity

The physical-capture client uses the dedicated service account
`physical-release-client@cfw-release-evidence-20260730.iam.gserviceaccount.com`.
It has `roles/run.invoker` only on the nonce-issuer and receipt-signer Cloud Run
services. The named release operator has
`roles/iam.serviceAccountTokenCreator` only on this service account, so local
capture can mint an ID token for the exact Cloud Run audience without receiving
project-wide editor, deployer, KMS, Firestore, or service-account-key access.
The former direct user `roles/run.invoker` bindings were removed from both
services after the impersonation preflight succeeded.

The source-pinned endpoint policy SHA-256 is
`8a2c3ee126d8dd619d2242bfb86b836d1559c8dc6d89ecebca66b3e3d6603e9b`.
Before either POST, the client requires the fixed active revision, sole 100
percent traffic target, origin and audience, then impersonates the dedicated
identity and locally verifies the JWT audience. The activation checks confirmed
both active revisions, both exact-audience tokens, and enabled schema gates
without sending a valid nonce or receipt request.

## Adversarial v3 collection boundary

The local collector contract now admits only `adversarial-clients-v3` and the
exact 138-subject set derived from the checked-in baseline plus 32-case table.
The pre-nonce producer in `scripts/physical_capture/adversarial.py` executes
source-selected absolute binaries through the session-owned observation
boundary with one case at a time, bounded streams and timeouts, process-group
cancellation, and mandatory reset verification for destructive cases. The
post-nonce path cannot execute a command; it reopens only the RAW_COMPLETED
manifest and materializes the 33 transcripts before composing the report. A
crash after nonce receipt may be retried: an already-published transcript is
accepted only after a bounded descriptor-relative reopen proves exact byte,
size, and digest equality with the transcript rederived from the frozen
observations. A mismatch fails closed; pre-nonce capture remains one-shot.

The installed controller and its five Foundation requirement variants are separate from the app
UI and are not bundled as a runtime feature. The fixed build/install script
requires the product signing identity, permits a genuinely non-product or
ad-hoc wrong-Team variant, and requires a distinct same-Team non-Developer-ID
Apple identity for the designated-requirement case. That variant must pass a
reduced Apple-anchor/Team/bundle/App-Group requirement and fail the complete
Developer-ID certificate/OID listener requirement with the real `codesign`
requirement-mismatch exit status. The script compiles every identity variant
with distinct code bytes, verifies every signature, and rejects any repeated
binary digest. The controller also retains the exact client-visible
`global_authority_interrupted` transport code; any unavailable/timeout result is
not accepted as an identity rejection. No XPC debug method, caller-selected
payload/path, or plaintext secret logging is added to the product.

This source contract is not physical evidence. The controller executes the
baseline, the five Foundation signing-requirement variants, and the three raw
protocol rejection cases (`oversize-message`, `deep-message`, and
`noncanonical-message`) through the public XPC API. The remaining 24 cases are
wired to fixed root-owned paths below
`.../Adversarial/PhysicalFixtures/<fixture-id>/<case-id>/CFWAdversarialFixture`;
the five external identity fixtures must also have distinct executable byte
digests, as required by the final matrix. Direct
fixtures receive only `execute|reset` plus the source-owned case ID, while the
UID, audit/login, journal, fast-user-switching, and secret-canary groups use
fixed `sudo -n` argv. An installed fixture therefore runs the normal signature,
Authority-log, state, isolation, and reset validators. A missing external
fixture or unavailable physical OS precondition returns canonical
`cfw-adversarial-precondition-unavailable-v1` with exit 69. That typed failure
is never archived as an observation, report/raw subject, PASS, or receipt
binding.

The source tree now contains one exact ten-controller SwiftPM closure for:
root-owned UID launcher (1), isolated audit-session controller (2), PID-reuse
controller (1), isolated console-session controller (1), Authority replay
controller (3), root-owned journal snapshot controller (4), bounded Authority
load controller (3), signed owner-liveness controller (2), fast-user-switch
controller (1), and root-owned secret-canary scanner (6). A shared support
target owns canonical output, public Authority XPC driving, kernel process/audit
observations, bounded command execution, state validation, and canary scanning;
each executable target remains a thin, closed case dispatcher. The installer
rebuilds every case with a compile-time case marker, signs and installs it at
the fixed root-owned path, verifies the exact SwiftPM product/target/path and
Host requirement, and rejects ownership, mode, hard-link, or digest reuse.

The UID rejection, isolated inherited-audit rejection/evidence, operation
prepare-cancel-replay, bounded read saturation, bounded PID-reuse observation,
and canary injection/scan drivers use real OS or installed Authority boundaries.
They emit no caller-authored pass flag. Provider ticket redemption, owner
liveness, journal stop/snapshot/restore, inactive-console, event-queue,
mutating-in-flight, and fast-user-switch cases still require their exact
role-signed executable or physical login/launchd precondition; until that
precondition is present they return only the typed exit-69 diagnostic and
cannot satisfy the matrix. The public SDK
does not expose `NSXPCConnection.auditToken`; `current()` is available only
inside an exported-object call, and direct audit-token member probes fail to
compile for the release target. Foundation instead documents that a listener
signing-requirement mismatch is rejected before its delegate runs. The product
therefore keeps that OS gate as the single identity boundary, and the
production scanner rejects direct member access plus private selector or
`unsafeBitCast` workarounds. Until all 32 cases run on both clean-OS lanes and
their resets validate, the physical release gate remains open.

## Audit retention and operational boundary

- Control project: `cfw-release-evidence-20260730`.
- Independent audit project: `cfw-release-audit-20260730`.
- Cross-project log bucket: `physical-release-control-audit` in `asia-east1`,
  3650-day retention, locked. Live routed records were observed for Cloud Run,
  Firestore and both denied and successful Cloud KMS `AsymmetricSign` calls
  before the irreversible lock was applied.
- Monthly budget: JPY 3000 with current-spend alerts at 50%, 80% and 100%, plus
  a 100% forecast alert. A budget is an alerting control, not a hard spending
  cap.

One local physical Mac is designated to supply both sequential clean-OS
evidence lanes; neither lane has been collected by this provisioning record.
The two future runs must use the same machine digest while
remaining independent in every run ID, nonce, receipt, report, and raw archive.
One human retains administrative authority over the GCP organization and both
projects, so the service identities provide technical and audit separation,
not independent two-person approval.
