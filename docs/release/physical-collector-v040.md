# v0.4.0 physical collector provisioning record

This record binds the v0.4.0 production collector trust root and its external
control plane. It does not grant `Signed_Installed_Verified`, replace the
same-machine two-clean-OS requirement, or authorize validation build 40002.

## Source and image binding

- Collector contract: `physical-collector-v1`, receipt v3, PS256.
- Reviewed source-closure SHA-256:
  `2439c826b23fc1c7f33f5d6003c9aa790268737d1da62db3577adcaa59e15caa`.
- Cloud Build ID: `0ca20d11-880c-40aa-bb88-460c4d08836d` in
  `asia-east1`; source-closure verification, `go test ./...`, `go vet ./...`,
  image build and push all completed successfully under the dedicated builder
  service account.
- Immutable OCI image:
  `asia-east1-docker.pkg.dev/cfw-release-evidence-20260730/physical-evidence-control/physical-collector@sha256:0fb9e2281730c6534101cfed26d31c04f718e3517a00c9e1bdb51dcf3c7bedd2`.
- On-demand scan:
  `projects/cfw-release-evidence-20260730/locations/asia/scans/b3bd8346-74a9-4b69-8674-d34298266def`;
  the result contained no vulnerability occurrences.
- Original activated trust-policy v2 SHA-256:
  `f7a3e459384537c5b74ac8766dc6e2874a1dce95342e7be288d1ce5989b2ad61`.

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
  `projects/cfw-release-evidence-20260730/occurrences/e10980bd-5fda-4d7f-99df-1607266760b4`.
- The occurrence was PAE-encoded, signed by the separate Cloud HSM ECDSA P-256
  key `collector-deploy-attestor-v040/cryptoKeyVersions/1`, and validated during
  creation. All temporary signing, occurrence-write, attestor-verifier and
  impersonation grants were removed afterward.
- The project Binary Authorization policy is
  `REQUIRE_ATTESTATION` with `ENFORCED_BLOCK_AND_AUDIT_LOG` and no application
  image exemption. The effective organization policy allows only the `default`
  Binary Authorization policy for Cloud Run.

## Runtime and replay ledger

- Nonce issuer: `physical-nonce-issuer-v040`, active revision
  `physical-nonce-issuer-v040-00002-fp4`, runtime identity
  `physical-nonce-issuer@cfw-release-evidence-20260730.iam.gserviceaccount.com`.
- Receipt signer: `physical-receipt-signer-v040`, active revision
  `physical-receipt-signer-v040-00002-q2b`, runtime identity
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

## Single-machine policy transition

Repository source now defines trust-policy schema v3 with exact SHA-256
`ed8538dbf11f49555a917617b3f20911801364c4853b05f9704fec99729293d0`.
Its signed `evidence_profile` authorizes only aggregate schema v5,
`physical-evidence-aggregator-v5-single-machine`, the two pinned OS/build
lanes, one-machine/two-clean-OS topology, distinct sealed boot environments,
the fixed machine/boot identity schemes, and a 3-hour-per-OS internal-release
soak. The image and HSM key do not need
to change because receipt v3 already signs the server-owned trust-policy hash.

The transition was activated on 2026-08-01 through a fail-closed maintenance
window: the receipt signer was disabled first, then the nonce issuer; both were
changed to the exact v3 policy digest while disabled; a fresh fixed-challenge
KMS preflight was independently verified with the checked-in RSA public key;
then signer and issuer were re-enabled in that order. The active revisions are:

- receipt signer `physical-receipt-signer-v040-00005-2tl`;
- nonce issuer `physical-nonce-issuer-v040-00005-dct`.

Both serve 100 percent of traffic from the unchanged immutable image digest,
retain Binary Authorization `default`, and report
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
response, and each IAM policy still grants `roles/run.invoker` only to the
named release operator. The original v2 hash and revision IDs above remain
historical evidence and are not rewritten as v5 activation.

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
