# v0.4.0 physical collector provisioning record

This record binds the v0.4.0 production collector trust root and its external
control plane. It does not grant `Signed_Installed_Verified`, replace the two
distinct clean-Mac requirement, or authorize validation build 40002.

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
- Canonical checked-in trust-policy SHA-256:
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

- Nonce issuer: `physical-nonce-issuer-v040`, runtime identity
  `physical-nonce-issuer@cfw-release-evidence-20260730.iam.gserviceaccount.com`.
- Receipt signer: `physical-receipt-signer-v040`, runtime identity
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
- Production nonce issuance and receipt signing remain disabled until the
  configured source pin is committed and the two services are updated to that
  exact policy digest.

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

One local Mac is sufficient to operate this control plane and may supply one
physical evidence lane. It cannot satisfy the source-pinned requirement for
two distinct clean Macs on the pinned macOS versions/builds. One human retains
administrative authority over the GCP organization and both projects, so the
service identities provide technical and audit separation, not independent
two-person approval.
