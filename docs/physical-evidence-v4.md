# Physical evidence v4: PS256 collector trust and final-artifact binding

`Signed_Installed_Verified` is granted only by
`scripts/harness/physical_evidence_aggregator.py`. Aggregate schema v4, receipt
schema v3, proof schema v3, and trust-policy schema v2 are mandatory; older
documents have no compatibility path. A syntactically correct report, a
reported SHA-256, or a string such as
`evidence_source: harness` is not physical proof.

## Artifact contract

The aggregate itself, every aggregate report, and every harness input use the
same exact descriptor:

```json
{"kind":"packet-pcap","path":"runs/run-123/packet/tcp-ipv4.pcap","sha256":"<64 lowercase hex>","size":12345}
```

The descriptor has no optional or unknown fields. `path` is a canonical POSIX
path relative to the evidence root supplied by the aggregate loader. Absolute
paths, `.`/`..`, backslashes, unbounded components, wrong extensions, unknown
kinds, duplicate paths, and duplicate content digests are rejected. The reader
enforces per-kind, total-byte, and artifact-count limits.

Resolution is fd-based. Each path component is opened relative to the held
evidence-root fd with `O_NOFOLLOW`; the final object must be a regular file with
one link. The reader checks descriptor size, reads and hashes through the open
fd, compares pre/post `fstat`, reopens the declared path, and compares inode and
metadata again. Aggregate, report, provenance, and raw bytes share one held root
fd. After semantic validation, every accepted object is reopened, reread, and
rehashed; the aggregate is checked last. A missing file, symlink, hardlink,
append, same-byte restore with metadata drift, path replacement, byte drift, or
TOCTOU-visible mutation fails the entire physical level.

## Harness recomputation

- Packet schema v3 binds one bounded `.pcap` or `.pcapng` plus one signed
  capture-provenance artifact per required case. The parser accepts only DLT
  NULL, Ethernet (including bounded VLAN/QinQ), RAW, LOOP, SLL, and SLL2; then
  decodes IPv4/IPv6 and TCP/UDP lengths before interpreting application data.
  Fragmented IP is rejected. DNS proof requires an A/AAAA question at the
  signed resolver endpoint. QUIC proof requires UDP, the QUIC fixed bit, a
  source-pinned v1 or v2 version that matches signed provenance, and bounded
  DCID/SCID fields; GREASE/private versions and TCP fallback to the same
  endpoint/window are rejected. Tokens count only in decoded TCP/UDP application
  data, DNS names, or QUIC connection IDs, never link/IP headers, pcapng
  options, report text, or metadata. This proves QUIC transport only and does
  not claim HTTP/3 application semantics.
- Every absence case additionally binds a signed raw send-attempt artifact. It
  proves successful submission of the exact token hash and byte count to the
  same local/remote endpoint tuple using an independently bound send-command
  digest, within the marker-bounded capture window. The attempt receipt binds
  the finalized capture-provenance digest and is recorded only after capture
  completion/signing; the packet report is signed after that recording. The
  collector run receipt then signs the report and both raw descriptors. Markers
  without this causal attempt receipt cannot prove stop-cleanup or
  IPv6-disabled absence.
- Capture provenance binds interface name/index/link type, capture point,
  independently named capture-command/capture-filter digests, endpoint tuple,
  and collection/signing times. The report binds those capture digests and the
  distinct send-command digest; they are never treated as interchangeable.
  Classic pcap has no interface-name field, so its DLT and endpoint tuple come
  from packet bytes while interface identity/capture point remain an attestation
  by the source-pinned collector. With pcapng, an available IDB interface name
  is also cross-checked byte-for-byte against that signed provenance.
- Lifecycle v3 probes reference raw command/event documents. Candidate, run,
  machine, macOS build, operation context, command, exit code, ordered event
  sequence, and structured attributes must all match the fixed matrix. Raw
  lifecycle event schema v1 and lifecycle report v2 are rejected; there is no
  compatibility path that can silently omit the v3 evidence described below.
- `renderer-ready-v2` additionally references a raw renderer trace. It binds
  exactly two distinct live process identities, the release Team ID and Host
  signing identifier, executable digest, Code Directory hash, designated-
  requirement digest, candidate signed-app-tree digest, main-window label, and
  the exact `migration-handoff-renderer-ready-v2` challenge generation/digest.
  The validator recomputes the fixed parent/child order from parent identity,
  child launch and identity, native readiness, renderer challenge,
  publication, parent consumption, and the parent's committed exit, through
  child-observed parent absence. Parent and child PIDs must differ; the parent
  start identity must predate the trace and the child start identity must fall
  strictly inside it. Reordered events, PID reuse, impossible start times, or
  signature drift fail before receipt acceptance.
- Network Extension approval, denial, and pending are three separate required
  probes. Each references a raw typed OS-state trace bound to the candidate
  tree and exact Host, Packet Tunnel provider, System Extension wrapper, Team,
  executable, Code Directory, and designated-requirement identities. Approval
  must terminate in activated/enabled state, denial in user denial, and pending
  must retain a non-terminal awaiting-approval state for at least 30 seconds.
  A handwritten `passed`, `approved`, or similar report field is not accepted.
- `sleep-wake` references both a raw typed power/capture trace and a raw pcap or
  pcapng. The trace binds independent capture, pre-sleep-send, and post-wake-
  send command digests, the exact utun/endpoint tuple, four unique tokens, and
  the capture digest. The packet parser independently proves the pre-sleep
  marker, a wake marker, a post-wake application-data token after that marker,
  and the end marker, then cross-checks their packet timestamps against the
  signed sleep/wake trace. A lifecycle `recovery-observed` string without those
  raw packet bytes cannot satisfy the probe.
- `wkwebview-850x603` references raw typed capture metadata and an uncompressed
  RGBA pixel buffer. The metadata binds the candidate tree, main `WKWebView`,
  exact 850 by 603 CSS-pixel viewport, backing scale, derived pixel dimensions,
  row stride, sRGB/opaque RGBA layout, capture-command digest, timestamps, and
  pixel-buffer digest. The validator recomputes the exact byte count, opacity,
  and a minimum non-blank color set from the pixel bytes. Metadata, a screenshot
  hash, or a UI declaration without the retained pixels is insufficient.
- Performance reports reference raw samples and control events. Percentiles,
  throughput ratio, switch count/resource growth, soak duration, and crash count
  are recomputed from raw arrays, records, and timestamps. Declared summaries
  cannot substitute for samples.
- Adversarial reports reference separately captured client-signature evidence
  plus baseline and per-case transcripts. Client binary/signature identity,
  request nonce, command, exit code, authorization decision, denial code,
  cleanup, and secret-observation result are checked against the fixed case.

Each report carries proof schema v3 with the same candidate identity, final
`artifact_hash_manifest_sha256`, collector source/tool digests, exact KMS key
version, `PS256` algorithm, run ID, and 256-bit run nonce. The aggregate
candidate carries that same manifest digest. The aggregate reopens the report
file itself, compares that common proof to its run, and rejects report/raw
reuse. Removing the manifest digest, restoring proof schema v2, changing the
key version or algorithm, or changing the digest in only one layer fails before
receipt acceptance.

Raw completion (including the full soak) must precede report completion and
signing, and every report must complete/sign before its run receipt is signed.
Reversed timestamps, timestamps before the 2026-07-27 stable-matrix GA, and
future-dated run receipts are rejected.

The two environment labels are release-source contracts, not collector-chosen
aliases. For this release, `macos15` is pinned to stable macOS `15.7.8` on the
exact build `24G824`, and `current-macos` is pinned to stable macOS `26.6` build
`25G72`. Same-train alternatives, a label/version swap, an older major, macOS 27
beta, or a lowercase-suffixed prerelease build are rejected before report or
receipt acceptance. Advancing the current stable matrix requires a reviewed
source change to these exact pins; the verifier never infers it from the
collection host.

## Private operational manifests and public upload boundary

The final-candidate binding and sealed outer manifest are explicitly marked
`visibility: private-release-operations`. They are retained operational
evidence, not public upload artifacts. They may contain machine hashes, internal
relative paths, and collection/signing timestamps needed to revalidate the
private archive.

The existing public publication-evidence bundle is not expanded with either
private manifest, the physical aggregate, packet captures, lifecycle events,
renderer/Network Extension/power traces, WKWebView pixels, performance samples,
adversarial transcripts, capture provenance, machine hashes, internal evidence
paths, or physical collection timestamps. Publication authorization consumes
the private sealed manifest before creating the public bundle; it does not copy
that manifest into the bundle.

The corresponding private release-evidence archive is the directory tree under
the explicitly supplied evidence root. The aggregate descriptor records its
canonical retained location relative to that root and its exact bytes; the
aggregate records every report descriptor; each report records every raw
descriptor. Thus every retained object has an exact relative path, byte count,
kind, and SHA-256 without leaking raw payloads into the public bundle. The
absolute storage root is an operational secret/configuration and is deliberately
not embedded in a portable release document.

Build, validation, sealed-manifest validation, and final publication
authorization all require that private root to remain available. Each gate
reopens and hashes the aggregate, recursively reopens every report and every raw
artifact, recomputes the harness results, verifies both collector receipts, and
then reopens the aggregate again after the descendant traversal. A stored
summary, `raw_artifact_manifest_sha256`, archive binding digest, or aggregate
SHA-256 without the retained bytes is insufficient and fails closed.

Archive retention, access control, immutability/WORM storage, backup, and expiry
are release-operations responsibilities outside this repository. Deleting or
making the private archive unavailable makes later validation and publication
authorization fail; no public digest can substitute for it.

Final-candidate schema v3 independently recomputes the physical-candidate
artifact-hash manifest from `final_artifacts`, then requires its digest to equal
the digest in the reopened, PS256-signed aggregate schema v4. There is no caller-supplied
`evidence_binding`, empty superseded list, or other declaration that can replace
that signed cross-check. If physical evidence is unavailable, the derived
physical manifest binding is absent and the candidate remains blocked.
This manifest freezes the signed/notarized runtime candidate before physical
collection; the later distribution artifact-set seal separately binds the DMG,
updater signature, upload bundle, and remote downloads.

## Collector receipt and trust policy

Each physical run has a PS256 receipt schema v3 over canonical JSON containing:

- the source-pinned trust-policy digest;
- exact candidate, receipt-intent build timestamp, and physical-candidate
  artifact-hash manifest digest;
- OS, machine, clean-install, run ID, run nonce, and capture timestamp;
- collector version, source digest, executable digest, complete versioned Cloud
  KMS resource name, and algorithm;
- all four report descriptors; and
- the complete harness/subject/raw-descriptor set.

The sole accepted signature contract is RSASSA-PSS with SHA-256 (`PS256`) using
an exact 3072-bit RSA modulus, exponent 65537, MGF1-SHA-256, a 32-byte salt,
`emBits=3071`, and trailer `0xbc`. Verification is implemented with the Python
standard library. It rejects RS256, PS384, variable salt length, alternate MGF,
non-canonical base64url, wrong-sized signatures, invalid PSS padding, and RSA
representatives outside the pinned modulus. It does not invoke an ambient
`openssl` binary or retain an algorithm fallback.

Production never accepts an operator-selected key. The only production policy
path and exact byte digest are constants in `raw_artifacts.py`; the final
candidate and sealed manifest also bind the accepted policy SHA-256. A caller-
selected policy is rejected outside explicit fixture mode; if an internal
production caller passes a policy object, the loader freshly reopens the
canonical policy and requires full object equality before use. Key provisioning
or rotation therefore requires a reviewed release-source change to the
canonical policy bytes and their pinned digest.

The checked-in production policy is `state: configured` and pins the reviewed
v0.4.0 Cloud KMS HSM key version, attestation bytes, DER public key, collector
source closure, and immutable OCI image digest. The external provisioning and
live preflight record is documented in
[`release/physical-collector-v040.md`](release/physical-collector-v040.md).
This closes the collector trust-root prerequisite only. It is not evidence that
the signed two-process migration, Network Extension user flows, sleep/wake
packets, 850 by 603 WKWebView rendering, or long-duration stability have run on
the two required clean physical Macs. Test fixtures still use a committed
test-only RSA-3072 private key only in fixture mode and are not a production
trust root.

### External Cloud KMS HSM provisioning gate

The configured policy accepts only `RSA_SIGN_PSS_3072_SHA256`, protection level
`HSM`, a complete `.../cryptoKeyVersions/N` resource, and the official Cloud HSM
attestation formats `CAVIUM_V1_COMPRESSED` or `CAVIUM_V2_COMPRESSED`.
`ATTESTATION_FORMAT_UNSPECIFIED`, `SOFTWARE`, `EXTERNAL`, and
`EXTERNAL_VPC` are rejected. The format values and `content` byte encoding are
defined by the [Cloud KMS KeyOperationAttestation API](https://docs.cloud.google.com/kms/docs/reference/rest/v1/KeyOperationAttestation).

The policy digests have exact byte meanings:

- `public_key_sha256` is SHA-256 over the DER SubjectPublicKeyInfo bytes obtained
  by removing the PEM envelope and base64-decoding the public key returned for
  the exact key version. The offline parser independently rebuilds the canonical
  DER SPKI from policy `n` and `e` and requires the digest to match.
- `attestation_sha256` is SHA-256 over the raw compressed bytes obtained by
  base64-decoding the REST API `attestation.content` value. It is not a digest
  of the JSON wrapper, base64 text, decompressed payload, or certificate chain.
  `attestation_format` records how those exact content bytes must be interpreted.

The repository parser pins these declarations but cannot by itself prove their
external origin. Provisioning or rotating this policy requires release
engineering to follow Google's
[attestation verification procedure](https://docs.cloud.google.com/kms/docs/attest-key):
verify the manufacturer and Google certificate chains, verify the attested key
version resource-name hash, verify the public key, require non-extractable HSM
generation, and record the reviewed raw attestation bytes. The signer identity
must have only permission to sign with the dedicated receipt key, key
administration must be separate, metadata-based workload identity must replace
service-account key files, and Cloud KMS Data Access audit logging must be
enabled and retained before the first production receipt. KMS unavailability
fails closed; there is no local-key or old-algorithm fallback. Those external
controls were provisioned and live-tested for the pinned v0.4.0 policy, but are
not created or silently repaired by repository code.

## Security boundary and remaining external proof

Hashes and race-resistant file reads detect drift; the signed receipt proves
that an approved collector attested to the exact bytes and identities. They do
not make a malicious operator, compromised collection host, compromised GCP
project, or compromised collector key trustworthy. Nonce issuance, the
Firestore replay ledger, key custody, Binary Authorization and locked audit
retention remain external release-process controls. The current provisioning
record verifies those controls for v0.4.0, but a single human administrator is
still logical role separation rather than independent two-person approval.

Standalone harness commands report only raw-byte structural verification.
Only the aggregate, with the source-pinned collector receipt and both required
physical macOS runs, can grant `Signed_Installed_Verified`.
