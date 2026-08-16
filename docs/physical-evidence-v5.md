# Physical evidence v5: single-machine PS256 collector trust

`Signed_Installed_Verified` is granted only by
`scripts/harness/physical_evidence_aggregator.py`. Aggregate schema v5 with
aggregator identity `physical-evidence-aggregator-v5-single-machine`, receipt
schema v3, proof schema v3, and trust-policy schema v3 are mandatory; older
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

- Packet schema v4 requires four distinct proof-free pre-nonce artifacts for
  every one of the 13 cases: a typed product-state observation, one bounded
  `.pcap` or `.pcapng`, capture provenance, and a send-attempt receipt. The two
  absence cases also require a later restored-state observation, so a valid
  matrix freezes 54 subjects in `raw/observation-manifest.json`; the later
  report carries the nonce proof but none of those retained documents does.
  Post-nonce materialization accepts a `NONCE_RECEIVED` session, reopens that
  exact manifest, and derives token, marker, timing and command fields from its
  bytes. It cannot rerun a command, accept replacement material, or recover a
  deleted state observation from a legal pcap. The parser accepts only DLT
  NULL, Ethernet (including bounded VLAN/QinQ), RAW, LOOP, SLL, and SLL2; then
  decodes IPv4/IPv6 and TCP/UDP lengths before interpreting application data.
  Fragmented IP is rejected. DNS proof requires three exact A/AAAA queries and
  their three authoritative, non-recursive TTL-zero responses at the
  source-pinned resolver endpoint. The product trigger is `getaddrinfo`; its
  local FakeIP result is retained but is not treated as the authoritative
  endpoint response. QUIC proof requires UDP, the QUIC fixed bit, a
  source-pinned v1 or v2 version that matches signed provenance, and bounded
  DCID/SCID fields; GREASE/private versions and TCP fallback to the same
  endpoint/window are rejected. Tokens count only in decoded TCP/UDP application
  data, DNS names, or QUIC connection IDs, never link/IP headers, pcapng
  options, report text, or metadata. This proves QUIC transport only and does
  not claim HTTP/3 application semantics.
- The product-state artifact retains the exact raw `/usr/bin/log show` NDJSON
  and `/usr/bin/codesign -d --verbose=4` output. It accepts only subsystem
  `com.bill.clashformac`, category `release-observation`, prefix
  `cfw-release-observation-v1 ` and canonical
  `cfw-product-observation-event-v1` bytes from the installed Host executable.
  Candidate version/build, process PID/start, monotonic per-process sequence,
  desired mode, phase, configuration digest, generation, owner, readiness and
  IPv6 state are checked against the case. `stop-cleanup` requires exact Off;
  `ipv6-disabled-absence` requires a ready exact Packet Tunnel owner with IPv6
  disabled. Both cases require a distinct later restart/re-enable product event
  after the absence interval and before the end marker.
- Every case binds three non-overlapping `start`/`target`/`end` sender commands,
  each with its own kernel-selected local tuple, exact argv and output receipt,
  token digest, route and interface observation, and authenticated Host stage.
  The fixed Host transaction proves strictly increasing baseline/test/restore
  generations and observation sequences; effective restored state must equal
  baseline. Local capture is one binary-stdout `pktap,all` DLT_RAW stream with
  a source-derived tuple/token BPF. Remote DNS capture also binds the dedicated
  service-account unique ID, ephemeral RSA-3072 generation and public-key
  receipts, two-minute OS Login key-import receipt, strict known-hosts file,
  IAP-only `gcloud compute ssh` argv, exact
  digest-bound `sudo tcpdump -c 6 -w -` command, 6/6/0 diagnostics, and the
  declared GCE transmit-checksum-offload context. The IAP role must be read
  from each IAP TCP tunnel instance resource policy (not Compute instance or
  project IAM), where condition `destination.port == 22` is mandatory. The
  route-selected send interface and independently captured pcap endpoint/DLT
  must agree. No
  handwritten interface, command digest, state JSON or success declaration can
  satisfy the contract.
- `scripts/physical_capture/packet.py` contains the closed Unified Log reader,
  fixed route/interface/tcpdump/send specifications and bounded dedicated
  sender. The receive-only peer source, tests, service unit and reproducible
  build instructions live in `tools/packet-evidence-endpoint/`; the pinned
  Linux/amd64 artifact digest is
  `fb92ecb25b77cd30c6710775501e5418cbf6415166326be37ddc443487fa2fc1`
  and the exact systemd unit digest is
  `7d485a9fe9081ebf019fcc8abc1d596358a64326e2490749d9903197262e3996`.
  The only supported Debian installation transaction is
  `install-endpoint.sh`, digest
  `6527983cf9b072ab99ecd820778ccb56c9d91d79e07fc4d558715c4ce8657049`;
  its fixed GCE metadata resolver configuration has digest
  `b290cc794e7f0faac9ebbd63f83aad67d23086b48206295d5d6a2767721c1e62`.
  The installed capture sudoers rule and local strict known-hosts bytes have
  digests `a91c2bc91a294622d44f14e2cad653b9703fcf70afa42bf91e0248ef240c3411`
  and `3741384531dbd24c65a2225386beae492bf92c61fdf2d5b90b57051d57be36ba`.
  `scripts/pinned_build_inputs.json` and its offline verifier bind those bytes,
  fixed TCP/UDP port 44333, UDP-only DNS port 53, CGO-disabled Linux/amd64
  build, source, tests, unit, resolver, installer, sudoers, endpoint identity
  policy and known-hosts file; the generated target binary is not tracked.
  The three GCE identities and twelve non-LAN case projections are pinned. The
  Host-owned DNS transaction and remote stream capture now have closed source
  paths, but the complete matrix entry still refuses collection because the
  controlled Android LAN peer is not provisioned or identity-pinned.
  It accepts no caller-supplied endpoint, profile, product state, pcap, or
  manual SSH result as a substitute. This is an explicit physical-run blocker,
  not a fixture fallback, and no physical candidate Packet evidence has been
  collected by this provisioning work.
- Lifecycle v4 has one exact 72-subject raw contract. Before nonce issuance it
  retains 32 `<probe>:observation` documents of kind
  `lifecycle-observation` plus the eight special trace/packet/pixel artifacts
  below. Those 40 subjects are the only lifecycle entries admitted to the
  immutable `RAW_COMPLETED` observation manifest, and none may contain a
  `proof` or `run_nonce` field. After nonce receipt, the deterministic
  materializer reopens only that frozen manifest and emits 32
  `lifecycle-event` v3 documents. Each event binds the nonce proof and exactly
  one retained observation descriptor; it contains no duplicated outcome that
  could drift from the observation. The final receipt must contain all 72
  subjects exactly once with unique paths and digests. Lifecycle report v3,
  proof-event v2, observation/event kind relabelling, missing observations,
  and added subjects are rejected without a compatibility path.
- The five identity probes are part of those same 32 pre-nonce observations,
  not an extra five-subject side channel. One fixed `verify_release_app.sh`
  execution produces their five distinct `lifecycle-observation` documents.
  Each binds the complete final candidate, run ID, lifecycle environment,
  probe ID, common verifier-batch digest, fixed command summary, exit status,
  original bounded stdout/stderr and timestamps. The validator rejects
  path/hash reuse, cross-run or cross-batch splicing, and any identity
  observation whose candidate/run/environment differs from its later event.
  Therefore the arithmetic remains 40 pre-nonce plus 32 post-nonce equals 72;
  it is not 77.
- `scripts/physical_capture/lifecycle.py` owns the two phases. Non-identity
  capture accepts output only from the fixed root-owned installed
  `CFWLifecycleProbe`; special outputs are copied from fixed root-owned paths
  and must byte-match the descriptors declared by that probe. Missing,
  writable, non-canonical, proof-bearing, or command/time/exit-mismatched
  output blocks before `RAW_COMPLETED`. Post-nonce event publication is
  crash-safe only by exact write-or-reopen: an existing byte-identical event is
  accepted on retry, while any mismatch blocks without replacement. The
  lifecycle-v4 Go collector source and trust-policy/image deployment must be
  rebound before a production nonce is authorized; local contract tests are
  not deployment evidence.
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
- Performance v3 binds exactly three proof-free pre-nonce subjects: a
  `performance-sample-ledger`, a durable shaping intent, and an independently
  query-verified shaping restoration. Every sample retains the fixed command
  argv/output and observer-executable digest, wall plus monotonic time, signed
  Host OSLog operation/generation/terminal mode, and the exact live PID/start/
  Team/identifier/CDHash/designated-requirement roster. The validator requires
  exact 20-sample latency/throughput/resource series, 20 recoveries for each of
  three fixed weak-network profiles, 101 alternating terminal switch records,
  37 five-minute soak heartbeats, 13 fifteen-minute real-traffic probes, and an
  empty covering DiagnosticReports/Unified Log crash delta. Percentiles,
  throughput ratio, switch growth, and soak duration are recomputed. The
  shaping intent also proves PF was already enabled by the host; collection
  blocks instead of silently loading ineffective dummynet rules or taking
  ownership of the machine-wide PF enable state. The
  post-nonce materializer reopens only the frozen manifest and cannot rerun a
  command or replace a missing restoration.
- Adversarial v3 is a source-pinned baseline plus exactly 32 cases. Every case
  binds four distinct raw subjects: a proof-free pre-nonce case observation,
  independent client and installed-Authority code-signature observations, and
  a post-nonce transcript derived only by reopening the frozen observation
  manifest. The six secret-surface cases bind a fifth raw coverage manifest,
  for an exact signed set of 138 adversarial subjects. Report entries cannot
  declare their own expected result: category, role, precondition, product
  event, accepted bit, stable code, state relation, cleanup state, isolation
  mode, and reset requirement all come from the checked-in case table.
  Its post-nonce transcript publication is retryable only as exact
  write-or-reopen: a destination left by an interrupted attempt is accepted
  solely when bounded secure reread bytes and SHA-256 equal the transcript
  rederived from the frozen manifest. Observation timestamps therefore remain
  the frozen pre-nonce values; conflicting prior bytes fail the run.
- The ten identity cases require ten distinct executable paths and byte
  digests. Wrong Team accepts a real non-product Team or ad-hoc signature;
  wrong bundle, designated requirement, and entitlement retain the other
  relevant baseline signing facts. The designated-requirement variant is a
  valid, launchable Apple-signed binary from the product Team with the exact
  Host identifier and App Group, but it uses a non-Developer-ID identity. Its
  reduced Team/bundle/entitlement requirement must pass while the listener's
  complete Developer-ID certificate/OID requirement fails. Foundation
  signing-gate rejections are proven by the exact listener requirement, the
  actual failed `codesign -R=...` exit status, connection invalidation before
  export, the actual client-visible `global_authority_interrupted` transport
  code, and zero accepted product events. They do not relabel an unavailable
  service as an identity denial or invent a server delegate callback that macOS
  never delivers.
  Post-listener policy and operation denials instead require the matching
  product-owned Unified Log envelope, actual kernel peer PID/euid/audit
  session, connection-identity digest, raw request SHA-256, actual stable code,
  and pre/post Authority state digests.
- Secret probes retain only a fresh one-way canary SHA-256 and complete,
  canonical per-location coverage entries. Plaintext canaries, locations, and
  secret-bearing output are not evidence fields. Any unreadable or excluded
  location, nonzero match count, missing surface, or disagreement on the one
  canary digest fails the matrix. Privileged identity, journal, fast-user-
  switching, and secret cases have explicit isolation/reset contracts; a
  failed reset stops the batch before another case can run.

Foundation's public SDK exposes `NSXPCConnection.current()` only while an
exported-object method is running and does not expose an `auditToken` member.
Compilation probes against the release deployment target therefore reject both
`connection.auditToken` and `NSXPCConnection.current()?.auditToken`. The public
listener API is the identity boundary: its SDK contract rejects peers that do
not satisfy the installed signing requirement before consulting the delegate.
The production-boundary scan rejects direct member access, selector lookup, and
`unsafeBitCast` protocols for the private audit-token accessor, so the product
cannot replace this gate with PID/path lookup or undocumented SPI.

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

Both OS runs must carry the same `machine_sha256`, binding the release policy's
declared single-hardware boundary. They must come from separate clean
installations or boot volumes with distinct `boot_environment_sha256` values
and retain distinct run IDs, nonces, receipts,
reports, and raw artifact bytes. Each OS run independently supplies a full
3-hour operator-observed wall-clock interval with no reported crash event, so
the sequential single-machine reservation takes at least 6 hours. The current
raw schema recomputes that interval from its start/end timestamps and validates
the ordered crash-event list; it does not cryptographically prove uninterrupted
process liveness or a monotonic-clock trace. That assurance is accepted only for
this controlled small internal distribution. A virtual
machine, an in-place label change, or the current macOS 27 beta installation
cannot substitute for either source-pinned environment. This policy accepts
the loss of hardware diversity; it does not weaken any lifecycle, packet,
performance, security, or cleanup assertion.

At the start of each OS run, create the private run context with the sole
supported producer:

```sh
/opt/homebrew/bin/python3 -I -S -B scripts/physical_capture/collector.py initialize \
  --lane macos15 \
  --attempt 01 \
  --confirm-clean-install \
  --network-profile controlled-ethernet \
  --uplink-mbps 1000 \
  --power-source ac
```

The producer exposes no machine, model, OS-version, OS-build, or boot-volume
override. It uses fixed absolute `uname`, `sysctl`, `ioreg`, `diskutil`, and
`sw_vers` commands; requires a non-virtualized physical Apple model; maps only
the two source-pinned OS/build pairs; and stores only domain-separated machine
and sealed-boot-volume digests. Before creating either a nonce or receipt
request it re-observes those values and fails on drift. The raw platform and
volume UUIDs must not enter a report, aggregate, seal, or public artifact.
Matching digests detect an accidental host or boot-volume switch under this
operator-controlled evidence model; they are not independent Secure Enclave
hardware attestation. `--confirm-clean-install` records an explicit operator
observation and is not cryptographic proof that an installation is pristine.

The six-hour production nonce authorizes and de-duplicates receipt signing; it
is requested after the complete raw run has finished and must be consumed
before expiry. It is not a collection-start challenge and therefore does not
truncate or replace the 3-hour raw soak timeline.
The producer binds the immutable service's six-hour TTL, derives the issue time
from `expires_at`, and refuses a nonce issued before raw completion, after the
local observation time, or after any proof-bearing report was signed. This is a
local controlled-operator guard; the receipt schema does not independently
carry or remotely attest that derived issue time.

Capture uses the exact source-owned producer order. Each successful command
records one immutable producer checkpoint; the fourth command freezes the
complete raw union. A checkpoint is reusable only when every retained file
still matches its path, size, kind, and SHA-256. An uncheckpointed partial
namespace cannot be resumed and forces attempt abandonment, except for the
separate fixed performance-shaping recovery transaction:

The next bounded attempt is admitted only after the prior abandonment binding
has one and only one strictly reopened closure record. Performance recovery is
not inferred from `restored: true`: its v3 record is bound to the same archive,
context, shaping intent and journal predecessor, captures the fixed
`sudo -n -v` preflight, uses a contiguous maximum of three attempts, and
revalidates every fixed restore/query command, digest, timestamp and
empty-state output.

```sh
/opt/homebrew/bin/python3 -I -S -B scripts/physical_capture/collector.py collect \
  --lane macos15 --attempt 01 --harness lifecycle
/opt/homebrew/bin/python3 -I -S -B scripts/physical_capture/collector.py collect \
  --lane macos15 --attempt 01 --harness adversarial
/opt/homebrew/bin/python3 -I -S -B scripts/physical_capture/collector.py collect \
  --lane macos15 --attempt 01 --harness packet
/opt/homebrew/bin/python3 -I -S -B scripts/physical_capture/collector.py collect \
  --lane macos15 --attempt 01 --harness performance
/opt/homebrew/bin/python3 -I -S -B scripts/physical_capture/collector.py finalize \
  --lane macos15 --attempt 01
```

`finalize` owns both one-shot Cloud Run POSTs. It archives and journals each
request before sending, never retries an outcome-unknown attempt, derives the
proof only after nonce receipt, then reopens and validates the four report/raw
sets before receipt signing and run-record finalization. Repeat the same fixed
flow with `--lane current-macos` on macOS 26.6. Once both lanes are finalized,
publish the aggregate without a caller-supplied evidence path:

```sh
/opt/homebrew/bin/python3 -I -S -B scripts/physical_capture/collector.py publish \
  --macos15-attempt 01 --current-macos-attempt 01
```

## Private operational manifests and public upload boundary

The final-candidate binding and sealed outer manifest are explicitly marked
`visibility: private-release-operations`. They are retained operational
evidence, not public upload artifacts. They may contain machine hashes, internal
relative paths, and collection/signing timestamps needed to revalidate the
private archive.

The existing public publication-evidence bundle is not expanded with either
private manifest, the physical aggregate, packet captures, lifecycle events,
renderer/Network Extension/power traces, WKWebView pixels, performance samples,
adversarial observations/signatures/transcripts/coverage manifests, capture
provenance, machine hashes, internal evidence
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
the digest in the reopened, PS256-signed aggregate schema v5. There is no caller-supplied
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

Receipt v3 signs the exact collector trust-policy SHA-256. Trust-policy schema
v3 embeds the exact aggregate schema, aggregator marker, one-machine/two-clean-
OS topology, OS/build matrix, 3-hour internal-release soak duration, machine-identity scheme,
and boot-environment scheme. The nonce intent is bound to that same server-
owned policy digest. Consequently, a receipt issued under the former policy
cannot be made valid by replacing only an unsigned aggregate marker; activating
this policy requires both private Cloud Run roles to use the new exact digest.

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
the same physical Mac in both required clean OS environments. Test fixtures
still use a committed test-only RSA-3072 private key only in fixture mode and
are not a production trust root.

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
that an approved collector signed the exact request bindings. The Cloud API
does not independently execute or enforce the local producer and does not
remotely attest the hardware model, virtualization state, boot volume, clean-
install claim, or continuous liveness. Those fields are operator observations
that the downstream aggregate cross-checks against the signed report bytes.
A direct API caller can bypass the recommended producer, so this profile is
appropriate only while the release operator and collection host remain inside
the stated trust boundary. These controls do
not make a malicious operator, compromised collection host, compromised GCP
project, or compromised collector key trustworthy. Nonce issuance, the
Firestore replay ledger, key custody, Binary Authorization and locked audit
retention remain external release-process controls. The current provisioning
record verifies those controls for v0.4.0, but a single human administrator is
still logical role separation rather than independent two-person approval.

Standalone harness commands report only raw-byte structural verification.
Only the aggregate, with the source-pinned collector receipt and both required
physical macOS runs, can grant `Signed_Installed_Verified`.
