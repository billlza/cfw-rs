# Physical evidence v2: proof-to-byte and collector trust

`Signed_Installed_Verified` is granted only by
`scripts/harness/physical_evidence_aggregator.py`. Version 1 claim-only JSON is
not accepted. A syntactically correct report, a reported SHA-256, or a string
such as `evidence_source: harness` is not physical proof.

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
metadata again. A missing file, symlink, hardlink, byte drift, path swap, or
TOCTOU-visible mutation fails the entire physical level.

## Harness recomputation

- Packet reports reference one bounded `.pcap` or `.pcapng` per required case.
  The parser validates capture/record/block lengths and timestamps. It searches
  only captured packet-record payloads, never capture headers, pcapng options,
  report text, or file metadata. Unique start/end markers establish a real
  1-second to 10-minute window. Presence tokens must occur in that window;
  absence tokens must not. Unsigned server-observation JSON is not accepted.
- Lifecycle probes reference raw command/event documents. Candidate, run,
  machine, macOS build, operation context, command, exit code, ordered event
  sequence, and structured attributes must all match the fixed matrix.
- Performance reports reference raw samples and control events. Percentiles,
  throughput ratio, switch count/resource growth, soak duration, and crash count
  are recomputed from raw arrays, records, and timestamps. Declared summaries
  cannot substitute for samples.
- Adversarial reports reference separately captured client-signature evidence
  plus baseline and per-case transcripts. Client binary/signature identity,
  request nonce, command, exit code, authorization decision, denial code,
  cleanup, and secret-observation result are checked against the fixed case.

Each v2 report carries the same candidate identity, collector source/tool
digests, run ID, and 256-bit run nonce. The aggregate reopens the report file
itself, compares that common proof to its run, and rejects report/raw reuse.

The two environment labels are release-source contracts, not collector-chosen
aliases. For this release, `macos15` is pinned to stable macOS `15.7.8` on the
`24G` build train and `current-macos` is pinned to stable macOS `26.6` on the
`25G` build train. A label/version swap, an older major, macOS 27 beta, or a
lowercase-suffixed prerelease build is rejected before report or receipt
acceptance. Advancing the current stable matrix requires a reviewed source
change to these exact pins; the verifier never infers it from the collection
host.

## Public manifest and private archive boundary

The final-candidate binding and sealed outer manifest do not publish packet
captures, lifecycle events, performance samples, adversarial transcripts, or
the aggregate document. Their public edge is the aggregate descriptor
`{kind,path,size,sha256}`, the source-pinned trust-policy digest, collector
receipt digests, the raw-artifact-manifest digest, bounded artifact counts and
bytes, and a canonical private-archive binding digest.

The corresponding private release-evidence archive is the directory tree under
the explicitly supplied evidence root. The aggregate descriptor records its
canonical retained location relative to that root and its exact bytes; the
aggregate records every report descriptor; each report records every raw
descriptor. Thus every retained object has an exact relative path, byte count,
kind, and SHA-256 without leaking raw payloads into the public manifest. The
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

## Collector receipt and trust policy

Each physical run has an RS256 receipt over canonical JSON containing:

- the source-pinned trust-policy digest;
- exact candidate and build timestamp;
- OS, machine, clean-install, run ID, run nonce, and capture timestamp;
- collector version, source digest, executable digest, key ID, and algorithm;
- all four report descriptors; and
- the complete harness/subject/raw-descriptor set.

RSASSA-PKCS1-v1_5 SHA-256 verification is implemented with the Python standard
library and locked by the RFC 7515 Appendix A.2 public vector and negative
tests. It does not invoke an ambient `openssl` binary.

Production never accepts an operator-selected key. The only production policy
path and exact byte digest are constants in `raw_artifacts.py`; the final
candidate and sealed manifest also bind the accepted policy SHA-256. A caller-
selected policy is rejected outside explicit fixture mode; if an internal
production caller passes a policy object, the loader freshly reopens the
canonical policy and requires full object equality before use. Key provisioning
or rotation therefore requires a reviewed release-source change to the
canonical policy bytes and their pinned digest.

The checked-in production policy is intentionally `state: not-configured`.
Until release engineering provisions an externally controlled public key and
approved collector source/executable digests, production physical evidence is
`blocked` and cannot be promoted or published. Test fixtures use the public RFC
example key only in fixture mode; it is not a production trust root.

## Security boundary and remaining external proof

Hashes and race-resistant file reads detect drift; the signed receipt proves
that an approved collector attested to the exact bytes and identities. They do
not make a malicious operator, compromised collection host, or compromised
collector key trustworthy, and they do not provide a cross-release replay
ledger. Collector key custody, host control, nonce issuance, audit retention,
and any replay ledger remain external release-process controls.

Standalone harness commands report only raw-byte structural verification.
Only the aggregate, with the source-pinned collector receipt and both required
physical macOS runs, can grant `Signed_Installed_Verified`.
