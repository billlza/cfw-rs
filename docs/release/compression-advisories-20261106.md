# Compression dependency advisories checked on 2026-11-06

The 51005 preparation scan and the Windows engine job for source
`0e22bfe8b555b22c987532fcab9579a88a2ee229` both failed on the two advisories
below. The official Go records were published on 2026-11-05 at 22:55:15Z
and 22:54:32Z respectively. This is a source correction before candidate
freeze; it retains build 51005 and preserves the failed preparation attempt.

| Advisory | Selected vulnerable version | Selected fixed version | Upstream correction |
| --- | --- | --- | --- |
| [GO-2026-6888](https://pkg.go.dev/vuln/GO-2026-6888), CVE-2026-111497 | `github.com/andybalholm/brotli v1.2.4` | `v1.2.7` | [Reject malformed block switches earlier](https://github.com/andybalholm/brotli/commit/33c2a9884269798192b5ecf171288f98939dbe42) |
| [GO-2026-6865](https://pkg.go.dev/vuln/GO-2026-6865), CVE-2026-116591 | `github.com/klauspost/compress v1.20.0` | `v1.20.2` | [Reject overflowing FSE counts and invalid Huffman table sizes](https://github.com/klauspost/compress/commit/7f5d8528720c895a6106f201719f87eb030a565d) |

Both scans reported affected symbols reachable in their source call graphs.
The Brotli finding concerns excessive allocation on malformed compressed
input; the compress finding can panic a decoder processing consecutive
blocks. Static reachability does not establish a remotely exploitable CFM
request, but it fails the existing release policy and requires correction.

Only these two requirements and their module checksums change in the
security-dependencies patch. All non-module sections and the other five
sing-box patches stay byte-identical. The fixed module archives resolve to
the two upstream commits above through the Go module proxy and checksum
database. Each fixed module's `go.mod` checksum and `LICENSE` bytes are
identical to its predecessor, so this update introduces no transitive module
requirement or license-text change. The source and combined patch digests
are regenerated and verified by the existing pinned-source contract.

An isolated reproduction using the upstream FSE count-overflow input runs
the same program against both compress versions. Version 1.20.0 panics with
an out-of-bounds decoder table access; 1.20.2 returns the corruption error
without a panic. Brotli 1.2.7's complete upstream package tests also pass.
These checks supplement the required engine tests and the scans of both
the original versioned graph and the private corrected build workspace;
they do not substitute for hosted Windows execution or signed app acceptance.

Private evidence is retained under
`target/service-upgrade-51005/compression-update/`, including the original
scan, module download receipt, old/new reproduction, license comparison,
and full gate logs. The original Windows failure is run
[42162557793](https://github.com/billlza/cfw-rs/actions/runs/42162557793),
job `127711415871`. Its saved artifact has SHA-256
`a54937698db6719928c06560f97006ad962bdc0ab5f269133ae53568a78bbd0c`.
No advisory is ignored and no affected-package or affected-symbol check is
relaxed.
