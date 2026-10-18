# GA build 40040 retirement

Build 40040 is classified as
`retired_security_dependency_change_before_notarization`. Its application
lineage is consumed and retired because the SSH dependency correction changes
the frozen product inputs, not because an evidence retry needs a new number.

## Immutable consumed lineage

The candidate-freeze intent binds build 40040 to:

- repository commit:
  `91ae4f2eede86e94172308d6fabcf3c50914d9e7`;
- release-source SHA-256:
  `85cb2f65d179bea480bbffe4be47cf3da89e9720b4f85044787d5fa08359e5e8`;
- product-input document SHA-256:
  `6c54e3172ceec71c972e7cc7b402eaabef8cbbef6a92a30f59636e95b1103c80`;
- frozen product-input semantic SHA-256:
  `6e83a828db854cc3d4ce3082ce436953fbd7af0625ba938314d67de60ffed3c8`;
- candidate-freeze intent SHA-256:
  `27894d74ef983108e139dfdff305be9cf319ec00acbc74993a5cd80b43a42110`;
- pre-sign application tree SHA-256:
  `462b9bfd275982e428a0b52f2e5c26259891fe7957da7ff61605edd734368d50`;
- canonical signing transformation receipt SHA-256:
  `6f5904bd41fc9f25e42cdef1eac5e561585771156a0312ab2918e0e9927f6e86`.

The frozen checkout at `target/release-worktrees/40040` and its candidate root
`target/candidates/0.4.0/ga/40040` remain unchanged. Canonical `signing-output`
exists. No app-notary transaction was claimed or submitted, and there is no
notarized `signed` application, package set, installed-runtime acceptance,
publication seal or public 0.4.0 release for this build. Preserve the original
cache authorization, journals, receipts, signed output and failed attempts.

## Newly published dependency findings

The original product CI run `33647446095` completed successfully at
`2026-09-02T16:01:55Z`. Its frozen-candidate hosted receipt was subsequently
verified and remains valid historical evidence for the original source.

[GO-2026-6354](https://vuln.go.dev/ID/GO-2026-6354.json) and
[GO-2026-6355](https://vuln.go.dev/ID/GO-2026-6355.json) were published at
`2026-09-02T19:12:04Z`, after that run. Tooling CI `33673673395` then failed
its actual `./experimental/libbox` symbol-level scan on
`golang.org/x/crypto v0.55.0`; the reported call path reaches `ssh.NewClientConn`
through the Libbox SSH outbound. The signed ProxyAgent and Packet Tunnel
binaries also contain the affected SSH symbol names. Normal CFM profiles do
not expose SSH, so these observations do not establish ordinary-config
exploitability. They do establish that the existing scan cannot be reported
as passing against the newly published findings.

## Dependency-change successor

The correction selects only `golang.org/x/crypto v0.56.0`, the upstream fixed
version, and raises the module's minimum Go version to the dependency's
required `1.26.0`. The compiler remains Go `1.26.6`; Rust remains `1.97.1`;
all other selected dependency versions remain unchanged. There is no ignore,
scan-scope reduction or alternate runtime implementation.

Build 40041 is the single active successor. It requires its own exact-source
CI, complete unsigned application, freeze, signing/notarization, source and
license closure, packaging, one-machine ordinary-GA acceptance and publication
verification. Source, CI and preflight retries before freeze retain 40041 and
use new attempt identities. No old candidate receipt is copied forward as
successful evidence. Earlier retirement documents keep their historical
successor descriptions; the allocation ledger defines current activity.
