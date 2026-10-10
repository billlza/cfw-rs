# GA build 50027 retirement

GA build 50027 is permanently classified as
`retired_after_notarization_before_install`. It must not be rebuilt, resumed,
re-signed, re-notarized, packaged, installed, promoted, relabelled, or reused as
the 0.5.0 GA application identity.

## Immutable consumed lineage

The candidate-freeze transaction permanently bound build 50027 to these
identities:

- repository commit:
  `c23353ee41aa00e9e2185388bf425078f07b8e50`;
- release-source SHA-256:
  `1216a40fcdcfe78c510ca4f2db09600e358f1d9444844e741762dfd727b6d558`;
- `product-input.json` file SHA-256:
  `ab3cd1c088f5e2c527f902500e02031ebba78dd1a75ac093a1da1f76c871a637`;
- frozen product-input semantic SHA-256:
  `757b6c748e74b1abd78395c60b43ee51a1e36fba5a341ae09922fa2eb5de3d96`;
- candidate-freeze intent SHA-256:
  `530569d45ddaab7368fe09d36223ea53835b0120ba8e017c398053f08b6617c0`;
- updater-key possession-proof SHA-256:
  `7cfe7b0071468516c939035d8fe2c242b6704d857c6a6209c3de4a38195c4379`;
- frozen Developer ID certificate SHA-256:
  `806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D`.

The frozen root
`target/release-worktrees/50027/target/candidates/0.5.0/ga/50027` of the
release operator checkout
`/Users/bill/.cfm-release-tooling/ga-050-20261007/operator-50027` and every
file below it are immutable historical evidence. They must not be deleted,
renamed, edited, resumed, or copied into a later candidate.

An owner-only evidence copy is retained at
`/Users/bill/cfw-release-history/ga-build-50027-evidence/candidate`. Its
`sha256-tree-v2` root is
`0d4854e66d6d263ae72b350f873a57d528c9b2ec4918d7f9457cf7775ec5db71`
over 1389 entries, equal to the source tree. The source and snapshot manifests
are retained separately as `ga-build-50027-evidence.source-tree-v2.json` and
`ga-build-50027-evidence.snapshot-tree-v2.json`. The complete builder log is
retained beside the copy as `signed-build.log` (SHA-256
`eca3992635d8f88118992b2e239fd5457b83c59f1455facbd596453b6201e851`), and the
operator logs of every later stage as `operator-logs/`.

## Completed stages

- Signing attempt `00000001` (intent SHA-256
  `3d0976973323eef0c57afd121f26e81951c1abb6ed4404586bad3b9305291e6f`) reached
  `published`; its terminal `event_sha256` is
  `8583412f0d5a9bb053f2fb9ddd8670b718730bd22add1f502dd31fa5ef454686`. The
  signed application tree SHA-256 is
  `522dffaa6508064fe735543763588328af25288d2f0573a41fa060f89386aba1` and the
  signing-transformation receipt SHA-256 is
  `909dae741201be4404bf47ffa3ff171e63f70d3050fa54059d07e555afb71184`.
- Apple notarization submission `05a7062c-5e88-4849-8c3c-144d19743158`
  (archive SHA-256
  `28025cadc42bd9f415f708b46b603ab6270367ee8500d1d4473ee76bd1ebbde1`) was
  Accepted. The first finalization failed with
  `notary_log_verification_failed`, because the notary log reported
  `arch: null` for resource tickets; the recovery that the transaction admits
  re-verified the log with the corrected executor and continued through
  stapling, Gatekeeper (`Notarized Developer ID`), application and
  distribution verification to `sealed` (event 19). No second submission was
  made.
- The hosted-CI receipt for run attempt 1 of the `CI` workflow on
  `c23353e` (SHA-256
  `e2eca6e80d52ce9446c186decb62bc6a183a90d6e6c1ce4a195f477cc6cd9083`) was
  captured.
- Publication evidence was finalized under `stage-inputs/publication`: machine
  closure SHA-256
  `7624d0340d8aa104cf2460be281f1b7dd5e8ade2d3089e008f2a98cf3ad0c1b6`, approved
  by the release owner; legal review SHA-256
  `48f8c87f9bb96742819047e6520c63f05c191f9def1d37249a89492722bb83aa`; evidence
  manifest SHA-256
  `b081a2dd7026fffadecf8a0ff661ebd363cfd89e36b47f31df41aeee0cbf4280`.
- The prepackage stage was sealed: `prepackage/manifest.json` SHA-256
  `6dcb8e2c3ad0450d9fa462266fdc03e02287d8830eca730b557842ef9a17875a`.

The release executor that ran these stages was `8415a1b`. Its corrections
after `c23353e` changed only release tooling: the notary-log ticket
architecture, Cargo license donors, the hosted-CI step names, the private
stage-input directory and the closing of HTTP error responses.

There is no DMG, updater package, distribution set, installation, GA runtime
acceptance, publication seal, tag, upload, or public release for build 50027.

## Cause

On 2026-10-08 the release owner paused 50027 at the sealed prepackage stage so
that the protocol compatibility gaps found by a client review would ship in
0.5.0 rather than after it. The release line then changed the application
bytes:

- Reality clients may opt in to the X25519MLKEM768 key share, which the pinned
  sing-box security patch, the libbox framework and the profile model carry;
- the sing-box 1.14 Hysteria2 options (hop interval range, gecko obfuscation,
  BBR profile) and Clash `ech-opts` are imported and validated;
- subscription redirects follow exactly the configured maximum;
- the import box is a single-row text area that keeps pasted line breaks.

The signed 50027 application contains none of these changes, so it cannot be
the 0.5.0 GA application. Retiring it before packaging leaves no package,
installation or published artifact to supersede.

## Successor generation

Build 50028 is now the only active 0.5.0 GA successor. It must start from one
new clean source identity and repeat the complete hosted-CI, build, freeze,
signing, notarization, publication-evidence, package, installation, runtime,
and final publication sequence. The retained installed preview 50025 remains
its migration predecessor. No application tree, profile copy, possession
proof, signature, manifest, attempt file, notarization transaction, hosted-CI
receipt, component review, legal review, approval, or evidence tree from build
50027 may be copied forward as successful evidence. A reviewer may compare the
50028 component review with the 50027 review, but 50028 needs its own legal
review and closure approval.
