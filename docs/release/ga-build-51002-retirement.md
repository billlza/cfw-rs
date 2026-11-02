# GA build 51002 retirement

GA build 51002 is permanently classified as
`retired_product_change_after_ga_runtime_acceptance_before_publication`.
It must not be rebuilt, resumed, re-signed, re-notarized, repackaged,
reinstalled, promoted, relabelled, published, or reused as the 0.5.1 GA
application identity.

## Immutable consumed lineage

The candidate-freeze transaction permanently bound build 51002 to these
identities:

- repository commit:
  `d5fda264e69f3e5225c7934c7c48230c39e0f819`;
- release-source SHA-256:
  `e5c48aa9b3b046b27dc05c97fcd3af416d4b9b2c6df53d6c2f595f3bac3a58da`;
- `product-input.json` file SHA-256:
  `0ab95dc95e63f926f89b584ab43db9e1eff93599df914068f01b8d52cc7c8f5a`;
- frozen product-input semantic SHA-256:
  `fbe678142e5fdf6426fafab80648809d8a2d66634d534672a2ce61fcaa931dbd`;
- candidate-freeze intent SHA-256:
  `f90119e150299598cc283aac1826884e77b1f0902431ebdf30656108f7e90587`;
- updater-key possession-proof SHA-256:
  `406585c2bc50713863f8324183d13ad3be660d605678509c6b75b59770c0d303`;
- frozen Developer ID certificate SHA-256:
  `806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D`.

The frozen root
`target/release-worktrees/51002/target/candidates/0.5.1/ga/51002` of the
release operator checkout
`/Users/bill/.cfm-release-tooling/releases/0.5.1/operator-51002` and every
file below it are immutable historical evidence. They must not be deleted,
renamed, edited, resumed, or copied into a later candidate.

## Completed stages

Build 51002 repeated the complete sequence of `scripts/cfm_release.sh`
(RELEASE.md, "Running a release with the driver"). Every stage from `enroll`
to `seal-publication` completed on the release Mac between 2026-11-01 and
2026-11-02; `publish` and `verify-remote` did not run.

- The hosted-CI receipt for run `41255931061` attempt 1 of the `CI` workflow
  (SHA-256 `444946115a33b645636910a552ceda8b3516fa8a88048fd78a77de8def85ef6b`)
  was captured before the freeze. The run tested `d5fda264` itself, and its
  three jobs succeeded on 2026-11-01.
- Signing attempt `00000001` (intent SHA-256
  `f32e49ca851b3dbb17acdf9a40baf64213a84c77ecf965f420bf0d8a81f32311`) reached
  `published`; its terminal `event_sha256` is
  `66bb61d401508557ee07b704550afd9eca7b03a8ac752f6cd32ee3cf8fc7853a`, and the
  signing-transformation receipt SHA-256 is
  `03c94fc3a7ef41e7d042152f7cd19484984343544cef7e918a241bb9bb902295`.
- Apple notarization submission `29e48171-1d50-42b7-a0cc-e022f8f9eba7`
  (archive SHA-256
  `71afc4341a28d50bf6164345ded794cea739d27300860a36bf97b0525d64c39b`) was
  Accepted. Its direct finalization continued through log verification,
  stapling, Gatekeeper (`Notarized Developer ID`), application and
  distribution verification to `sealed` (event 15) without a recovery. No
  second submission was made. The publish-ready receipt SHA-256 is
  `299a5d2d9818ce4a0ef4787742bd6711a3785697dd43382b0354b5f8442973eb`, and the
  stapled application has the `sha256-tree-v2` root
  `3860382230d212a6607fb27c560cb9bd3bc82b272325b8af90b4d416eac5ed81`.
- The component review reused four decisions of the published 0.5.0 build
  50030 after the exact comparison and recorded three new decisions by the
  release owner (`review/51002` of the release home): node 26.12.1, and
  swift 6.4.2 and xcode 27.2, whose component identities the Xcode 27.2 pin
  changed.
- Publication evidence was finalized under `stage-inputs/publication`: machine
  closure SHA-256
  `cfddc2b8c4d69d6b49565fb197f4d022076a7d600ad642ea54212ef9111634d2`, approved
  by the release owner on 2026-11-01; legal review SHA-256
  `2a7e34d200e61e21e9054e98feaa47e5cbe8c99378008d545b5a7b3e78be2579`; evidence
  manifest SHA-256
  `f2a7a9d5d14f07a335e054e88524fc4e312ebd41d7a62f47925d2c86ed993a79`. The
  prepared publication inputs were moved to private history (below).
- The prepackage stage was sealed: `prepackage/manifest.json` SHA-256
  `fb37ae979eeec2fa8bb4833426ae326bd92e8e99f6c83c0f1e2815696a8954ae`.
- The DMG `Clash.for.Mac_0.5.1_arm64.dmg` was notarized as submission
  `6c40f2a8-15ed-4d3e-8aff-b9cc5b1bc438` (Accepted), stapled, assessed by
  Gatekeeper as `Notarized Developer ID`, and its transaction reached
  `published` (event 12). The stapled DMG SHA-256 is
  `1e3928cd22e848e08eec139e415563de5b462277d56bfae6c3da56c06b8cc8ad` (47007921
  bytes) and the `dmg-set.seal.json` SHA-256 is
  `01b7a020526584ed9332df220ffd2bfbc750bcc479f5fb461b1342c416c9501e`.
- The updater archive `Clash.for.Mac_0.5.1_aarch64.app.tar.gz` (SHA-256
  `0e49291c2194c5a2ae455ae7476447c7761e8509022d2864f8e6d2ddbb190d82`, 46507768
  bytes), its signature (SHA-256
  `614f03b5073a8bd10fd4e59efbc48345fa4a6486e3582c86ad3b09cd8165aa3e`) and
  `latest.json` (SHA-256
  `63a4914ee27a1fb63cbb5bbc3e6e1ff194a4dd396719bfd976cca22bb898175c`) were
  produced; the embedded public key verified the signature, and the
  `updater-set.seal.json` SHA-256 is
  `32a730da9cace01277192aff8e3c1af5ebea38ce7215694a926e3288f824515b`.
- Build 51002 was installed on the release Mac over the retired GA build
  51001 (tree
  `274c9ed1bce0630724032a016869acc264682650311c90c87b15d6c8da2fa9c3`). The
  completed 50030 -> 51001 installation history was first retained under
  `/Applications/.com.bill.clashformac.install-history-v1/51001`. Dormant
  install transaction `74755989-9b28-43a7-bd65-79e6670a3837` completed on its
  first run, without a recovery and without launching the application.
  Service transaction `07a4d420-1dee-49c0-b7e1-459ccd9f67d4` decommissioned
  the services before the install and recommissioned them after it. The
  installed application tree SHA-256 is
  `3860382230d212a6607fb27c560cb9bd3bc82b272325b8af90b4d416eac5ed81`, equal to
  the stapled candidate. The migration journals 51001 -> 51002 were exported
  into `stage-inputs/ga-acceptance/migration-journals` by transaction
  `2bdb1a1a-a057-491e-b0cb-fe59c10c787b`; the export receipt SHA-256 is
  `aa30dae93d685e1f4427e249581ab2da1aad71c7f54d5919e29ab78daac500a3`.
- One GA runtime collection was aborted before runtime evidence was written
  and was recovered; its journal is retained as
  `stage-inputs/ga-acceptance/runtime-collection-aborted-722836a0-c469-45fb-88b2-74e58cb28a1f`.
  Tunnel mode was not selected within the collector's window; this is not a
  defect of the 51002 bytes.
- GA runtime collection session `05d6bb7a-a7ee-4148-b1ce-eccd6e701e9c`
  (intent SHA-256
  `2f7cf16a9c714c88799f687f283ba0fbb9e633e4f49aeac218e61f657b408b9d`)
  completed on 2026-11-01 with the stored direct-route profile selected and
  was sealed: `stage-inputs/ga-acceptance/runtime-acceptance.json` SHA-256
  `30e7e22c552a89d7a015cc7901e5292c5371a40bcf800443ab5a089187de549b`, twelve
  raw-derived checks, runtime evidence under
  `stage-inputs/ga-acceptance/runtime-evidence`.
- The GA acceptance seal `ga-acceptance/manifest.json` has SHA-256
  `d006ebed425d2b60ab9fc4692915f58f4a23a36951e2a4be32f216f3a5105b48`.
- The publication seal `publication/manifest.json` has SHA-256
  `12b7fb4ce2f0a2d27e3b0aa3d157657b6cff5d7e4484ee66793129e1af45164c`, and the
  distribution set under `packages/distribution/v0.5.1` was written:
  `Clash.for.Mac_0.5.1_publication.tar.gz` (SHA-256
  `bccfe7217854289b304c777088ad681badc101ee5fa76f91319a825cbc818297`,
  115164004 bytes), `Clash.for.Mac_0.5.1_arm64.gatekeeper.public.json`,
  `publication-bundle.manifest.json` and `distribution-set.seal.json`
  (SHA-256
  `fe16351f5db8035a4ec0c1ffccbe29b6a836ab5e81ff5c0f87766878e5ff97e6`, sealed
  2026-11-01T21:15:50Z).

There is no tag, upload, public release, or remote-byte verification for
build 51002.

## Cause

On 2026-11-02 the release owner decided that the dashboard fix of commit
`23d79a26` (PR #44), made after 51002 was sealed, ships in 0.5.1. Every
dashboard refresh rebuilt the page markup together with the element that
scrolls inside the page, so switching a setting, a status update or opening a
dialog sent Settings and the other long pages back to the top; the page and
its dialogs now keep their scroll offsets while they stay shown. The commit
records it in the 0.5.1 section of `CHANGELOG.md`. It changes the bundled
interface and therefore the application bytes, so the installed 51002
application cannot be the 0.5.1 GA application. The other commits merged
since `d5fda264`, `63dd9bf5` (PR #43, the Windows credential worker, built
only for Windows) and `58039714` (PR #38, the release driver's terminal
pipe), do not change the macOS application.

## Successor generation

Build 51003 is now the only active 0.5.1 GA successor. It must start from one
new clean source identity and repeat the complete hosted-CI, build, freeze,
signing, notarization, publication-evidence, package, installation, runtime,
and final publication sequence. The installed build 51002 is its migration
predecessor: the completed 51001 -> 51002 install and service journals are
retained as installation history before the 51003 install reuses their
namespace. No application tree, profile copy, possession proof, signature,
manifest, attempt file, notarization transaction, package, hosted-CI receipt,
component review, legal review, approval, installation journal,
runtime-collection journal, seal, distribution set, or evidence tree from
build 51002 may be copied forward as successful evidence. A reviewer may
compare the 51003 component review with the 51002 review, but 51003 needs its
own legal review and closure approval.

## Evidence locations

- Frozen candidate root: see "Immutable consumed lineage" above. It holds the
  freeze intent, signing attempt, notarization transactions, packages,
  prepackage, GA-acceptance and publication seals, stage inputs, the exported
  migration journals, the runtime-collection journals and the distribution
  set.
- Release home `/Users/bill/.cfm-release-tooling/releases/0.5.1`: the driver
  logs `logs/51002` (`001-enroll.log` to `040-seal-publication.log`), the
  stage records `records/51002`, and the component-review comparison,
  decisions and closure approval `review/51002`.
- Prepared publication inputs moved out of the candidate:
  `/Users/bill/.cfm-release-tooling/releases/0.5.1/history/publication-prepared-51002`
  (`sha256-tree-v2` root
  `a1d474b65a31928469c01bd74bd3be01d087545257c6da6e9832e06c42dcfe99` over
  34752 entries).
- Release Mac: `/Applications/Clash for Mac.app` is build 51002 until the
  51003 install replaces it;
  `/Applications/.com.bill.clashformac.dormant-install.json`, the service
  transaction `/Applications/.com.bill.clashformac.service-transaction-v3`
  and the retained 50030 -> 51001 history
  `/Applications/.com.bill.clashformac.install-history-v1/51001`.
