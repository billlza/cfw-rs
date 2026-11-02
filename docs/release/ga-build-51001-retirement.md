# GA build 51001 retirement

GA build 51001 is permanently classified as
`retired_product_change_after_ga_runtime_acceptance_before_publication`.
It must not be rebuilt, resumed, re-signed, re-notarized, repackaged,
reinstalled, promoted, relabelled, published, or reused as the 0.5.1 GA
application identity.

## Immutable consumed lineage

The candidate-freeze transaction permanently bound build 51001 to these
identities:

- repository commit:
  `f5fd1048f993752f9a116dee6683677db962f3c0`;
- release-source SHA-256:
  `7b95c193b9321b2afc0cbae4c00b89ab15a40f9492be68552ba78fa730da622c`;
- `product-input.json` file SHA-256:
  `03ff528dbb7367baff67d9347c7d3127bae4516413a3095dd5b8cd6958b4a630`;
- frozen product-input semantic SHA-256:
  `23f44ba7757a866d7266f74d6810ab0e67de278bfa455a1ecf99ab2ddec9b045`;
- candidate-freeze intent SHA-256:
  `d3fb52c5ff241465c1186d086434052dae910da4d25b7a36c0d3995f0f68669b`;
- updater-key possession-proof SHA-256:
  `4fc28c1557933b82de5186dcb6e798e1062332374894c84d1ac85ff66f843a88`;
- frozen Developer ID certificate SHA-256:
  `806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D`.

The frozen root
`target/release-worktrees/51001/target/candidates/0.5.1/ga/51001` of the
release operator checkout
`/Users/bill/.cfm-release-tooling/releases/0.5.1/operator-51001` and every
file below it are immutable historical evidence. They must not be deleted,
renamed, edited, resumed, or copied into a later candidate.

## Completed stages

Build 51001 was the first release run by `scripts/cfm_release.sh`
(RELEASE.md, "Running a release with the driver"). Every stage from `enroll`
to `seal-publication` completed on the release Mac between 2026-10-28 and
2026-10-29; `publish` and `verify-remote` did not run.

- The hosted-CI receipt for run `40694830108` attempt 1 of the `CI` workflow
  (SHA-256 `aed2285a45785fd05a2e7d5610c53a7de045ac06b79b04042ff8541aa17023f2`)
  was captured before the freeze. The run tested `f5fd1048` itself, and its
  three jobs succeeded on 2026-10-28.
- Signing attempt `00000001` (intent SHA-256
  `eff3e2dc2afb20048ccc43c7b1e9db308d359709f9b2df1f35b3222aac8b3b4b`) reached
  `published`; its terminal `event_sha256` is
  `333b60045381da3726ede996c49ec4a44a0f87055ae70304a82c5fad7f7217fb`, and the
  signing-transformation receipt SHA-256 is
  `dcf603323b54f6375d7a6e9f23a3a41c4ce4eb9d8607b3799ccf4e9792ede89a`.
- Apple notarization submission `e4815704-0c23-49f5-a810-6ac5362cf67c`
  (archive SHA-256
  `366dd41622d716568cccb8ba1264571e0f4501921f7874f6e0cd351dcb02d357`) was
  Accepted. Its direct finalization continued through log verification,
  stapling, Gatekeeper (`Notarized Developer ID`), application and
  distribution verification to `sealed` (event 15) without a recovery. No
  second submission was made. The publish-ready receipt SHA-256 is
  `a62dab73315f878543716ec88d8eae61773c5a853ce840e6cd02510d226797e8`, and the
  stapled application has the `sha256-tree-v2` root
  `274c9ed1bce0630724032a016869acc264682650311c90c87b15d6c8da2fa9c3`.
- The component review reused six decisions of the published 0.5.0 build
  50030 after the exact comparison and recorded one new decision, for
  node 26.12.1, by the release owner (`review/51001` of the release home).
- Publication evidence was finalized under `stage-inputs/publication`: machine
  closure SHA-256
  `83a67c9d25cb627096e567756e91ab192d9885ab09acf309617942ae610ccfb4`, approved
  by the release owner on 2026-10-28; legal review SHA-256
  `4e1c44560017eee8af265d6d019cd6a9388f94c65c034e8c10a110e06067b73d`; evidence
  manifest SHA-256
  `6a6e66abf509f7627b4b42211ba420dbb53a5e0abccfb30c824ac90434a583c8`. The
  prepared publication inputs were moved to private history (below).
- The prepackage stage was sealed: `prepackage/manifest.json` SHA-256
  `3640dd7e5b193c1bfd726622a7d9a15d269fee3aedfa4707923b4124e5486737`.
- The DMG `Clash.for.Mac_0.5.1_arm64.dmg` was notarized as submission
  `83674a5c-2bd2-443b-8e12-b3ff9153001e` (Accepted), stapled, assessed by
  Gatekeeper as `Notarized Developer ID`, and its transaction reached
  `published` (event 12). The stapled DMG SHA-256 is
  `e946d1757b7dc5f02077cfc84b19f381bca72b7697baa48f56f8fb9e5fd94413` (46997681
  bytes) and the `dmg-set.seal.json` SHA-256 is
  `71242e2027dcf862c3221d0b4fb7313641e8d35a4ff2b34fbb1b4053580f019c`.
- The updater archive `Clash.for.Mac_0.5.1_aarch64.app.tar.gz` (SHA-256
  `e1f1ab3a427adafc9411f092cf9504ace25d059228bbd836b59b3bac981fcb9a`, 46497532
  bytes), its signature (SHA-256
  `1313b01f806ff5a60b82f77033721d4cf65bef9af0c8d068a6afe2420807a905`) and
  `latest.json` (SHA-256
  `b112eaab3c490675b31f419b22691de6ff8d23b485cc75971ebf450582345489`) were
  produced; the embedded public key verified the signature, and the
  `updater-set.seal.json` SHA-256 is
  `9484eec28907a8dfa1e5441c1d26efb1f9428f15f76ab1d59afc58147184b67c`.
- Build 51001 was installed on the release Mac over the published GA build
  50030 (tree
  `078b0ab7c044a79be83595c68419e908d5c94d442faffa59ec2d5c2e0f7260f3`). The
  completed 50029 -> 50030 installation history was first retained under
  `/Applications/.com.bill.clashformac.install-history-v1/50030`. Dormant
  install transaction `eb0e3ae8-1c4c-449e-8f7a-57b4d171beb8` completed on its
  first run, without a recovery and without launching the application; the
  stage's first attempt had stopped in the decommission preflight, before any
  journal was written, because the 50030 services were not running after a
  reboot. Service transaction `75b32ec5-6203-44b5-a4c3-981eedc331b0`
  decommissioned the services before the install and recommissioned them
  after it. The installed application tree SHA-256 is
  `274c9ed1bce0630724032a016869acc264682650311c90c87b15d6c8da2fa9c3`, equal to
  the stapled candidate. The migration journals 50030 -> 51001 were exported
  into `stage-inputs/ga-acceptance/migration-journals` by transaction
  `8e108bce-ce9a-4b9d-94a2-9a4a7ffb4be3`; the export receipt SHA-256 is
  `ac6400271d72a02407e27988f5331010614157505f2386e1edefe5e9a18fe4cd`.
- Three GA runtime collections were aborted before runtime evidence was
  written and were recovered; their journals are retained as
  `stage-inputs/ga-acceptance/runtime-collection-aborted-<session>` for the
  sessions `449d4377-dbf7-4a7a-a467-cb6cc0f3c5fd`,
  `571ca3e6-95f8-4f33-a93c-49bd5d4b01d0` and
  `f07607cd-78f0-4ed7-a4f7-f6eb570ae1e8`. In two of them Tunnel mode was not
  selected within the collector's window; in the third the selected profile
  routed the evidence resolver through an unreachable proxy node. None of
  them is a defect of the 51001 bytes.
- GA runtime collection session `b6141df8-8071-47e3-86b7-afa7511821ef`
  (intent SHA-256
  `7038187d0317237b75e4483c8b2cc8b0261a3fdec86023a7edc75c5c071d4f5a`)
  completed on 2026-10-29 with the stored direct-route profile selected and
  was sealed: `stage-inputs/ga-acceptance/runtime-acceptance.json` SHA-256
  `a8907afdce90608f1e7b7bf039fddf24310254f1afd2208c14dc8a44fe9fb583`, twelve
  raw-derived checks, runtime evidence under
  `stage-inputs/ga-acceptance/runtime-evidence`.
- The GA acceptance seal `ga-acceptance/manifest.json` has SHA-256
  `c499bf787c475ede1a206a9678150333541bb653120e7ba1a55bcb32849578c6`.
- The publication seal `publication/manifest.json` has SHA-256
  `2f7782209e0ff478c1f4a3455dc64a23ac1454c7751e1e74d1be901f11f31db8`, and the
  distribution set under `packages/distribution/v0.5.1` was written:
  `Clash.for.Mac_0.5.1_publication.tar.gz` (SHA-256
  `92bb415caaba4155d6de3eaafe9bc505de92dc47b49d3726c9cf155ac88c357f`,
  115148143 bytes), `Clash.for.Mac_0.5.1_arm64.gatekeeper.public.json`,
  `publication-bundle.manifest.json` and `distribution-set.seal.json`
  (SHA-256
  `7b26ae851797b6f4b27e87f6c46e70cee1d7aa61f4370934ad9e9d371c2922aa`, sealed
  2026-10-29T17:42:15Z).

The release owner handed the stapled DMG to pilot testers directly (AirDrop).
There is no tag, upload, public release, or remote-byte verification for
build 51001.

## Cause

On 2026-10-31 the release owner decided that the Settings > Engine > DNS leak
protection switch of commit `25b86af2` (PR #40), made after 51001 was sealed,
ships in 0.5.1: with the switch on, every Tunnel projection refuses port 853
right after the plain-DNS hijack, so DNS over TLS and DNS over QUIC that an
application carries itself cannot pass names around the core's resolver. The
commit records it in the 0.5.1 section of `CHANGELOG.md`. It changes the
application bytes, so the installed 51001 application cannot be the 0.5.1 GA
application. Commit `03b026a4` (PR #42) only makes one of that change's tests
deterministic.

Independently of that decision, the remaining 51001 stages cannot run on the
release Mac as it is now. The frozen `f5fd1048` release tooling accepts only
its pinned Xcode 27.1 (27A9275): before it acts, the entry point of every
stage checks `xcodebuild -version` against that pin in
`cfw_select_release_apple_toolchain` (`scripts/release_tool_environment.sh`)
and otherwise stops with `error: Xcode 27.1 (27A9275) is required`. On
2026-10-31 `/Applications/Xcode.app`, the only Xcode on the release Mac,
became Xcode 27.2 (27B52), so that check now fails. Commit `8a25e313`
(PR #41) moves the pin to Xcode 27.2 (27B52).

## Successor generation

Build 51002 is now the only active 0.5.1 GA successor. It must start from one
new clean source identity and repeat the complete hosted-CI, build, freeze,
signing, notarization, publication-evidence, package, installation, runtime,
and final publication sequence. The installed build 51001 is its migration
predecessor: the completed 50030 -> 51001 install and service journals are
retained as installation history before the 51002 install reuses their
namespace. No application tree, profile copy, possession proof, signature,
manifest, attempt file, notarization transaction, package, hosted-CI receipt,
component review, legal review, approval, installation journal,
runtime-collection journal, seal, distribution set, or evidence tree from
build 51001 may be copied forward as successful evidence. A reviewer may
compare the 51002 component review with the 51001 review, but 51002 needs its
own legal review and closure approval.

## Evidence locations

- Frozen candidate root: see "Immutable consumed lineage" above. It holds the
  freeze intent, signing attempt, notarization transactions, packages,
  prepackage, GA-acceptance and publication seals, stage inputs, the exported
  migration journals, the runtime-collection journals and the distribution
  set.
- Release home `/Users/bill/.cfm-release-tooling/releases/0.5.1`: the driver
  logs `logs/51001` (`001-enroll.log` to `043-seal-publication.log`), the
  stage records `records/51001`, and the component-review comparison,
  decisions and closure approval `review/51001`.
- Prepared publication inputs moved out of the candidate:
  `/Users/bill/.cfm-release-tooling/releases/0.5.1/history/publication-prepared-51001`
  (`sha256-tree-v2` root
  `307b4b29712b4e6e211c6ef2e31d2e619246e3bead8abaacbc3d6889fb459bc4` over
  34745 entries).
- Release Mac: `/Applications/Clash for Mac.app` is build 51001 until the
  51002 install replaces it;
  `/Applications/.com.bill.clashformac.dormant-install.json`, the service
  transaction `/Applications/.com.bill.clashformac.service-transaction-v3`
  and the retained 50029 -> 50030 history
  `/Applications/.com.bill.clashformac.install-history-v1/50030`.
