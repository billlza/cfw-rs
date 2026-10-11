# GA build 50028 retirement

GA build 50028 is permanently classified as
`retired_security_dependency_change_after_install_before_ga_runtime_acceptance`.
It must not be rebuilt, resumed, re-signed, re-notarized, repackaged,
reinstalled, promoted, relabelled, or reused as the 0.5.0 GA application
identity.

## Immutable consumed lineage

The candidate-freeze transaction permanently bound build 50028 to these
identities:

- repository commit:
  `d686a859a0645b3f9b37f97f1568f54fa87cfae0`;
- release-source SHA-256:
  `c42175b3da517a3dacb4c88511ee711eee588a3b7725e3cfaa037f5cc5abedaa`;
- `product-input.json` file SHA-256:
  `3b9ac0a012407ab78eb99a8a8b9b8e6735f6c084bf71f0b4eb91ea1e9ab9db01`;
- frozen product-input semantic SHA-256:
  `008900f9d6cc49e79c01a25038e42cbfa1a3d9f2c8e76b8c052ab3bdb244182a`;
- candidate-freeze intent SHA-256:
  `11d0a4ebceedebc5bc582aa4afce4e22c30c1510b04f3056e42a370f7eac5712`;
- updater-key possession-proof SHA-256:
  `45e788943efc90d30140c58b36d8e6e3a835a4b4fed15b2fc7bf95bf8833d963`;
- frozen Developer ID certificate SHA-256:
  `806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D`.

The frozen root
`target/release-worktrees/50028/target/candidates/0.5.0/ga/50028` of the
release operator checkout
`/Users/bill/.cfm-release-tooling/ga-050-20261007/operator-50028` and every
file below it are immutable historical evidence. They must not be deleted,
renamed, edited, resumed, or copied into a later candidate.

## Completed stages

- Signing attempt `00000001` (intent SHA-256
  `0ec8b5d64588bdbd8d12491337af9a78e8a86b0d6f87b0d3c516dbc85c921f40`) reached
  `published`; its terminal `event_sha256` is
  `330e510ebb07ef1bbea7505707a9edaefe6f1cf7b095f461cb4095c28636ba90`. The
  signed application tree SHA-256 is
  `62bfba69d1960558c108781d50fb93141fdb22f9abf31e8e37e87f3bb13b9a1e` and the
  signing-transformation receipt SHA-256 is
  `cd72cd1593ec09d5d20340b1583d73ff8053a8e783c39918312f2ff773f5e81c`.
- Apple notarization submission `fe3a0f0a-a165-427a-8212-74acb2649e86`
  (archive SHA-256
  `97c1b35da2c4281ec8552b90043a1e9db4340058d78ad71ac0ba3f84578e01b5`) was
  Accepted. Its direct finalization continued through log verification,
  stapling, Gatekeeper (`Notarized Developer ID`), application and
  distribution verification to `sealed` (event 15) without a recovery. No
  second submission was made. The publish-ready receipt SHA-256 is
  `f09328691f959e8de95f505851529616c02c4c7aa113b64be0ead31e278bcad4`, and the
  stapled application has the `sha256-tree-v2` root
  `dd8a27dc6c22893e469a34433393b83d5be02edb07455752c39b6c0ffe77786d`.
- The hosted-CI receipt for run `37772318013` attempt 1 of the `CI` workflow
  on `d686a85`, whose three jobs succeeded on 2026-10-08 (SHA-256
  `23dc22d5fdaebae30b07fe1eab8da0ab263b1e394089e8fa680715fb3ab8c673`), was
  captured.
- Publication evidence was finalized under `stage-inputs/publication`: machine
  closure SHA-256
  `00d493dea03a8ce7121544bc5a34ce16f3c68868663bfcc253146dd206aabd30`, approved
  by the release owner on 2026-10-09; legal review SHA-256
  `b750e3dfc17aac62e939a62c69c09eae4011fd4c7285dd8e11678643eccb7a11`; evidence
  manifest SHA-256
  `12c2622fcd951bdd2c1e3245c1277e09df032c28295d7d76dae9de9f9e4551e4`.
- The prepackage stage was sealed: `prepackage/manifest.json` SHA-256
  `e6c39903994f4d6783da7b5a8302719a41361a65779ab4a75b59f6d6868332e3`.
- The DMG `Clash.for.Mac_0.5.0_arm64.dmg` was notarized as submission
  `18e9935e-6989-46a8-91be-4d184f150302` (Accepted), stapled, assessed by
  Gatekeeper as `Notarized Developer ID`, and its transaction reached
  `published` (event 12). The stapled DMG SHA-256 is
  `19ab732248d3c5be9d9124dfba5a290fed291982ac10c7fcff071f06e56ddbfc` (45400241
  bytes) and the `dmg-set.seal.json` SHA-256 is
  `177a7e06599435a9e28bf6a29d38c26608986bfebbdacd77e036735d135c307b`.
- The updater archive `Clash.for.Mac_0.5.0_aarch64.app.tar.gz` (SHA-256
  `8fb313e35d42c8e51b6a9514681626170adc34f7fd5f11f62d7d4910000280a4`, 44919053
  bytes), its signature (SHA-256
  `89b91c66973ae9138f57bcacc7eda20bd285b4e154dc6a89664ddc4b1dd994ed`) and
  `latest.json` (SHA-256
  `04d55822d515c31c99e941cce6a49a67efda00f71fabb9a7ddae8443da1f439f`) were
  produced; the embedded public key verified the signature, and the
  `updater-set.seal.json` SHA-256 is
  `b80c0154e5f86757fc7998ddcde86f6fd76100b7a51bb58808574377d7cdcf12`.
- Build 50028 was installed on the release Mac over the retained preview 50025
  (tree
  `d5a8a7f951fa3530ed0fa1982cc01ac7b9d6ec1b7f4579ec59883f99303302b9`). The
  completed 40073 installation history was first retained under
  `/Applications/.com.bill.clashformac.install-history-v1/40073`. Dormant
  install transaction `aa9cb7dd-68f1-4be8-b3a9-f3519ed6e71a` stopped on its
  first run with `tree_identity_unavailable`; its recovery completed the
  installation without launching the application. Service transaction
  `c4f6b720-fda7-4b1e-9b4a-a0de448673d7` decommissioned the services before
  the install and recommissioned them after the recovery (a recommission
  attempted before the recovery was refused with `journal_not_terminal`).
  The installed application tree SHA-256 is
  `dd8a27dc6c22893e469a34433393b83d5be02edb07455752c39b6c0ffe77786d`, equal to
  the stapled candidate. The migration journals 50025 -> 50028 were exported
  into `stage-inputs/ga-acceptance/migration-journals`; the export receipt
  SHA-256 is
  `efe9f8d5013d5349d9877616d902d1fcbe160e0ee7681f33cf39664d79ba5476`.

There is no GA runtime acceptance, publication seal, tag, upload, or public
release for build 50028.

## Cause

Release policy requires the libbox vulnerability scan to report zero affected
symbols and imported packages. The 50028 source gates ran that scan against
Go 1.27.1 and `golang.org/x/net` v0.59.0 and found none.
Once the 2026-10-08 Go security releases entered the vulnerability database,
hosted CI's libbox vulnerability scan began failing for `9c1cb9c`, a
descendant of the 50028 commit with the same Go version pin and sing-box
security patch: eleven go1.27.1 standard-library advisories, the matching
`golang.org/x/net` v0.59.0 HTTP/2 advisories, and two `html/template`
advisories in imported packages (commit `f5b425d`). The failing hosted run
itself is not recorded in the 50028 evidence.

Commit `f5b425d` moved the build to Go 1.27.2 and `golang.org/x/net` v0.60.0.
The installed 50028 application was built with the affected dependencies, so
it cannot be the 0.5.0 GA application. GA runtime acceptance had not been
completed when it was retired, and nothing was published.

## Successor generation

Build 50029 is now the only active 0.5.0 GA successor. It must start from one
new clean source identity and repeat the complete hosted-CI, build, freeze,
signing, notarization, publication-evidence, package, installation, runtime,
and final publication sequence. The installed build 50028 is its migration
predecessor: the completed 50025 -> 50028 install and service journals are
retained as installation history before the 50029 install reuses their
namespace. No application tree, profile copy, possession proof, signature,
manifest, attempt file, notarization transaction, package, hosted-CI receipt,
component review, legal review, approval, installation journal, or evidence
tree from build 50028 may be copied forward as successful evidence. A reviewer
may compare the 50029 component review with the 50028 review, but 50029 needs
its own legal review and closure approval.

## Evidence locations

- Frozen candidate root: see "Immutable consumed lineage" above. It holds the
  freeze intent, signing attempt, notarization transactions, packages,
  prepackage seal, stage inputs and exported migration journals.
- Operator logs: `/Users/bill/.cfm-release-tooling/ga-050-20261007/logs/d686a85`,
  including the builder log `signed-build.log` (SHA-256
  `fc43a6719b55deaf462c130f2df1568757533b8189751be742c1a69e8e20bdcc`), the
  package logs and the installation logs.
- Release-owner closure approval and the component-review comparison:
  `/Users/bill/.cfm-release-tooling/ga-050-20261007/publication-50028`.
- Prepared publication inputs moved out of the candidate:
  `/Users/bill/.cfm-release-tooling/ga-050-20261007/history/publication-prepared-50028`
  (`sha256-tree-v2` root
  `bcc1a9e89c10176160b1731159678ac28135390ed81d74b02d5ed48da58220ce` over
  34003 entries).
- Release Mac: `/Applications/.com.bill.clashformac.dormant-install.json`, the
  service transaction `/Applications/.com.bill.clashformac.service-transaction-v3`
  and the installed `/Applications/Clash for Mac.app`.

An owner-only evidence copy under `/Users/bill/cfw-release-history` is not
recorded for build 50028.
