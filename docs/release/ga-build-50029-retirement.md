# GA build 50029 retirement

GA build 50029 is permanently classified as
`retired_product_change_after_install_before_ga_runtime_acceptance`.
It must not be rebuilt, resumed, re-signed, re-notarized, repackaged,
reinstalled, promoted, relabelled, or reused as the 0.5.0 GA application
identity.

## Immutable consumed lineage

The candidate-freeze transaction permanently bound build 50029 to these
identities:

- repository commit:
  `124e8e3d64e24a99d90ff0f1c57bf4c12e416b8a`;
- release-source SHA-256:
  `d30794da42668aec1a3e59686130d6d8c1b1fcecc490118d1672397adac6da9b`;
- `product-input.json` file SHA-256:
  `1ffbfa957e5d1d9ee5dceec253a041b7f0765ba2f6d049d4cd7789fe6872d11b`;
- frozen product-input semantic SHA-256:
  `08944a962380c5657017bf444c33bd928649d9b0c141c7e1eba29886b16d1161`;
- candidate-freeze intent SHA-256:
  `4a3b6546ffdefbc06c8375c3b9a808acf2504c12c690fd1824cfb8c8ce91de7c`;
- updater-key possession-proof SHA-256:
  `4439700f0b5a9c4503f645e5a399434d6f19b892c7873af2dc16fff2b5ee47df`;
- frozen Developer ID certificate SHA-256:
  `806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D`.

The frozen root
`target/release-worktrees/50029/target/candidates/0.5.0/ga/50029` of the
release operator checkout
`/Users/bill/.cfm-release-tooling/ga-050-20261007/operator-50029` and every
file below it are immutable historical evidence. They must not be deleted,
renamed, edited, resumed, or copied into a later candidate.

## Completed stages

- Signing attempt `00000001` (intent SHA-256
  `c2266ed41b72d1c5ca7c4349a179f76e5bb48b3d4000042dfac6696fa0eb5a8e`) reached
  `published`; its terminal `event_sha256` is
  `1dd71c82ccd22eac30a043d295fcbe323f30470100939cd351ecd3747c6c11b4`. The
  signed application tree SHA-256 is
  `e7990cf4dd37419978ab01b9f2e83dec7fc2360ca304ad8ac0fa586039e63223` and the
  signing-transformation receipt SHA-256 is
  `db9642318efc45bad1ff780ad40cab6b631a6bdcf107d557e00c2b648c9b49c7`.
- Apple notarization submission `82e37e34-a63f-4d04-941b-f67a360c8606`
  (archive SHA-256
  `fcbbd49a44302b21a855308e10760f14b7f48fa245989d33e49a30f55c789a5b`) was
  Accepted. Its direct finalization continued through log verification,
  stapling, Gatekeeper (`Notarized Developer ID`), application and
  distribution verification to `sealed` (event 15) without a recovery. No
  second submission was made. The publish-ready receipt SHA-256 is
  `30cbbff1d409a056ab72ba0c1eb665782ca24e8104295910fbe33ddded3190ff`, and the
  stapled application has the `sha256-tree-v2` root
  `aa67685e1cea4c77a90ded3d9a70264912f8e3711b8e7c1d83ebdb9442339483`.
- The hosted-CI receipt for run `38141133214` attempt 1 of the `CI` workflow
  (SHA-256
  `a867fe7cfacf36cebdc30a810427543533a47e6c6a2fa6bc5b7ad733216c38e0`) was
  captured. The run tested `7256caf`, a child of `124e8e3` that changes only
  `scripts/tests/release_publication_gate_test.sh`, and its three jobs
  succeeded on 2026-10-11. The operator checkout keeps that commit as
  `refs/cfw-hosted-ci/50029-tested`. Hosted CI for `124e8e3` itself (run
  `38135599814`) had failed in its `Lint shell scripts with pinned ShellCheck`
  step on findings in that test; that run is not recorded in the 50029
  evidence.
- Publication evidence was finalized under `stage-inputs/publication`: machine
  closure SHA-256
  `8e125c4cb00486bb82e956bb749ead8ac3881015c68f31bec0b8b56c4c97492e`, approved
  by the release owner on 2026-10-11; legal review SHA-256
  `8f8f9b2c30ecfca6fb53bfc1d620629b572922252eaaa4493e0a1a31037bf449`; evidence
  manifest SHA-256
  `a1285edbba0588c4e81cc3d524318373bb659fc30e6e2a29f899479fa170bbe4`.
- The prepackage stage was sealed: `prepackage/manifest.json` SHA-256
  `4db97d6766561827edbe2f515043fe3e59ecc6d61562bba326031d8c435931f7`.
- The DMG `Clash.for.Mac_0.5.0_arm64.dmg` was notarized as submission
  `d423777e-b032-4fd7-8c29-f4e69bbb9b59` (Accepted), stapled, assessed by
  Gatekeeper as `Notarized Developer ID`, and its transaction reached
  `published` (event 12). The stapled DMG SHA-256 is
  `fa04775ae58b56de6ff54ab7d54ea6302946ed63020d7c5f45d0f27f57aec34f` (45419698
  bytes) and the `dmg-set.seal.json` SHA-256 is
  `f023d886b6326f45d2a84a1d9ec82fb33b21e3d159e03e88e53348e6430d1624`.
- The updater archive `Clash.for.Mac_0.5.0_aarch64.app.tar.gz` (SHA-256
  `223209163891a33e7eb55a7cc46b636b771012a2083fff685662810de64baefa`, 44934788
  bytes), its signature (SHA-256
  `a4bcbba0f60fc96dff8f95cccce9dcf9691144269f1f419edd18e00519b9bfe7`) and
  `latest.json` (SHA-256
  `4405e3bae312667c3f3ebf15adf437630eb609c980c0d873c3f6be453af57e6b`) were
  produced; the embedded public key verified the signature, and the
  `updater-set.seal.json` SHA-256 is
  `7617110c6103718d1ff129e4e96c22756d60ae6c4a6e4572c70a14442d917920`.
- Build 50029 was installed on the release Mac over the installed GA build
  50028 (tree
  `dd8a27dc6c22893e469a34433393b83d5be02edb07455752c39b6c0ffe77786d`). The
  completed 50025 -> 50028 installation history was first retained under
  `/Applications/.com.bill.clashformac.install-history-v1/50028`. Dormant
  install transaction `ca1b695d-6ef5-4eea-925c-bd3b2930f432` completed on its
  first run, without a recovery and without launching the application.
  Service transaction `444b6bfa-72e0-42ac-be54-5aeefce8c4b5` decommissioned
  the services before the install and recommissioned them after it. The
  installed application tree SHA-256 is
  `aa67685e1cea4c77a90ded3d9a70264912f8e3711b8e7c1d83ebdb9442339483`, equal to
  the stapled candidate. The migration journals 50028 -> 50029 were exported
  into `stage-inputs/ga-acceptance/migration-journals`; the export receipt
  SHA-256 is
  `7622b122981be7115bb7681a4cb4f941e143f0054afde32424be155c6a14468f`.
- On 2026-10-11 GA runtime collection session
  `463ccb20-a2fd-4289-8de3-b996ba63306d` started; its intent (SHA-256
  `e61246efa450f85b6d07007038d9a55391d979a7f65fdb6005aedfb635fbf9d4`) binds
  those journals and the DMG set. Its journal under
  `stage-inputs/ga-acceptance/runtime-collection` records the
  `dmg-gatekeeper` step as completed and the `dmg-contained-app-byte-proof`
  step as started, and then ends with `aborted_before_mutation`. The
  collector reported
  `GA collection dmg-contained-app-byte-proof command identity, exit, or duration is invalid`.
  No runtime evidence or runtime acceptance record was written, and the
  session was not recovered afterwards.

There is no GA runtime acceptance, publication seal, distribution set, tag,
upload, or public release for build 50029.

## Cause

On 2026-10-16 the release owner decided that the changes of commit `d828f92`,
made after 50029 was installed, ship in 0.5.0: the Settings > Engine >
Mainland China direct switch, the import of Clash GEOSITE rules, the import of
a Hysteria2 link's `pinSHA256` as the node's certificate pin, a bounded engine
start for System Proxy and TUN, and a spent runtime state once an engine
cannot be closed. The commit records them in the 0.5.0 section of
`CHANGELOG.md`. These change the application bytes, so the installed 50029
application cannot be the 0.5.0 GA application.

The 50029 application was also built with rustls 0.23.45, as its SBOM
records. On 2026-10-14 four rustls advisories were published that cover that
version and are fixed in 0.23.46: RUSTSEC-2026-0346, -0347, -0348 and -0349.
None of them affects how the application uses rustls, but release policy
admits no advisory in the Rust dependency graph (`deny.toml` ignores none),
and on 2026-10-16 the `rust-target-audit` and `cargo-deny` gates reported
all four for `d828f92`, which has the same rustls. Commit `d7f2dcd` moves
rustls to 0.23.46.

Independently of that decision, the remaining 50029 stages cannot run on the
release Mac as it is now. The frozen `124e8e3` release tooling accepts only its
pinned Xcode 27.0 (27A266a): before it acts, the entry point of every remaining
stage checks `xcodebuild -version` against that pin in
`cfw_select_release_apple_toolchain` (`scripts/release_tool_environment.sh`)
and otherwise stops with `error: Xcode 27.0 (27A266a) is required`. On
2026-10-16 `/Applications/Xcode.app`, the only Xcode on the release Mac,
became Xcode 27.1 (27A9275), so that check now fails. This follows from the
frozen code and the installed Xcode; no retained 50029 log records it. Commit
`d828f92` moves the pin to Xcode 27.1 (27A9275).

GA runtime acceptance had not been completed when 50029 was retired. The
evidence points to a check that needs Apple's servers, not to the 50029 bytes.
The `dmg-contained-app-byte-proof` step runs `release_artifact_set_cli.py
verify-dmg` as a child process. That child reopens the sealed prepackage stage
twice, and each reopen ran `verify_release_app.sh`, which validated the stapled
ticket with `stapler validate` and asked Gatekeeper for a fresh assessment.
Both contact Apple. The release Mac's unified log records its Apple Push
Service connection dropping at 19:19:15 BST, during the child's first reopen,
which then took about 40 seconds longer than in the passing reruns described
below. The connection returned at 19:22:02 and dropped again, for under a
second, at 19:23:30, 23 seconds into the second reopen. The child ended at
19:24:15, after 6 minutes 27 seconds: well inside the step's 30-minute bound,
and before a passing run finishes that reopen. The collector's command check
kept neither the child's exit status nor its standard error, so it reported
only `command identity, exit, or duration is invalid`, and no retained 50029
log shows which check failed. With network access denied, `stapler validate`
on a copy of the signed 50029 application fails at once with error 68. The
same verification command, rerun read-only on the same bytes at 19:28 and
19:37 while the connection was steady, passed both times
(`19a-runtime-dmg-proof-diagnostic.log` and `19b-runtime-dmg-proof-receipt.json`
in the operator logs). Release tooling commit `7b70d18` makes reopening
a sealed stage verify notarization offline, keeps one live check in each of the
prepackage and publication seals, before packaging and at upload, and reports
a failed command's exit status and the end of its output. Nothing was
published.

Had that step passed, the frozen collector would still have stopped later.
Its installed-application check compared the installed bundle's three-field
identity with the install journal's six-field candidate record, so it always
raised. Its wait for the operator to select Tunnel also failed: the mode change
holds the Host's maintenance lease, and the collector treated the resulting
`maintenance_busy` refusal as final. Each poll also used one of the signed
Host's 64 launcher tickets, which stay live for 305 seconds, so a wait longer
than about 80 seconds ran out of tickets. Commit `7b70d18` fixes all
three.

## Successor generation

Build 50030 is now the only active 0.5.0 GA successor. It must start from one
new clean source identity and repeat the complete hosted-CI, build, freeze,
signing, notarization, publication-evidence, package, installation, runtime,
and final publication sequence. The installed build 50029 is its migration
predecessor: the completed 50028 -> 50029 install and service journals are
retained as installation history before the 50030 install reuses their
namespace. No application tree, profile copy, possession proof, signature,
manifest, attempt file, notarization transaction, package, hosted-CI receipt,
component review, legal review, approval, installation journal,
runtime-collection journal, or evidence tree from build 50029 may be copied
forward as successful evidence. A reviewer may compare the 50030 component
review with the 50029 review, but 50030 needs its own legal review and closure
approval.

## Evidence locations

- Frozen candidate root: see "Immutable consumed lineage" above. It holds the
  freeze intent, signing attempt, notarization transactions, packages,
  prepackage seal, stage inputs, the exported migration journals and the
  runtime-collection journal.
- Operator logs: `/Users/bill/.cfm-release-tooling/ga-050-20261007/logs/124e8e3`
  holds the hosted-CI capture, publication, package, installation and
  runtime-collection logs, and a read-only diagnostic rerun of the DMG
  verification command that is not GA runtime evidence. The builder log is
  `/Users/bill/.cfm-release-tooling/ga-050-20261007/logs/50029-builder-1.log`
  (SHA-256
  `e0d5cee1f8531dfd40c49493ec84210a32ef05f1f618e06aa8015c26f1fefab4`), and the
  pre-build gate logs are in
  `/Users/bill/.cfm-release-tooling/ga-050-20261007/logs/50029-prep`.
- Operator launchers and their runbook `RUNBOOK-50029.md`:
  `/Users/bill/.cfm-release-tooling/ga-050-20261007/launchers-50029`.
- Release-owner closure approval and the component-review comparison:
  `/Users/bill/.cfm-release-tooling/ga-050-20261007/publication-50029`.
- Prepared publication inputs moved out of the candidate:
  `/Users/bill/.cfm-release-tooling/ga-050-20261007/history/publication-prepared-50029`
  (`sha256-tree-v2` root
  `0eab29cdd131bade319ba3f495813a8720cac31018ae6d1f975ce25e7845225f` over
  33963 entries).
- Release Mac: `/Applications/.com.bill.clashformac.dormant-install.json`, the
  service transaction `/Applications/.com.bill.clashformac.service-transaction-v3`,
  the retained 50025 -> 50028 history
  `/Applications/.com.bill.clashformac.install-history-v1/50028`, the
  install's staging directory
  `/Applications/.com.bill.clashformac.dormant-install.ca1b695d-6ef5-4eea-925c-bd3b2930f432`,
  which holds the displaced 50028 application, and the installed
  `/Applications/Clash for Mac.app`.

An owner-only evidence copy under `/Users/bill/cfw-release-history` is not
recorded for build 50029.
