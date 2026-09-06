# GA build 40043 retirement

Build 40043 is classified as
`retired_product_change_after_install_before_ga_runtime_acceptance`. The
consumed application lineage is retired because authenticated profile import
exposed a cross-language credential-receipt defect in signed candidate product code.
The correction changes the application; it is not an evidence-tool retry.

## Preserved application and release evidence

The frozen product source is commit
`e268723c1104e3dddc45b45945e8c6371640e138`. Its exact hosted CI run
`33970713729` and all 27 local candidate lanes passed. The candidate completed
Developer ID signing, application notarization with submission
`3f62fd2d-ea41-476b-8082-3067798eadd2`, stapling and Gatekeeper assessment.

The preserved prepackage manifest SHA-256 is
`8abed1925722b4e72dcd0e2f5ea2134de922ffbb1cda1ff85c25b22eb6864e2c`.
It was sealed by release tooling at
`aefde5bb10c4b15fe7ca62e48be8dd7b5f144575` and subsequently reopened without
changing that seal. Later packaging used release tooling at
`cfa2c7bd477317a011118f47c8a8dde6a9ea7dfd`; the tool identity does not replace
the frozen product source identity.

Both local package sets completed:

- DMG SHA-256:
  `250f751dcdd1993a51d433c8dfd7637a64c16891f5b458052eeec7d7c9319967`;
  DMG set seal:
  `6a379890d3ee0031eaed753ff6e46075e230912584114412b3802660a0fa93f3`;
  accepted DMG notarization submission:
  `165ecb03-6730-438b-9d82-165fe1f95c98`.
- Updater archive SHA-256:
  `c6cbaa861530af1bc970dc630389cadf219a10a6c8583110ad89cfcf6de1ccfa`;
  updater set seal:
  `4cdb19d3036804978874c5eb1e1e9fc8a3a99ba38795eb2fadb03aae511eff9b`.

The guarded 40041-to-40043 installation transaction
`94689a5d-7612-4418-af77-28ef3273e8ee` completed through its existing recovery
path after an initial post-exchange identity-read error. Recovery performed no
second copy or exchange. Service recommission, journal export and independent
export verification also completed. The installed application's
`candidate_sha256_tree_v2` is
`429d40db9095775a9498a9445799025536c88ff4e900dde14f7a018d8723edf5`;
its distinct `publication_entry_list_sha256` is
`2a3883c2293a37ffb26e2f9d9f2efc621f89e6476553cbbb21764707d3261d4a`.
These digests use different definitions and are not directly comparable.

## Product failure and evidence boundary

The fresh installed application displayed its dashboard correctly. A formal
import of authenticated SOCKS5 profiles failed before the profile repository
commit. A probe linked to the actual shared-protocol implementation reproduced
the cause using only synthetic, non-secret inputs: `NativeCredentialReceipt`
used synthesized `UUID` encoding, which emitted uppercase hexadecimal letters.
The Rust response validator requires canonical lowercase profile UUIDs and
rejected that otherwise successful receipt. Its generic `IdentityRejected`
mapping then reported the misleading message that the credential vault was
corrupt.

The native vault compare-and-swap precedes receipt production. A missing
profile therefore cannot establish whether the vault write completed. The
failure does not authorize deleting vault data or treating a retry as success.
The fix delegates receipt encoding and decoding to the existing
`CredentialAudience` contract and distinguishes vault corruption from protocol
identity rejection. Strict UUID and digest assertions remain enforced.

GA runtime acceptance collection had not started. No GA acceptance seal,
publication seal or public v0.4.0 release was created. The application was
normally closed, the current protocol proved Off, and the protected Clash for
Windows process and network guard remained unchanged. The earlier transient
migration-window exit and recoverable installation error are not the basis of
this retirement.

## Product-change successor

Build 40044 is the single active successor. It requires its own exact-source
CI, complete unsigned application, candidate freeze, signing and notarization,
source and license closure, packaging, guarded 40043-to-40044 installation,
ordinary GA runtime acceptance and publication verification. Tests and source
checks before candidate freeze do not consume additional build numbers.

The frozen checkout at `target/release-worktrees/40043`, its candidate root at
`target/candidates/0.4.0/ga/40043`, all original outputs, failed attempts and
installation journals remain unchanged. No old receipt is copied forward as
successful 40044 evidence. Earlier retirement documents retain their historical
successor descriptions; the allocation ledger defines current activity.
