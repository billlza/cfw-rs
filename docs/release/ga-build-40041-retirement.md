# GA build 40041 retirement

Build 40041 is classified as
`retired_product_change_after_install_before_ga_runtime_acceptance`. Its
application lineage is consumed and retired because the shipped application's
legacy cutover preflight changes: it attributed the live Clash for Windows
System Proxy and tunnel to the retired legacy installation and demanded their
absence, while GA runtime acceptance requires exactly that state to be
preserved. The correction changes product bytes; it is not an evidence retry.

## Immutable consumed lineage

The candidate-freeze intent binds build 40041 to:

- repository commit:
  `b2bb20267074420aab200438637a224e4ca814f7`;
- release-source SHA-256:
  `cd7813bec4cbe9aec073a9539dd59d6ce60a98721a4b9dac9496ea36920242e2`;
- product-input document SHA-256:
  `24c0b46568d580b534678fd77877e999a42843bcb48e1f07094aa8569bf0e677`;
- frozen product-input semantic SHA-256:
  `addf7c4cdb657ef0ae1d6cd0ad384706dc38e4ea49bee624e9f59afd78cc6baa`;
- candidate-freeze intent SHA-256:
  `dddd06e284f60fafd463248e745213b63fed2cee55afb6f662710ac287b9ca2c`;
- pre-sign application tree SHA-256:
  `480b300ef7180c7ddc42b07a4f529113872af92b64d0a1bc872b8f82e5c49ee5`;
- canonical signing transformation receipt SHA-256:
  `b71301d5afc0120e3beb8f0fe118962576cb798c781eb5e8feaf45e9698804e5`.

Beyond freeze and canonical signing, the lineage was consumed through:

- hosted CI run `33710106376` (attempt 1, `success`, head
  `b2bb20267074420aab200438637a224e4ca814f7`);
- app notarization attempt `8bc6055d-6e9c-400d-a84a-e16cc5cbbbda` with
  submission `451e6be8-8d08-422d-8035-018d6da7e4fc`; DMG notarization
  `e91b02a1-8c99-44f1-a143-eb5b65d0ff16` (`Accepted`) and a Gatekeeper
  `accepted` assessment;
- sealed package sets: `Clash.for.Mac_0.4.0_arm64.dmg` SHA-256
  `9eb4b8f6eff0f006f9a97c74ea5be19474bd6a203aebc69c86bc60d48dc0eb2f`
  (`dmg-set.seal.json`
  `71fba031afef5215695e8eef10f7a625c92d1237ea893653cb9d20678681a4a7`), the
  updater set (`updater-set.seal.json`
  `21136c77d384e36488067121862537c02a3ad589c3e41b2ec8472e691d1ff277`) and the
  prepackage manifest
  `3aad29a3de20ab2237a6e18b2cf0be48e102afef54ad9ac2b23e69caf6b336c9`;
- the closed 40019 → 40041 dormant install journal (`dormant-install.json`
  `6836e7ac36c4e76ef1372a200b9405c1f91980613829103681a640ec0128bce4`; previous
  tree `527ac309a3047fb5aa1ec8eebacd759de3cba8fc71c5f2b1910d0827dcf4b225`,
  candidate tree
  `d7b12dc1659ab0d812a249219195697f946329dbdd3fcf6b5f07b43a4c04ca37`) and its
  export receipt
  `aa85e2c6d98be6c1b3b56876a49f3fe13fddc60df44620799a8a2b4fd50c2d6d`.

Build 40041 is installed at `/Applications/Clash for Mac.app` with the sealed
tree `d7b12dc1659ab0d812a249219195697f946329dbdd3fcf6b5f07b43a4c04ca37`; it is
the observed predecessor of the successor install. The frozen checkout at
`target/release-worktrees/40041` and its candidate root
`target/candidates/0.4.0/ga/40041` remain unchanged. GA runtime acceptance
collection `1412394a-ecab-40b2-b315-fe9f1c0ee775` aborted before any mutation
after the DMG Gatekeeper step and its runtime recovery completed; there is no
GA acceptance seal, publication seal or public 0.4.0 release for this build.
Preserve every journal, receipt, seal, signed output and failed attempt.

## Why the lineage cannot be accepted

GA runtime acceptance check `legacy_cfw_preserved` requires Clash for Windows
to keep `127.0.0.1:7890` (HTTP, HTTPS, SOCKS) and its `198.18.0.0/16` tunnel
routes throughout collection, and the CFW guard refuses to capture otherwise.
Clash for Windows must remain running on the release Mac for the whole release.
The installed 40041 application starts in
`LegacyRetirementStatus::AwaitingConfirmation`, which masks every network mode
until the one-way legacy cutover completes, and its cutover preflight required
the retired installation's System Proxy and tunnel fingerprints to be absent
while attributing the live Clash for Windows state to that installation. The
cutover therefore could not be confirmed while the GA precondition held; the
two requirements were mutually exclusive on the release Mac.

## Product-change successor

The correction attributes legacy network absence to the retired installation
only: the legacy fingerprint ignores live interfaces and the legacy proxy check
verifies only the ports the retired installation owned (`f37f678`). GA service
registration is bound to the real launchd job contract (`77b7848`), and the
install tooling selects its service vocabulary from the observed predecessor
instead of a declared one (`4633671`, `fd845e1`), so the successor
installs over the installed 40041 without a new compatibility path.

Build 40042 is the single active successor. It requires its own exact-source
CI, complete unsigned application, freeze, signing/notarization, source and
license closure, packaging, one-machine ordinary-GA acceptance over the
40041 → 40042 migration, and publication verification. No 40041 candidate
receipt is copied forward as successful evidence. Earlier retirement documents
keep their historical successor descriptions; the allocation ledger defines
current activity.
