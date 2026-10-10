# GA build 40042 retirement

Build 40042 is classified as
`retired_after_notarization_before_install_lane_test_not_hermetic`. Its
application lineage is consumed and retired because its own frozen source
cannot pass the local deterministic CI lane reproduction: one release-tooling
test in that source read the ambient `CFW_TOOLCHAIN_ROOT` selection that the
lane collector exports for every lane, so the `release-tooling-tests` lane
failed inside the frozen checkout while the same suite passed in the operator
checkout and in hosted CI. The correction is a test-isolation change to the
release source, which is a new lineage; it is not an evidence retry.

## Immutable consumed lineage

The candidate-freeze intent binds build 40042 to:

- repository commit:
  `15d0e63fb3504a42bc28a7f409e11b28ff36dcac`;
- release-source SHA-256:
  `353ade4cd685828c0545c8a10175c3abcd25116b45289f4e5d5e5271064614b8`;
- product-input document SHA-256:
  `9ff54a67d21885a8dda20ad98927b675d2757657028798b681616893d109838c`;
- frozen product-input semantic SHA-256:
  `ff3b9aa965b03e0e9a5161d7a99bd9a541e4c190f134c04b902e8b5ea6af4972`;
- candidate-freeze intent SHA-256:
  `3e195a3b8a62213108ace86ab4aa6b138d825dca5f0a02460d90b26b57b6b720`;
- pre-sign application tree SHA-256:
  `6f619b5f3adcc4f90521aceeaef34fcfa9f4e6f54cd94708174cb8e0fdf906e7`;
- canonical signing transformation receipt SHA-256:
  `0c6da1cb303931f93207c2ba558d8540c8d23d251bf55ea76b533ab369e90e7e`.

Beyond freeze and canonical signing, the lineage was consumed through:

- hosted CI run `33959600134` (attempt 1, `success`, head
  `15d0e63fb3504a42bc28a7f409e11b28ff36dcac`), captured and live-verified as
  `stage-inputs/hosted-ci.json`
  (`059d8f363a4c371594a483fcf5dc1eb1565ede1d79a5840cc018a4f57da16e5a`);
- app notarization attempt `893df92e-5a12-447b-8e5f-96cfb5fa5014`, submission
  `ab4ea05d-cd1d-4064-a6be-63698bdb05b4`, sealed with a stapled ticket; the
  signed application tree is
  `8227be5ecdda74a10029a0facca567909f1b89c80531ebc7b246ec24dc2cfffc` and
  Gatekeeper assessed it as accepted (Notarized Developer ID);
- the local deterministic lane record `stage-inputs/local-ci-lanes.json`
  (`6105e5af4eddded168272db03561a88e6f28920e526f4cc7869b89c07434348f`), 27
  lanes, of which `release-tooling-tests` is recorded as failed with exit
  code 1 and is the reason for this retirement;
- a regenerated component review and a publication closure draft
  (`machine-closure.draft.json`,
  `1eb08dd97922b7e5cc84083c287bd52a52b50f2cdb326aa313f5ee69e7684859`) that
  were never legally approved or finalized.

The frozen checkout at `target/release-worktrees/40042` and its candidate root
`target/candidates/0.4.0/ga/40042` remain unchanged. There is no prepackage
seal, DMG or updater package set, installation, GA acceptance, publication
seal or public 0.4.0 release for this build. Preserve every journal, receipt,
seal, signed output and failed attempt. Build 40041 remains the installed
application on the release Mac and the observed predecessor of the successor.

## Test-isolation successor

The correction makes
`test_artifact_toolchain_failure_stops_admission_before_app_or_service_actions`
run without the ambient toolchain selection it does not model, so the frozen
source's own lane reproduction and the operator checkout's gate exercise the
same scenario. No application, entitlement, profile, dependency or
nested-code input changes.

Build 40043 is the single active successor. It requires its own exact-source
CI, complete unsigned application, freeze, signing/notarization, source and
license closure, packaging, one-machine ordinary-GA acceptance over the
40041 → 40043 migration, and publication verification. No 40042 candidate
receipt is copied forward as successful evidence. Earlier retirement documents
keep their historical successor descriptions; the allocation ledger defines
current activity.
