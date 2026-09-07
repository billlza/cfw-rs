# GA build 40037 retirement

GA build 40037 is permanently classified as
`retired_after_candidate_freeze_before_canonical_signing_output`. It must not
be rebuilt, resumed, re-signed, notarized, installed, promoted, relabelled, or
reused as the v0.4.0 GA application identity.

## Immutable consumed lineage

The candidate-freeze transaction completed before signing and permanently
bound build 40037 to these identities:

- repository commit:
  `93774984fbe1b893f169e5fe804d0aee4da8d6a2`;
- release-source SHA-256:
  `66d374b5bb08a0cc73a24e3beff92146656a63d74f6e7fe631957de44b121fbc`;
- `product-input.json` file SHA-256:
  `95d734fa848938d2e4335597e0eabf31e67a12848aa74d4a2edd9cddad0ac3d4`;
- frozen product-input semantic SHA-256:
  `0b0f4ea6e56191460d752e9a3908e1253fee260f6f87ee010bf47abd51c76a07`;
- candidate-freeze intent SHA-256:
  `63dc657350f088977c298211ae7bf993c8f2697f2f379b4738dc37de6c19a601`;
- updater-key possession-proof SHA-256:
  `2c761467468fd3cffd426f6fb53be866f42baa593f0719733d31403e2fa780b7`;
- frozen Developer ID certificate SHA-256:
  `806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D`.

The frozen root
`target/release-worktrees/40037/target/candidates/0.4.0/ga/40037` and every
file below it are immutable historical evidence. They must not be deleted,
renamed, edited, resumed, or copied into a later candidate.

An owner-only evidence copy is retained at
`/Users/bill/cfw-release-history/ga-build-40037-evidence/candidate`. Its
`sha256-tree-v2` root is
`ab4e52c57f19de841e885f7df7b8919eb63782eb58a56b0debd2d9310aeb356d`
over 240 entries. The source and snapshot manifests are retained separately as
`ga-build-40037-evidence.source-tree-v2.json` and
`ga-build-40037-evidence.snapshot-tree-v2.json`; both the evidence directory
and manifests are owner-only.

## Private signing-attempt evidence

Signing attempt `00000001` invoked the signing helper once. The helper returned
success, the private Developer ID-signed application and signed native products
were written below the attempt's `work` directory, and the complete
`signing-transformation.json` receipt was durably present. The attempt intent
SHA-256 is
`57e6bcb264cdc245ceebe7bf3115ccda05d3a8b37429cdc6269e0b49b6e93683`.
The transformation receipt file SHA-256 is
`1b2708c10599d187886994b1a5d5cb0336b8f456c038e5bb305e8f9acce3eb62`,
and it binds the private signed-app tree SHA-256
`d9743b9029f5acc7eeca101d8c04892ecf511ad68ceb3a4eb94226d9feef0db6`.

This is private attempt evidence only. There is no `publish-ready` directory,
canonical `signing-output`, canonical `signed` application, notarization
transaction, Apple submission, package, installation, runtime acceptance,
physical acceptance, tag, upload, or public release for build 40037.

## Terminal verification failure

After the receipt was written, the mandatory read-only transformation replay
failed while reopening the consumed candidate freeze. The attempt journal
therefore reached terminal `failed` with failure code
`signing_transformation_failed`. The terminal event file SHA-256 is
`f5c65d34a7cd259f5cad72147f8ff5d6d4577d3e0fe7c8fd2aa2bf05daac4c8c`;
its internal `event_sha256` is
`a4d4c9d03d6f84906898851cee231b9d6ad4fd9d93889a65a9f5ed547261ff9e`.

Later read-only replays of the same frozen intent and updater possession proof
succeeded. This rules out a currently persistent source or proof drift, but it
does not rewrite the append-only journal and cannot establish the exact nested
cause of the historical failure: the frozen implementation retained only the
generic outer failure code. The source identity that produced build 40037 has
no transition out of `failed`, so a later recovery implementation cannot be
applied retroactively to this consumed identity.

## Successor generation

Build 40038 became the active GA successor and was later consumed and retired
independently; its history is recorded in `ga-build-40038-retirement.md`.
Build 40039 is now the only active GA successor. Its source retains the narrow
post-receipt recovery rule and adds one in-process fresh-session replay for a
typed operational verifier failure after signing succeeds. Neither rule can be
applied retroactively to this terminal build-40037 attempt.

Build 40039 must start from one new clean source identity and repeat the
complete hosted-CI, build, freeze, signing, notarization,
publication-evidence, package, installation, runtime, physical, and final
publication sequence. No application tree, profile copy, possession proof,
signature, manifest, attempt file, receipt, review, or evidence tree from
build 40037 may be copied forward as successful evidence.
