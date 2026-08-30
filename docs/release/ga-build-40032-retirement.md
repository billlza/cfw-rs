# GA build 40032 retirement

GA build 40032 is permanently classified as
`retired_after_candidate_freeze_before_canonical_signing_output`. It must not
be rebuilt, resumed, re-signed, notarized, installed, promoted, relabelled, or
reused as the v0.4.0 GA application identity.

## Immutable consumed lineage

The candidate-freeze transaction completed before signing and permanently
bound build 40032 to these identities:

- repository commit:
  `f6a04c2cb1b6b7b8c11061ccfe92158374205168`;
- release-source SHA-256:
  `3317401453449864cda1f795c06f079d7dcc5d4e3caade7e698a762228536f83`;
- `product-input.json` SHA-256:
  `fcee99a8cde900e936abd1147546e96abd78c3126539096a7fb12030f6d88fb8`;
- candidate-freeze intent SHA-256:
  `5e753f617f69b00bb46fb37ded0957e0f1da3263e06b8954cc6541a298a51096`;
- frozen Developer ID certificate SHA-256:
  `806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D`.

The frozen root `target/candidates/0.4.0/ga/40032` and every file below it are
immutable historical evidence. They must not be deleted, renamed, edited,
resumed, or copied into a later candidate.

## Terminal signing attempt

Signing attempt `00000001` is the only signing attempt for build 40032. Its
intent SHA-256 is
`7456470db49cdfd7b5ba24638dc8064ae9f21b793ab4e0ab2e1047c88464905d`.
Its append-only journal records `prepared`, `signing`, then terminal `failed`
with `failure_code=signing_helper_failed` and `exit_code=1`. The terminal event
file SHA-256 is
`07bb659c409b8038923fe6ac9dc1538997f45d09b4c085bad39dfade578ed3b7`;
the event's internal `event_sha256` is
`aeafa7f1ac7ffbd8bc6c220f08b9a8eebba6815c5fc1d8fc96be0adc541b385d`.

Five nested products were Developer ID signed, timestamped, verified, and
bound to promoted signed manifests inside the private attempt work directory.
The Host remained ad-hoc linker-signed. Before Host signing, the outer release
verifier admitted the exact private signing-attempt layout while its inner
candidate verifier accepted only canonical `signing-output` native products.
The inner check therefore rejected the private `work/signed-native-products`
root. This was a deterministic path-contract defect in tracked release source,
not an unknown external signing or notarization outcome.

There is no build-40032 canonical `signing-output`, final signed application,
notarization submission, stapled artifact, package, installation, runtime
acceptance, physical evidence, upload, or publication. The private signed
nested products are failure evidence only and cannot be promoted or reused.

## Successor generation

Unifying the verifier path contract changed tracked release source after build
40032 was consumed, so build 40033 became its successor. Build 40033 was later
consumed and retired independently; its history is recorded in
`ga-build-40033-retirement.md`. Build 40034 was later consumed and retired in
`ga-build-40034-retirement.md`. Build 40035 was later consumed and retired in
`ga-build-40035-retirement.md`. Build 40036 was later signed, notarized, and
retired before install; its history is recorded in
`ga-build-40036-retirement.md`. Build 40037 is therefore the only active GA
successor. It must start from one new clean source identity and repeat the
complete source, hosted-CI, build, freeze, signing, notarization, package,
installation, runtime, and publication evidence sequence. No application tree,
profile, possession proof, signature, manifest, attempt file, or receipt from
build 40032 may be copied forward as successful evidence.
