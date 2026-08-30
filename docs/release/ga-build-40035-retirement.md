# GA build 40035 retirement

GA build 40035 is permanently classified as
`retired_after_candidate_freeze_before_canonical_signing_output`. It must not
be rebuilt, resumed, re-signed, notarized, installed, promoted, relabelled, or
reused as the v0.4.0 GA application identity.

## Immutable consumed lineage

The candidate-freeze transaction completed before signing and permanently
bound build 40035 to these identities:

- repository commit:
  `e31a4a80ddf875c010e69625b501695ffa9769e2`;
- release-source SHA-256:
  `2501aac94d297fb9839c60fd1aa04123ac1cab0e3b3e7450dec1f43cfe0ccdeb`;
- `product-input.json` file SHA-256:
  `d3562ea88501d3e9c4a62a2f677988a9a0ffbd9a149a31930b2b54ab3422d8cd`;
- frozen product-input semantic SHA-256:
  `448ef52cce9083a35042382cf57cad5abe364c74a51f27b2bfb5446542290e8f`;
- candidate-freeze intent SHA-256:
  `7fd879dcbd12e3c5d0b8d1f9fe6eb18a96b36a12cd8d932f71931d25ddd1fc26`;
- updater-key possession-proof SHA-256:
  `cf87fbeaa5c599458d6734eb1ee54134995baea5f8dad5613e7fd7c7f1ebbe32`;
- frozen Developer ID certificate SHA-256:
  `806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D`.

The frozen root `target/candidates/0.4.0/ga/40035` and every file below it are
immutable historical evidence. They must not be deleted, renamed, edited,
resumed, or copied into a later candidate.

## Terminal signing attempt

Signing attempt `00000001` is the only signing attempt for build 40035. Its
intent SHA-256 is
`e2000edb54fdf24a76fdd7adba5c69d81bd6ef739d47bfefbf9a4d757274ccfc`.
Its append-only journal records `prepared`, `signing`, then terminal `failed`
with `failure_code=signed_output_verification_failed` and `exit_code=null`.
The terminal event file SHA-256 is
`7bdb85b8a62a8579dfd3e1d09ea5888c7a75300b90c66571c35c581c5fda63b5`;
the event's internal `event_sha256` is
`438a17fa5f12258cccc9fd8aeb843eaa35355962663668ef10ce6cb10bbb990c`.

The durable journal does not identify a narrower failing substage. The release
transaction deliberately maps several private-output preparation and complete
verification failures to this terminal code, so no more specific root cause is
asserted here. Any bytes in the private attempt work directory are failure
evidence only and must not be modified, promoted, or reused.

There is no build-40035 canonical `signing-output`, publish-ready directory,
final signed application, notarization submission, stapled artifact, package,
installation, runtime acceptance, physical evidence, upload, or publication.
The failure outcome is known and terminal.

## Successor generation

Retiring the consumed identity and binding the corrected release source to a
new allocation made build 40036 its successor. Build 40036 was later signed,
notarized, and retired before install; its history is recorded in
`ga-build-40036-retirement.md`. Build 40037 is now the only active GA successor.
It must start from one new clean source identity and repeat the complete source,
hosted-CI, build, freeze, signing, notarization, package, installation, runtime,
and publication evidence sequence. No application tree, profile copy,
possession proof, signature, manifest, attempt file, or receipt from build 40035
may be copied forward as successful evidence.
