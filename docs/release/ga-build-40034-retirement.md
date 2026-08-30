# GA build 40034 retirement

GA build 40034 is permanently classified as
`retired_after_candidate_freeze_before_canonical_signing_output`. It must not
be rebuilt, resumed, re-signed, notarized, installed, promoted, relabelled, or
reused as the v0.4.0 GA application identity.

## Immutable consumed lineage

The candidate-freeze transaction completed before signing and permanently
bound build 40034 to these identities:

- repository commit:
  `554efc192f7041025f6457c4a0576cadd6ff66ba`;
- release-source SHA-256:
  `57309bc407c4b71db0d804977a5032518b817d38330ee7ff997c9aca23949f95`;
- `product-input.json` SHA-256:
  `7f48efe3ead51b868e7f77cbb1a71d75ab393817a72b90d358823d5c512a8424`;
- candidate-freeze intent SHA-256:
  `d06b81a94324eb7dd2a1f9ee8a66291f047519675343018f69b80242749b401e`;
- updater-key possession-proof SHA-256:
  `357f69e71f57f01bb1c8f808071aa218a9855880730ca9a899ec300345e7a5c7`;
- frozen Developer ID certificate SHA-256:
  `806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D`.

The frozen root `target/candidates/0.4.0/ga/40034` and every file below it are
immutable historical evidence. They must not be deleted, renamed, edited,
resumed, or copied into a later candidate.

## Terminal signing attempt

Signing attempt `00000001` is the only signing attempt for build 40034. Its
intent SHA-256 is
`bb6023d9f0b97f0c4414ee96ac4c5963ea183cfbec2a948a5834fba2ae259ad6`.
Its append-only journal records `prepared`, `signing`, then terminal `failed`
with `failure_code=signing_helper_failed` and `exit_code=1`. The terminal event
file SHA-256 is
`774bdfa9e16033e43d24ad6f9800cb0dbe3f6cb633a28b5ab2db375a46224e85`;
the event's internal `event_sha256` is
`59965385144e16191bc596e82f640b7bbb0016f9b1dc8980af3d6a6ca6cf0843`.

All five nested code roles and the outer Host application were Developer ID
signed, timestamped, and verified in the private attempt work directory. The
scoped distribution-mode codesign boundary worked as intended: every generated
`CodeResources` file is `0644`, while transaction-private state remains
private. No signature or file from this attempt may be promoted or reused.

The post-sign verifier then rejected the correctly promoted
`CFWLegacyTombstone.manifest.json`. The promoted manifest correctly contains
`preSignArtifactSha256=a8519d57bd0a080b1ef144e6ae2f29a435f1ec7e41b118f1d71776f539b0369f`
and
`preSignManifestSha256=3f805d37e20763d62dc86013010b278924542bc5143eff403117892e765b5405`.
Those values exactly bind the frozen pre-sign artifact and manifest, and its
source, crate manifest, and `Cargo.lock` digests also match the frozen source.
The failure was a producer/consumer schema mismatch: the release verifier used
an exact metadata comparison but omitted the two mandatory promotion-lineage
fields.

There is no build-40034 canonical `signing-output`, publish-ready directory,
final signed application, notarization submission, stapled artifact, package,
installation, runtime acceptance, physical evidence, upload, or publication.
The failure outcome is known and terminal.

## Successor generation

The shared tombstone-promotion verifier and its regression tests change tracked
release source after build 40034 was consumed. Build 40035 became its successor
and was later consumed and retired independently; its history is recorded in
`ga-build-40035-retirement.md`. Build 40036 was later signed, notarized, and
retired before install; its history is recorded in
`ga-build-40036-retirement.md`. Build 40037 was later consumed and retired in
`ga-build-40037-retirement.md`. Build 40038 was later consumed and retired in
`ga-build-40038-retirement.md`. Build 40039 is now the only active GA successor.
It must start from one new clean source identity and repeat the complete source,
hosted-CI, build, freeze, signing, notarization, package, installation, runtime,
and publication evidence sequence. No application tree, profile copy,
possession proof, signature, manifest, attempt file, or receipt from build 40034
may be copied forward as successful evidence.
