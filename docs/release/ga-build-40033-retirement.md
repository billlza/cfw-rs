# GA build 40033 retirement

GA build 40033 is permanently classified as
`retired_after_candidate_freeze_before_canonical_signing_output`. It must not
be rebuilt, resumed, re-signed, notarized, installed, promoted, relabelled, or
reused as the v0.4.0 GA application identity.

## Immutable consumed lineage

The candidate-freeze transaction completed before signing and permanently
bound build 40033 to these identities:

- repository commit:
  `fee8fac446ef8805e45ccd9738fd9f77eb1992dd`;
- release-source SHA-256:
  `a1d7d966bcecd73d4100c5c2cb5cf885a1a4e4b060333fed0d7b7eca8c01e4a3`;
- `product-input.json` SHA-256:
  `f0e214f65411ed4b050d84d698ff550f53f19e3cba1381c40af421824398c8a4`;
- candidate-freeze intent SHA-256:
  `90398902e0b0b85ac0f49f38d8b2cc432b8f1ff8827cf2608399a0cf4a4109aa`;
- updater-key possession-proof SHA-256:
  `8f25a58e5d52d125ead88f96ca1867170ac1d90b9e9fbcc1174dd04e140d3915`;
- frozen Developer ID certificate SHA-256:
  `806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D`.

The frozen root `target/candidates/0.4.0/ga/40033` and every file below it are
immutable historical evidence. They must not be deleted, renamed, edited,
resumed, or copied into a later candidate.

## Terminal signing attempt

Signing attempt `00000001` is the only signing attempt for build 40033. Its
intent SHA-256 is
`3d4bfdde6bc12099e83747b3c95db60a0a9f96d7fa6ef318c68325eab3ef92a5`.
Its append-only journal records `prepared`, `signing`, then terminal `failed`
with `failure_code=signing_helper_failed` and `exit_code=1`. The terminal event
file SHA-256 is
`9ef1e3231848a2fcdfe22c9a5ce0ceaff4e756780f310ee2005757992a4bd0ec`;
the event's internal `event_sha256` is
`6ef404f6129e2233a60a07c00d3289483fc46a2fc7d6dc41c1ac59f396291cc4`.

Five nested products were Developer ID signed, timestamped, and verified in
the private attempt work directory. The transaction-owned helper's private
`umask 077` also applied to resource files created by `codesign`, so the
framework, ProxyAgent, and PacketTunnel `CodeResources` files were created as
`0600`; their promoted private copies preserved the same mode. The candidate
bundle verifier correctly requires distributable bundle files to be `0644` or
`0755` and rejected the private signing input before Host signing.

There is no build-40033 canonical `signing-output`, final signed application,
notarization submission, stapled artifact, package, installation, runtime
acceptance, physical evidence, upload, or publication. The failure outcome is
known and terminal; the private signed nested products are failure evidence
only and cannot be modified, promoted, or reused.

## Successor generation

Scoping distribution mode creation around the fixed `codesign` boundary and
closing unsafe fresh-signing recovery change tracked release source after
build 40033 was consumed. Build 40034 became its successor and was later
consumed and retired independently; its history is recorded in
`ga-build-40034-retirement.md`. Build 40035 was later consumed and retired in
`ga-build-40035-retirement.md`. Build 40036 is therefore the only active GA
successor. It must start from one new clean source identity and repeat the
complete source, hosted-CI, build, freeze, signing, notarization, package,
installation, runtime, and publication evidence sequence. No application tree,
profile, possession proof, signature, manifest, attempt file, or receipt from
build 40033 may be copied forward as successful evidence.
