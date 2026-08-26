# GA build 40031 retirement

GA build 40031 is permanently classified as
`retired_after_candidate_freeze_before_canonical_signing_output`. It must not
be rebuilt, re-signed, notarized, installed, promoted, relabelled, or reused as
the v0.4.0 GA application identity.

## Immutable consumed lineage

The candidate-freeze transaction completed before signing and permanently
bound build 40031 to these identities:

- repository commit:
  `fc762f130efce47fe23feeb6d1d7572714d78a6e`;
- release-source SHA-256:
  `0a2152334795e95e9035b1f92f17844beda510d953d656bcca764e84139cd495`;
- `product-input.json` SHA-256:
  `ad2691497e39e35905ddf74eca88cbff320608b79325497fc9f23368f4556a86`;
- candidate-freeze intent SHA-256:
  `75a3a326e2e343585bac18fe1c5ec97dfa3a94aef9576df9017f7a0ee58d10bb`.

The frozen root
`target/candidates/0.4.0/ga/40031` and all files below it are immutable
historical evidence. They must not be deleted, renamed, copied into a new
candidate, or edited to make a later transaction appear successful.

## Terminal signing attempt

Signing attempt `00000001` is the only signing attempt for build 40031. Its
intent SHA-256 is
`64c6166b667d7339708b27912e5b66bc69450f37c477787f3ecb2b0b173972da`.
Its append-only journal records `prepared`, `signing`, then terminal `failed`
with `failure_code=signing_helper_failed` and `exit_code=1`. The terminal event
file SHA-256 is
`0d4d91c4d9daf5bfcdefce395cb872d6c11d1829fab1ca3a695509f5633b80b7`;
the event's internal `event_sha256` is
`f6b80168183f242545a2674b8f2edcf54e908017f0bcad35fe97eecd0c505abf`.

Five nested products were Developer ID signed and verified inside the private
attempt work directory. The release helper then invoked a repository Python
CLI directly under isolated mode, so its required sibling module was not on
the reviewed import path. Manifest promotion failed before Host signing and
before any canonical signing output was published.

There is no build-40031 canonical `signing-output`, final signed application,
notarization submission, stapled artifact, package, installation, runtime
acceptance, physical evidence, upload, or publication. The failure outcome is
known and terminal; it is not an outcome-unknown external transaction.

## Successor generation

Correcting the release-helper invocation changed the tracked release source
after build 40031 was consumed, so build 40032 became its successor. Build
40032 was later consumed and retired independently; its history is recorded in
`ga-build-40032-retirement.md`. Build 40033 was later consumed and retired in
`ga-build-40033-retirement.md`. Build 40034 is now the only active GA identity
and must repeat the complete source, hosted-CI, build, signing, notarization,
package, installation, runtime, and publication evidence sequence. No
application tree, profile, possession proof, signature, manifest, attempt
file, or receipt from build 40031 may be copied forward as successful evidence.
