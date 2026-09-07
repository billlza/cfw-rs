# Validation build 40021 retirement record

Build 40021 is permanently classified as
`retired_after_notarization_before_install`.

It completed the Apple and local artifact gates:

- repository commit: `3a152f02ad4ba65838c3a5c6af0964bfd67cf1f4`;
- release-source SHA-256:
  `6d833bfe14784ee369c042278d77fe4f50406821a38681d756045ab9751c89a2`;
- signed app tree SHA-256:
  `983e0bb287f406338b8cf0ca142a90fdafe4598dc6d3e96f964092eec675fbb8`;
- Apple submission: `29f581a9-ee90-4c21-830d-9de9838c6e79`, Accepted with
  zero notarization issues and warnings;
- stapling, live Gatekeeper assessment, release-app verification, manifest
  verification, and the sealed publish-ready receipt all passed.

It was not installed and is not eligible for validation approval. Its source
closure still fixed the dormant installer to validation build 40009, and it did
not contain the signed-Host ProxyAgent/GlobalAuthority
decommission/recommission transaction required to make the installed bundle
dormant before an atomic swap.

The following evidence roots are immutable and must remain in place:

- `target/candidates/0.4.0/notary-build-claims/40021`;
- `target/candidates/0.4.0/notary-attempts/validation/40021`;
- `target/candidates/0.4.0/validation/40021`.

Do not delete, rename, copy to a new build number, resubmit, install, or use
these bytes as the input to `validated-candidate.json`. The next validation and
final pair is 40022/40023 from a new clean source identity.
