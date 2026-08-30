# GA build 40036 retirement

GA build 40036 is permanently classified as
`retired_after_notarization_before_install`. It must not be rebuilt, resumed,
re-signed, resubmitted, installed, promoted, relabelled, or reused as the
v0.4.0 GA application identity.

## Immutable consumed lineage

The candidate-freeze transaction completed before signing and permanently
bound build 40036 to these identities:

- repository commit:
  `57a589dd2edae28a9e8f5908ca5a0acd40ec8de2`;
- release-source SHA-256:
  `17e2593d884a449ddcab595e3bb4d7303de93428e57d0c38e72908f8669e8fb3`;
- `product-input.json` file SHA-256:
  `a384dcc00064cd8dc3c6f0cd11262eae475a8df76d5d7aa2eb9ab1afb1c4d956`;
- frozen product-input semantic SHA-256:
  `e563172fe920ada4df268bfcba473e8ed80de38913f2e9b042623b096569a3c0`;
- candidate-freeze intent SHA-256:
  `08f9cca9998cc58f94da4e43f8bea39b38af226311c30e8e2f94da7a7fa204a2`;
- updater-key possession-proof SHA-256:
  `97e48bd60ddcdffbf440ef73149474d881b7f6ebc2c1dd7f2a6be3586cf25567`;
- frozen Developer ID certificate SHA-256:
  `806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D`.

The frozen root
`target/release-worktrees/40036/target/candidates/0.4.0/ga/40036` and every
file below it are immutable historical evidence. They must not be deleted,
renamed, edited, resumed, or copied into a later candidate.

## Accepted signing and notarization evidence

Signing attempt `00000001` reached the terminal `published` state. In this
journal, `published` means that one canonical signed-output container was
durably published; it does not mean that an application release was published.
The attempt intent SHA-256 is
`4448831a59b0e9a282ca1ed6fe831f59eb0e7ccd194cb8cef4ee542a404dce46`.
The terminal event file SHA-256 is
`bf69112935b4427e45e2f5cef2fea2f98e0fe3a34df572ee6eb7ccb546ad8f48`;
its internal `event_sha256` is
`6d5a2091a8cf1f2aaaf2dce54b09ea1ce60af76479d6b57e27b0543b9e2339a8`.

The canonical signing and accepted Apple evidence are bound by:

- signing-transformation file SHA-256:
  `eb4c53a30144aa1ed98a65bd14d7e078e7ff620829612cd8b999897298b00a1a`;
- pre-staple signed-app tree SHA-256:
  `ed840f9b9af40205e3c24fe999777e7c0081066555384bc1bde6128b2c3d2fff`;
- notarization archive SHA-256:
  `052887a6137e3c04b049f05e741a08b70c86a760776284b5e592416ab6cc1c50`;
- notarization result file SHA-256:
  `2f3fca92a76fc952fbcbd1e93cb718f4259694faf82025437817545a46bafd62`;
- accepted notarization log file SHA-256:
  `1c200718e97004e4a9f2400ac97f668336cf954e2fafc281f832ff0de216a0e3`;
- post-staple signed-app tree SHA-256:
  `358b7f80f871ce92bef26706421eac75aa1b069034380aaadc4cfff0f32da41b`;
- signed-app manifest file SHA-256:
  `0c36aa454b61521691be7b0a0956d1def92ceb002f35cab8756a0c5373b9d1b3`;
- Gatekeeper evidence file SHA-256:
  `21e8b377f6f9beb5ac5ea40191cfe0cbc877ec30baab23c318b2bb65736874bd`.

Apple reported `Accepted`, status code zero, and no issues. Strict inside-out
code-signing verification, stapling validation, and Gatekeeper's enabled
Notarized Developer ID assessment passed. Hosted CI run `33233239639` passed
all three required jobs for the exact frozen repository commit. Its retained
receipt SHA-256 is
`65ca3f0c51cd5069d75f56b0141ce5cb46f051115dfbc875280c5523daa8d5dd`.
The separate deterministic local record passed all 27 lanes.

These results remain valid historical evidence for build 40036 only. They are
not source, signing, notarization, package, installation, runtime, or
publication evidence for build 40037.

## Prepackage boundary failure

Publication preparation exposed two fail-closed contract defects. The generic
command runner rejected a successful release-app verification because
`codesign` writes its structured success evidence to standard error. The
subsequent machine-closure allowlist also omitted the signed
`Contents/Library/HelperTools/CFWGlobalAuthority` code object.

Correcting these defects changes tracked files below `scripts/`. The current
release-source identity includes that complete directory, and the v1 product
input binds the release-source digest and repository commit into the semantic
`product_input_sha256`. There is no executable evidence-policy identity split
that can prove the corrected source has the same frozen product input.
Therefore build 40036 cannot be reopened for the corrected source and must be
retired in favor of a successor.

There is no build-40036 sealed prepackage stage, package set, DMG submission,
installation journal, GA runtime or physical acceptance, final publication
stage, distribution seal, tag, upload, or public release. The component review
and publication-blocker report are incomplete prepackage inputs only and must
not be copied forward as build-40037 approval.

## Successor generation

Build 40037 is the only active GA successor. It must start from one new clean
source identity and repeat the complete hosted-CI, build, freeze, signing,
notarization, publication-evidence, package, installation, runtime, physical,
and final publication sequence. No application tree, profile copy, possession
proof, signature, manifest, attempt file, receipt, review, or evidence tree
from build 40036 may be copied forward as successful evidence.
