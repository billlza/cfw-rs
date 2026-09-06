# GA build 40038 retirement

GA build 40038 is permanently classified as
`retired_after_candidate_freeze_before_canonical_signing_output`. It must not
be rebuilt, resumed, re-signed, notarized, installed, promoted, relabelled, or
reused as the v0.4.0 GA application identity.

## Immutable consumed lineage

The candidate-freeze transaction permanently bound build 40038 to these
identities:

- repository commit:
  `70b45a5d2988829c39f16644d07d6f7fd70d6673`;
- release-source SHA-256:
  `a26e5b55260bc7b63650f9da3a2809fa171e4f3a6e72d782e7b6f407bafc8883`;
- `product-input.json` file SHA-256:
  `4129b6fe1346b3a88cafad92cae02851465140db34493c83f9f8dcdb43f4d2cc`;
- frozen product-input semantic SHA-256:
  `638e360d174e59564161012d0549d590e3dee0de6a8d6a3440c3ccdf5fd96c1a`;
- candidate-freeze intent SHA-256:
  `00d5e142b607b893bdd318e5e360288b1349bbd914ceb5fd4027b839127af4b3`;
- updater-key possession-proof SHA-256:
  `5423f6efdd9875623e71331c27d7470262fb59b8d5612de4263571ff4ad06abc`;
- frozen Developer ID certificate SHA-256:
  `806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D`.

The frozen root
`target/release-worktrees/40038/target/candidates/0.4.0/ga/40038` and every
file below it are immutable historical evidence. They must not be deleted,
renamed, edited, resumed, or copied into a later candidate.

An owner-only evidence copy is retained at
`/Users/bill/cfw-release-history/ga-build-40038-evidence/candidate`. Its
`sha256-tree-v2` root is
`57ec633cdcb125e9e6b12a4699c437d8917ad0b826219cf2960f8db51684c818`
over 239 entries. The source and snapshot manifests are retained separately as
`ga-build-40038-evidence.source-tree-v2.json` and
`ga-build-40038-evidence.snapshot-tree-v2.json`; both manifests have the same
root and entry count. The evidence directory and manifests are owner-only.

## Private signing-attempt evidence

Signing attempt `00000001` invoked the signing helper once. The helper returned
success and wrote a private Developer ID-signed application plus signed native
products below the attempt's `work` directory. The attempt intent SHA-256 is
`1a13b09b0c69da867293293127062b34a54d75fd6e62843ab935de8f18cbd8d8`.
The private signed application has `sha256-tree-v2` root
`0ad2defb61526b28db6e965cf1d0cdd225ec3800fc6b9c9eaf9dcbfcb02e5b2d`
over 61 entries, and the signed-native-products root is
`c284892af598b0c051d8f4c33627fe56cf48eca5a5043ebe8aafc099b45487b2`
over 48 entries. The Host and its five nested code objects passed read-only
`codesign` and designated-requirement checks.

This is private attempt evidence only. No
`work/signing-transformation.json` receipt was durably created. There is no
`publish-ready` directory, canonical `signing-output`, canonical `signed`
application, notarization transaction, Apple submission, package,
installation, runtime acceptance, physical acceptance, tag, upload, or public
release for build 40038.

## Terminal pre-receipt verification failure

After signing completed, the transformation receipt was not written. The outer
diagnostic reported that a mandatory dynamic replay of the source-pinned public
updater verifier was unavailable. The attempt journal reached terminal
`failed` with failure code `signing_transformation_failed`. The terminal event
file SHA-256 is
`9a7dbf16ed8b1300f41c77cc928ccbdf1b174e42651da6f3df940545dabdb34a`;
its internal `event_sha256` is
`57d0e529d1d24aa7b9141be3ba8776aa7379dc599e4db20c9e96ecf4ddd0a7b5`.

The outer diagnostic reported an unavailable operation-scoped verifier, but
the frozen implementation could also map semantic or cleanup failures to that
same message. The retained evidence therefore does not prove one narrower
operational reason. The durable journal and missing receipt are authoritative:
the attempt has no transition into `verification_blocked`, and a later source
change cannot reinterpret or recover this consumed identity.

## Successor generation

Build 40039 is the only active GA successor. Its source permits at most one
fresh verifier session after the signing helper returns exact success and only
for a typed, allowlisted operational replay failure. The old session must close
first; the complete public proof is replayed against the same frozen root; the
signing helper and receipt creator are never rerun. Semantic failure, cleanup
failure, fresh-session startup failure, a second operational failure, or a
binding mismatch remains terminal. This forward-only rule is unavailable to
build 40038.

Build 40039 must start from one new clean source identity and repeat the
complete hosted-CI, build, freeze, signing, notarization,
publication-evidence, package, installation, runtime, physical, and final
publication sequence. No application tree, profile copy, possession proof,
signature, manifest, attempt file, receipt, review, or evidence tree from build
40038 may be copied forward as successful evidence.
