# GA build 51004 retirement

GA build 51004 is permanently classified as
`retired_product_change_after_ga_runtime_acceptance_before_publication`.
Its signed application, both package sets, approvals, installation journals and
successful local runtime collection remain valid historical evidence. Independent
manual-upgrade acceptance found a product defect, so this build is not publishable.

## Consumed identity and completed stages

The immutable candidate remains under
`/Users/bill/.cfm-release-tooling/releases/0.5.1/operator-51004/target/release-worktrees/51004/target/candidates/0.5.1/ga/51004`.
It binds source commit `f8bc16c3a99657858e5ba18f3348f70ee5f2cefe` and:

- release-source SHA-256
  `feb189ebb0d28713b11461437a4bf0d81c47c2972f684eaa975c6f03cea38a82`;
- product-input document SHA-256
  `249dc01902f57a1a48a08246a62474e4f8ac8799f6e0a8cff72f7b8dee4737d1`;
- product-input semantic SHA-256
  `7676713b5613a416304807aa7b15822df899458fe41c43f6bcbbe031abb92451`;
- candidate-freeze intent SHA-256
  `e27b12bd48e79d97a6b3c6b96782d3150b9d3fc8d740ce3eb04132cdf09caf43`;
- signed/stapled application tree-v2 SHA-256
  `5cb832cdc1fa8828c8e6f7b61023cd42d03ac22ad463aef0bce4cd1cd5b7fd1e`.

Exact-source CI run `42024085261`, attempt 2, passed all three required jobs.
Apple accepted app submission `6c0da3f8-0f9d-4f52-9201-37833a8def7d` and DMG
submission `5a125c99-c27e-4fa4-b645-467aa5c001fd`; both were stapled and passed
Gatekeeper assessment. The final DMG SHA-256 is
`f05b5a5519d163ab7027e2d15fe59e06b3a150a9909f27d37b709f79c4443127`.
The verified updater archive SHA-256 is
`72cccac27b4c5def0383a7bb64101cd4fb12287a8a5e6c521ba1cc8b9ecab50e`.

Ziang Li explicitly approved the license texts and corresponding-source scope
of closure `f41d06512acdc49826a1dac61482e6b34aa93f7a5eebc151cc59568a2e37fa01`
(418 distributed components and 11 external build tools). That exact approval
belongs to 51004. Prepared publication inputs were finalized and preserved;
the prepackage seal SHA-256 is
`71441b91e949bfc7e2171492a0d972f8cfebb65519a419d88f9a6e2c086b2baa`.

The release Mac completed and exported the four 51002 → 51004 installation
transactions. The ordinary GA collector exited zero and sealed all twelve
raw-derived checks with runtime seal
`86e0bbf1f8e59e53362ebb010ebabd0003bb48b99b64bda9e4b2d5345da6aa56`.
Both authorized cloud peers stopped after about 61 minutes each and their
original scheduling was restored; cleanup reported no failures. An additional
Off-only Host launch after the collector's shutdown proofs, followed by normal
Quit, is retained separately as an operator observation. Supplemental installed
diagnostics, cancellation, route-failure, selector persistence and MTU refusal
checks also ran. These checks do not supersede the independent upgrade failure.

The final candidate GA-acceptance seal and publication seal were not produced.
No public tag or release assets were uploaded for 51004.

## Independent upgrade failure

An M4 Max on macOS 26.7.2 normally quit published 50030, replaced the app using
the exact verified DMG, and launched 51004 from Applications. Two launches failed
`query_status` with `IdentityRejected`, after 687 ms and 859 ms respectively.
The raw logs bind both launches to build 51004 and source `f8bc16c3`.

Read-only collection at `2026-11-06T03:26:38Z` found valid strict signatures on
the installed Host, ProxyAgent and GlobalAuthority, all matching 51004. However,
the still-running ProxyAgent and Authority had started before replacement.
Both PID-based strict checks reported that disk code did not match running code;
both registered jobs had run once and never exited. The raw report SHA-256 is
`f7f4140583dd7d9b27b27a10d72b7698b6249c07b0f76c1b5779b2c79693b3b4`.

A second read-only collection at `2026-11-06T03:52:38Z` authenticated both
surviving processes through Security's kernel-backed view using the exact
original 50030 metadata. Both strict checks passed, returned build 50030 and
matched the published predecessor's CDHashes. Supplying 51004 metadata instead
was rejected with `errSecCSInfoPlistFailed`. This report has SHA-256
`29d60a3b32301cbfd86701d1c5888aa4ce92e3940bd947b728fa1e34bf738715`.
Neither collection restarted or unregistered a service.

The service-build observer uses the default Security process view, which resolves
signing metadata through the executable's current disk path. Replacing that path
while the old service survives makes the strict check fail before ordered service
handoff. A separate unprivileged, ad-hoc-signed fixture reproduced the same
`errSecCSStaticCodeChanged` boundary. Retaining the original executable preserves
its identity; simply using dynamic signing information without the original
authenticated metadata does not repair the replacement case.

The correction is tracked in [service build metadata](service-build-metadata.md).
It must preserve strict signer/identifier checks, exact code identities, the
strictly older-version rule, authenticated XPC observations, stable Off proofs
and the existing Proxy → Authority unregister / Authority → Proxy register order.
A machine restart or forced service termination is not product remediation.

## Successor

Build 51005 is the new active allocation. It must repeat exact-source CI, freeze,
signing, notarization, final source/license review, packaging, installation from
51004 and current-build physical acceptance. The independent manual-upgrade case
must also pass on the corrected build. Until those steps complete, 51005 is not
release-ready. Do not rebuild, re-sign, relabel, promote or publish 51004, and do
not copy its successful receipts forward as evidence for the new source.
