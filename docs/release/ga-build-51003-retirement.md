# GA build 51003 retirement

GA build 51003 is permanently classified as
`retired_product_change_notarization_outcome_unknown`.
The application was accepted by Apple, but its separate DMG submission has
no terminal result in the retained transaction. Retirement does not turn that
unknown package outcome into a success, rejection or cancellation.

## Consumed identity and completed work

The immutable candidate is under
`/Users/bill/.cfm-release-tooling/releases/0.5.1/operator-51003/target/release-worktrees/51003/target/candidates/0.5.1/ga/51003`.
It binds:

- source commit `93e38c0560fefd3248914c22e306f967029e4fa8`;
- release-source SHA-256
  `e862ea71648267bddd66212c2ebbfe3eb8746a7fa95b82d1ec1f7b7b0f636ac6`;
- product-input document SHA-256
  `2c30f94ad3a43ba43df3f93c4f8b4c0e570f2b4a79545c04c380694df8d66af9`;
- product-input semantic SHA-256
  `268566df480e748b359685af99324d13769f737a3004abc7cbbb0145af69d6ec`;
- candidate-freeze intent SHA-256
  `1abce8b4564f35ea21465d4374a7b9d5efa189d58ce214191e60685933c94409`.

The exact-source CI run `41947527897`, attempt 2, passed all three required
jobs. Signing attempt `00000001` published its private signed output; its
transformation receipt SHA-256 is
`2b45deb77110e2fc0cbb06f4c2471da47e662d74a16f13203506e579246975ef`.
App submission `bff61b54-765d-42e3-8e83-cf4360b73084` was Accepted, stapled
and assessed as Notarized Developer ID. Its final application tree is
`063c9c6a083d2a5ac9aef625026f21db39ac343c8e837d1a5031952ab27da2bf`.

The release owner explicitly approved the exact source/license closure
`84c324a67b6daf467f0077d6eb4c205ed19c0b5b1f446e462333ec48adb0a7ce`
(418 distributed components and 11 external build tools) and authorized the
reviewer name Ziang Li. That approval remains bound to 51003. Publication
inputs were finalized, preserved under
`history/publication-prepared-51003/publication-prepared` in the release home,
and the prepackage seal completed with SHA-256
`f59956bf822a2ef09620e84e3b8199f4d5a076c79c7655127e0348bfa748bc1e`.
The prepared-input preservation tree is
`487bb63bb12b0f0eb92f1f9dc296222963036e63c74d000e89a747431503c847`.

## Retained package failure

Driver log `logs/51003/067-dmg.log` ended with `invalid_command_output`.
The durable DMG journal progressed through `prepared`, `submitting`, then
`outcome_unknown`, without persisting a submission identity. The last event
`transactions/dmg-notary/v0.5.1/events/00000003.json` has SHA-256
`e5b7abc243a2e28b0c5813c8d85c2eb4f5e75bc1b5b0b3810bb8118a3ecbcfcd`.
The retained pre-staple DMG is 47,175,024 bytes, SHA-256
`234f80ce0f7123a77527d1037cdfdf5168540bfad4d1a38e7ae9c21e48806873`.

A subsequent read-only Apple history query returned DMG submission
`b2e83362-dc21-48ca-b033-ce7d89ea05ab`, created at
`2026-11-05T11:25:55.982Z`, inside the journal's submit window. The explicit
info query also reported In Progress. This observation is not a recovered
package seal or proof of complete upload. The raw history/info and the failure
reproduction are retained in the source worktree's
`target/mtu-boundary-51003`; the original journal is unchanged. Do not rebuild
or resubmit this DMG. Only read-only reconciliation of its outcome is allowed.

No updater, candidate installation, GA runtime collection, final acceptance
seal, publication seal, public tag or upload was produced for this build.
The installed predecessor remains 51002. Neither of the two authorized cloud
test instances was started for 51003.

## Product correction and successor

Release acceptance preparation found that the settings UI and generic stored
preferences accept TUN MTU up to 9000, while the Apple descriptor and packet
pump accept only 1280–1500. A value saved while Off could therefore fail at
the native boundary after a later mode switch had stopped the previous owner.
The actual UI helper accepted 1501 and 9000, and the coordinator regression
failed against the old source before the correction. No user settings or
live network were changed to reproduce this defect.

The correction exposes backend MTU limits to both settings forms, rejects
unsupported writes before acquiring mutation admission, and validates TUN
transitions, active changes and cutover preparation before native operations.
Existing stored values remain readable for correction. Generic projection,
Windows fixture ranges and the native wire protocol are not widened.

Build 51004 is the new active successor and must repeat exact-source CI,
freeze, signing, notarization, source/license review, packaging, installation
from 51002 and ordinary-GA physical acceptance. Nothing from 51003 may be
copied forward as successful evidence for 51004. The 51003 source, artifacts,
approvals, journals and logs remain intact; it must not be rebuilt, re-signed,
installed, promoted, relabelled, published or reused.
