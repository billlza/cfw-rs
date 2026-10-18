# Build 40057 Provider audit-session correction

40057 was frozen at `3d789633d8e0d060087fba4cf74baad15f3c5be9`, signed,
notarized (`fb563d85-ab29-43e9-83e2-a2e86e840235`) and installed. Its signed
application tree digest is
`991cb5b16d41ab6764f15596f18c25ce113d9a4d33e9a376178c0869166f0e7f`.
It was not accepted as a working TUN build.

The real Provider reached the start callback with four platform fields and a
32-byte ticket, confirming the platform-options correction. Authority
preparation also succeeded with the corrected issuance/expiry pair. The next
failure was an explicit `global_authority_identity_rejected` decision for the
Provider: PID 72990, effective UID 0, audit session 100018. Exact Developer ID,
Team ID, bundle identifier and Packet Tunnel entitlements were independently
verified on that running system-extension executable.

The role policy incorrectly required the Provider audit session to equal zero.
macOS assigned a nonzero session to the root system extension. 40058 accepts
assigned sessions as connection context, still rejects the allocation sentinel,
and preserves the exact signing/capability requirements, root effective UID,
one-time ticket redemption, per-request authorization and bound owner identity.
Host/Proxy Agent login-session and lease-owner checks are unchanged.

A regression reproduces the old rejection with the observed session 100018;
the corrected policy and full service redemption/replay path are covered.
All 633 native tests passed with warnings treated as errors. Installed 40058
startup, independent forwarding and cleanup remain required.

The retained notarization archive's first upload had an unknown outcome. A
recorded same-archive retry was accepted and adopted through the existing
recovery transaction; no source was changed for that upload recovery. The new
allocation is solely for the subsequent product identity-policy correction.
All 40057 bytes, manifests, upload records and failed runtime evidence remain
unchanged under the frozen checkout and external evidence directory. CFW stayed
running; cancelling the failed request returned CFM's switches and engine to Off.
