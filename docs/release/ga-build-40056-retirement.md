# Build 40056 ticket lifetime and platform option correction

40056 was frozen at `9b7ca5722598ffd2b09efdea6211d734220a986b`, signed,
notarized (`c9187333-3096-483c-8a0c-9dbf072e3c86`) and installed. Its first-time
VPN consent succeeded after an intentional eight-second delay. It was not
accepted as a working TUN build.

The first start failed with Authority `invalid_message` before preparation was
committed. The service sampled the clock before decoding and enrollment, while
the ticket lifecycle separately sampled it to set its ten-second expiry. The
reducer therefore rejected any preparation crossing a millisecond boundary as
exceeding the ten-second lifetime. An advancing-clock regression reproduces the
error with both one- and twenty-millisecond steps. 40057 binds the reducer to the
ticket's actual issuance and expiry pair; expiry rejection and replay controls
remain unchanged.

A retry reached the real Provider, which still rejected its start options.
The documented provider-session API introduced in 40056 alone did not solve
that rejection. On this macOS build it delegates to the same connection start
implementation. Static inspection of Apple's session manager shows it builds
connection parameters including `ServerAddress` and `VendorData`, then merges
the application's options for a modern provider. The Provider incorrectly
required the entire platform dictionary to have exactly one entry.

40057 extracts only the exact-sized opaque ticket. Supplementary platform
fields never supply configuration, credentials or alternate authorization;
those still require authenticated, single-use Authority redemption. Regressions
cover supplemented options, missing/malformed tickets and rejected redemption
with no engine or packet pump start. A bounded structural log records only field
count, ticket byte count and the presence of two known metadata fields, without
any option values or secret bytes.

40056's files, signed manifest, freeze, notarization and failed runtime evidence
remain unchanged. CFW stayed running and the original system proxy was retained.
Installed 40057 startup, independent forwarding and cleanup remain required.
