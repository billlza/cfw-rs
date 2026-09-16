# Validation build 40022 retirement record

Build 40022 is permanently classified as
`retired_after_notarization_before_install_preflight_protocol_incompatible`.
Its reserved but unbuilt final companion, build 40023, is permanently
classified as `retired_unbuilt_reserved_final_companion` and must not be
reassigned to another source closure or lane.

Build 40022 completed the Apple and local artifact gates:

- repository commit: `8de7baa6757136510c7f749e15b3869c792fb722`;
- release-source SHA-256:
  `08c86803849c867118b2369045901da41861bb9220b7f9eaa807e56030573ff8`;
- notarization archive SHA-256:
  `6f1706d40fc25f3481e4a3de3c48b32216f5623e934eab46b7a117781c2198c7`;
- stapled signed app tree SHA-256:
  `59487a75d7a0197046281800b488ae8d767c2fd27bd8e4266eb13e7323beb5bb`;
- Apple submission: `498a2113-725d-42c6-8738-0715ef156a26`, Accepted with
  zero notarization issues;
- inside-out signature verification, stapling, live Gatekeeper assessment,
  release-app verification, manifest verification, and the notarization
  transaction receipt all passed.

The signed candidate was never installed and is not eligible for validation
approval. Its read-only service-maintenance preflight failed before any durable
service or installation journal was created and before any SMAppService or app
mutation. The installed build 40019 ProxyAgent speaks EngineProtocol schema 5
and its GlobalAuthority speaks v1.0, while build 40022 attempted only the
current schema 6 / Authority v1.1 Off proof. The Host therefore failed closed
instead of unregistering an owner whose Off state had not been proven.

The following evidence roots are immutable and must remain in place:

- `target/release-worktrees/40022`;
- `target/release-worktrees/40022/target/candidates/0.4.0/notary-build-claims/40022`;
- `target/release-worktrees/40022/target/candidates/0.4.0/notary-attempts/validation/40022`;
- `target/release-worktrees/40022/target/candidates/0.4.0/validation/40022`.

The operator repository has a one-time, non-candidate lifecycle receipt under
the main Git administrative entry for this already verified worktree. It binds
the existing admin, detached HEAD, worktree, reciprocal marker, and target
identities solely so the workspace secret gate can distinguish this live
historical tree from the stale 40007 Git record. The receipt must not be copied,
regenerated after an identity change, or treated as candidate evidence.

Do not delete, rename, copy to another build number, resubmit, install, or use
these bytes as input to `validated-candidate.json`. Do not allocate build 40023.
Build 40024 and its unbuilt reserved final companion 40025 were later retired
under their own immutable record. Build 40026 was then notarized and retired
before installation when its read-only admission preflight exposed a
toolchain-binding mismatch; build 40027 remained unbuilt. The active successor
pair is 40028/40029 from one new clean source identity.
