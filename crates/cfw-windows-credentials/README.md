# Windows credential persistence

`WindowsCredentialStore` implements the synchronous Windows persistence part of
the CFM 0.5.0 credential contract: atomic immutable provisioning, exact
profile/digest binding, presence, retained-credential rebind, engine resolution,
and versioned garbage collection. It uses the existing private Windows storage
crate for owner/DACL validation, handle-relative access, bounded cross-process
locking and atomic publication. Only DPAPI ciphertext reaches disk, including
temporary files. Publication without a confirmed directory flush returns
`OutcomeUnknown`, never a confirmed rollback or success.

Encryption uses current-user `CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN`.
It never uses `CRYPTPROTECT_LOCAL_MACHINE`. The public optional entropy string
separates this document format; it is not a key or an application identity.
The store rejects impersonating threads. DPAPI protects the user's data at rest;
it does not authenticate other processes running as that user. A privileged
Windows broker and its authenticated IPC are separate, unfinished boundaries.
See Microsoft's [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
and [CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata)
contracts.

Every operation opens and checks the private directory afresh. Mutations hold
one OS lock through decrypt, complete validation, encryption, rename and flush.
No plaintext cache, generated encryption key file, or plaintext fallback exists.
The plaintext format is closed and canonical, with an explicit schema version,
random revision, at most 8,192 bindings, 448 KiB aggregate secret bytes and an
8 MiB encoded ceiling, matching the GA resource limits. Its schema is Windows
specific; it is not a reader for the Mac Keychain format. Secret buffers and the
native DPAPI output allocation are erased when dropped. Debug output is
redacted. This does not claim erasure of OS/internal serializer buffers or
protection against process compromise.

The storage API does **not** implement `CredentialVaultProvisioner` itself.
`cfw-windows-engine::credential_lifecycle::WindowsCredentialLifecycle` now wraps
it with a cross-process lifecycle guard and persisted LocalProxy/SystemProxy
bindings correlated with the authenticated Authority, for both GC phases. It
also implements the shared async vault trait with bounded blocking workers and
explicit cancellation/admission. Full application wiring and Tunnel/persisted
candidate integration are still required. Failure to observe runtime state must fail maintenance; an empty
list cannot substitute for a failed observation. Call these synchronous methods
on a blocking worker, and authenticate the exact engine request before calling
`resolve_for_engine`. No credential-resolution UI command is provided.

`OwnedCredentialProvision` copies only a checked borrowed provisioning request
for transfer to a blocking worker. Its aggregate secret limit reuses the vault
budget, and its secret buffers use Zeroizing. It has no serialization, Clone or
Debug representation. This erases only the transfer's owned copies; callers
remain responsible for their original buffers. Owned and borrowed provisioning
share the same immutable transaction and failure semantics.

Native Windows tests exercise real DPAPI, private files, cross-process reopen,
concurrent writers, lock contention, exact audience separation, immutable
conflicts, rebind, corrupt/oversized/hardlinked input, process-identity checks,
capacity rejection, and vault/runtime changes between GC preview and commit.
These tests do not establish cross-user service IPC, desktop integration,
power-loss durability or release acceptance.
