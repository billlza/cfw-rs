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

The API deliberately does **not** implement `CredentialVaultProvisioner` yet.
The Windows engine owner must first serialize lifecycle mutations, obtain the
repository and active/pending/persisted runtime bindings, and supply those
bindings to both maintenance calls. Failure to observe runtime state must fail
maintenance. Replacing that observation with an empty list would risk deleting
credentials used by an older running generation. The owner must also execute
these synchronous calls on a blocking worker, and authenticate engine requests
before calling `resolve_for_engine`. No credential-resolution UI command is
provided.

Native Windows tests exercise real DPAPI, private files, cross-process reopen,
concurrent writers, lock contention, exact audience separation, immutable
conflicts, rebind, corrupt/oversized/hardlinked input, process-identity checks,
capacity rejection, and vault/runtime changes between GC preview and commit.
These tests do not establish cross-user service IPC, desktop integration,
power-loss durability or release acceptance.
