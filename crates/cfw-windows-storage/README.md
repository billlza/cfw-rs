# Windows private application storage

This crate is the Windows filesystem boundary used by `cfw-core` for settings,
window state, diagnostics and migration, and by `cfw-profiles` for profile files,
selection journals and repository transactions. Profile schemas, credential
references and recovery policy stay in `cfw-profiles`. This crate does not
implement a credential vault, network service or Windows application shell.

Directories capture the effective Windows token identity when opened. A thread
token is used when present; only `ERROR_NO_TOKEN` permits using the process token.
New objects receive an explicit protected DACL granting the owner and LocalSystem
full access. Existing objects are inspected through their opened handles. The
directory owner must match the captured identity, and its protected DACL must
not grant other principals access. Files must be regular disk files with one
link, the same owner and a permitted DACL. Reparse points are rejected.

`LegacyReadOnly` accepts an existing owner's file with additional read/execute
grants, but refuses grants that permit another principal to change it. This is
an integrity policy for pre-existing migration sources, not a confidentiality
claim about those sources. Newly written application files always use the private
policy. Privileged administrators and other software running as the same user
are not isolated by this store; network-origin inputs must not select its root.

File operations use `NtCreateFile` relative to the opened directory. Rename and
delete target opened handles, so changing the original directory pathname cannot
redirect a transaction. `.cfw-storage-lock-v1` is a persistent, empty private lock
file. Every transaction opens its own handle without delete sharing and uses the
OS shared/exclusive lock. `LockFileEx` queues one overlapped request with a
three-second admission wait, avoiding repeated polling races against a writer
that releases and reacquires. On timeout, the exact request is cancelled and
its completion is drained before releasing its event and OVERLAPPED memory.
Driver cancellation acknowledgement can extend teardown beyond the admission
deadline; the code never releases a buffer still owned by the kernel. Other
errors remain errors. A transaction retains its lock until dropped.

Directory enumeration uses the existing directory handle with a bounded
`NtQueryDirectoryFile` buffer. A per-handle mutex serializes complete scans and
each scan restarts its cursor. Cursor contention is bounded to three seconds;
poisoning and timeout are explicit errors. It validates record lengths and offsets, rejects
incomplete results, enforces the caller's entry limit and excludes only the
already-validated storage lock. It never resolves a handle back into a pathname.
Missing stores are distinguished from invalid or inaccessible ancestors, which
must remain errors instead of appearing as an empty repository.

Application record names are single leaves of at most 250 UTF-16 code units.
The `.cfw-` prefix and dot-prefixed names ending in `.tmp` are reserved for
internal state and rejected by all public record operations, including case
variants. An application record cannot alias a temporary belonging to a different
record. Other hidden records, such as migration journals, remain supported,
as do Unicode directory and record names within these limits.

Replacement validates existing state, writes a private temporary, flushes its
contents, renames within the same opened directory and flushes directory
metadata. Creating a private directory also flushes its parent entry. Failure
after publication is `CommitUncertain`, not an assertion that
the old value remains. Pre-publication cleanup failures retain both errors.
The file snapshot identity covers the volume, the complete 128-bit file ID and
the bytes; equal bytes in a replacement file still invalidate a stale revision.

Repositories can publish with their canonical UUID temporary names, retaining
their existing crash-recovery rules. `Publication::CreateNew` refuses to replace
an existing destination in the native rename operation. Opened private files
remain read-only handles; the decoder owns its format and read-size bounds.
Explicit managed cleanup can unlink a file, hard link or reparse point without
reading its contents or following its target. It refuses real subdirectories
and the active lock. This batch operation requires the caller to track partial
removal and call `sync_directory`; ordinary record removal still flushes itself.

The Windows CI uses real temporary files and OS locks. Tests cover malformed
names, namespace redirection, symlinks, hard links, broadened ACLs, bounded reads,
atomic replacement, lost-update prevention and contention. `cfw-core` runs its
shared settings, migration and diagnostic tests on Windows as well as macOS.
These checks do not establish physical power-loss recovery, all filesystem and
network-share implementations, standard-user/enterprise deployment, or release
acceptance. Those remain runtime qualification work.

The direct dependency on `windows-sys` reuses version 0.61.2 already present in
the workspace lockfile. It provides Microsoft's typed native API bindings; no
new registry package version or checksum is introduced.

API references:

- [NtCreateFile and directory-relative names](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
- [Handle-relative rename](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
- [File and directory flush](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
- [Handle-relative directory enumeration](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerydirectoryfile)
- [Security information from an opened handle](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
