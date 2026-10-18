# Windows engine child ownership

This crate owns one `cfw-engine-host.exe` and its private control pipes. The
worker uses the same pinned sing-box source and six patches as CFM 0.5.0.
`scripts/windows_engine.py` creates a separate build tree containing those
unchanged source bytes plus `native/windows/engine-host`; it preserves and
verifies the original GA tree independently.

The component currently starts only `ProjectionMode::LocalProxy`. The other modes
require Windows platform authority and restoration contracts which are not yet
implemented. This is not a replacement `EngineBackend`, a Windows service, or
proof of `NativeEngineStatus::Off`. The full Windows feature/UI target remains
in `docs/planning/cfw-0.5.0.md`.

## Configuration and identity

- `ResolvedProjection` accepts the opaque shared `ProjectedConfig`, validates exact
  typed credential coverage and empty injection slots, and keeps the original
  projection digest. Resolved secret bytes are never hashed into public identity.
  The caller must first resolve material for the projection's exact audience
  under its lifecycle guard. This component does not grant vault authorization.
  All four modes can be checked. `PreparedConfig` separately admits only local
  proxy starts, so a checked tunnel projection is not a start capability.
- Credential strings in the Rust document and serialized buffers are zeroized
  when dropped. Serialization reserves its bounded buffer once. Go runtime
  copies remain in the child until it exits; this is not a promise that all Go
  allocator copies are explicitly erased.
- `VerifiedExecutable` needs a digest from a trusted installation descriptor,
  never an untrusted adjacent receipt. It verifies the x64 PE and content hash
  and retains non-replaceable file/ancestor handles. Publisher signing and
  installation policy remain outside this component.
- The runtime directory must have an existing parent. Its path is retained and
  its leaf uses the shared current-user/SYSTEM private storage ACL. Config and
  credentials are not written to that directory; projected routing caches may
  be written there by the engine.

## Lifecycle

`WindowsEngineGenerationStore` implements the shared generation-store contract
using a canonical generic Credential Manager record for the current process
user. `CRED_PERSIST_LOCAL_MACHINE` persists across that user's logon sessions;
it does not grant other users access. A private Global-namespace mutex uses the
current SID and authority target to serialize cooperating processes across
sessions, independently of the application's selected home directory.

The store rejects impersonation, malformed/noncanonical documents, stale CAS
expectations and counter exhaustion. An instance binds its first confirmed
installation identity; disappearance or replacement cannot silently reset that
coordinator's lineage. A fresh instance after deliberate credential removal
uses a fresh installation UUID. Writes require exact readback; a failed readback
reports an uncertain outcome without promising rollback. This is user lineage,
not privileged-service authentication, rollback resistance against another
process with the same user's full authority, or proof of global Off.

The shared coordinator pins a backend's declared runtime platform when its actor
starts. Windows user-agent/tunnel-service owners have distinct wire names from
Apple owners. Start, restart and status paths retain exact owner/context/digest
checks. These contracts prepare the application seam; they do not instantiate a
Windows service or remove the desktop application's existing build restriction.

The child has no console window. It is assigned to an unnamed, non-inheritable
Windows Job Object before the first request is sent. The job has
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and no breakaway flags. See Microsoft's
[Job Objects contract](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

One sequential pipe worker exchanges bounded length-prefixed JSON. Protocol,
session, request sequence, PID, engine version, state and configuration digest
must all match. Engine failures return closed error codes without configuration
or raw diagnostic text. Unstructured stderr is not persisted or forwarded;
observable runtime logs remain available through the authenticated Clash API.

`start` and `observe` require a live retained process handle and Windows TCP
listener-table evidence for every projected TCP endpoint. `stop` requires the
actual `Box.Close` success reply, exit status 0, completed pipe thread, empty job
and no listeners owned by the retained process. It returns only `StoppedChild`,
which says nothing about global system proxy/TUN restoration or other owners.

`check` uses a disposable worker to parse the exact resolved configuration,
construct the real engine and close it without calling `Start`. Success also
requires exit 0, completed pipe I/O, an empty job and no owned listeners. Its
`CheckedConfiguration` receipt is distinct from running and stopped receipts.

Each operation accepts a nonzero timeout up to 120 seconds. A failed operation
terminates the owned job and allows a separate five-second cleanup interval;
cleanup failure is reported together with the original error. Drop is emergency
cleanup and never produces a successful stop receipt. A background thread whose
OS I/O cannot be retired within cleanup is not reported as successfully joined.

## Validation

The native CI job builds both the stock CLI and worker twice using independent
Go caches. The existing HTTP/SOCKS TCP/UDP smoke test still covers the CLI. A
mandatory Rust integration target uses the real worker and shared projection:

```powershell
cargo test --locked -p cfw-windows-engine --features native-engine-validation --test native_engine -- --test-threads=1
```

The job supplies `CFW_ENGINE_HOST_PATH`, `CFW_ENGINE_HOST_SHA256` and
`CFW_ENGINE_HOST_VERSION` from that exact build. Missing inputs fail. Tests cover
all four projected modes with both listener ports deliberately occupied, real
HTTP traffic, controller authorization, normal stop and listener release,
startup conflicts, process crash, deadline cleanup, owner drop and wrong binary
or version rejection. The credential test uses the real DPAPI store and engine
to authenticate a SOCKS outbound and return HTTP data. Its peer binds the
runner's own private IPv4 interface because validated remote proxy endpoints
reject loopback IPs. It sends no traffic to an external proxy and does not relax
endpoint validation. These checks do not establish TUN, system proxy recovery,
interactive UI, sleep/wake, installation/update, signing or release acceptance.
