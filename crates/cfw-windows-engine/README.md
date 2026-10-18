# Windows engine child ownership

This crate owns one `cfw-engine-host.exe` and its private control pipes. The
worker uses the same pinned sing-box source and six patches as CFM 0.5.0.
`scripts/windows_engine.py` creates a separate build tree containing those
unchanged source bytes plus `native/windows/engine-host`; it preserves and
verifies the original GA tree independently.

The Windows build tree also applies one narrowly checked test-only overlay.
The DNS rcode fixture waits for its TXT reply and A/AAAA reuse-probe response
writes before test teardown can close the transport. All write failures and
rcode/fallback assertions remain failures, with the original deadline. The
overlay cannot change production files; its before/after hashes are recorded
separately. The original GA tree and six patch pins remain unchanged. Native CI
also repeats the corrected fixture 200 times and retains the full event log.

The component starts local and SystemProxy data planes; SystemProxy settings
require the separate durable owner described below. Tunnel modes still require
Windows platform authority and restoration contracts. This is not an
`EngineBackend`, a Windows service, or
proof of `NativeEngineStatus::Off`. The full Windows feature/UI target remains
in `docs/planning/cfw-0.5.0.md`.

## Configuration and identity

- `ResolvedProjection` accepts the opaque shared `ProjectedConfig`, validates exact
  typed credential coverage and empty injection slots, and keeps the original
  projection digest. Resolved secret bytes are never hashed into public identity.
  The caller must first resolve material for the projection's exact audience
  under its lifecycle guard. This component does not grant vault authorization.
  All four modes can be checked. `PreparedConfig` separately admits local and
  SystemProxy data planes, so a checked tunnel projection is not a start
  capability. A local projection cannot become SystemProxy ownership.
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

`SystemProxyAuthorization` is a shared application contract. The Apple adapter
delegates to its existing native rights request without changing restoration
intent or error classifications. The Windows implementation runs current-user identity,
policy and ownership checks on a blocking worker. Authorization never changes
settings, starts/stops an engine or substitutes for a native ownership lease.

`WindowsSystemProxy` owns the current user's WinINet default/LAN HTTP and HTTPS
settings. It refuses service/session-zero, restricted, AppContainer and low-
integrity users, machine-wide proxy policy, prohibited proxy changes and an
existing explicit proxy/PAC. It does not change WinHTTP, RAS/VPN connection
settings or policy. Active autodetection is saved and restored with all original
option values; native UTF-16 is preserved without lossy conversion.

A SID-scoped global mutex serializes cooperating owners. A bounded private
journal binds the full engine context, projection digest, process ID/creation
time, endpoint and exact before/applied settings. Durable publication precedes
the first WinINet mutation. Activation reobserves the actual owned engine and
listeners before and after applying settings. Repeated activation must match
that complete binding. Recovery can reopen a crashed predecessor's record, but
only restores settings matching the original or application-owned values.
Other values are a conflict, and the journal remains. Native write/notification
failure does not promise rollback. Successful restoration requires OS readback
and journal removal before the authority stops the engine.

WinINet has no atomic compare-and-write operation against non-cooperating apps.
The adapter rechecks values and reports observed conflicts; it does not claim
elimination of that OS race. Synchronous native calls have no hard deadline.
The process owner installs a restoration obligation before the first possible
settings effect. Explicit stop and error cleanup restore settings before closing
the engine/control pipes; a restoration failure retains the process owner for
retry. Expired request waiters cannot independently close those pipes. Drop is
abnormal ownership loss and only attempts restoration; kernel job closure still
terminates the child. A durable record alone does not restore settings after a
process crash: user-agent/service supervision and desktop lifecycle
integration remain required. A settings restoration receipt is not global Off.

Native mutation tests require `CFW_NATIVE_PROXY_MUTATION_TESTS=1`, an absolute
`CFW_NATIVE_PROXY_RECEIPTS` output directory and `CFW_NATIVE_PROXY_SOURCE`. They are invoked
only in the disposable Windows engine CI job. They exercise an actual WinINet
HTTP request through the engine, restoration while the engine is still alive,
owner-process exit, stale-context rejection and an independent settings change.
Fixtures attempt exact cleanup even when assertions fail. Read-only package
tests do not opt into proxy mutation. Physical sleep/wake and multi-session
authority acceptance remain separate.

Microsoft documents [connection option allocation and restoration](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_optionw),
[LAN versus RAS scope](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_option_listw)
and [the proxy-change policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-internetexplorer#disableproxychange).

## Service peer admission

`LocalServicePipe` opens a fixed local named-pipe path from a validated service
name with identification-only SQOS. It exposes stream I/O without raw-handle
import or mutable access to the inner client. `WindowsServicePeer` binds that
exact connection to a retained SCM service object, live PID/creation time and
the file identity of an already hash-verified installation executable. A new
pipe cannot reuse the old admission. The expected name, path and hash must come
from the trusted installation; neither IPC nor an adjacent untrusted receipt is
a trust root.

The adapter requests query/read-control SCM rights and limited process-query
plus synchronization rights. It does not request SYSTEM-token access, start or
reconfigure services, or elevate the UI. The service must be a running dedicated
process in session zero, configured as LocalSystem with the exact quoted image
and no arguments. The owner must be SYSTEM or Administrators; other principals
may query, but may not change configuration, start/stop/control the service, or
rewrite its security. All observations are rechecked before admitting a result.

Microsoft specifies that [service configuration may describe the next launch](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw),
so the live image is verified independently. This does not inspect the running
service token: the trusted service must check its own SYSTEM identity before
opening its endpoint. Missing, stopped, inaccessible and conflicting services
are errors, never global Off or a readiness proof. The full privileged backend,
runtime authorization, service installation/signing and lifecycle supervision
remain separate work.

The `native-service-fixture` example installs two uniquely named disposable
SYSTEM services only with `CFW_NATIVE_SERVICE_MUTATION_TESTS=1`. It checks actual
SCM/pipe/image identity, another SYSTEM peer, ACL/configuration changes, a
byte-identical replacement file, missing/stopped services and a medium-integrity
client with Administrators disabled and privileges removed. It stops and removes
the services, waits for their processes and verifies deletion before emitting a
source-bound receipt. The fixture is not shipped as a product service. Package
tests never install services. Native execution must pass before this boundary is
reported as verified.

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

`NativePeerProcess` observes the actual named-pipe peer PID, retains the process
handle and creation time, and records its full SID, logon authentication ID,
session, integrity level, AppContainer and restricted-token state. These types
cannot be constructed from deserialized caller claims. Server-side verification
must follow a request read: the pipe's last-message token must also match the
observed process identity. The synchronous token capture immediately restores
the observer before inspecting data or returning; restoration failure terminates
the process instead of continuing under an unknown security context.

This is peer observation, not publisher or SCM service authentication, and not
permission to change network state. The caller must serialize reads/admission
on a fixed pipe instance. An unprivileged UI may be unable to query a SYSTEM
process token; permission failures stay errors, and this helper must not be used
to require UI elevation or assume that any SYSTEM peer is the product service.
The service connector still needs SCM identity and trusted installation binding.

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
