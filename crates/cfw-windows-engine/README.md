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
  Optional LAN sharing remains a separate observed listener. Only the
  `cfw-system-proxy` inbound supplies the current-user OS proxy endpoint;
  `cfw-lan-proxy` cannot replace it or cause an otherwise valid shared
  projection to be rejected. Shared LAN validation and its source allowlist
  remain unchanged.
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

`CheckedStartConfiguration` accepts the existing shared `EngineStartRequest`
instead of creating a second configuration schema. It verifies canonical bytes,
content and schema-7 identity digests, request context, mode/options and exact
credential-slot placeholders. The digest calculation is shared with the Rust
projection producer; existing identity fields and Mac wire schemas are unchanged.
Proxy preparation additionally checks the app-owned loopback controller, distinct
mixed/LAN roles and the shared LAN source policy. A checked tunnel candidate
cannot become UserAgent proxy ownership.

The template contains the original process's controller key, so a receiver keeps
those bytes rather than reprojecting with a different key. Owned template and
resolved buffers are erased on drop. `UserAgentPlan::from_start_request` binds
the request to the exact lease root and both digests before any vault access;
`UserAgentSession` resolves its exact audience/references only after native
binding succeeds. Failure stays an error, and the original pre-resolved API
remains a lower-level component entry point. The native fixture exercises this
shared request path and rejects a deliberately wrong ticket before a configured
invalid vault path or runtime directory is used.

`user_agent::handoff::UserAgentLaunch` carries that exact request and its binding
in a versioned, length-prefixed frame. The two-MiB payload limit is separate from
the small Authority command limit. Decoding rejects incomplete/trailing bytes,
unknown/duplicate fields and noncanonical encodings, then rechecks the existing
request and exact binding. Frame/template owners erase their buffers on drop;
callers still own input-buffer erasure, I/O deadlines and cancellation. The frame
cannot select service, executable or vault paths, and never grants a start lease.

`LaunchSender` creates a private, already connected message pipe for an explicit
inherited-handle list. `LaunchReceiver` checks the inherited endpoint type and
read mode, the live server's full user/logon/session identity and its installed
Desktop file identity. The shared overlapped I/O implementation now supports a
cancellation signal without changing service RPC limits. Cancellation requests
are followed by kernel completion before any buffer is released. Both endpoints
are consumed after one attempt, including uncertain failures. A bounded reply
correlates the received frame's SHA-256; it attests decoding only, before native
Authority binding. The caller still owns child supervision and must resolve
uncertain delivery through Authority.

`UserAgentChild` launches the installed image through an explicit inherited
handle list. It requires the exact medium-integrity lease owner and checks that
the caller's own session is still attached/active at the console. This client
preflight never obtains a console-user token or constructs `LiveConsoleSession`;
the SYSTEM Authority retains full SID/logon admission before runtime effects.
The launcher checks the created child's actual token and installed image before
sending configuration. The frame never becomes a command-line argument. Failed
creation preserves its cleanup context; any failure after process creation also
returns the retained child. A successful launch confirms decoding only, and
`wait_for_exit` separately observes the held process and retires its launch
worker. Neither observation constructs global Off. Once the agent can receive
configuration, this component never force-kills it: the Desktop supervisor must
revoke through Authority and retain the child until cleanup/exit is established.
That full lifecycle supervisor and the installed entrypoints still need assembly.

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
name and closed `Desktop`/`UserAgent` role with identification-only SQOS. It owns
a native message-mode handle without raw-handle import or mutable access to the
inner client. `WindowsServicePeer` binds that
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

Before publishing the endpoint, the dedicated SYSTEM service calls
`configure_service_process_observation`. This replaces only its own process
DACL, retains SYSTEM/Administrators control and grants authenticated users
`PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`. It verifies a SYSTEM or
Administrators object owner independently of the required SYSTEM primary user,
the protected DACL and exact ACE readback. The helper rejects a non-SYSTEM primary
identity, another session, an AppContainer or restricted identity before mutation.
It does not grant access to process memory, modification, handle duplication or
the SYSTEM token. Without these explicit query rights the ordinary UI correctly
fails admission instead of elevating itself or dropping live-process checks.

Microsoft specifies that [service configuration may describe the next launch](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw),
so the live image is verified independently. This does not inspect the running
service token: the trusted service must check its own SYSTEM identity before
opening its endpoint. Missing, stopped, inaccessible and conflicting services
are errors, never global Off or a readiness proof. The full privileged backend,
runtime authorization, service installation/signing and lifecycle supervision
remain separate work.

`LocalServiceListener` binds a fixed role to an already verified client image
from the trusted installation. Each complete message is immediately checked
against its native last-message token, retained primary process, file identity,
SID, logon authentication ID, session and integrity. Request fields cannot
choose a role or supply the native identity. Only the subsequent authority
layer can decide whether that observed user/session has a current runtime
lease; this transport does not grant one.

The dedicated worker uses one native overlapped read per Windows message and
does not prefetch. This follows the
[last-message token contract](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient).
The listener rejects remote clients and gives ordinary clients only individual
data/attribute/query rights, excluding
[creation of further pipe instances](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).
It reserves at most 15 connections and retains a fresh listening instance;
listener poll deadlines retain the exact pending/completed connection for the
next poll. Explicit listener close cancels and drains pending native I/O before
releasing its stable `OVERLAPPED` storage. Accepted/failed instances are replaced
without recycling them for another client. Messages are bounded by the shared 1 MiB
envelope limit, with at most one pending request per connection. Requests and
replies must match the exact connection and sequence. Buffers are zeroized.

`ServiceChannel` authenticates the service before sending and after receiving.
An I/O, identity or ordering failure closes the channel; a timed-out command is
delivery-uncertain and is never replayed automatically. Low-level pipe I/O
poisons the handle on failure so it cannot be readmitted. Cancellation drains
the exact native operation before releasing its buffer. Kernel completion can
outlast the requested deadline, so callers must keep the worker alive until it
returns. These are blocking worker APIs, not UI-thread operations.

The `native-service-fixture` example installs two uniquely named disposable
SYSTEM services only with `CFW_NATIVE_SERVICE_MUTATION_TESTS=1`. It checks actual
SCM/pipe/image identity, another SYSTEM peer, ACL/configuration changes, a
byte-identical replacement file, missing/stopped services and a medium-integrity
client with Administrators disabled and `DISABLE_MAX_PRIVILEGE` applied. Only the
new token's default DACL grants its user/SYSTEM control of its new objects; the
runner's elevated default DACL would otherwise depend on the disabled group.
The client also requires access denied for service memory/mutation rights and
SYSTEM-token queries. Separate installed desktop and user-agent file identities
exercise both roles. The fixture additionally rejects a wrong role, an identical
client file copy, a medium-impersonated message queued before a primary-identity
message, oversized messages and ordinary-client pipe-instance creation. Client
and server read deadlines are exercised separately, followed by a fresh successful
exchange. The fixture serves each role serially; connection saturation is not
yet native-tested. All 17 service/transport cases passed on hosted Windows at
[`50a3db7`](https://github.com/billlza/cfw-rs/actions/runs/39184109050/job/117842791151);
the downloaded source-bound receipt and all three client reports were audited.
The client uses a temporary user/SYSTEM-only window station and desktop at medium
integrity; the controller restores its prior selections before launch. Existing
user-object ACLs are not modified. This is not desktop UI qualification.
The fixture stops and removes
the services, waits for their processes and verifies deletion before emitting a
source-bound receipt. The fixture is not shipped as a product service. Package
tests never install services. Native execution must pass before this boundary is
reported as verified.

## Live session and role authorization

`NativeUserSession` preserves the full SID, logon authentication LUID and Windows
session number as one native observation. A later logon by the same account is
a different owner. The released Mac `owner_uid` wire field is unchanged; a
Windows SID is never truncated or hashed into that numeric identity.

`LiveConsoleSession` runs only inside the validated SYSTEM service. It resolves
the physical console session, requires an active connection state and compares
two fresh primary-token observations. The
[console-session API](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-wtsgetactiveconsolesessionid)
and [WTS user-token API](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
provide these observations; user tokens are not impersonated or returned to the
client. Token handles are closed. WTS/permission failures stay errors. A missing
console denies admission and says nothing about globally restored network state.

`authorize_service_request` binds the pending request to that current console
logon. A user-agent method additionally needs the service's exact lease owner;
only a dispatcher-selected connection/bound-lease observation can admit no
lease, and it still rejects another logon's lease. The API rechecks the actual
pending connection/message/image after the WTS calls and retains the process
object. Authorization failure closes the connection. Callers hold their
lifecycle/lease guard through admission and dispatch; this peer authorization
does not allocate a runtime lease or bypass command/context checks. Session
change, process loss and heartbeat supervision remain required runtime work.

The native fixture now exercises this authorization before responses, with
fixture ownership established by an admitted desktop. It adds real no-lease
and foreign-owner rejection plus the narrow unleased observation case. This
fixture owner is not a durable product lease. The initial 21-case run reached
the final service exchange, then failed with a closing pipe. Its ordinary-client
authorization checks passed, but the complete native gate did not. A delayed
terminal-read case and exact read/write diagnostics are now included (22 cases)
to distinguish reply lifetime from connection timing. That 22-case run passed
at `8d1bd4e`, including the delayed read; it did not explain the earlier failure.
A bounded 256-exchange post-stop connection test is now added (23 cases); its
first error fails the test without retrying a request. It reproduced a closing
pipe on exchange 33's first write. Listener polling now preserves in-flight
accepts across wait deadlines; native completion/worker-transfer regressions
and the full stress case must pass before this repair is considered validated.
RDP/session switching,
lock/unlock and sleep/wake behavior remain separate qualification gates.

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
The service connector uses `WindowsServicePeer` for SCM identity and trusted
installation binding, with query-only process access instead of SYSTEM-token
inspection by the UI.

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

`UserAgentSession` binds a checked `UserAgentPlan` through the native Authority
channel before starting the child. The plan separately checks the configuration
bytes digest and product identity digest and rejects tunnel modes. A dedicated
control worker renews the same bound connection while native engine operations
run. Revocation interrupts engine RPC waits; an Authority/transport failure
remains an error. The synchronous lifecycle owner must run on a dedicated
thread, and its caller retains it on failure for explicit cleanup/recovery.

Ready requires observed child listeners, exact proxy ownership for SystemProxy
and an authenticated Authority acknowledgement. Stop restores the exact prior
proxy settings before stopping the child, then observes its retained process,
empty job, drained control worker and absence of owned listeners. Only these
observations produce the per-instance Stopped report. Failed restoration keeps
the child owner and journal, closes the Authority control worker and returns the
error. No result here constructs independent global `CleanupEvidence` or Off.

The engine CI job also invokes `native-service-fixture --runtime-validation`
with both service and proxy mutation opt-ins. It runs a medium-integrity,
non-administrator UserAgent through an actual temporary SYSTEM service and the
real engine, checks HTTP traffic in LocalProxy and SystemProxy modes, and tests
Authority-driven cancellation of both modes. The fixture verifies held process
exit, released listeners, original proxy settings, native Stopped replies and
service deletion. A distinct Desktop image/process prepares the original shared
request and sends a launch frame larger than the private pipe's buffer hint
to each medium-integrity child through the product `UserAgentChild` launcher.
The runtime Desktop itself now runs at medium integrity with administrator
membership disabled; elevated setup remains in the outer disposable fixture.
Only its input/output handles are inherited;
the receiver authenticates the installed Desktop image and acknowledges the
decoded frame through the inherited duplex channel. The parent supervises the
child and joins the cancellable writer after observed exit. The
parent uses its original controller key to verify authenticated access and also
checks unauthenticated rejection. Test-only readiness files contain process and
operation IDs, never templates, keys or tickets; they grant no capability.
Initial/final global cleanup evidence is still test-injected, so
these checks do not prove production global recovery or an assembled backend.

Native transport tests separately force reads and full-pipe writes into
`ERROR_IO_PENDING`, cancel those exact operations, and observe their final
`ERROR_OPERATION_ABORTED` result. Other tests cover frame/ack correlation,
deadline without an acknowledgement, cancellation and a byte-identical copy of
the wrong parent executable. These native tests require Windows execution;
cross compilation alone does not establish their runtime result.

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
endpoint validation. These checks do not establish TUN, global service recovery,
interactive UI, sleep/wake, installation/update, signing or release acceptance.
