//! Async application contract backed by the installed SCM service and Agent.
//! Native owners stay on their original thread through stop/recovery. Dropped
//! futures cannot turn unfinished work into Off or release retained evidence.
use crate::{
    runtime_host::{HostError, InstalledDesktop, SERVICE_NAME},
    user_agent::{
        desktop::{DesktopError, DesktopReady, DesktopStatusObserver, DesktopUserAgent},
        launcher::UserAgentInvocation,
    },
};
use cfw_engine_api::{
    BackendError, BackendErrorKind as Kind, BackendFuture, EngineBackend, EngineCommandContext,
    EngineRuntimePlatform, EngineStartRequest, NativeEngineStatus, RuntimeIdentity,
    SystemProxyAuthorization, TunnelInstallOutcome, authority_v1::AuthorityState,
};
use cfw_singbox_config::ProjectionMode;
use std::{
    fs::File,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tokio::{runtime::Handle, sync::Semaphore, task::AbortHandle};
use zeroize::Zeroize;
mod error;
mod profile;
use error::{desktop_error, host_error};

type Result<T> = std::result::Result<T, BackendError>;
const LIMIT: Duration = Duration::from_secs(60);
const NATIVE_LIMIT: Duration = Duration::from_secs(30);
/// Ready for a Tunnel run includes SYSTEM's adapter creation, which may first
/// install the pinned Wintun driver. Still inside the worker's `LIMIT`.
const TUNNEL_READY_LIMIT: Duration = Duration::from_secs(55);
/// The application watchdog outlives bounded native admission and retirement;
/// it never changes a native timeout or admits an uncertain cleanup as Off.
pub const OUTER_WATCHDOG: Duration = Duration::from_secs(65);

struct PendingRequest(Option<EngineStartRequest>);
impl PendingRequest {
    fn take(&mut self) -> Result<EngineStartRequest> {
        self.0
            .take()
            .ok_or_else(|| fail(Kind::Internal, "configuration was already consumed"))
    }
}
impl Drop for PendingRequest {
    fn drop(&mut self) {
        if let Some(request) = &mut self.0 {
            request.config_json.zeroize();
        }
    }
}

#[derive(Clone)]
pub struct WindowsEngineBackend {
    shared: Arc<Shared>,
}
struct Shared {
    desktop: Arc<InstalledDesktop>,
    diagnostics: Arc<File>,
    state: Mutex<State>,
    capacity: Arc<Semaphore>,
    checks: Arc<Semaphore>,
    probes: Arc<Semaphore>,
}
#[derive(Default)]
struct State {
    active: Option<Active>,
    retired: Option<Retired>,
}
struct Retired {
    context: EngineCommandContext,
    mode: ProjectionMode,
    prepared: bool,
}
impl Retired {
    fn matches(
        &self,
        context: &EngineCommandContext,
        mode: ProjectionMode,
        snapshot: &crate::authority::AuthoritySnapshot,
    ) -> bool {
        self.context == *context
            && self.mode == mode
            && snapshot.state == AuthorityState::Off
            && snapshot.revision.is_some()
            && snapshot.root.is_some()
            && (!self.prepared || off_matches(snapshot, context))
    }
}
struct Active {
    context: EngineCommandContext,
    digest: String,
    mode: ProjectionMode,
    stop: Arc<AtomicBool>,
    observer: DesktopStatusObserver,
    _ready: Option<DesktopReady>,
    completion: Receiver<(bool, Result<()>)>,
    owner_prepared: Option<bool>,
    finished: Option<Result<()>>,
    retirement: Option<SyncSender<()>>,
    worker: Option<JoinHandle<()>>,
}
impl Drop for Active {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // The owner performs its bounded native cleanup before observing this
        // disconnect. It retains the original connection/reference meanwhile.
        self.retirement.take();
        if let Some(worker) = self.worker.take()
            && worker.is_finished()
            && worker.join().is_err()
        {
            eprintln!("Windows runtime lifecycle worker panicked");
        }
    }
}
impl Active {
    fn retire_until(&mut self, deadline: Instant) -> Result<()> {
        self.retirement.take();
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            thread::sleep(left(deadline)?.min(Duration::from_millis(10)));
        }
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| fail(Kind::Internal, "runtime lifecycle worker panicked"))?;
        }
        Ok(())
    }
    fn finish(&mut self, deadline: Instant) -> Result<()> {
        if self.finished.is_none() {
            let (prepared, result) =
                self.completion
                    .recv_timeout(left(deadline)?)
                    .map_err(|error| match error {
                        mpsc::RecvTimeoutError::Timeout => {
                            fail(Kind::Timeout, "runtime cleanup has not completed")
                        }
                        mpsc::RecvTimeoutError::Disconnected => fail(
                            Kind::OwnerUnresponsive,
                            "runtime worker ended without a cleanup result",
                        ),
                    })?;
            self.owner_prepared = Some(prepared);
            self.finished = Some(result);
        }
        self.finished
            .as_ref()
            .ok_or_else(|| fail(Kind::Internal, "missing runtime result"))?
            .clone()
    }
    fn matches(&self, runtime: &RuntimeIdentity) -> bool {
        runtime.owner == owner(self.mode)
            && runtime.ready
            && runtime.context == self.context
            && runtime.config_digest == self.digest
    }
}

struct Cancel {
    signal: Arc<AtomicBool>,
    worker: AbortHandle,
    armed: bool,
}
impl Drop for Cancel {
    fn drop(&mut self) {
        if self.armed {
            self.signal.store(true, Ordering::Release);
            self.worker.abort();
        }
    }
}
impl WindowsEngineBackend {
    /// The application supplies its native diagnostic sink. Installation paths,
    /// executable admission and service identity come only from InstalledDesktop.
    pub fn new(desktop: Arc<InstalledDesktop>, diagnostics: File) -> Self {
        Self {
            shared: Arc::new(Shared {
                desktop,
                diagnostics: Arc::new(diagnostics),
                state: Mutex::new(State::default()),
                capacity: Arc::new(Semaphore::new(4)),
                checks: Arc::new(Semaphore::new(1)),
                probes: Arc::new(Semaphore::new(1)),
            }),
        }
    }
    async fn native<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&Shared, &mut State, Arc<AtomicBool>, Instant) -> Result<T>
        + Send
        + 'static,
    ) -> Result<T> {
        self.worker(&self.shared.capacity, move |shared, signal, deadline| {
            let mut state = shared
                .state
                .lock()
                .map_err(|_| fail(Kind::Internal, "native backend state is poisoned"))?;
            left(deadline)?;
            if signal.load(Ordering::Acquire) {
                return Err(fail(
                    Kind::GlobalAuthorityInterrupted,
                    "native request cancelled before lifecycle admission",
                ));
            }
            operation(shared, &mut state, signal, deadline)
        })
        .await
    }
    async fn worker<T: Send + 'static>(
        &self,
        capacity: &Arc<Semaphore>,
        operation: impl FnOnce(&Shared, Arc<AtomicBool>, Instant) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        cfw_windows_storage::require_process_identity()
            .map_err(|error| fail(Kind::PermissionDenied, error.to_string()))?;
        let runtime = Handle::try_current().map_err(|_| {
            fail(
                Kind::Unavailable,
                "native backend requires its application executor",
            )
        })?;
        let permit = Arc::clone(capacity).try_acquire_owned().map_err(|_| {
            fail(
                Kind::ResourceExhausted,
                "native backend worker capacity reached",
            )
        })?;
        let deadline = Instant::now() + LIMIT;
        let watchdog = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::pin!(watchdog);
        let signal = Arc::new(AtomicBool::new(false));
        let admitted = Arc::clone(&signal);
        let shared = Arc::clone(&self.shared);
        let mut worker = runtime.spawn_blocking(move || {
            let _permit = permit;
            left(deadline)?;
            if admitted.load(Ordering::Acquire) {
                return Err(fail(
                    Kind::GlobalAuthorityInterrupted,
                    "native request cancelled before admission",
                ));
            }
            operation(&shared, admitted, deadline)
        });
        let mut guard = Cancel {
            signal,
            worker: worker.abort_handle(),
            armed: true,
        };
        let result = tokio::select! {
            biased;
            _ = &mut watchdog => Err(fail(Kind::Timeout, "native operation exceeded its deadline; completion is not established")),
            result = &mut worker => result.map_err(|_| fail(Kind::Internal, "native request worker failed"))?,
        };
        if result.is_ok() {
            guard.armed = false;
        }
        result
    }
    fn start(
        &self,
        request: EngineStartRequest,
        mode: ProjectionMode,
    ) -> BackendFuture<'_, RuntimeIdentity> {
        let mut pending = PendingRequest(Some(request));
        Box::pin(self.native(move |shared, state, stop, deadline| {
            let request = crate::CheckedStartConfiguration::new(pending.take()?)
                .map_err(|error| host_error(HostError::Executable(error)))?;
            if request.mode() != mode {
                return Err(fail(
                    Kind::ConfigurationRejected,
                    "requested proxy mode differs from operation",
                ));
            }
            if !matches!(query(shared, state, deadline)?, NativeEngineStatus::Off) {
                return Err(fail(Kind::GlobalLeaseConflict, "another runtime is active"));
            }
            let context = request.context().clone();
            let digest = request.digest().to_owned();
            let (ready, receive_ready) = mpsc::sync_channel(1);
            let (completion, receive_completion) = mpsc::sync_channel(1);
            let (retirement, retain) = mpsc::sync_channel(1);
            let (observer, queries) = DesktopStatusObserver::channel();
            let desktop = Arc::clone(&shared.desktop);
            let diagnostics = Arc::clone(&shared.diagnostics);
            let worker_stop = Arc::clone(&stop);
            let worker = thread::Builder::new()
                .name("cfw-desktop-runtime".into())
                .spawn(move || {
                    // This thread owns every !Send native connection. Retain the
                    // owner on failure until an independent Off observation permits
                    // retirement, or the application shuts down its backend.
                    let (owner, outcome) =
                        run_owned(&desktop, &diagnostics, request, worker_stop, ready, queries);
                    let failed = outcome.is_err();
                    if let Err(undelivered) = completion.send((owner.is_some(), outcome)) {
                        drop(undelivered);
                    }
                    if failed && owner.is_some() {
                        // Both explicit retirement and sender destruction release
                        // the waiting owner. Neither implies successful cleanup.
                        match retain.recv() {
                            Ok(()) | Err(_) => {}
                        }
                    }
                    drop(owner);
                })
                .map_err(|error| fail(Kind::ResourceExhausted, error.to_string()))?;
            state.active = Some(Active {
                context,
                digest,
                mode,
                stop,
                observer,
                _ready: None,
                completion: receive_completion,
                owner_prepared: None,
                finished: None,
                retirement: Some(retirement),
                worker: Some(worker),
            });
            let active = state
                .active
                .as_mut()
                .ok_or_else(|| fail(Kind::Internal, "runtime owner was not retained"))?;
            let ready_limit = if mode.has_tunnel() {
                TUNNEL_READY_LIMIT
            } else {
                NATIVE_LIMIT
            };
            let observed = receive_ready.recv_timeout(left(deadline)?.min(ready_limit));
            let ready = match observed {
                Ok(ready) => ready,
                Err(error) => {
                    active.stop.store(true, Ordering::Release);
                    let original = fail(
                        Kind::OwnerUnresponsive,
                        format!("runtime Ready was not delivered: {error}"),
                    );
                    return match active.finish(deadline) {
                        Ok(()) => Err(original),
                        Err(rejection) if active.owner_prepared == Some(false) => Err(rejection),
                        Err(cleanup) => Err(combined(original, cleanup)),
                    };
                }
            };
            let scope = &ready.context().operation;
            if scope.root.installation_id.to_string() != active.context.installation_id
                || scope.root.epoch != active.context.config_epoch
                || scope.root.generation != active.context.generation
                || crate::user_agent::hex(&scope.identity_sha256) != active.digest
                || scope.mode
                    != match mode {
                        ProjectionMode::LocalProxy => {
                            cfw_engine_api::authority_v1::AuthorityMode::LocalProxy
                        }
                        ProjectionMode::SystemProxy => {
                            cfw_engine_api::authority_v1::AuthorityMode::SystemProxy
                        }
                        ProjectionMode::Tunnel => {
                            cfw_engine_api::authority_v1::AuthorityMode::Tunnel
                        }
                        ProjectionMode::TunnelSystemProxy => {
                            return Err(fail(Kind::Internal, "invalid runtime owner mode"));
                        }
                    }
                || ready.authority().state != AuthorityState::Active
            {
                return Err(fail(
                    Kind::IdentityRejected,
                    "runtime Ready changed its requested identity",
                ));
            }
            active._ready = Some(ready);
            let live = active
                .observer
                .query_until(deadline.min(Instant::now() + NATIVE_LIMIT))
                .map_err(desktop_error)?;
            if !active.matches(&live.runtime) {
                return Err(fail(
                    Kind::IdentityRejected,
                    "fresh startup observation differs",
                ));
            }
            Ok(live.runtime)
        }))
    }
    fn stop(&self, context: EngineCommandContext, mode: ProjectionMode) -> BackendFuture<'_, ()> {
        Box::pin(self.native(move |shared, state, _, deadline| {
            let Some(active) = state.active.as_mut() else {
                let snapshot = shared
                    .desktop
                    .observe_authority(deadline)
                    .map_err(host_error)?;
                if state
                    .retired
                    .as_ref()
                    .is_some_and(|retired| retired.matches(&context, mode, &snapshot))
                {
                    return Ok(());
                }
                return Err(fail(
                    Kind::StaleOperation,
                    "stop has no matching retained runtime",
                ));
            };
            if active.context != context || active.mode != mode {
                return Err(fail(
                    Kind::StaleOperation,
                    "stop cannot revoke another runtime",
                ));
            }
            active.stop.store(true, Ordering::Release);
            let finished = active.finish(deadline);
            let snapshot = shared
                .desktop
                .observe_authority(deadline)
                .map_err(host_error);
            match snapshot {
                Ok(snapshot)
                    if off_matches(&snapshot, &context)
                        || (active.owner_prepared == Some(false)
                            && snapshot.state == AuthorityState::Off) =>
                {
                    // A failed lifecycle result remains observable even after
                    // later independent global cleanup succeeds.
                    if let Err(retirement) = active.retire_until(deadline) {
                        return match finished {
                            Ok(()) => Err(retirement),
                            Err(operation) => Err(combined(operation, retirement)),
                        };
                    }
                    state.retired = Some(Retired {
                        context,
                        mode,
                        prepared: active.owner_prepared != Some(false),
                    });
                    state.active.take();
                    finished
                }
                observation => {
                    let error = match observation {
                        Err(error) => error,
                        Ok(_) => fail(
                            Kind::CleanupUnproven,
                            "Authority has not verified global Off",
                        ),
                    };
                    match finished {
                        Ok(()) => Err(error),
                        Err(operation) => Err(combined(operation, error)),
                    }
                }
            }
        }))
    }
    /// Read-only native evidence for the disposable installed-product fixture.
    /// No injected observation or process-control capability enters the backend.
    #[cfg(feature = "native-service-validation")]
    pub fn observe_runtime_for_validation(
        &self,
    ) -> BackendFuture<'_, crate::user_agent::desktop::DesktopLive> {
        Box::pin(self.native(|_, state, _, deadline| {
            let active = state
                .active
                .as_mut()
                .ok_or_else(|| fail(Kind::OwnerUnresponsive, "no retained runtime to observe"))?;
            let live = active
                .observer
                .query_until(deadline.min(Instant::now() + NATIVE_LIMIT))
                .map_err(desktop_error)?;
            if !active.matches(&live.runtime) {
                return Err(fail(
                    Kind::IdentityRejected,
                    "validation observation differs from runtime",
                ));
            }
            Ok(live)
        }))
    }
}
fn run_owned(
    desktop: &InstalledDesktop,
    diagnostics: &File,
    request: crate::CheckedStartConfiguration,
    stop: Arc<AtomicBool>,
    ready: SyncSender<DesktopReady>,
    queries: crate::user_agent::desktop::DesktopStatusRequests,
) -> (Option<DesktopUserAgent>, Result<()>) {
    let mut owner = match desktop.prepare_checked_run(request, Instant::now() + NATIVE_LIMIT) {
        Ok(owner) => owner,
        Err(error) => return (None, Err(host_error(error))),
    };
    let operated = UserAgentInvocation::installed(SERVICE_NAME)
        .map_err(DesktopError::from)
        .and_then(|invocation| owner.run_observed(invocation, diagnostics, stop, ready, queries))
        .map_err(desktop_error);
    let cleanup = owner
        .finish_global_stop(desktop.storage().proxy(), Instant::now() + NATIVE_LIMIT)
        .map(|_| ())
        .map_err(desktop_error);
    let result = match (operated, cleanup) {
        (Ok(_), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(combined(operation, cleanup)),
    };
    (Some(owner), result)
}
fn query(shared: &Shared, state: &mut State, deadline: Instant) -> Result<NativeEngineStatus> {
    let snapshot = shared
        .desktop
        .observe_authority(deadline)
        .map_err(host_error)?;
    if snapshot.state == AuthorityState::Off {
        if snapshot.revision.is_none() || snapshot.root.is_none() {
            return Err(fail(
                Kind::IdentityRejected,
                "Authority Off lacks committed scope",
            ));
        }
        if let Some(active) = &mut state.active {
            active.stop.store(true, Ordering::Release);
            let result = active.finish(deadline);
            // A rejected preparation never launched an Agent. Independent Off
            // may therefore still name the preceding generation; keep the
            // rejection observable while retiring this unlaunched attempt.
            if active.owner_prepared != Some(false) && !off_matches(&snapshot, &active.context) {
                return Err(fail(
                    Kind::IdentityRejected,
                    "Off belongs to another runtime",
                ));
            }
            if let Err(retirement) = active.retire_until(deadline) {
                return match result {
                    Ok(()) => Err(retirement),
                    Err(operation) => Err(combined(operation, retirement)),
                };
            }
            state.retired = Some(Retired {
                context: active.context.clone(),
                mode: active.mode,
                prepared: active.owner_prepared != Some(false),
            });
            state.active.take();
            result?;
        }
        return Ok(NativeEngineStatus::Off);
    }
    if snapshot.state != AuthorityState::Active {
        return Err(fail(
            Kind::GlobalAuthorityRecovering,
            "Authority has not admitted a stable runtime state",
        ));
    }
    let active = state.active.as_mut().ok_or_else(|| {
        fail(
            Kind::GlobalLeaseConflict,
            "active runtime belongs to another Desktop owner",
        )
    })?;
    let live = active
        .observer
        .query_until(deadline.min(Instant::now() + NATIVE_LIMIT))
        .map_err(desktop_error)?;
    if !active.matches(&live.runtime) {
        return Err(fail(
            Kind::IdentityRejected,
            "native runtime identity changed",
        ));
    }
    match active.mode {
        ProjectionMode::LocalProxy => Ok(NativeEngineStatus::LocalProxy {
            runtime: live.runtime,
        }),
        ProjectionMode::SystemProxy => Ok(NativeEngineStatus::SystemProxy {
            runtime: live.runtime,
        }),
        ProjectionMode::Tunnel => Ok(NativeEngineStatus::Tunnel {
            runtime: live.runtime,
        }),
        ProjectionMode::TunnelSystemProxy => Err(fail(
            Kind::Internal,
            "runtime owner contained the combined mode",
        )),
    }
}
/// The shared coordinator's owner of a Windows run: the UserAgent for proxy
/// modes, and the SYSTEM tunnel service, which owns the adapter and pump while
/// the UserAgent hosts the engine, for Tunnel.
fn owner(mode: ProjectionMode) -> cfw_engine_api::EngineOwner {
    if mode.has_tunnel() {
        EngineRuntimePlatform::Windows.tunnel_owner()
    } else {
        EngineRuntimePlatform::Windows.proxy_owner()
    }
}
fn off_matches(
    snapshot: &crate::authority::AuthoritySnapshot,
    context: &EngineCommandContext,
) -> bool {
    snapshot.state == AuthorityState::Off
        && snapshot.revision.is_some()
        && snapshot.root.as_ref().is_some_and(|root| {
            root.installation_id.to_string() == context.installation_id
                && root.epoch == context.config_epoch
                && root.generation == context.generation
        })
}
fn fail(kind: Kind, message: impl Into<String>) -> BackendError {
    BackendError::new(kind, message)
}
fn left(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| fail(Kind::Timeout, "native request deadline expired"))
}
fn combined(operation: BackendError, cleanup: BackendError) -> BackendError {
    fail(
        Kind::CleanupUnproven,
        format!("{operation}; cleanup: {cleanup}"),
    )
}
fn combined_unavailable<T: Send + 'static>(
    request: EngineStartRequest,
) -> BackendFuture<'static, T> {
    let pending = PendingRequest(Some(request));
    Box::pin(async move {
        let _pending = pending;
        Err(fail(
            Kind::Unavailable,
            "the combined Tunnel and System Proxy mode is not yet available on Windows",
        ))
    })
}
impl SystemProxyAuthorization for WindowsEngineBackend {
    fn authorize_system_proxy(&self, restoration_only: bool) -> BackendFuture<'_, ()> {
        // Reuse the installed user's native policy/journal check. Worker
        // admission rejects caller impersonation before crossing threads;
        // capacity remains held until the read actually completes. No runtime
        // state lock or ownership lease is needed for this read-only decision.
        Box::pin(self.worker(&self.shared.capacity, move |shared, _, _| {
            shared
                .desktop
                .authorize_system_proxy(restoration_only)
                .map_err(host_error)
        }))
    }
}
impl EngineBackend for WindowsEngineBackend {
    fn runtime_platform(&self) -> EngineRuntimePlatform {
        EngineRuntimePlatform::Windows
    }
    fn query_status(&self) -> BackendFuture<'_, NativeEngineStatus> {
        Box::pin(self.native(|shared, state, _, deadline| query(shared, state, deadline)))
    }
    fn check_configuration(&self, request: EngineStartRequest) -> BackendFuture<'_, ()> {
        let mut pending = PendingRequest(Some(request));
        // Parser work has a separate slot and never holds the runtime state
        // mutex, so candidate checks cannot queue ahead of an authorized stop.
        Box::pin(
            self.worker(&self.shared.checks, move |shared, _, deadline| {
                shared
                    .desktop
                    .check_configuration(pending.take()?, deadline)
                    .map(|_| ())
                    .map_err(host_error)
            }),
        )
    }
    fn start_local_proxy(&self, request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity> {
        self.start(request, ProjectionMode::LocalProxy)
    }
    fn start_system_proxy(
        &self,
        request: EngineStartRequest,
    ) -> BackendFuture<'_, RuntimeIdentity> {
        self.start(request, ProjectionMode::SystemProxy)
    }
    fn stop_local_proxy(&self, context: EngineCommandContext) -> BackendFuture<'_, ()> {
        self.stop(context, ProjectionMode::LocalProxy)
    }
    fn stop_system_proxy(&self, context: EngineCommandContext) -> BackendFuture<'_, ()> {
        self.stop(context, ProjectionMode::SystemProxy)
    }
    /// The MSI installs the SYSTEM service and the official Wintun DLL with
    /// administrator consent; there is no per-user extension to approve. The
    /// installed service is admitted here exactly as for any other run.
    fn install_tunnel(&self, _: EngineCommandContext) -> BackendFuture<'_, TunnelInstallOutcome> {
        Box::pin(self.worker(&self.shared.capacity, |shared, _, deadline| {
            shared
                .desktop
                .observe_authority(deadline)
                .map(|_| TunnelInstallOutcome::Ready)
                .map_err(host_error)
        }))
    }
    fn cancel_tunnel_install(&self, _: EngineCommandContext) -> BackendFuture<'_, ()> {
        // `install_tunnel` never waits for an approval, so nothing is pending.
        Box::pin(async {
            Err(fail(
                Kind::StaleOperation,
                "no Windows tunnel installation approval is pending",
            ))
        })
    }
    /// No first-time consent exists on Windows: the installed SYSTEM service
    /// already owns the tunnel network. The request is still checked so an
    /// unsupported mode fails here rather than at start.
    fn authorize_tunnel_configuration(&self, request: EngineStartRequest) -> BackendFuture<'_, ()> {
        if request.mode == ProjectionMode::TunnelSystemProxy {
            return combined_unavailable(request);
        }
        let mut pending = PendingRequest(Some(request));
        Box::pin(async move {
            let request = crate::CheckedStartConfiguration::new(pending.take()?)
                .map_err(|error| host_error(HostError::Executable(error)))?;
            if request.mode() != ProjectionMode::Tunnel {
                return Err(fail(
                    Kind::ConfigurationRejected,
                    "requested tunnel mode differs from operation",
                ));
            }
            Ok(())
        })
    }
    fn start_tunnel(&self, request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity> {
        if request.mode == ProjectionMode::TunnelSystemProxy {
            return combined_unavailable(request);
        }
        self.start(request, ProjectionMode::Tunnel)
    }
    fn stop_tunnel(&self, context: EngineCommandContext) -> BackendFuture<'_, ()> {
        self.stop(context, ProjectionMode::Tunnel)
    }
}
