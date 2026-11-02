//! The native operations the application coordinator drives.

use std::pin::Pin;

use crate::{
    BackendError, EngineCommandContext, EngineRuntimePlatform, EngineStartRequest,
    NativeEngineStatus, RuntimeIdentity, TunnelInstallOutcome,
};

pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BackendError>> + Send + 'a>>;

/// Native authorization before a System Proxy transition or recovery.
///
/// This may require interactive consent and therefore runs before a short-lived
/// engine start/cleanup transaction. It neither starts/stops an engine nor
/// changes proxy settings or claims an ownership lease. Implementations must
/// authenticate the intended user and respect the platform's access policy.
/// `restoration_only` permits restoring settings already owned by this app, not
/// taking over new settings. A refusal or unanswered consent request remains an
/// explicit error; callers must not stop a working engine before resolving it.
pub trait SystemProxyAuthorization: Send + Sync + 'static {
    fn authorize_system_proxy(&self, restoration_only: bool) -> BackendFuture<'_, ()>;
}

/// Native engine operations used by the application coordinator.
///
/// A successful stop is a barrier: the process has stopped libbox, released
/// its cross-process lease, and will issue no more callbacks for that runtime.
pub trait EngineBackend: Send + Sync + 'static {
    /// Fixed for this backend's lifetime. The coordinator uses this closed
    /// mapping for start, recovery and observation; a peer cannot choose it.
    fn runtime_platform(&self) -> EngineRuntimePlatform;

    /// Queries both native owners and returns one fresh, mutually-exclusive
    /// typed observation. Implementations must reject conflicting simultaneous
    /// owners instead of selecting one, and must not return a cached Active
    /// result after the ProxyAgent, provider, libbox runtime, or readiness
    /// attestation has disappeared. A running result is valid only when its
    /// owner, command context, configuration digest, and readiness are all
    /// currently proven at the native boundary.
    fn query_status(&self) -> BackendFuture<'_, NativeEngineStatus>;

    /// Checks a candidate using the native parser and exact credential audience.
    /// This must not start a runtime or change any OS network setting.
    fn check_configuration(&self, request: EngineStartRequest) -> BackendFuture<'_, ()>;

    fn start_local_proxy(&self, request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity>;

    fn stop_local_proxy(&self, context: EngineCommandContext) -> BackendFuture<'_, ()>;

    fn start_system_proxy(&self, request: EngineStartRequest)
    -> BackendFuture<'_, RuntimeIdentity>;

    fn stop_system_proxy(&self, context: EngineCommandContext) -> BackendFuture<'_, ()>;

    fn install_tunnel(
        &self,
        context: EngineCommandContext,
    ) -> BackendFuture<'_, TunnelInstallOutcome>;

    /// Cancels only the local wait for a submitted System Extension approval.
    /// It must not be implemented by stopping a tunnel runtime. The adapter
    /// remains responsible for reconciling any late OS delegate completion.
    fn cancel_tunnel_install(&self, context: EngineCommandContext) -> BackendFuture<'_, ()>;

    /// Obtains first-time consent for a disabled VPN configuration before issuing
    /// a short-lived start ticket. This operation never starts network forwarding.
    fn authorize_tunnel_configuration(&self, request: EngineStartRequest) -> BackendFuture<'_, ()>;

    fn start_tunnel(&self, request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity>;

    fn stop_tunnel(&self, context: EngineCommandContext) -> BackendFuture<'_, ()>;
}
