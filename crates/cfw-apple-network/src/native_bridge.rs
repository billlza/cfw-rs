use std::ffi::c_void;
use std::sync::Arc;

use cfw_engine_api::{
    CutoverPreflightOutcome, CutoverPreflightRequest, EngineCommandContext, EngineStartRequest,
    NativeBridgeCommand, NativeBridgeResult, NativeEngineStatus, NativeRequestEnvelope,
    RuntimeIdentity, TunnelInstallOutcome,
};
use tokio::sync::oneshot;
use zeroize::Zeroize;

use crate::{NativeBridge, NativeBridgeError, NativeBridgeErrorCode, NativeBridgeFuture};

mod credentials;
mod transport;

use transport::{CallbackState, bridge_completion, parse_response};

const MAXIMUM_REQUEST_BYTES: usize = 1_048_576;

type Completion = unsafe extern "C" fn(*mut c_void, *const u8, isize);
type Execute = unsafe extern "C" fn(*const u8, isize, Option<Completion>, *mut c_void) -> i32;

struct LoadedABI {
    execute: Execute,
    library_handle: Option<*mut c_void>,
}

// The dlopen handle and resolved C function are immutable after construction.
// Native requests copy their input and never retain a Rust reference to this
// object; the enclosing Arc keeps the framework loaded for the backend life.
unsafe impl Send for LoadedABI {}
unsafe impl Sync for LoadedABI {}

impl Drop for LoadedABI {
    fn drop(&mut self) {
        if let Some(handle) = self.library_handle {
            // SAFETY: handle was returned by a successful dlopen in `load` and
            // is closed exactly once when the final Arc is released.
            unsafe {
                libc::dlclose(handle);
            }
        }
    }
}

#[derive(Clone)]
pub struct NativeFrameworkBridge {
    state: Arc<BridgeState>,
}

enum BridgeState {
    Available(LoadedABI),
    Unavailable(String),
}

impl std::fmt::Debug for NativeFrameworkBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeFrameworkBridge")
            .field("available", &self.is_available())
            .finish_non_exhaustive()
    }
}

impl NativeFrameworkBridge {
    /// Resolves the versioned ABI from the linked image or the fixed framework
    /// location inside the current application bundle. No environment or
    /// user-controlled search path is accepted.
    pub fn load() -> Self {
        match LoadedABI::load() {
            Ok(abi) => Self {
                state: Arc::new(BridgeState::Available(abi)),
            },
            Err(message) => Self {
                state: Arc::new(BridgeState::Unavailable(message)),
            },
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self.state.as_ref(), BridgeState::Available(_))
    }

    pub fn unavailable_reason(&self) -> Option<&str> {
        match self.state.as_ref() {
            BridgeState::Available(_) => None,
            BridgeState::Unavailable(message) => Some(message),
        }
    }

    fn invoke(&self, command: NativeBridgeCommand) -> NativeBridgeFuture<'_, NativeBridgeResult> {
        let request = NativeRequestEnvelope::new(command);
        let request_id = request.request_id;
        Box::pin(async move {
            let request_bytes = serde_json::to_vec(&request).map_err(|_| {
                NativeBridgeError::new(
                    NativeBridgeErrorCode::ConfigurationRejected,
                    "native request serialization failed",
                )
            })?;
            self.invoke_bytes(request_id, request_bytes).await
        })
    }

    fn invoke_bytes(
        &self,
        request_id: uuid::Uuid,
        mut request_bytes: Vec<u8>,
    ) -> NativeBridgeFuture<'_, NativeBridgeResult> {
        Box::pin(async move {
            if request_bytes.is_empty() || request_bytes.len() > MAXIMUM_REQUEST_BYTES {
                request_bytes.zeroize();
                return Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::ConfigurationRejected,
                    "native request exceeds the fixed bridge bound",
                ));
            }
            let abi = match self.state.as_ref() {
                BridgeState::Available(abi) => abi,
                BridgeState::Unavailable(message) => {
                    request_bytes.zeroize();
                    return Err(NativeBridgeError::new(
                        NativeBridgeErrorCode::Unavailable,
                        message.clone(),
                    ));
                }
            };
            let (sender, receiver) = oneshot::channel();
            let callback_state = Box::new(CallbackState {
                sender: Some(sender),
                _bridge: Arc::clone(&self.state),
            });
            let callback_context = Box::into_raw(callback_state).cast::<c_void>();
            // SAFETY: request bytes remain valid for the duration of the call;
            // Swift copies them synchronously. Zero status transfers the boxed
            // callback context to the exactly-once completion.
            let status = unsafe {
                (abi.execute)(
                    request_bytes.as_ptr(),
                    request_bytes.len() as isize,
                    Some(bridge_completion),
                    callback_context,
                )
            };
            request_bytes.zeroize();
            if status != 0 {
                // SAFETY: nonzero admission guarantees no callback.
                unsafe {
                    drop(Box::from_raw(callback_context.cast::<CallbackState>()));
                }
                return Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    format!("native bridge rejected request admission with status {status}"),
                ));
            }
            let mut response_bytes = receiver.await.map_err(|_| {
                NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native bridge callback channel closed without a response",
                )
            })??;
            let parsed = parse_response(request_id, &response_bytes);
            response_bytes.zeroize();
            parsed
        })
    }
}

impl NativeBridge for NativeFrameworkBridge {
    fn query_status(&self) -> NativeBridgeFuture<'_, NativeEngineStatus> {
        Box::pin(async move {
            match self.invoke(NativeBridgeCommand::QueryStatus).await? {
                NativeBridgeResult::Status(status) => Ok(status),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native query returned the wrong result kind",
                )),
            }
        })
    }

    fn start_system_proxy(
        &self,
        request: EngineStartRequest,
    ) -> NativeBridgeFuture<'_, RuntimeIdentity> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::StartSystemProxy { request })
                .await?
            {
                NativeBridgeResult::Runtime(runtime) => Ok(runtime),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native proxy start returned the wrong result kind",
                )),
            }
        })
    }

    fn stop_system_proxy(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::StopSystemProxy { context })
                .await?
            {
                NativeBridgeResult::Acknowledged => Ok(()),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native proxy stop returned the wrong result kind",
                )),
            }
        })
    }

    fn install_tunnel(
        &self,
        context: EngineCommandContext,
    ) -> NativeBridgeFuture<'_, TunnelInstallOutcome> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::InstallTunnel { context })
                .await?
            {
                NativeBridgeResult::TunnelInstall(outcome) => Ok(outcome),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native tunnel install returned the wrong result kind",
                )),
            }
        })
    }

    fn cancel_tunnel_install(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::CancelTunnelInstall { context })
                .await?
            {
                NativeBridgeResult::Acknowledged => Ok(()),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native tunnel install cancellation returned the wrong result kind",
                )),
            }
        })
    }

    fn start_tunnel(&self, request: EngineStartRequest) -> NativeBridgeFuture<'_, RuntimeIdentity> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::StartTunnel { request })
                .await?
            {
                NativeBridgeResult::Runtime(runtime) => Ok(runtime),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native tunnel start returned the wrong result kind",
                )),
            }
        })
    }

    fn stop_tunnel(&self, context: EngineCommandContext) -> NativeBridgeFuture<'_, ()> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::StopTunnel { context })
                .await?
            {
                NativeBridgeResult::Acknowledged => Ok(()),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native tunnel stop returned the wrong result kind",
                )),
            }
        })
    }

    fn preflight_cutover(
        &self,
        request: CutoverPreflightRequest,
    ) -> NativeBridgeFuture<'_, CutoverPreflightOutcome> {
        Box::pin(async move {
            match self
                .invoke(NativeBridgeCommand::PreflightCutover { request })
                .await?
            {
                NativeBridgeResult::CutoverPreflight(outcome) => Ok(outcome),
                _ => Err(NativeBridgeError::new(
                    NativeBridgeErrorCode::Internal,
                    "native cutover preflight returned the wrong result kind",
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ffi_request_bound_accepts_exact_maximum_and_rejects_maximum_plus_one() {
        let bridge = NativeFrameworkBridge {
            state: Arc::new(BridgeState::Unavailable("test bridge unavailable".into())),
        };
        let request_id = uuid::Uuid::nil();

        let exact_error = bridge
            .invoke_bytes(request_id, vec![b' '; MAXIMUM_REQUEST_BYTES])
            .await
            .expect_err("exact maximum must pass the size admission check");
        assert_eq!(exact_error.code, NativeBridgeErrorCode::Unavailable);

        let oversized_error = bridge
            .invoke_bytes(request_id, vec![b' '; MAXIMUM_REQUEST_BYTES + 1])
            .await
            .expect_err("maximum plus one must fail before bridge invocation");
        assert_eq!(
            oversized_error.code,
            NativeBridgeErrorCode::ConfigurationRejected
        );
    }
}
