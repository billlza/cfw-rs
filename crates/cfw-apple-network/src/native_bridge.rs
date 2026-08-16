use std::ffi::c_void;
use std::sync::Arc;
use std::time::Duration;

use cfw_engine_api::{
    CutoverPreflightOutcome, CutoverPreflightRequest, EngineCommandContext, EngineStartRequest,
    NativeBridgeCommand, NativeBridgeResult, NativeEngineStatus, NativeRequestEnvelope,
    RuntimeIdentity, TunnelInstallOutcome,
};
use tokio::sync::oneshot;
use tokio::time::{Instant, timeout_at};
use zeroize::Zeroize;

use crate::{NativeBridge, NativeBridgeError, NativeBridgeErrorCode, NativeBridgeFuture};

mod credentials;
mod transport;

use transport::{CallbackState, bridge_completion, parse_response};

const MAXIMUM_REQUEST_BYTES: usize = 1_048_576;

const NATIVE_BRIDGE_OPERATION_BUDGET_MILLISECONDS: u64 = 30_000;
const NATIVE_BRIDGE_CLEANUP_GRACE_MILLISECONDS: u64 = 20_000;
const NATIVE_BRIDGE_OUTER_WATCHDOG_MILLISECONDS: u64 = 55_000;

const _: () = assert!(
    NATIVE_BRIDGE_OUTER_WATCHDOG_MILLISECONDS
        > NATIVE_BRIDGE_OPERATION_BUDGET_MILLISECONDS + NATIVE_BRIDGE_CLEANUP_GRACE_MILLISECONDS
);

const NATIVE_BRIDGE_OPERATION_BUDGET: Duration =
    Duration::from_millis(NATIVE_BRIDGE_OPERATION_BUDGET_MILLISECONDS);
const NATIVE_BRIDGE_CLEANUP_GRACE: Duration =
    Duration::from_millis(NATIVE_BRIDGE_CLEANUP_GRACE_MILLISECONDS);
pub const NATIVE_BRIDGE_OUTER_WATCHDOG: Duration =
    Duration::from_millis(NATIVE_BRIDGE_OUTER_WATCHDOG_MILLISECONDS);

type Completion = unsafe extern "C" fn(*mut c_void, *const u8, isize);
type Execute = unsafe extern "C" fn(*const u8, isize, Option<Completion>, *mut c_void) -> i32;
type Cancel = unsafe extern "C" fn(*const u8, isize) -> i32;

struct LoadedABI {
    execute: Execute,
    cancel: Cancel,
    library_handle: Option<*mut c_void>,
}

#[derive(Clone, Copy)]
struct InvocationTiming {
    operation_budget: Duration,
    cleanup_grace: Duration,
}

impl InvocationTiming {
    const PRODUCTION: Self = Self {
        operation_budget: NATIVE_BRIDGE_OPERATION_BUDGET,
        cleanup_grace: NATIVE_BRIDGE_CLEANUP_GRACE,
    };
}

struct InvocationCancellation {
    cancel: Cancel,
    request_id: [u8; 36],
    armed: bool,
    cancellation_delivered: bool,
}

impl InvocationCancellation {
    fn new(cancel: Cancel, request_id: uuid::Uuid) -> Self {
        let text = request_id.hyphenated().to_string();
        let request_id = text
            .as_bytes()
            .try_into()
            .expect("canonical UUID is exactly 36 bytes");
        Self {
            cancel,
            request_id,
            armed: true,
            cancellation_delivered: false,
        }
    }

    fn cancel(&mut self) -> Result<(), NativeBridgeError> {
        if !self.armed || self.cancellation_delivered {
            return Ok(());
        }
        // SAFETY: request_id is a live canonical UUID buffer for this call and
        // the v1 ABI copies it synchronously.
        let status =
            unsafe { (self.cancel)(self.request_id.as_ptr(), self.request_id.len() as isize) };
        match status {
            0 | 3 => {
                // Status 3 is the only valid completion race: Swift removed the
                // exact request immediately before this cancellation arrived.
                self.cancellation_delivered = true;
                Ok(())
            }
            _ => Err(NativeBridgeError::new(
                NativeBridgeErrorCode::Internal,
                format!("native bridge rejected exact cancellation with status {status}"),
            )),
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for InvocationCancellation {
    fn drop(&mut self) {
        if self.armed && !self.cancellation_delivered {
            // Future cancellation cannot surface an error to its caller. The
            // exact request is still cancelled, while the callback allocation
            // retains framework residency until Swift reports terminal cleanup.
            if let Err(error) = self.cancel() {
                // No request identity or user data is included. Drop cannot
                // return an error, so this is the hard observable boundary for
                // an ABI contract violation during caller cancellation.
                eprintln!(
                    "native bridge exact cancellation failed during future drop: {}",
                    error.message
                );
            }
        }
    }
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
        request_bytes: Vec<u8>,
    ) -> NativeBridgeFuture<'_, NativeBridgeResult> {
        self.invoke_bytes_with_timing(request_id, request_bytes, InvocationTiming::PRODUCTION)
    }

    fn invoke_bytes_with_timing(
        &self,
        request_id: uuid::Uuid,
        mut request_bytes: Vec<u8>,
        timing: InvocationTiming,
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
            let (sender, mut receiver) = oneshot::channel();
            let callback_state = Box::new(CallbackState {
                sender: Some(sender),
                _bridge: Arc::clone(&self.state),
            });
            let callback_context = Box::into_raw(callback_state).cast::<c_void>();
            // SAFETY: request bytes remain valid for the duration of the call;
            // Swift copies them synchronously. Zero status transfers the boxed
            // callback context to the exactly-once completion.
            let admitted_at = Instant::now();
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
            let mut cancellation = InvocationCancellation::new(abi.cancel, request_id);
            let operation_deadline = admitted_at + timing.operation_budget;
            match timeout_at(operation_deadline, &mut receiver).await {
                Ok(callback) => {
                    let callback = callback.map_err(|_| {
                        NativeBridgeError::new(
                            NativeBridgeErrorCode::Internal,
                            "native bridge callback channel closed without a response",
                        )
                    })?;
                    // The native callback has consumed its context. Malformed
                    // callback bytes are terminal and must not trigger a second
                    // cancellation attempt against a completed request.
                    cancellation.disarm();
                    let mut response_bytes = callback?;
                    let parsed = parse_response(request_id, &response_bytes);
                    response_bytes.zeroize();
                    parsed
                }
                Err(_) => {
                    cancellation.cancel()?;
                    let cleanup_deadline = Instant::now() + timing.cleanup_grace;
                    if let Ok(Ok(Ok(mut response_bytes))) =
                        timeout_at(cleanup_deadline, &mut receiver).await
                    {
                        // The watchdog owns the terminal result. A racing native
                        // success is deliberately discarded after cancellation.
                        response_bytes.zeroize();
                    }
                    Err(NativeBridgeError::new(
                        NativeBridgeErrorCode::Timeout,
                        "native bridge operation exceeded its bounded execution budget",
                    ))
                }
            }
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
    use std::sync::{Mutex, OnceLock};

    #[derive(Default)]
    struct FakeNativeState {
        request_id: Option<uuid::Uuid>,
        completion: Option<Completion>,
        context: Option<usize>,
        cancel_request_ids: Vec<String>,
        cancel_completion: FakeCancelCompletion,
        close_callback_channel_on_execute: bool,
        cancel_status: i32,
        callback_count: usize,
    }

    #[derive(Clone, Copy, Default)]
    enum FakeCancelCompletion {
        #[default]
        None,
        QueryStatusSuccess,
    }

    fn fake_native_state() -> &'static Mutex<FakeNativeState> {
        static STATE: OnceLock<Mutex<FakeNativeState>> = OnceLock::new();
        STATE.get_or_init(|| Mutex::new(FakeNativeState::default()))
    }

    fn ffi_test_serialization() -> &'static tokio::sync::Mutex<()> {
        static SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        SERIAL.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    fn reset_fake_native(
        cancel_completion: FakeCancelCompletion,
        close_callback_channel_on_execute: bool,
        cancel_status: i32,
    ) {
        *fake_native_state().lock().expect("fake native lock") = FakeNativeState {
            cancel_completion,
            close_callback_channel_on_execute,
            cancel_status,
            ..FakeNativeState::default()
        };
    }

    unsafe extern "C" fn fake_execute(
        request_bytes: *const u8,
        request_length: isize,
        completion: Option<Completion>,
        context: *mut c_void,
    ) -> i32 {
        if request_bytes.is_null()
            || request_length <= 0
            || completion.is_none()
            || context.is_null()
        {
            return 2;
        }
        // SAFETY: the test caller supplies this readable buffer for the call.
        let request_bytes =
            unsafe { std::slice::from_raw_parts(request_bytes, request_length as usize) };
        let Ok(request) = serde_json::from_slice::<NativeRequestEnvelope>(request_bytes) else {
            return 2;
        };
        let mut state = fake_native_state().lock().expect("fake native lock");
        if state.context.is_some() {
            return 3;
        }
        state.request_id = Some(request.request_id);
        if state.close_callback_channel_on_execute {
            drop(state);
            // SAFETY: this intentionally simulates an ABI violation that drops
            // the accepted callback owner without invoking it.
            unsafe {
                drop(Box::from_raw(context.cast::<CallbackState>()));
            }
            return 0;
        }
        state.completion = completion;
        state.context = Some(context as usize);
        0
    }

    unsafe extern "C" fn fake_cancel(request_id_bytes: *const u8, request_id_length: isize) -> i32 {
        if request_id_bytes.is_null() || request_id_length != 36 {
            return 2;
        }
        // SAFETY: the test caller supplies one readable canonical UUID buffer.
        let bytes =
            unsafe { std::slice::from_raw_parts(request_id_bytes, request_id_length as usize) };
        let Ok(request_id) = std::str::from_utf8(bytes) else {
            return 2;
        };
        let terminal = {
            let mut state = fake_native_state().lock().expect("fake native lock");
            state.cancel_request_ids.push(request_id.to_owned());
            if state.request_id.map(|id| id.hyphenated().to_string()) != Some(request_id.to_owned())
            {
                return 3;
            }
            if state.cancel_status != 0 {
                return state.cancel_status;
            }
            if !matches!(state.cancel_completion, FakeCancelCompletion::None) {
                let Some(completion) = state.completion.take() else {
                    return 3;
                };
                let Some(context) = state.context.take() else {
                    return 3;
                };
                let cancel_completion = state.cancel_completion;
                state.callback_count += 1;
                Some((
                    completion,
                    context,
                    request_id.to_owned(),
                    cancel_completion,
                ))
            } else {
                None
            }
        };
        if let Some((completion, context, request_id, cancel_completion)) = terminal {
            let response = match cancel_completion {
                FakeCancelCompletion::None => unreachable!("no callback was requested"),
                FakeCancelCompletion::QueryStatusSuccess => format!(
                    "{{\"schema_version\":{},\"request_id\":\"{request_id}\",\"result\":{{\"kind\":\"status\",\"value\":{{\"status\":\"off\"}}}},\"failure\":null}}",
                    cfw_engine_api::ENGINE_PROTOCOL_VERSION
                ),
            };
            // SAFETY: fake_execute transferred one live callback context, and
            // response remains readable for the callback duration.
            unsafe {
                completion(
                    context as *mut c_void,
                    response.as_ptr(),
                    response.len() as isize,
                );
            }
        }
        0
    }

    fn fake_bridge() -> NativeFrameworkBridge {
        NativeFrameworkBridge {
            state: Arc::new(BridgeState::Available(LoadedABI {
                execute: fake_execute,
                cancel: fake_cancel,
                library_handle: None,
            })),
        }
    }

    fn query_request(request_id: uuid::Uuid) -> Vec<u8> {
        serde_json::to_vec(&NativeRequestEnvelope {
            schema_version: cfw_engine_api::ENGINE_PROTOCOL_VERSION,
            request_id,
            command: NativeBridgeCommand::QueryStatus,
        })
        .expect("query request")
    }

    fn complete_fake_native_late() {
        let terminal = {
            let mut state = fake_native_state().lock().expect("fake native lock");
            let completion = state.completion.take().expect("pending completion");
            let context = state.context.take().expect("pending context");
            state.callback_count += 1;
            (completion, context)
        };
        let response = b"{}";
        // SAFETY: the fake accepted exactly one live callback context.
        unsafe {
            (terminal.0)(
                terminal.1 as *mut c_void,
                response.as_ptr(),
                response.len() as isize,
            );
        }
    }

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

    #[tokio::test]
    async fn watchdog_cancels_the_exact_request_and_never_returns_racing_success() {
        let _serial = ffi_test_serialization().lock().await;
        reset_fake_native(FakeCancelCompletion::QueryStatusSuccess, false, 0);
        let bridge = fake_bridge();
        let request_id = uuid::Uuid::new_v4();

        let error = bridge
            .invoke_bytes_with_timing(
                request_id,
                query_request(request_id),
                InvocationTiming {
                    operation_budget: Duration::ZERO,
                    cleanup_grace: Duration::from_millis(100),
                },
            )
            .await
            .expect_err("watchdog owns the terminal result");

        assert_eq!(error.code, NativeBridgeErrorCode::Timeout);
        assert_eq!(
            error.message,
            "native bridge operation exceeded its bounded execution budget"
        );
        let state = fake_native_state().lock().expect("fake native lock");
        assert_eq!(
            state.cancel_request_ids,
            [request_id.hyphenated().to_string()]
        );
        assert_eq!(state.callback_count, 1);
        assert!(state.context.is_none());
    }

    #[tokio::test]
    async fn dropping_future_cancels_exact_request_and_retains_framework_until_late_callback() {
        let _serial = ffi_test_serialization().lock().await;
        reset_fake_native(FakeCancelCompletion::None, false, 0);
        let bridge = fake_bridge();
        let weak_state = Arc::downgrade(&bridge.state);
        let request_id = uuid::Uuid::new_v4();
        let mut invocation = bridge.invoke_bytes_with_timing(
            request_id,
            query_request(request_id),
            InvocationTiming {
                operation_budget: Duration::from_secs(60),
                cleanup_grace: Duration::from_secs(1),
            },
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut invocation)
                .await
                .is_err()
        );
        drop(invocation);
        {
            let state = fake_native_state().lock().expect("fake native lock");
            assert_eq!(
                state.cancel_request_ids,
                [request_id.hyphenated().to_string()]
            );
            assert_eq!(state.callback_count, 0);
            assert!(state.context.is_some());
        }

        drop(bridge);
        assert!(weak_state.upgrade().is_some());
        complete_fake_native_late();
        assert!(weak_state.upgrade().is_none());
        assert_eq!(
            fake_native_state()
                .lock()
                .expect("fake native lock")
                .callback_count,
            1
        );
    }

    #[tokio::test]
    async fn callback_channel_close_is_internal_and_still_cancels_exact_request() {
        let _serial = ffi_test_serialization().lock().await;
        reset_fake_native(FakeCancelCompletion::None, true, 0);
        let bridge = fake_bridge();
        let request_id = uuid::Uuid::new_v4();

        let error = bridge
            .invoke_bytes_with_timing(
                request_id,
                query_request(request_id),
                InvocationTiming {
                    operation_budget: Duration::from_secs(1),
                    cleanup_grace: Duration::from_millis(1),
                },
            )
            .await
            .expect_err("closed callback owner must fail");

        assert_eq!(error.code, NativeBridgeErrorCode::Internal);
        let state = fake_native_state().lock().expect("fake native lock");
        assert_eq!(
            state.cancel_request_ids,
            [request_id.hyphenated().to_string()]
        );
        assert_eq!(state.callback_count, 0);
    }

    #[tokio::test]
    async fn unexpected_cancel_status_is_internal_and_late_callback_still_releases_context() {
        let _serial = ffi_test_serialization().lock().await;
        reset_fake_native(FakeCancelCompletion::None, false, 2);
        let bridge = fake_bridge();
        let weak_state = Arc::downgrade(&bridge.state);
        let request_id = uuid::Uuid::new_v4();

        let error = bridge
            .invoke_bytes_with_timing(
                request_id,
                query_request(request_id),
                InvocationTiming {
                    operation_budget: Duration::from_millis(1),
                    cleanup_grace: Duration::from_millis(1),
                },
            )
            .await
            .expect_err("unexpected cancel status must fail");

        assert_eq!(error.code, NativeBridgeErrorCode::Internal);
        {
            let state = fake_native_state().lock().expect("fake native lock");
            assert_eq!(
                state.cancel_request_ids,
                [
                    request_id.hyphenated().to_string(),
                    request_id.hyphenated().to_string()
                ]
            );
            assert_eq!(state.callback_count, 0);
            assert!(state.context.is_some());
        }
        drop(bridge);
        assert!(weak_state.upgrade().is_some());
        complete_fake_native_late();
        assert!(weak_state.upgrade().is_none());
    }

    #[tokio::test]
    async fn cleanup_grace_expiry_is_bounded_and_late_callback_releases_framework() {
        let _serial = ffi_test_serialization().lock().await;
        reset_fake_native(FakeCancelCompletion::None, false, 0);
        let bridge = fake_bridge();
        let weak_state = Arc::downgrade(&bridge.state);
        let request_id = uuid::Uuid::new_v4();

        let error = bridge
            .invoke_bytes_with_timing(
                request_id,
                query_request(request_id),
                InvocationTiming {
                    operation_budget: Duration::ZERO,
                    cleanup_grace: Duration::ZERO,
                },
            )
            .await
            .expect_err("cleanup grace expiry must return its bounded timeout");

        assert_eq!(error.code, NativeBridgeErrorCode::Timeout);
        assert_eq!(
            error.message,
            "native bridge operation exceeded its bounded execution budget"
        );
        {
            let state = fake_native_state().lock().expect("fake native lock");
            assert_eq!(
                state.cancel_request_ids,
                [request_id.hyphenated().to_string()]
            );
            assert_eq!(state.callback_count, 0);
            assert!(state.context.is_some());
        }

        drop(bridge);
        assert!(weak_state.upgrade().is_some());
        complete_fake_native_late();
        assert!(weak_state.upgrade().is_none());
        assert_eq!(
            fake_native_state()
                .lock()
                .expect("fake native lock")
                .callback_count,
            1
        );
    }

    #[test]
    fn c_header_and_rust_watchdog_constants_match() {
        let header = include_str!("../../../native/macos/Headers/CFWNativeBridge.h");
        assert!(header.contains("CFW_NATIVE_BRIDGE_OPERATION_BUDGET_MILLISECONDS 30000u"));
        assert!(header.contains("CFW_NATIVE_BRIDGE_CLEANUP_GRACE_MILLISECONDS 20000u"));
        assert!(header.contains("CFW_NATIVE_BRIDGE_OUTER_WATCHDOG_MILLISECONDS 55000u"));
        assert!(
            NATIVE_BRIDGE_OUTER_WATCHDOG
                > NATIVE_BRIDGE_OPERATION_BUDGET + NATIVE_BRIDGE_CLEANUP_GRACE
        );
    }
}
