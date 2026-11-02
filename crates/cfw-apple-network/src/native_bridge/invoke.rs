//! One native invocation: the request bound, admission, the watchdog, and
//! the exact cancellation of a request that outlives its budget.

use std::{ffi::c_void, sync::Arc, time::Duration};

use cfw_engine_api::{NativeBridgeCommand, NativeBridgeResult, NativeRequestEnvelope};
use tokio::{
    sync::oneshot,
    time::{Instant, timeout_at},
};
use zeroize::Zeroize;

use crate::{
    NativeBridgeError, NativeBridgeErrorCode, NativeBridgeFuture, NativeFrameworkBridge,
    native_bridge::{
        BridgeState,
        abi::Cancel,
        budget::{
            InvocationTiming, NATIVE_BRIDGE_AUTHORIZATION_BUDGET_MILLISECONDS,
            NATIVE_BRIDGE_CLEANUP_GRACE, waits_for_person,
        },
        transport::{CallbackState, bridge_completion, parse_response},
    },
};

const MAXIMUM_REQUEST_BYTES: usize = 8 * 1024 * 1024;

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

impl NativeFrameworkBridge {
    pub(super) fn invoke(
        &self,
        command: NativeBridgeCommand,
    ) -> NativeBridgeFuture<'_, NativeBridgeResult> {
        let authorization = waits_for_person(&command);
        let request = NativeRequestEnvelope::new(command);
        let request_id = request.request_id;
        Box::pin(async move {
            let request_bytes = serde_json::to_vec(&request).map_err(|_| {
                NativeBridgeError::new(
                    NativeBridgeErrorCode::ConfigurationRejected,
                    "native request serialization failed",
                )
            })?;
            if authorization {
                self.invoke_bytes_with_timing(
                    request_id,
                    request_bytes,
                    InvocationTiming {
                        operation_budget: Duration::from_millis(
                            NATIVE_BRIDGE_AUTHORIZATION_BUDGET_MILLISECONDS,
                        ),
                        cleanup_grace: NATIVE_BRIDGE_CLEANUP_GRACE,
                    },
                )
                .await
            } else {
                self.invoke_bytes(request_id, request_bytes).await
            }
        })
    }

    pub(super) fn invoke_bytes(
        &self,
        request_id: uuid::Uuid,
        request_bytes: Vec<u8>,
    ) -> NativeBridgeFuture<'_, NativeBridgeResult> {
        self.invoke_bytes_with_timing(request_id, request_bytes, InvocationTiming::PRODUCTION)
    }

    pub(super) fn invoke_bytes_with_timing(
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

#[cfg(test)]
mod tests;
