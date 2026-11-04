//! A fake Host Bridge framework behind the real C ABI function pointers, so
//! invocations run their admission, watchdog and cancellation paths in tests.
//! It holds each admitted request until a test completes or cancels it, or
//! answers at once with a response built from the request.

use std::{
    ffi::c_void,
    sync::{Arc, Mutex, OnceLock},
};

use cfw_engine_api::{
    BackendErrorKind, NativeBridgeCommand, NativeBridgeFailure, NativeBridgeResult,
    NativeRequestEnvelope, NativeResponseEnvelope,
};

use crate::{
    NativeFrameworkBridge,
    native_bridge::{
        BridgeState,
        abi::{Completion, LoadedABI},
        transport::CallbackState,
    },
};

#[derive(Default)]
pub(super) struct FakeNativeState {
    pub(super) request_id: Option<uuid::Uuid>,
    pub(super) completion: Option<Completion>,
    pub(super) context: Option<usize>,
    pub(super) cancel_request_ids: Vec<String>,
    pub(super) cancel_completion: FakeCancelCompletion,
    pub(super) close_callback_channel_on_execute: bool,
    pub(super) cancel_status: i32,
    pub(super) callback_count: usize,
    pub(super) answer: Option<FakeAnswer>,
    pub(super) admitted: Vec<AdmittedRequest>,
}

/// One request the fake admitted: its identity and its complete JSON body.
#[derive(Clone, Debug)]
pub(crate) struct AdmittedRequest {
    pub(crate) request_id: uuid::Uuid,
    pub(crate) body: serde_json::Value,
}

/// Builds the bytes the fake answers an admitted request with.
pub(crate) type FakeAnswer = Box<dyn Fn(&AdmittedRequest) -> Vec<u8> + Send>;

#[derive(Clone, Copy, Default)]
pub(crate) enum FakeCancelCompletion {
    #[default]
    None,
    QueryStatusSuccess,
}

pub(crate) fn fake_native_state() -> &'static Mutex<FakeNativeState> {
    static STATE: OnceLock<Mutex<FakeNativeState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(FakeNativeState::default()))
}

pub(crate) fn ffi_test_serialization() -> &'static tokio::sync::Mutex<()> {
    static SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    SERIAL.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub(crate) fn reset_fake_native(
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
    if request_bytes.is_null() || request_length <= 0 || completion.is_none() || context.is_null() {
        return 2;
    }
    // SAFETY: the test caller supplies this readable buffer for the call.
    let request_bytes =
        unsafe { std::slice::from_raw_parts(request_bytes, request_length as usize) };
    let Some(request) = admitted_request(request_bytes) else {
        return 2;
    };
    let mut state = fake_native_state().lock().expect("fake native lock");
    if state.context.is_some() {
        return 3;
    }
    state.request_id = Some(request.request_id);
    state.admitted.push(request.clone());
    if let Some(answer) = state.answer.as_ref() {
        let response = answer(&request);
        state.callback_count += 1;
        drop(state);
        // SAFETY: the accepted callback context is completed exactly once,
        // here, as a framework answering before `execute` returns may.
        unsafe {
            completion.expect("checked above")(context, response.as_ptr(), response.len() as isize);
        }
        return 0;
    }
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

/// A request body with a canonical request identity, whatever its command.
fn admitted_request(bytes: &[u8]) -> Option<AdmittedRequest> {
    let body: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let request_id = uuid::Uuid::parse_str(body.get("request_id")?.as_str()?).ok()?;
    Some(AdmittedRequest { request_id, body })
}

unsafe extern "C" fn fake_cancel(request_id_bytes: *const u8, request_id_length: isize) -> i32 {
    if request_id_bytes.is_null() || request_id_length != 36 {
        return 2;
    }
    // SAFETY: the test caller supplies one readable canonical UUID buffer.
    let bytes = unsafe { std::slice::from_raw_parts(request_id_bytes, request_id_length as usize) };
    let Ok(request_id) = std::str::from_utf8(bytes) else {
        return 2;
    };
    let terminal = {
        let mut state = fake_native_state().lock().expect("fake native lock");
        state.cancel_request_ids.push(request_id.to_owned());
        if state.request_id.map(|id| id.hyphenated().to_string()) != Some(request_id.to_owned()) {
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

pub(crate) fn fake_bridge() -> NativeFrameworkBridge {
    NativeFrameworkBridge {
        state: Arc::new(BridgeState::Available(LoadedABI {
            execute: fake_execute,
            cancel: fake_cancel,
            library_handle: None,
        })),
    }
}

pub(crate) fn query_request(request_id: uuid::Uuid) -> Vec<u8> {
    serde_json::to_vec(&NativeRequestEnvelope {
        schema_version: cfw_engine_api::ENGINE_PROTOCOL_VERSION,
        request_id,
        command: NativeBridgeCommand::QueryStatus,
    })
    .expect("query request")
}

pub(crate) fn complete_fake_native_late() {
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

/// Resets the fake to answer every admitted request at once with `answer`.
pub(crate) fn answer_fake_native(answer: impl Fn(&AdmittedRequest) -> Vec<u8> + Send + 'static) {
    *fake_native_state().lock().expect("fake native lock") = FakeNativeState {
        answer: Some(Box::new(answer)),
        ..FakeNativeState::default()
    };
}

/// The requests the fake admitted since it was last reset.
pub(crate) fn admitted_requests() -> Vec<AdmittedRequest> {
    fake_native_state()
        .lock()
        .expect("fake native lock")
        .admitted
        .clone()
}

/// The success response to `request` carrying `result`.
pub(crate) fn result_for(request: &AdmittedRequest, result: NativeBridgeResult) -> Vec<u8> {
    serde_json::to_vec(&NativeResponseEnvelope {
        schema_version: cfw_engine_api::ENGINE_PROTOCOL_VERSION,
        request_id: Some(request.request_id),
        result: Some(result),
        failure: None,
    })
    .expect("success response")
}

/// The failure response to `request` with `code`.
pub(crate) fn failure_for(request: &AdmittedRequest, code: BackendErrorKind) -> Vec<u8> {
    serde_json::to_vec(&NativeResponseEnvelope {
        schema_version: cfw_engine_api::ENGINE_PROTOCOL_VERSION,
        request_id: Some(request.request_id),
        result: None,
        failure: Some(NativeBridgeFailure {
            code,
            message: "native failure".to_owned(),
        }),
    })
    .expect("failure response")
}
