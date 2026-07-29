use std::ffi::{CStr, CString, c_void};
use std::path::PathBuf;
use std::sync::Arc;

use cfw_engine_api::{
    CutoverPreflightOutcome, EngineMode, EngineOwner, MAX_CREDENTIAL_SLOTS, NativeBridgeFailure,
    NativeBridgeResult, NativeEngineStatus, NativeResponseEnvelope, RuntimeIdentity,
};
use tokio::sync::oneshot;

use crate::{NativeBridgeError, NativeBridgeErrorCode};

use super::{BridgeState, Cancel, Execute, LoadedABI};

const MAXIMUM_RESPONSE_BYTES: usize = 1_048_576;
const EXECUTE_SYMBOL: &CStr = c"cfw_native_bridge_execute_v1";
const CANCEL_SYMBOL: &CStr = c"cfw_native_bridge_cancel_v1";

pub(super) fn parse_response(
    request_id: uuid::Uuid,
    response_bytes: &[u8],
) -> Result<NativeBridgeResult, NativeBridgeError> {
    let response: NativeResponseEnvelope =
        serde_json::from_slice(response_bytes).map_err(|_| {
            NativeBridgeError::new(
                NativeBridgeErrorCode::Internal,
                "native bridge returned a malformed response",
            )
        })?;
    if response.schema_version != cfw_engine_api::ENGINE_PROTOCOL_VERSION {
        return Err(NativeBridgeError::new(
            NativeBridgeErrorCode::IdentityRejected,
            "native bridge response schema does not match Rust",
        ));
    }
    if response.result.is_some() == response.failure.is_some() {
        return Err(NativeBridgeError::new(
            NativeBridgeErrorCode::Internal,
            "native bridge response has an invalid result/failure shape",
        ));
    }
    if let Some(failure) = response.failure {
        if response.request_id.is_some() && response.request_id != Some(request_id) {
            return Err(NativeBridgeError::new(
                NativeBridgeErrorCode::IdentityRejected,
                "native bridge failure response has a mismatched request identity",
            ));
        }
        return Err(map_wire_failure(failure));
    }
    if response.request_id != Some(request_id) {
        return Err(NativeBridgeError::new(
            NativeBridgeErrorCode::IdentityRejected,
            "native bridge success response has a mismatched request identity",
        ));
    }
    let result = response.result.ok_or_else(|| {
        NativeBridgeError::new(
            NativeBridgeErrorCode::Internal,
            "native bridge response omitted both result and failure",
        )
    })?;
    validate_result(&result)?;
    Ok(result)
}

fn validate_result(result: &NativeBridgeResult) -> Result<(), NativeBridgeError> {
    let rejected = || {
        NativeBridgeError::new(
            NativeBridgeErrorCode::IdentityRejected,
            "native bridge response contains a non-canonical identity",
        )
    };
    match result {
        NativeBridgeResult::Status(NativeEngineStatus::Off)
        | NativeBridgeResult::TunnelInstall(_)
        | NativeBridgeResult::Acknowledged => Ok(()),
        NativeBridgeResult::Status(NativeEngineStatus::SystemProxy { runtime }) => {
            validate_runtime(runtime, EngineOwner::ProxyAgent)
        }
        NativeBridgeResult::Status(NativeEngineStatus::Tunnel { runtime }) => {
            validate_runtime(runtime, EngineOwner::PacketTunnelSystemExtension)
        }
        NativeBridgeResult::Runtime(runtime) => validate_runtime(runtime, runtime.owner),
        NativeBridgeResult::CredentialReceipt(receipt) => canonical_uuid(&receipt.profile_id)
            .then_some(())
            .ok_or_else(rejected),
        NativeBridgeResult::CredentialPresence(presence) => (presence.len()
            <= MAX_CREDENTIAL_SLOTS)
            .then_some(())
            .ok_or_else(rejected),
        NativeBridgeResult::CredentialGarbageCollectionPreview(preview) => {
            preview.validate().map_err(|_| rejected())
        }
        NativeBridgeResult::CredentialGarbageCollectionReceipt(receipt) => {
            receipt.validate().map_err(|_| rejected())
        }
        NativeBridgeResult::CutoverPreflight(CutoverPreflightOutcome::Ready { attestation }) => {
            attestation.validate().then_some(()).ok_or_else(rejected)
        }
        NativeBridgeResult::CutoverPreflight(CutoverPreflightOutcome::AwaitingApproval {
            target,
            context,
            system_proxy_config_digest,
            tunnel_config_digest,
            ..
        }) => (*target != EngineMode::Off
            && canonical_uuid(&context.installation_id)
            && context.config_epoch > 0
            && context.generation > 0
            && sha256_digest(system_proxy_config_digest)
            && sha256_digest(tunnel_config_digest))
        .then_some(())
        .ok_or_else(rejected),
    }
}

fn validate_runtime(
    runtime: &RuntimeIdentity,
    expected_owner: EngineOwner,
) -> Result<(), NativeBridgeError> {
    if runtime.owner == expected_owner
        && canonical_uuid(&runtime.context.installation_id)
        && runtime.context.config_epoch > 0
        && runtime.context.generation > 0
        && sha256_digest(&runtime.config_digest)
        && runtime.ready
    {
        Ok(())
    } else {
        Err(NativeBridgeError::new(
            NativeBridgeErrorCode::IdentityRejected,
            "native runtime attestation is incomplete or non-canonical",
        ))
    }
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
}

fn sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl LoadedABI {
    pub(super) fn load() -> Result<Self, String> {
        // SAFETY: RTLD_DEFAULT is a process-global pseudo-handle valid for
        // dlsym. The symbol is copied into a typed function pointer below.
        let default_execute = unsafe { libc::dlsym(libc::RTLD_DEFAULT, EXECUTE_SYMBOL.as_ptr()) };
        // SAFETY: RTLD_DEFAULT is valid for both symbols in the same image.
        let default_cancel = unsafe { libc::dlsym(libc::RTLD_DEFAULT, CANCEL_SYMBOL.as_ptr()) };
        if !default_execute.is_null() || !default_cancel.is_null() {
            if default_execute.is_null() || default_cancel.is_null() {
                return Err(
                    "linked native bridge exports only part of the required ABI v1 pair".to_owned(),
                );
            }
            return Ok(Self {
                // SAFETY: the versioned symbol's C header fixes this signature.
                execute: unsafe { std::mem::transmute::<*mut c_void, Execute>(default_execute) },
                // SAFETY: the versioned cancel symbol's C header fixes this signature.
                cancel: unsafe { std::mem::transmute::<*mut c_void, Cancel>(default_cancel) },
                library_handle: None,
            });
        }

        let framework = fixed_framework_binary()?;
        let framework_c = CString::new(framework.as_os_str().as_encoded_bytes())
            .map_err(|_| "native bridge framework path contains an embedded NUL".to_owned())?;
        // SAFETY: framework_c is NUL terminated and the fixed bundle path is
        // not influenced by configuration, environment, or user input.
        let handle =
            unsafe { libc::dlopen(framework_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            return Err(format!(
                "signed native bridge framework could not be loaded: {}",
                dl_error()
            ));
        }
        // SAFETY: handle is a live dlopen handle and symbol is NUL terminated.
        let execute_symbol = unsafe { libc::dlsym(handle, EXECUTE_SYMBOL.as_ptr()) };
        // SAFETY: handle remains live and the cancel symbol is NUL terminated.
        let cancel_symbol = unsafe { libc::dlsym(handle, CANCEL_SYMBOL.as_ptr()) };
        if execute_symbol.is_null() || cancel_symbol.is_null() {
            let message = format!(
                "signed native bridge framework does not export the complete ABI v1 pair: {}",
                dl_error()
            );
            // SAFETY: no symbol call can be in flight before construction.
            unsafe {
                libc::dlclose(handle);
            }
            return Err(message);
        }
        Ok(Self {
            // SAFETY: the exported v1 C header fixes this exact signature.
            execute: unsafe { std::mem::transmute::<*mut c_void, Execute>(execute_symbol) },
            // SAFETY: the exported cancel v1 C header fixes this exact signature.
            cancel: unsafe { std::mem::transmute::<*mut c_void, Cancel>(cancel_symbol) },
            library_handle: Some(handle),
        })
    }
}

fn fixed_framework_binary() -> Result<PathBuf, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("resolve current executable for native bridge: {error}"))?;
    let macos_directory = executable
        .parent()
        .ok_or_else(|| "current executable has no parent directory".to_owned())?;
    let contents_directory = macos_directory
        .parent()
        .ok_or_else(|| "current executable is outside a macOS application bundle".to_owned())?;
    Ok(contents_directory
        .join("Frameworks")
        .join("CFWNativeBridge.framework")
        .join("CFWNativeBridge"))
}

fn dl_error() -> String {
    // SAFETY: dlerror returns either null or a process-owned NUL-terminated
    // string valid until the next dynamic-loader call on this thread.
    let pointer = unsafe { libc::dlerror() };
    if pointer.is_null() {
        "dynamic loader returned no diagnostic".to_owned()
    } else {
        // SAFETY: non-null dlerror results are valid C strings.
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    }
}

pub(super) struct CallbackState {
    pub(super) sender: Option<oneshot::Sender<Result<Vec<u8>, NativeBridgeError>>>,
    // Keeps a dlopen-backed framework resident even if the Rust future is
    // cancelled before Swift's accepted exactly-once callback arrives.
    pub(super) _bridge: Arc<BridgeState>,
}

pub(super) unsafe extern "C" fn bridge_completion(
    context: *mut c_void,
    response_bytes: *const u8,
    response_length: isize,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: the accepted C ABI call transfers exactly one Box allocation to
    // this exactly-once callback.
    let mut state = unsafe { Box::from_raw(context.cast::<CallbackState>()) };
    let result = if response_length <= 0 {
        Err(NativeBridgeError::new(
            NativeBridgeErrorCode::Internal,
            "native bridge returned an empty response",
        ))
    } else if response_length as usize > MAXIMUM_RESPONSE_BYTES {
        Err(NativeBridgeError::new(
            NativeBridgeErrorCode::Internal,
            "native bridge response exceeds the fixed bound",
        ))
    } else if response_bytes.is_null() {
        Err(NativeBridgeError::new(
            NativeBridgeErrorCode::Internal,
            "native bridge returned a null response pointer",
        ))
    } else {
        // SAFETY: the ABI guarantees response_bytes points to response_length
        // readable bytes for the callback duration; copy before returning.
        Ok(
            unsafe { std::slice::from_raw_parts(response_bytes, response_length as usize) }
                .to_vec(),
        )
    };
    if let Some(sender) = state.sender.take() {
        let _receiver_was_dropped = sender.send(result);
    }
}

fn map_wire_failure(failure: NativeBridgeFailure) -> NativeBridgeError {
    let code = failure.code;
    NativeBridgeError::new(code.into(), code.stable_message())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfw_engine_api::BackendErrorKind;

    #[test]
    fn unknown_wire_failure_maps_to_stable_internal_non_retryable_error() {
        let request_id =
            uuid::Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("request UUID");
        let response = format!(
            "{{\"schema_version\":4,\"request_id\":\"{request_id}\",\"result\":null,\"failure\":{{\"code\":\"future_authority_code\",\"message\":\"/private/path secret identity\"}}}}"
        );
        let error = parse_response(request_id, response.as_bytes()).expect_err("unknown code");
        assert_eq!(error.code, NativeBridgeErrorCode::Internal);
        assert_eq!(error.message, BackendErrorKind::Internal.stable_message());
        assert!(!error.message.contains("private"));
        assert!(!error.message.contains("secret"));
        let kind = BackendErrorKind::from(error.code);
        assert!(!kind.allows_automatic_retry(true));
    }

    #[test]
    fn global_authority_failure_preserves_code_and_discards_wire_text() {
        let error = map_wire_failure(NativeBridgeFailure {
            code: BackendErrorKind::GlobalAuthorityUnavailable,
            message: "/Users/alice/private/secret localized diagnostic".into(),
        });
        assert_eq!(
            error.code,
            NativeBridgeErrorCode::GlobalAuthorityUnavailable
        );
        assert_eq!(
            error.message,
            BackendErrorKind::GlobalAuthorityUnavailable.stable_message()
        );
        assert!(!error.message.contains("alice"));
        assert!(!error.message.contains("secret"));
    }

    #[test]
    fn cross_language_preview_response_is_validated() {
        let request_id =
            uuid::Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("request UUID");
        let result = parse_response(
            request_id,
            include_bytes!("../../../../contracts/native-bridge-v4/gc-preview-response.json"),
        )
        .expect("cross-language response");
        let NativeBridgeResult::CredentialGarbageCollectionPreview(preview) = result else {
            panic!("unexpected response kind");
        };
        assert_eq!(preview.orphan_count, 1);
    }

    #[test]
    fn response_identity_mismatch_fails_closed() {
        let expected =
            uuid::Uuid::parse_str("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee").expect("request UUID");
        let error = parse_response(
            expected,
            include_bytes!("../../../../contracts/native-bridge-v4/gc-preview-response.json"),
        )
        .expect_err("mismatched response must fail");
        assert_eq!(error.code, NativeBridgeErrorCode::IdentityRejected);
    }

    #[tokio::test]
    async fn callback_keeps_dynamic_bridge_state_alive_after_future_cancellation() {
        let bridge = Arc::new(BridgeState::Unavailable("test".into()));
        let weak = Arc::downgrade(&bridge);
        let (sender, receiver) = oneshot::channel();
        let callback = Box::new(CallbackState {
            sender: Some(sender),
            _bridge: Arc::clone(&bridge),
        });
        let context = Box::into_raw(callback).cast::<c_void>();
        drop(bridge);
        assert!(weak.upgrade().is_some());
        let bytes = b"{}";
        // SAFETY: context is one live CallbackState allocation and bytes stay
        // readable for the callback duration.
        unsafe {
            bridge_completion(context, bytes.as_ptr(), bytes.len() as isize);
        }
        assert_eq!(
            receiver.await.expect("callback result").expect("bytes"),
            bytes
        );
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn callback_rejects_negative_response_length_without_reading_memory() {
        let bridge = Arc::new(BridgeState::Unavailable("test".into()));
        let (sender, receiver) = oneshot::channel();
        let callback = Box::new(CallbackState {
            sender: Some(sender),
            _bridge: bridge,
        });
        let context = Box::into_raw(callback).cast::<c_void>();

        // SAFETY: context is one live CallbackState allocation. A negative
        // length must be rejected before the null byte pointer is inspected.
        unsafe {
            bridge_completion(context, std::ptr::null(), -1);
        }

        let error = receiver
            .await
            .expect("callback result")
            .expect_err("negative length must fail closed");
        assert_eq!(error.code, NativeBridgeErrorCode::Internal);
    }
}
