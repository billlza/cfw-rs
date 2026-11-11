use std::{ffi::c_void, sync::Arc};

use cfw_engine_api::{
    CutoverPreflightOutcome, EngineMode, EngineOwner, MAX_CREDENTIAL_SLOTS, NativeBridgeFailure,
    NativeBridgeResult, NativeEngineStatus, NativeResponseEnvelope, RuntimeIdentity,
};
use tokio::sync::oneshot;

use super::BridgeState;
use crate::{NativeBridgeError, NativeBridgeErrorCode};

const MAXIMUM_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

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
        NativeBridgeResult::InstallationRecovery(state) => state
            .identity
            .as_ref()
            .is_none_or(|identity| {
                !identity.installation_id.is_nil()
                    && identity.revision > 0
                    && identity.accepted_epoch < u64::MAX
                    && identity.console_uid > 0
                    && identity.console_uid != u32::MAX
            })
            .then_some(())
            .ok_or_else(rejected),
        NativeBridgeResult::ProfileDelays(results) => (results.len() <= 32
            && results.iter().all(|result| {
                !result.name.is_empty()
                    && result.name.len() <= 512
                    && matches!(
                        (result.delay, result.error_kind),
                        (Some(1..), None) | (None, Some(_))
                    )
            }))
        .then_some(())
        .ok_or_else(rejected),
        NativeBridgeResult::Status(NativeEngineStatus::Off)
        | NativeBridgeResult::TunnelInstall(_)
        | NativeBridgeResult::TunnelApproval(_)
        | NativeBridgeResult::Acknowledged => Ok(()),
        NativeBridgeResult::Status(NativeEngineStatus::LocalProxy { runtime })
        | NativeBridgeResult::Status(NativeEngineStatus::SystemProxy { runtime }) => {
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
        NativeBridgeResult::ServiceMaintenance(result) => {
            result.validate().then_some(()).ok_or_else(rejected)
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
mod tests;
