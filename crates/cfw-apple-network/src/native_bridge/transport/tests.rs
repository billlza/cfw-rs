use cfw_engine_api::{
    BackendErrorKind, CredentialAudience, CredentialGarbageCollectionReceipt, CredentialKind,
    CredentialPresence, CredentialRef, CutoverPreflightAttestation, ENGINE_PROTOCOL_VERSION,
    EngineCommandContext, NativeServiceMaintenanceAction, NativeServiceMaintenanceResult,
    NativeServiceRegistrationStatus, ProfileProbeFailure, ProfileProxyDelay, TunnelApprovalWait,
};

use super::*;

const REQUEST: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn request_id() -> uuid::Uuid {
    uuid::Uuid::parse_str(REQUEST).expect("request UUID")
}

/// The wire form of a response to the request.
fn envelope(
    result: Option<NativeBridgeResult>,
    failure: Option<NativeBridgeFailure>,
) -> serde_json::Value {
    serde_json::to_value(NativeResponseEnvelope {
        schema_version: ENGINE_PROTOCOL_VERSION,
        request_id: Some(request_id()),
        result,
        failure,
    })
    .expect("response wire")
}

fn parsed(envelope: serde_json::Value) -> Result<NativeBridgeResult, NativeBridgeError> {
    parse_response(
        request_id(),
        &serde_json::to_vec(&envelope).expect("response bytes"),
    )
}

/// What the bridge makes of a success response carrying `result`.
fn answered(result: NativeBridgeResult) -> Result<NativeBridgeResult, NativeBridgeError> {
    parsed(envelope(Some(result), None))
}

fn non_canonical() -> Result<NativeBridgeResult, NativeBridgeError> {
    Err(NativeBridgeError::new(
        NativeBridgeErrorCode::IdentityRejected,
        "native bridge response contains a non-canonical identity",
    ))
}

fn incomplete_runtime() -> Result<NativeBridgeResult, NativeBridgeError> {
    Err(NativeBridgeError::new(
        NativeBridgeErrorCode::IdentityRejected,
        "native runtime attestation is incomplete or non-canonical",
    ))
}

fn context() -> EngineCommandContext {
    EngineCommandContext {
        installation_id: "60fb4b30-53da-47ca-a933-e98268ce5703".to_owned(),
        config_epoch: 4,
        generation: 9,
    }
}

fn runtime(owner: EngineOwner) -> RuntimeIdentity {
    RuntimeIdentity {
        owner,
        context: context(),
        config_digest: "a".repeat(64),
        ready: true,
    }
}

fn failure() -> NativeBridgeFailure {
    NativeBridgeFailure {
        code: BackendErrorKind::Busy,
        message: "native detail".to_owned(),
    }
}

mod callback;
mod failures;
mod responses;
mod results;

#[test]
fn installation_recovery_rejects_invalid_identity_floors_and_users() {
    use cfw_engine_api::{InstallationRecoveryIdentity, InstallationRecoveryState};
    let valid = InstallationRecoveryIdentity {
        installation_id: request_id(),
        accepted_epoch: 0,
        revision: 1,
        console_uid: 501,
    };
    assert!(
        answered(NativeBridgeResult::InstallationRecovery(
            InstallationRecoveryState { identity: None }
        ))
        .is_ok()
    );
    assert!(
        answered(NativeBridgeResult::InstallationRecovery(
            InstallationRecoveryState {
                identity: Some(valid.clone())
            }
        ))
        .is_ok()
    );
    for identity in [
        InstallationRecoveryIdentity {
            installation_id: uuid::Uuid::nil(),
            ..valid.clone()
        },
        InstallationRecoveryIdentity {
            accepted_epoch: u64::MAX,
            ..valid.clone()
        },
        InstallationRecoveryIdentity {
            revision: 0,
            ..valid.clone()
        },
        InstallationRecoveryIdentity {
            console_uid: 0,
            ..valid.clone()
        },
        InstallationRecoveryIdentity {
            console_uid: u32::MAX,
            ..valid
        },
    ] {
        assert_eq!(
            answered(NativeBridgeResult::InstallationRecovery(
                InstallationRecoveryState {
                    identity: Some(identity)
                }
            )),
            non_canonical()
        );
    }
}
