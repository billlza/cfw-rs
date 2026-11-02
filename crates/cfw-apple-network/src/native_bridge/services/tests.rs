use cfw_engine_api::{
    BackendError, BackendErrorKind, NativeServiceRegistrationStatus, ProfileDelayBackend,
    ProfileDelayTestRequest, ProfileProbeFailure, ProfileProxyDelay,
};

use super::*;
use crate::native_bridge::fake_native::{
    admitted_requests, answer_fake_native, failure_for, fake_bridge, ffi_test_serialization,
    result_for,
};
use crate::test_support::tunnel_request;

/// Answers every request with `result`.
fn answer(result: NativeBridgeResult) {
    answer_fake_native(move |request| result_for(request, result.clone()));
}

fn receipt(
    action: NativeServiceMaintenanceAction,
    registration: NativeServiceRegistrationStatus,
) -> NativeServiceMaintenanceResult {
    NativeServiceMaintenanceResult {
        action,
        engine_status: None,
        global_authority: registration,
        off_proof_profile: None,
        proxy_agent: registration,
    }
}

fn delay_request(proxies: &[&str]) -> ProfileDelayTestRequest {
    let request = tunnel_request();
    ProfileDelayTestRequest {
        audience: request.credential_audience,
        config_json: request.config_json,
        credential_slots: Vec::new(),
        proxies: proxies.iter().map(|proxy| (*proxy).to_owned()).collect(),
        timeout_ms: 5_000,
        target_url: None,
        expected_status: None,
    }
}

fn measured() -> Vec<ProfileProxyDelay> {
    vec![
        ProfileProxyDelay {
            name: "Tokyo".to_owned(),
            delay: Some(120),
            error_kind: None,
        },
        ProfileProxyDelay {
            name: "Osaka".to_owned(),
            delay: None,
            error_kind: Some(ProfileProbeFailure::Timeout),
        },
    ]
}

#[tokio::test]
async fn service_maintenance_accepts_only_the_receipt_of_its_own_action() {
    let _serial = ffi_test_serialization().lock().await;
    let bridge = fake_bridge();
    let status = receipt(
        NativeServiceMaintenanceAction::Status,
        NativeServiceRegistrationStatus::Enabled,
    );
    answer(NativeBridgeResult::ServiceMaintenance(status.clone()));
    assert_eq!(
        bridge
            .maintain_current_services(NativeServiceMaintenanceAction::Status)
            .await,
        Ok(status)
    );
    assert_eq!(
        admitted_requests()[0].body["command"],
        serde_json::to_value(NativeBridgeCommand::MaintainCurrentServices {
            action: NativeServiceMaintenanceAction::Status
        })
        .expect("maintenance wire")
    );

    answer(NativeBridgeResult::ServiceMaintenance(receipt(
        NativeServiceMaintenanceAction::RetireOrphanedServices,
        NativeServiceRegistrationStatus::NotRegistered,
    )));
    assert_eq!(
        bridge
            .maintain_current_services(NativeServiceMaintenanceAction::Status)
            .await,
        Err(NativeBridgeError::new(
            NativeBridgeErrorCode::IdentityRejected,
            "native service maintenance response action does not match the request"
        ))
    );

    answer(NativeBridgeResult::Acknowledged);
    assert_eq!(
        bridge
            .maintain_current_services(NativeServiceMaintenanceAction::Status)
            .await,
        Err(NativeBridgeError::new(
            NativeBridgeErrorCode::Internal,
            "native service maintenance returned the wrong result kind"
        ))
    );
}

#[tokio::test]
async fn profile_delays_must_answer_every_proxy_in_order() {
    let _serial = ffi_test_serialization().lock().await;
    let bridge = fake_bridge();
    let request = delay_request(&["Tokyo", "Osaka"]);

    answer(NativeBridgeResult::ProfileDelays(measured()));
    assert_eq!(
        bridge.test_profile_delays(request.clone()).await,
        Ok(measured())
    );
    assert_eq!(
        admitted_requests()[0].body["command"],
        serde_json::to_value(NativeBridgeCommand::TestProfileDelays {
            request: request.clone()
        })
        .expect("probe wire")
    );

    let mismatch = Err(NativeBridgeError::new(
        NativeBridgeErrorCode::Internal,
        "native profile probe response does not match the request",
    ));
    let mut reordered = measured();
    reordered.reverse();
    for answered in [
        NativeBridgeResult::ProfileDelays(measured()[..1].to_vec()),
        NativeBridgeResult::ProfileDelays(reordered),
        NativeBridgeResult::Acknowledged,
    ] {
        answer(answered);
        assert_eq!(bridge.test_profile_delays(request.clone()).await, mismatch);
    }
}

#[tokio::test]
async fn the_profile_delay_backend_reports_native_failures_as_backend_errors() {
    let _serial = ffi_test_serialization().lock().await;
    let bridge = fake_bridge();
    answer(NativeBridgeResult::ProfileDelays(measured()));
    assert_eq!(
        ProfileDelayBackend::test_profile_delays(&bridge, delay_request(&["Tokyo", "Osaka"])).await,
        Ok(measured())
    );

    answer_fake_native(|request| failure_for(request, BackendErrorKind::Busy));
    assert_eq!(
        ProfileDelayBackend::test_profile_delays(&bridge, delay_request(&["Tokyo"])).await,
        Err(BackendError::new(
            BackendErrorKind::Busy,
            BackendErrorKind::Busy.stable_message()
        ))
    );
}
