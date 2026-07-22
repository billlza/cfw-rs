use std::sync::Arc;

use cfw_engine_api::{EngineMode, EngineState};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};

use crate::EngineCoordinatorError;

use super::support::{FakeBackend, coordinator};

fn replacement_profile() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(
        r#"{
          "outbounds": [
            {
              "type": "shadowsocks",
              "tag": "replacement",
              "server": "example.com",
              "server_port": 443,
              "method": "aes-128-gcm",
              "credential_ref": {
                "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "kind": "shadowsocks_password"
              }
            }
          ]
        }"#,
    )
    .expect("replacement profile")
}

#[tokio::test]
async fn cutover_preparation_rejects_off_and_direct_only_profiles() {
    let coordinator = coordinator(Arc::new(FakeBackend::default()));
    let settings = EngineSettings::default();
    assert!(matches!(
        coordinator
            .prepare_cutover(
                EngineMode::Tunnel,
                ValidatedSingBoxProfile::direct(),
                settings.clone(),
            )
            .await,
        Err(EngineCoordinatorError::CutoverRequiresRemoteOutbound)
    ));
    assert!(matches!(
        coordinator
            .prepare_cutover(EngineMode::Off, replacement_profile(), settings)
            .await,
        Err(EngineCoordinatorError::InvalidCutoverPreparation(_))
    ));
}

#[tokio::test]
async fn cutover_preparation_is_read_only_and_binds_both_next_generation_projections() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend.clone());
    let settings = EngineSettings::default();
    let profile = replacement_profile();
    let request = coordinator
        .prepare_cutover(EngineMode::SystemProxy, profile.clone(), settings.clone())
        .await
        .expect("prepare cutover");

    assert_eq!(request.target(), EngineMode::SystemProxy);
    assert_eq!(
        request.system_proxy_request().context,
        request.tunnel_request().context
    );
    assert_eq!(request.system_proxy_request().context.generation, 1);
    assert!(request.system_proxy_request().tunnel_options.is_none());
    assert!(request.tunnel_request().tunnel_options.is_some());
    assert!(backend.operations().is_empty());

    let active = coordinator
        .set_mode(EngineMode::SystemProxy, profile, settings)
        .await
        .expect("start the preflighted projection");
    assert!(matches!(active.state, EngineState::ProxyActive { .. }));
    assert_eq!(
        backend.proxy_requests(),
        vec![request.system_proxy_request().clone()]
    );
}

#[tokio::test]
async fn active_runtime_cannot_issue_a_cutover_preparation() {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = coordinator(backend);
    let profile = replacement_profile();
    let settings = EngineSettings::default();
    coordinator
        .set_mode(EngineMode::SystemProxy, profile.clone(), settings.clone())
        .await
        .expect("start proxy");

    assert!(matches!(
        coordinator
            .prepare_cutover(EngineMode::Tunnel, profile, settings)
            .await,
        Err(EngineCoordinatorError::CutoverRequiresOff)
    ));
}
