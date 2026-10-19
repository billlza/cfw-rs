use super::*;
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};

fn launch(mode: ProjectionMode) -> UserAgentLaunch {
    let (binding, _) = super::super::tests::inputs(mode);
    let projected =
        ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .unwrap()
            .project(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                mode,
                &EngineSettings::default(),
            )
            .unwrap();
    let root = &binding.context.operation.root;
    let request = EngineStartRequest {
        context: EngineCommandContext {
            installation_id: root.installation_id.to_string(),
            config_epoch: root.epoch,
            generation: root.generation,
        },
        mode,
        credential_audience: projected.credential_audience().clone(),
        config_json: projected.as_json().into(),
        config_content_digest: projected.configuration_digest().into(),
        config_digest: projected.digest().into(),
        credential_slots: projected.credential_slots().to_vec(),
        tunnel_options: None,
    };
    UserAgentLaunch::new(binding, request).unwrap()
}
fn changed(frame: &[u8], from: &str, to: &str) -> Zeroizing<Vec<u8>> {
    let text = std::str::from_utf8(&frame[4..]).unwrap();
    assert_eq!(text.matches(from).count(), 1);
    let payload = Zeroizing::new(text.replacen(from, to, 1));
    let mut result = Zeroizing::new(vec![0; payload.len() + 4]);
    result[..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    result[4..].copy_from_slice(payload.as_bytes());
    result
}

#[test]
fn launch_frame_preserves_the_original_configuration_and_one_ticket() {
    for mode in [ProjectionMode::LocalProxy, ProjectionMode::SystemProxy] {
        let original = launch(mode);
        let frame = original.encode().unwrap();
        let received = UserAgentLaunch::decode(frame.as_bytes()).unwrap();
        assert_eq!(received.context(), original.context());
        assert_eq!(received.mode(), mode);
        assert!(received.request.shared_request() == original.request.shared_request());
        received
            .binding
            .ticket
            .with_bytes(|ticket| assert!(ticket == [7; 32]));
        assert!(received.encode().unwrap().as_bytes() == frame.as_bytes());
    }
}

#[test]
fn launch_length_and_trailing_data_fail_before_any_request_is_admitted() {
    let frame = launch(ProjectionMode::LocalProxy).encode().unwrap();
    for end in [0, 1, 3, 4, frame.as_bytes().len() - 1] {
        assert!(matches!(
            UserAgentLaunch::decode(&frame.as_bytes()[..end]),
            Err(HandoffError::Length)
        ));
    }
    let mut extra = Zeroizing::new(frame.as_bytes().to_vec());
    extra.push(0);
    assert!(matches!(
        UserAgentLaunch::decode(&extra),
        Err(HandoffError::Length)
    ));
    assert!(matches!(
        UserAgentLaunch::decode(&u32::MAX.to_le_bytes()),
        Err(HandoffError::Length)
    ));
    assert!(matches!(
        UserAgentLaunch::decode(&vec![0; MAX_FRAME_BYTES + 1]),
        Err(HandoffError::Length)
    ));
}

#[test]
fn launch_protocol_and_all_request_layers_are_closed() {
    let frame = launch(ProjectionMode::LocalProxy).encode().unwrap();
    let version = changed(frame.as_bytes(), "\"version\":1,", "\"version\":2,");
    assert!(matches!(
        UserAgentLaunch::decode(&version),
        Err(HandoffError::Version)
    ));
    for (from, to) in [
        ("\"binding\":{", "\"service\":\"foreign\",\"binding\":{"),
        (
            "\"request\":{",
            "\"request\":{\"executable\":\"foreign.exe\",",
        ),
        (
            "\"request\":{\"context\":{",
            "\"request\":{\"context\":{\"extra\":true,",
        ),
        ("\"version\":1,", "\"version\":1,\"version\":1,"),
    ] {
        let bytes = changed(frame.as_bytes(), from, to);
        assert!(UserAgentLaunch::decode(&bytes).is_err());
    }
}

#[test]
fn a_well_formed_frame_cannot_move_the_configuration_to_another_generation() {
    let frame = launch(ProjectionMode::LocalProxy).encode().unwrap();
    let bytes = changed(
        frame.as_bytes(),
        "\"config_epoch\":1,\"generation\":1",
        "\"config_epoch\":1,\"generation\":2",
    );
    assert!(matches!(
        UserAgentLaunch::decode(&bytes),
        Err(HandoffError::Binding(UserAgentError::ConfigurationMismatch))
    ));
}
