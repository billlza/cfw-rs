use super::*;
use crate::test_support::{PROFILE_ID, audience};

fn request() -> ProfileDelayTestRequest {
    ProfileDelayTestRequest {
        audience: audience(PROFILE_ID),
        config_json: "never-print-this-config".into(),
        credential_slots: Vec::new(),
        proxies: vec!["first-node".into(), "second-node".into()],
        timeout_ms: 5_000,
        target_url: None,
        expected_status: None,
    }
}

#[test]
fn a_delay_request_debug_counts_nodes_and_hides_the_configuration() {
    let debug = format!("{:?}", request());
    assert!(debug.contains("proxy_count: 2"), "{debug}");
    assert!(debug.contains("timeout_ms: 5000"), "{debug}");
    for hidden in ["never-print-this-config", "first-node", "second-node"] {
        assert!(!debug.contains(hidden), "{debug}");
    }
}

#[test]
fn an_unset_probe_target_is_left_off_the_wire() {
    let wire = serde_json::to_value(request()).expect("encode");
    assert!(wire.get("target_url").is_none());
    assert!(wire.get("expected_status").is_none());
    assert_eq!(
        serde_json::from_value::<ProfileDelayTestRequest>(wire).expect("decode"),
        request()
    );

    let targeted = ProfileDelayTestRequest {
        target_url: Some("https://www.gstatic.com/generate_204".into()),
        expected_status: Some("204".into()),
        ..request()
    };
    let wire = serde_json::to_value(&targeted).expect("encode");
    assert_eq!(wire["target_url"], "https://www.gstatic.com/generate_204");
    assert_eq!(wire["expected_status"], "204");
}

#[test]
fn a_probe_result_names_its_failure_kind() {
    for (failure, name) in [
        (ProfileProbeFailure::Timeout, "timeout"),
        (ProfileProbeFailure::NotFound, "not_found"),
        (ProfileProbeFailure::ProbeFailed, "probe_failed"),
    ] {
        let delay = ProfileProxyDelay {
            name: "node".into(),
            delay: None,
            error_kind: Some(failure),
        };
        let wire = serde_json::to_value(&delay).expect("encode");
        assert_eq!(wire["error_kind"], name);
        assert_eq!(
            serde_json::from_value::<ProfileProxyDelay>(wire).expect("decode"),
            delay
        );
    }
}
