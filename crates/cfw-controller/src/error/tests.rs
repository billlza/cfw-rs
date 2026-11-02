use super::*;
use crate::ProvidersSnapshot;

#[test]
fn pinned_provider_capability_is_explicitly_unsupported() {
    let error = unsupported_provider_subsystem::<ProvidersSnapshot>()
        .expect_err("the strict pinned schema has no provider subsystem");
    assert!(matches!(
        error,
        ControllerError::UnsupportedByPinnedEngine {
            capability: "provider management"
        }
    ));
    assert_eq!(
        error.to_string(),
        "controller capability `provider management` is unsupported by the pinned sing-box engine"
    );
}

#[test]
fn provider_management_admission_refuses_the_pinned_engine() {
    assert!(matches!(
        require_provider_management(),
        Err(ControllerError::UnsupportedByPinnedEngine {
            capability: "provider management"
        })
    ));
}

#[test]
fn errors_name_what_failed_and_its_limit() {
    assert_eq!(
        ControllerError::InvalidEndpoint("port 0".into()).to_string(),
        "invalid controller endpoint: port 0"
    );
    assert_eq!(
        ControllerError::Status {
            status: 409,
            body: "busy".into()
        }
        .to_string(),
        "controller rejected request with HTTP 409: busy"
    );
    assert_eq!(
        ControllerError::ResponseTooLarge {
            status: 200,
            maximum: 16
        }
        .to_string(),
        "controller HTTP 200 response exceeds the 16-byte limit"
    );
    assert_eq!(
        ControllerError::PayloadLimit {
            resource: "rule set",
            maximum: 3
        }
        .to_string(),
        "controller rule set exceeds the 3-entry limit"
    );
    let decode = serde_json::from_str::<u8>("x").expect_err("not a number");
    assert_eq!(
        ControllerError::Json(decode).to_string(),
        "controller JSON decode failed: expected value at line 1 column 1"
    );
}
