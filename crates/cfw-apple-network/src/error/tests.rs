use cfw_engine_api::BackendErrorKind;

use super::*;

#[test]
fn authority_error_mapping_is_one_to_one() {
    for kind in BackendErrorKind::AUTHORITY_KINDS {
        let bridge = NativeBridgeErrorCode::from(kind);
        assert_eq!(BackendErrorKind::from(bridge), kind);
    }
}

#[test]
fn proxy_agent_approval_mapping_is_one_to_one() {
    let kind = BackendErrorKind::ProxyAgentApprovalRequired;
    let bridge = NativeBridgeErrorCode::from(kind);
    assert_eq!(bridge, NativeBridgeErrorCode::ProxyAgentApprovalRequired);
    assert_eq!(BackendErrorKind::from(bridge), kind);
}
