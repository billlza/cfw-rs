use cfw_engine_api::BackendErrorKind;

use super::*;
use crate::test_support::{CODE_KIND_PAIRS, listed_code, listed_kind};

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

#[test]
fn every_code_maps_to_the_backend_kind_of_the_same_name_and_back() {
    for &(code, kind) in CODE_KIND_PAIRS {
        listed_code(code);
        listed_kind(kind);
        assert_eq!(BackendErrorKind::from(code), kind);
        assert_eq!(NativeBridgeErrorCode::from(kind), code);
    }
}
