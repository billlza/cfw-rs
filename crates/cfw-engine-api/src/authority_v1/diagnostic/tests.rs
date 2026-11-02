use super::*;
use crate::authority_v1::test_support::digest;

#[test]
fn a_bare_diagnostic_names_only_its_code() {
    assert_eq!(
        AuthorityDiagnostic::new(BackendErrorKind::Busy).to_string(),
        "code=busy"
    );
}

#[test]
fn every_role_renders_its_wire_name() {
    for (role, name) in [
        (AuthorityRole::Host, "host"),
        (AuthorityRole::ProxyAgent, "proxy_agent"),
        (AuthorityRole::Provider, "provider"),
    ] {
        assert_eq!(
            AuthorityDiagnostic::new(BackendErrorKind::Busy)
                .with_role(role)
                .to_string(),
            format!("code=busy role={name}")
        );
    }
}

#[test]
fn only_a_full_lowercase_digest_leaves_a_prefix() {
    for invalid in [
        String::new(),
        digest('a')[..63].to_owned(),
        digest('A'),
        digest('g'),
    ] {
        assert_eq!(
            AuthorityDiagnostic::new(BackendErrorKind::Busy).with_digest(&invalid),
            Err(CodecError::BoundViolation),
            "{invalid}"
        );
    }
}
