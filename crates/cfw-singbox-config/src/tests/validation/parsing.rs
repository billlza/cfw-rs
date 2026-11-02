//! The closed schema: canonical digests, forbidden keys, classified parse errors and size bounds.

use super::*;

#[test]
fn canonical_digest_does_not_depend_on_object_order() {
    let first = ValidatedSingBoxProfile::parse(
        r#"{"route":{"final":"proxy"},"outbounds":[{"tag":"proxy","type":"direct"}]}"#,
    )
    .expect("first profile");
    let second = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"direct","tag":"proxy"}],"route":{"final":"proxy"}}"#,
    )
    .expect("second profile");
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.as_json(), second.as_json());
}

#[test]
fn application_owned_inbounds_are_rejected() {
    let error = ValidatedSingBoxProfile::parse(r#"{"inbounds":[]}"#)
        .expect_err("profile must not control listeners");
    assert_eq!(
        error,
        ConfigError::UnsupportedTopLevelKey("inbounds".into())
    );
}

#[test]
fn process_matching_is_rejected_at_any_depth() {
    let error =
        ValidatedSingBoxProfile::parse(r#"{"route":{"rules":[{"process_name":["Safari"]}]}}"#)
            .expect_err("process matching is unavailable in the unprivileged design");
    assert!(matches!(
        error,
        ConfigError::ForbiddenKey { key, .. } if key == "process_name"
    ));
}

#[test]
fn executable_and_file_path_options_are_rejected_at_any_depth() {
    for key in [
        "command",
        "script",
        "executable",
        "certificate_path",
        "download_url",
    ] {
        let input = format!(r#"{{"outbounds":[{{"type":"direct","{key}":"/tmp/x"}}]}}"#);
        let error = ValidatedSingBoxProfile::parse(&input)
            .expect_err("executable and file path options must be rejected");
        assert!(matches!(
            error,
            ConfigError::ForbiddenKey { key: rejected, .. } if rejected == key
        ));
    }
}

#[test]
fn engine_managed_remote_resources_are_rejected() {
    let remote_rule_set = ValidatedSingBoxProfile::parse(
        r#"{"route":{"rule_set":[{"type":"remote","tag":"blocked","url":"http://169.254.169.254/latest"}]}}"#,
    )
    .expect_err("the engine must not fetch remote rule sets");
    assert!(matches!(
        remote_rule_set,
        ConfigError::RemoteResource { path } if path == "$.route.rule_set[0]"
    ));

    let health_check = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"selector","tag":"automatic","url":"https://example.com"}]}"#,
    )
    .expect_err("URL probes are admitted only in the typed automatic group");
    assert!(matches!(
        health_check,
        ConfigError::ForbiddenKey { key, .. } if key == "url"
    ));
}

#[test]
fn classified_parse_separates_unrecognized_input_from_invalid_profiles() {
    let oversized = " ".repeat(MAX_PROFILE_BYTES + 1);
    let too_wide = format!(
        r#"{{"outbounds":[{}]}}"#,
        std::iter::repeat_n("0", MAX_PROFILE_NODES)
            .collect::<Vec<_>>()
            .join(",")
    );
    // `None` marks serde's own message: malformed syntax, then a schema shape.
    for (label, input, expected) in [
        (
            "oversized",
            oversized.as_str(),
            Some(ConfigError::TooLarge {
                actual: MAX_PROFILE_BYTES + 1,
                maximum: MAX_PROFILE_BYTES,
            }),
        ),
        (
            "too many JSON nodes",
            too_wide.as_str(),
            Some(ConfigError::TooComplex {
                maximum: MAX_PROFILE_NODES,
            }),
        ),
        ("malformed JSON", "{", None),
        ("array root", "[]", Some(ConfigError::RootMustBeObject)),
        (
            "application-owned key",
            r#"{"inbounds":[]}"#,
            Some(ConfigError::UnsupportedTopLevelKey("inbounds".into())),
        ),
        (
            "forbidden key",
            r#"{"route":{"rules":[{"process_name":["Safari"]}]}}"#,
            Some(ConfigError::ForbiddenKey {
                path: "$.route.rules[0]".into(),
                key: "process_name".into(),
            }),
        ),
        (
            "remote resource",
            r#"{"route":{"rule_set":[{"type":"remote","tag":"remote"}]}}"#,
            Some(ConfigError::RemoteResource {
                path: "$.route.rule_set[0]".into(),
            }),
        ),
        (
            "inline secret",
            r#"{"outbounds":[{"type":"shadowsocks","tag":"s","server":"s.example","server_port":8388,"method":"aes-256-gcm","password":"secret"}]}"#,
            Some(ConfigError::CredentialRequiresKeychain {
                path: "$.outbounds[0]".into(),
                key: "password".into(),
            }),
        ),
        ("schema shape", r#"{"outbounds":[{"type":"direct"}]}"#, None),
        (
            "noncanonical credential id",
            r#"{"outbounds":[{"type":"vless","tag":"vless","server":"vless.example.com","server_port":443,"credential_ref":{"id":"33333333333343338333333333333333","kind":"vless_uuid"}}]}"#,
            None,
        ),
    ] {
        let error = ValidatedSingBoxProfile::parse(input).expect_err(label);
        match expected {
            Some(expected) => assert_eq!(error, expected, "{label}"),
            None => assert!(matches!(error, ConfigError::InvalidJson(_)), "{label}"),
        }
        assert_eq!(
            ValidatedSingBoxProfile::parse_classified(input).expect_err(label),
            ProfileParseError::Unrecognized(error),
            "{label}"
        );
    }

    let reality_without_utls = format!(
        r#"{{"outbounds":[{{"type":"vless","tag":"vless","server":"vless.example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},"tls":{{"enabled":true,"server_name":"www.example.com","reality":{{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}}}}}}]}}"#
    );
    let wrong_kind = format!(
        r#"{{"outbounds":[{{"type":"vless","tag":"vless","server":"vless.example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vmess_uuid"}}}}]}}"#
    );
    let crossed_kinds = format!(
        r#"{{"outbounds":[{{"type":"vless","tag":"vless","server":"vless.example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}}}},{{"type":"vmess","tag":"vmess","server":"vmess.example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vmess_uuid"}}}}]}}"#
    );
    let policy_shape = |path: &str, reason: &str| ConfigError::UnsupportedPolicyShape {
        path: path.into(),
        reason: reason.into(),
    };
    for (label, input, expected) in [
        (
            "Reality without uTLS",
            reality_without_utls.as_str(),
            policy_shape("$.outbounds[0].tls.utls", "Reality requires uTLS"),
        ),
        (
            "duplicate tags",
            r#"{"outbounds":[{"type":"direct","tag":"d"},{"type":"block","tag":"d"}]}"#,
            policy_shape("$.outbounds[1].tag", "outbound tags must be unique"),
        ),
        (
            "dangling final route",
            r#"{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"missing"}}"#,
            policy_shape(
                "$.route.final",
                "final must reference a declared outbound tag",
            ),
        ),
        (
            "credential kind of another protocol",
            wrong_kind.as_str(),
            ConfigError::CredentialKindMismatch {
                path: "$.outbounds[0].credential_ref".into(),
                expected: CredentialKind::VlessUuid,
                actual: CredentialKind::VmessUuid,
            },
        ),
        (
            "one credential id with two kinds",
            crossed_kinds.as_str(),
            ConfigError::ConflictingCredentialReference {
                id: VLESS_ID.into(),
            },
        ),
        (
            "no outbounds",
            r#"{"outbounds":[]}"#,
            policy_shape(
                "$.outbounds",
                &format!("outbound count is outside the accepted 1..={MAX_OUTBOUNDS} range"),
            ),
        ),
    ] {
        assert_eq!(
            ValidatedSingBoxProfile::parse_classified(input).expect_err(label),
            ProfileParseError::Invalid(expected.clone()),
            "{label}"
        );
        assert_eq!(
            ValidatedSingBoxProfile::parse(input).expect_err(label),
            expected,
            "{label}"
        );
    }

    let direct = r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#;
    assert_eq!(
        ValidatedSingBoxProfile::parse_classified(direct).expect("classified profile"),
        ValidatedSingBoxProfile::parse(direct).expect("profile")
    );
}

#[test]
fn untyped_network_and_credential_bearing_features_fail_closed() {
    for input in [
        r#"{"dns":{"servers":[{"address":"https://169.254.169.254"}]},"outbounds":[{"type":"direct","tag":"direct"}]}"#,
        r#"{"outbounds":[{"type":"hysteria","tag":"proxy","auth_str":"secret"}]}"#,
        r#"{"outbounds":[{"type":"direct","tag":"direct","tls":{"client_key":"secret"}}]}"#,
        r#"{"outbounds":[{"type":"direct","tag":"direct","headers":{"Authorization":"secret"}}]}"#,
    ] {
        assert!(ValidatedSingBoxProfile::parse(input).is_err());
    }
}

#[test]
fn excessively_wide_profiles_are_rejected_before_projection() {
    // One byte per node keeps the input well under the 384 KiB byte ceiling so
    // the rejection can only come from the node budget.
    let outbounds = std::iter::repeat_n("0", MAX_PROFILE_NODES)
        .collect::<Vec<_>>()
        .join(",");
    let input = format!(r#"{{"outbounds":[{outbounds}]}}"#);
    assert!(input.len() < MAX_PROFILE_BYTES);
    let error = ValidatedSingBoxProfile::parse(&input)
        .expect_err("node count must remain bounded independently of byte size");
    assert_eq!(
        error,
        ConfigError::TooComplex {
            maximum: MAX_PROFILE_NODES
        }
    );
}
