//! A required hybrid key exchange reaches the projection without a classical
//! downgrade.

use super::*;

#[test]
fn required_hybrid_key_exchange_reaches_projection_without_classical_downgrade() {
    let tls = json!({"enabled":true,"server_name":"proxy.example.com","min_version":"1.3","curve_preferences":["X25519MLKEM768"]});
    let profile = ValidatedSingBoxProfile::parse(&tls_profile(tls.clone()).to_string())
        .expect("hybrid profile");
    let runtime: Value = serde_json::from_str(
        profile
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("projection")
            .as_json(),
    )
    .expect("runtime");
    assert_eq!(runtime["outbounds"][0]["tls"], tls);
    for (field, invalid) in [
        ("min_version", json!("1.2")),
        ("min_version", json!("1.1")),
        ("enabled", json!(false)),
        ("utls", json!({"enabled":true,"fingerprint":"chrome"})),
        (
            "curve_preferences",
            json!(["X25519MLKEM768", "X25519MLKEM768"]),
        ),
        ("curve_preferences", json!(["invented"])),
    ] {
        let mut value = tls.clone();
        value[field] = invalid;
        assert!(
            ValidatedSingBoxProfile::parse(&tls_profile(value).to_string()).is_err(),
            "admitted {field}"
        );
    }
    let mut preferred = tls;
    preferred["curve_preferences"] = json!(["X25519MLKEM768", "X25519"]);
    ValidatedSingBoxProfile::parse(&tls_profile(preferred).to_string())
        .expect("explicit classical compatibility");
}
