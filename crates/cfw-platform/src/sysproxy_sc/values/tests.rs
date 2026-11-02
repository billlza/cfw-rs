use super::*;

#[test]
fn proxy_enable_flags_accept_only_zero_and_one() {
    assert!(!validate_enabled_flag_value("proxy", 0).expect("zero"));
    assert!(validate_enabled_flag_value("proxy", 1).expect("one"));
    assert!(validate_enabled_flag_value("proxy", -1).is_err());
    assert!(validate_enabled_flag_value("proxy", 2).is_err());
}
