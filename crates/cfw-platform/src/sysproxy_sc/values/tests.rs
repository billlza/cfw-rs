use super::*;
use crate::sysproxy_sc::test_support::{Proxies, float, number, pac_enable_key, text};

#[test]
fn proxy_enable_flags_accept_only_zero_and_one() {
    assert!(!validate_enabled_flag_value("proxy", 0).expect("zero"));
    assert!(validate_enabled_flag_value("proxy", 1).expect("one"));
    assert!(validate_enabled_flag_value("proxy", -1).is_err());
    assert!(validate_enabled_flag_value("proxy", 2).is_err());
}

#[test]
fn an_enable_flag_is_off_when_absent_and_otherwise_an_integer_zero_or_one() {
    let key = pac_enable_key();
    let read = |proxies: Proxies| {
        let dictionary = proxies.build();
        enabled_flag(as_config_dict(&dictionary), key, "PAC proxy configuration")
            .map_err(|error| error.to_string())
    };
    assert_eq!(read(Proxies::default()), Ok(false));
    assert_eq!(read(Proxies::default().with(key, number(0))), Ok(false));
    assert_eq!(read(Proxies::default().with(key, number(1))), Ok(true));
    assert_eq!(
        read(Proxies::default().with(key, number(2))),
        Err("PAC proxy configuration enable flag has invalid value 2; expected 0 or 1".into())
    );
    assert_eq!(
        read(Proxies::default().with(key, text("1"))),
        Err("PAC proxy configuration enable flag has an unexpected CoreFoundation type".into())
    );
    assert_eq!(
        read(Proxies::default().with(key, float(0.5))),
        Err("PAC proxy configuration enable flag is not an integer".into())
    );
}

#[test]
fn a_number_is_absent_or_an_integer() {
    let key = pac_enable_key();
    let read = |proxies: Proxies| {
        let dictionary = proxies.build();
        number_value(as_config_dict(&dictionary), key, "HTTP proxy port")
            .map_err(|error| error.to_string())
    };
    assert_eq!(read(Proxies::default()), Ok(None));
    assert_eq!(
        read(Proxies::default().with(key, number(7890))),
        Ok(Some(7890))
    );
    assert_eq!(
        read(Proxies::default().with(key, text("7890"))),
        Err("HTTP proxy port has an unexpected CoreFoundation type".into())
    );
    assert_eq!(
        read(Proxies::default().with(key, float(7890.5))),
        Err("HTTP proxy port is not an integer".into())
    );
}

#[test]
fn a_string_is_absent_or_text() {
    let key = pac_enable_key();
    let read = |proxies: Proxies| {
        let dictionary = proxies.build();
        string_value(as_config_dict(&dictionary), key, "HTTP proxy server")
            .map_err(|error| error.to_string())
    };
    assert_eq!(read(Proxies::default()), Ok(None));
    assert_eq!(
        read(Proxies::default().with(key, text("127.0.0.1"))),
        Ok(Some("127.0.0.1".into()))
    );
    assert_eq!(
        read(Proxies::default().with(key, number(1))),
        Err("HTTP proxy server has an unexpected CoreFoundation type".into())
    );
}
