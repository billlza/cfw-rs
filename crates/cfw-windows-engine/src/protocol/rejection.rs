//! The engine host's rejection codes, the only engine text that reaches an
//! error. Any other code is a protocol failure: free-form engine output and
//! configuration text never leave the child.

/// The engine could not build the configuration it was given.
pub(crate) const CONSTRUCT_FAILED: &str = "construct_failed";
/// The engine built the configuration and could not start it: a LAN
/// listener another program holds, or any other failure of the start itself.
pub(crate) const START_FAILED: &str = "start_failed";
/// Another program holds the loopback proxy listener's address.
pub(crate) const MIXED_ENDPOINT_IN_USE: &str = "mixed_endpoint_in_use";
/// Another program holds the controller's address.
pub(crate) const CONTROLLER_ENDPOINT_IN_USE: &str = "controller_endpoint_in_use";

const CODES: [&str; 22] = [
    "invalid_request",
    "invalid_start",
    "invalid_check",
    "invalid_config",
    "invalid_log_output",
    CONSTRUCT_FAILED,
    START_FAILED,
    MIXED_ENDPOINT_IN_USE,
    CONTROLLER_ENDPOINT_IN_USE,
    "invalid_observation",
    "invalid_stop",
    "close_failed",
    "invalid_operation",
    "invalid_probe",
    "probe_failed",
    "probe_cleanup_failed",
    "probe_response_invalid",
    "invalid_packet_capability",
    "invalid_packet_operation",
    "invalid_packet_config",
    "packet_capability_required",
    "packet_io_failed",
];

/// The code a reply named, if the engine host defines it.
pub(super) fn known(code: &str) -> Option<&'static str> {
    CODES.into_iter().find(|known| *known == code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_defined_codes_are_known() {
        for code in CODES {
            assert_eq!(known(code), Some(code));
            assert_eq!(CODES.iter().filter(|other| **other == code).count(), 1);
        }
        assert_eq!(known(MIXED_ENDPOINT_IN_USE), Some("mixed_endpoint_in_use"));
        assert_eq!(
            known(CONTROLLER_ENDPOINT_IN_USE),
            Some("controller_endpoint_in_use")
        );
        for unknown in [
            "",
            "Start_Failed",
            "start_failed ",
            "endpoint_in_use",
            "lan_endpoint_in_use",
        ] {
            assert_eq!(known(unknown), None);
        }
    }

    #[test]
    fn an_endpoint_refusal_reaches_the_owner_as_its_code() {
        let reply = |error: &str| -> super::super::Response {
            serde_json::from_value(serde_json::json!({"protocol":1,"session":"session","id":2,
                "pid":123,"version":"1.14.4","state":"idle","digest":"","error":error}))
            .unwrap()
        };
        let validate =
            |error: &str| reply(error).validate("session", 2, 123, "1.14.4", "running", "digest");
        for code in [MIXED_ENDPOINT_IN_USE, CONTROLLER_ENDPOINT_IN_USE] {
            assert!(
                matches!(validate(code), Err(crate::Error::Rejected(actual)) if actual == code)
            );
        }
        assert!(matches!(
            validate("lan_endpoint_in_use"),
            Err(crate::Error::Protocol("unknown rejection code"))
        ));
    }
}
