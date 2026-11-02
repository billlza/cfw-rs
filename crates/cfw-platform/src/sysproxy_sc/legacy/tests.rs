use super::*;

#[test]
fn legacy_absence_refuses_to_prove_anything_without_a_recorded_endpoint() {
    // Absence is only provable against a known endpoint. An empty or zero
    // port list must never be a vacuous pass; both return before any
    // SCPreferences session is opened.
    for ports in [vec![], vec![0u16], vec![0u16, 7902]] {
        let error = verify_no_legacy_owned_proxy(&ports, false)
            .expect_err("an unknown retired endpoint cannot prove absence");
        assert!(
            error.to_string().contains("owned proxy port is unknown"),
            "{error}"
        );
    }
}
