//! The malformation battery: mutations every canonical encoding must fail.

use cfw_engine_api::authority_v1::*;

use crate::{commands::command_kind, generators::CaseChoices};

/// Replaces the first occurrence of `needle` in the UTF-8 bytes with
/// `replacement`, returning `None` when the needle is absent.
pub(crate) fn replace_once(data: &[u8], needle: &str, replacement: &str) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    if !text.contains(needle) {
        return None;
    }
    Some(text.replacen(needle, replacement, 1).into_bytes())
}

/// Every malformed / incompatible / out-of-bound derivative of a valid canonical
/// envelope. Each entry is `(label, bytes)`; the codec must reject all of them.
pub(crate) fn malformed_envelopes(
    choices: &CaseChoices,
    canonical: &[u8],
) -> Vec<(String, Vec<u8>)> {
    let mut cases: Vec<(String, Vec<u8>)> = vec![
        // Empty and truncated inputs are structurally malformed.
        ("empty".into(), Vec::new()),
        (
            "truncated".into(),
            canonical[..canonical.len() / 2].to_vec(),
        ),
        // Trailing / leading whitespace is a noncanonical representation.
        ("trailing_space".into(), [canonical, b" "].concat()),
        ("leading_space".into(), [b" ", canonical].concat()),
        // Oversize exceeds the envelope bound before parsing.
        ("oversize".into(), vec![b' '; MAX_ENVELOPE_BYTES + 1]),
    ];

    // Duplicate key and unknown extra field.
    if let Some(bytes) = replace_once(canonical, "\"major\":", "\"major\":1,\"major\":") {
        cases.push(("duplicate_key".into(), bytes));
    }
    if let Some(bytes) = replace_once(canonical, "\"major\":", "\"extra\":0,\"major\":") {
        cases.push(("unknown_field".into(), bytes));
    }

    // Unsupported protocol version and required feature bits.
    if let Some(bytes) = replace_once(canonical, "\"major\":1", "\"major\":9") {
        cases.push(("unsupported_major".into(), bytes));
    }
    if let Some(bytes) = replace_once(canonical, "\"minor\":1", "\"minor\":7") {
        cases.push(("unsupported_minor".into(), bytes));
    }
    if let Some(bytes) = replace_once(
        canonical,
        "\"required_feature_bits\":0",
        "\"required_feature_bits\":1",
    ) {
        cases.push(("unsupported_feature".into(), bytes));
    }

    // Invalid type: a fractional number where an integer is required.
    if let Some(bytes) = replace_once(canonical, "\"minor\":1", "\"minor\":1.0") {
        cases.push(("float_number".into(), bytes));
    }

    // Unknown command kind.
    let kind = command_kind(choices);
    if let Some(bytes) = replace_once(
        canonical,
        &format!("\"kind\":\"{kind}\""),
        "\"kind\":\"nope_unknown_command\"",
    ) {
        cases.push(("unknown_command".into(), bytes));
    }

    // Exceeded command-specific bound: an oversized configuration byte count.
    if choices.command_index == 1
        && let Some(bytes) = replace_once(
            canonical,
            &format!("\"byte_count\":{}", choices.byte_count),
            "\"byte_count\":999999999",
        )
    {
        cases.push(("byte_count_bound".into(), bytes));
    }

    cases
}
