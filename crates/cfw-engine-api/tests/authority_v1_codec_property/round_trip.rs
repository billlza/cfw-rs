//! Evaluating one case: canonical encodings round-trip, and every malformation
//! is rejected before a value is yielded.

use cfw_engine_api::authority_v1::*;

use crate::{
    commands::build_command,
    generators::{CaseChoices, uuid_from},
    malformed::{malformed_envelopes, replace_once},
    records::{global_lease_of, preference_receipt_of, replay_cursor_of, snapshot_of},
};

/// Round-trips a standalone canonical model and asserts value equivalence,
/// returning a violation description on any failure.
fn check_canonical_round_trip<T>(label: &str, value: &T) -> Option<String>
where
    T: serde::Serialize + serde::de::DeserializeOwned + WireValidate + PartialEq,
{
    let bytes = match encode_canonical(value) {
        Ok(bytes) => bytes,
        Err(error) => return Some(format!("{label}: valid model failed to encode: {error:?}")),
    };
    let decoded = match decode_canonical::<T>(&bytes) {
        Ok(decoded) => decoded,
        Err(error) => {
            return Some(format!(
                "{label}: canonical bytes failed to decode: {error:?}"
            ));
        }
    };
    if &decoded != value {
        return Some(format!(
            "{label}: decoded value is not equivalent to the original"
        ));
    }
    match encode_canonical(&decoded) {
        Ok(reencoded) if reencoded == bytes => None,
        Ok(_) => Some(format!(
            "{label}: re-encoding decoded value is not byte-stable"
        )),
        Err(error) => Some(format!(
            "{label}: decoded value failed to re-encode: {error:?}"
        )),
    }
}

/// Returns `None` when the case satisfies Property 2, or a description of the
/// first violation otherwise.
pub(crate) fn evaluate(choices: &CaseChoices) -> Option<String> {
    // 1. Valid envelope round trip: encode → decode → re-encode is byte stable,
    //    which is the canonical form's notion of an equivalent value (the
    //    envelope holds non-cloneable secret material, so byte stability is the
    //    equivalence witness).
    let command = build_command(choices);
    let envelope = match RequestEnvelope::new(uuid_from(choices.entropy, 0), 0, command) {
        Ok(envelope) => envelope,
        Err(error) => {
            return Some(format!(
                "valid command rejected by RequestEnvelope::new: {error:?}"
            ));
        }
    };
    let canonical = match encode_request(&envelope) {
        Ok(bytes) => bytes,
        Err(error) => return Some(format!("valid envelope failed to encode: {error:?}")),
    };
    let decoded = match decode_request(&canonical) {
        Ok(decoded) => decoded,
        Err(error) => return Some(format!("canonical envelope failed to decode: {error:?}")),
    };
    match encode_request(&decoded) {
        Ok(reencoded) if reencoded == canonical => {}
        Ok(_) => return Some("decoded envelope re-encodes to different bytes".into()),
        Err(error) => return Some(format!("decoded envelope failed to re-encode: {error:?}")),
    }

    // 2. Every malformed / incompatible / out-of-bound derivative must be
    //    rejected before a value (and therefore any state mutation) is produced.
    for (label, mutated) in malformed_envelopes(choices, &canonical) {
        if decode_request(&mutated).is_ok() {
            return Some(format!(
                "malformed envelope '{label}' decoded instead of being rejected"
            ));
        }
    }

    // 3. Standalone canonical models round-trip with true value equality.
    let snapshot = snapshot_of(choices);
    if let Some(reason) = check_canonical_round_trip("AuthoritySnapshot", &snapshot) {
        return Some(reason);
    }
    let cursor = replay_cursor_of(choices);
    if let Some(reason) = check_canonical_round_trip("ReplayCursor", &cursor) {
        return Some(reason);
    }
    let lease = global_lease_of(choices);
    if let Some(reason) = check_canonical_round_trip("GlobalLease", &lease) {
        return Some(reason);
    }
    let receipt = preference_receipt_of(choices);
    if let Some(reason) = check_canonical_round_trip("PreferenceMutationReceipt", &receipt) {
        return Some(reason);
    }

    // 4. An out-of-bound standalone model must be rejected on decode. A valid
    //    ReplayCursor with its revision forced to the illegal value 0 keeps a
    //    canonical shape yet must fail validation before yielding a value.
    let cursor_bytes = encode_canonical(&cursor).expect("valid cursor encodes");
    if let Some(zeroed) = replace_once(
        &cursor_bytes,
        &format!("\"revision\":{}", choices.revision),
        "\"revision\":0",
    ) && decode_canonical::<ReplayCursor>(&zeroed).is_ok()
    {
        return Some(
            "out-of-bound ReplayCursor (revision=0) decoded instead of being rejected".into(),
        );
    }

    None
}
