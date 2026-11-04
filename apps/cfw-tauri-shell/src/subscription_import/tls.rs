use base64::{Engine as _, engine::general_purpose::STANDARD};

/// Mihomo fingerprints hash the DER certificate, not its public key. Keep that
/// distinction in the model; accepting a pin never disables name/time checks.
/// Mihomo removes only `:` separators.
pub(super) fn certificate_fingerprint(value: &str) -> Result<String, String> {
    certificate_sha256_from_hex(value, &[':'], "TLS certificate fingerprint")
}

/// A Hysteria 2 link's `pinSHA256`: the SHA-256 of the server's DER leaf
/// certificate. The reference client lowercases the value and removes every
/// `:` and `-` before comparing, so both separators are accepted anywhere.
pub(super) fn hysteria2_pin_sha256(value: &str) -> Result<String, String> {
    certificate_sha256_from_hex(value, &[':', '-'], "Hysteria2 pinSHA256")
}

/// Canonical base64 for `tls.certificate_sha256` from exactly 64 hex digits
/// of either case once `separators` are removed. Nothing else is skipped, and
/// the error never repeats the value.
fn certificate_sha256_from_hex(
    value: &str,
    separators: &[char],
    label: &str,
) -> Result<String, String> {
    let nibbles = value
        .chars()
        .filter(|character| !separators.contains(character))
        .map(|character| character.to_digit(16))
        .collect::<Option<Vec<_>>>()
        .filter(|nibbles| nibbles.len() == 64)
        .ok_or_else(|| format!("{label} must be a SHA256 hex value"))?;
    let digest = nibbles
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[high, low]| u8::try_from((high << 4) | low).expect("two hex digits are one byte"))
        .collect::<Vec<_>>();
    Ok(STANDARD.encode(digest))
}

#[cfg(test)]
mod tests;
