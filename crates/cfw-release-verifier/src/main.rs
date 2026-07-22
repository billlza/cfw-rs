use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use minisign_verify::{PublicKey, Signature};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 16 * 1024;
const MAX_TRUSTED_COMMENT_BYTES: usize = 1024;
const MAX_ARCHIVE_NAME_BYTES: usize = 255;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let [config_path, archive_path, signature_path] = arguments.as_slice() else {
        return Err("usage: cfw-release-verifier <tauri.conf.json> <archive> <archive.sig>".into());
    };

    let config = read_bounded_regular_file(Path::new(config_path), MAX_CONFIG_BYTES)?;
    let signature_envelope =
        read_bounded_regular_file(Path::new(signature_path), MAX_SIGNATURE_BYTES)?;
    let encoded_public_key = extract_updater_public_key(&config)?;
    let public_key_envelope = decode_base64_utf8(&encoded_public_key, "public key")?;
    let signature = decode_base64_utf8(
        std::str::from_utf8(&signature_envelope)
            .map_err(|error| format!("signature envelope is not UTF-8: {error}"))?
            .trim(),
        "signature",
    )?;

    let public_key = PublicKey::decode(&public_key_envelope)
        .map_err(|error| format!("embedded updater public key is invalid: {error}"))?;
    let signature = Signature::decode(&signature)
        .map_err(|error| format!("updater signature is invalid: {error}"))?;
    let expected_archive_name = archive_file_name(Path::new(archive_path))?;
    let mut verifier = public_key
        .verify_stream(&signature)
        .map_err(|error| format!("cannot initialize updater signature verification: {error}"))?;
    let mut archive = open_regular_file(Path::new(archive_path))?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = archive
            .read(&mut buffer)
            .map_err(|error| format!("read updater archive: {error}"))?;
        if count == 0 {
            break;
        }
        verifier.update(&buffer[..count]);
    }
    verifier.finalize().map_err(|error| {
        format!("updater signature does not match the embedded public key: {error}")
    })?;
    validate_signature_archive(&signature, expected_archive_name)
}

fn archive_file_name(path: &Path) -> Result<&str, String> {
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| {
            format!(
                "updater archive path has no canonical UTF-8 file name: {}",
                path.display()
            )
        })?;
    validate_archive_name(name)?;
    Ok(name)
}

fn validate_signature_archive(
    signature: &Signature,
    expected_archive_name: &str,
) -> Result<(), String> {
    let actual_archive_name = parse_trusted_comment(signature.trusted_comment())?;
    if actual_archive_name != expected_archive_name {
        return Err("updater signature names a different archive".into());
    }
    Ok(())
}

// Keep this grammar identical to the runtime verifier in
// apps/cfw-tauri-shell/src/updater/download.rs. Minisign authenticates this
// trusted comment only when stream finalization succeeds.
fn parse_trusted_comment(comment: &str) -> Result<&str, String> {
    if comment.len() > MAX_TRUSTED_COMMENT_BYTES
        || comment.bytes().any(|byte| byte.is_ascii_control() && byte != b'\t')
    {
        return Err("updater signature trusted comment is invalid".into());
    }
    let mut fields = comment.split('\t');
    let timestamp = fields
        .next()
        .and_then(|field| field.strip_prefix("timestamp:"))
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| {
            "updater signature trusted comment lacks a canonical timestamp field".to_owned()
        })?;
    if timestamp.len() > 20 {
        return Err("updater signature timestamp field is too long".into());
    }
    let parsed_timestamp = timestamp
        .parse::<u64>()
        .map_err(|error| format!("updater signature timestamp is out of range: {error}"))?;
    if parsed_timestamp.to_string() != timestamp {
        return Err("updater signature timestamp is not canonical".into());
    }

    let archive_name = fields
        .next()
        .and_then(|field| field.strip_prefix("file:"))
        .ok_or_else(|| {
            "updater signature trusted comment lacks a canonical file field".to_owned()
        })?;
    validate_archive_name(archive_name)?;
    if fields.next().is_some() {
        return Err("updater signature trusted comment has an unexpected field".into());
    }
    Ok(archive_name)
}

fn validate_archive_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > MAX_ARCHIVE_NAME_BYTES
        || matches!(name, "." | "..")
        || name.contains(['/', '\\', ':'])
        || name.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("updater signature archive name is not a safe basename".into());
    }
    Ok(())
}

fn extract_updater_public_key(config: &[u8]) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_slice(config)
        .map_err(|error| format!("Tauri configuration is invalid JSON: {error}"))?;
    value
        .pointer("/plugins/updater/pubkey")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "Tauri updater public key is missing".into())
}

fn decode_base64_utf8(value: &str, label: &str) -> Result<String, String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|error| format!("{label} envelope is invalid base64: {error}"))?;
    String::from_utf8(bytes).map_err(|error| format!("{label} envelope is not UTF-8: {error}"))
}

fn open_regular_file(path: &Path) -> Result<File, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if metadata.nlink() != 1 {
        return Err(format!(
            "{} must have exactly one hard link",
            path.display()
        ));
    }
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("inspect opened {}: {error}", path.display()))?;
    if metadata.dev() != opened.dev() || metadata.ino() != opened.ino() {
        return Err(format!("{} changed while it was opened", path.display()));
    }
    Ok(file)
}

fn read_bounded_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let mut file = open_regular_file(path)?;
    let length = file
        .metadata()
        .map_err(|error| format!("inspect {}: {error}", path.display()))?
        .len();
    if length == 0 || length > maximum {
        return Err(format!(
            "{} size is outside the accepted 1..={maximum} byte range",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.by_ref()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.len() as u64 > maximum {
        return Err(format!("{} exceeds {maximum} bytes", path.display()));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V035_SIGNATURE: &str = concat!(
        "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkK",
        "UlVUZElOVklSNGhuUVgrL3NFZk9VN0NkckJxbmxiVmFUcXl2QnQyUU9NYTVidm5MZjBD",
        "K2tIeTM5Yzd6YzZ2U3JuVU1zcFRxZ3dBZ2gwV256bUM1UnVhc0Jnek90eGl2Q0FrPQp0",
        "cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzg0NjM5ODc0CWZpbGU6Q2xhc2guZm9y",
        "Lk1hY18wLjMuNV9hYXJjaDY0LmFwcC50YXIuZ3oKckhKallPaXFqTjJIUDVxTDdYZzRI",
        "dldMNWl0akhqMGwxZkU4Yi8rZDMxNXBlUVBxVjgwejdxbDBIMm5kb0JaSW9vWDBRZW5v",
        "Y1U5UFVGMHJNMXRZQnc9PQo="
    );

    #[test]
    fn extracts_only_the_expected_public_key_location() {
        let config = br#"{"plugins":{"updater":{"pubkey":"encoded"}}}"#;
        assert_eq!(extract_updater_public_key(config), Ok("encoded".into()));
        assert!(extract_updater_public_key(br#"{"pubkey":"wrong"}"#).is_err());
        assert!(extract_updater_public_key(br#"{"plugins":{"updater":{"pubkey":""}}}"#).is_err());
    }

    #[test]
    fn rejects_non_base64_envelopes() {
        assert!(decode_base64_utf8("%%%", "test").is_err());
    }

    #[test]
    fn signed_archive_filename_must_match_the_staged_archive() {
        let envelope =
            decode_base64_utf8(V035_SIGNATURE, "signature").expect("historical signature envelope");
        let signature = Signature::decode(&envelope).expect("historical signature");
        validate_signature_archive(&signature, "Clash.for.Mac_0.3.5_aarch64.app.tar.gz")
            .expect("matching staged archive");
        assert!(
            validate_signature_archive(&signature, "Clash.for.Mac_0.4.0_aarch64.app.tar.gz")
                .is_err()
        );
    }

    #[test]
    fn trusted_comment_requires_one_canonical_timestamp_and_safe_basename() {
        assert_eq!(
            parse_trusted_comment("timestamp:1784639874\tfile:archive.tar.gz")
                .expect("canonical trusted comment"),
            "archive.tar.gz"
        );
        for comment in [
            "file:archive.tar.gz\ttimestamp:1784639874",
            "timestamp:now\tfile:archive.tar.gz",
            "timestamp:01784639874\tfile:archive.tar.gz",
            "timestamp:18446744073709551616\tfile:archive.tar.gz",
            "timestamp:1784639874\tfile:../archive.tar.gz",
            "timestamp:1784639874\tfile:archive.tar.gz\tfile:second.tar.gz",
            "timestamp:1784639874\tfile:archive.tar.gz\nfile:second.tar.gz",
        ] {
            assert!(
                parse_trusted_comment(comment).is_err(),
                "malformed trusted comment was accepted: {comment:?}"
            );
        }
    }

    #[test]
    fn staged_archive_path_must_have_a_safe_utf8_basename() {
        assert_eq!(
            archive_file_name(Path::new("/tmp/archive.tar.gz")),
            Ok("archive.tar.gz")
        );
        assert!(archive_file_name(Path::new("/tmp/archive:name.tar.gz")).is_err());
    }

    #[test]
    fn trusted_comment_diagnostics_do_not_echo_untrusted_names() {
        let secret = "must-not-reach-diagnostics";
        let oversized = format!("timestamp:1784639874\tfile:{secret}{}", "a".repeat(1024));
        let diagnostic = parse_trusted_comment(&oversized)
            .expect_err("oversized comment must fail");
        assert!(!diagnostic.contains(secret));

        let mismatch = validate_signature_archive_for_names(secret, "expected.tar.gz")
            .expect_err("mismatched names must fail");
        assert!(!mismatch.contains(secret));
    }

    fn validate_signature_archive_for_names(actual: &str, expected: &str) -> Result<(), String> {
        if actual == expected {
            Ok(())
        } else {
            Err("updater signature names a different archive".into())
        }
    }
}
