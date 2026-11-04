use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use minisign_verify::{PublicKey, Signature};
use serde_json::json;
use sha2::{Digest as _, Sha256};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 16 * 1024;
const MAX_TRUSTED_COMMENT_BYTES: usize = 1024;
const MAX_ARCHIVE_NAME_BYTES: usize = 255;

fn main() {
    match run(&env::args_os().skip(1).collect::<Vec<_>>()) {
        Ok(Some(receipt)) => println!("{receipt}"),
        Ok(None) => {}
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}

fn run(arguments: &[OsString]) -> Result<Option<serde_json::Value>, String> {
    let (config_path, archive_path, signature_path, emit_json) = match arguments {
        [config_path, archive_path, signature_path] => {
            (config_path, archive_path, signature_path, false)
        }
        [config_path, archive_path, signature_path, output] if output == "--json" => {
            (config_path, archive_path, signature_path, true)
        }
        _ => {
            return Err(
                "usage: cfw-release-verifier <tauri.conf.json> <archive> <archive.sig> [--json]"
                    .into(),
            );
        }
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
    let archive_size = archive
        .metadata()
        .map_err(|error| format!("inspect updater archive: {error}"))?
        .len();
    let mut archive_sha256 = Sha256::new();
    let mut bytes_read = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = archive
            .read(&mut buffer)
            .map_err(|error| format!("read updater archive: {error}"))?;
        if count == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(count as u64)
            .ok_or_else(|| "updater archive size overflowed".to_owned())?;
        archive_sha256.update(&buffer[..count]);
        verifier.update(&buffer[..count]);
    }
    if bytes_read != archive_size {
        return Err("updater archive changed while it was verified".into());
    }
    verifier.finalize().map_err(|error| {
        format!("updater signature does not match the embedded public key: {error}")
    })?;
    validate_signature_archive(&signature, expected_archive_name)?;
    if !emit_json {
        return Ok(None);
    }
    Ok(Some(json!({
        "archive_filename": expected_archive_name,
        "archive_sha256": encode_hex(archive_sha256.finalize().as_ref()),
        "archive_size": archive_size,
        "document": "cfw-updater-embedded-pubkey-verification-v1",
        "embedded_public_key_sha256": sha256_hex(public_key_envelope.as_bytes()),
        "result": "verified",
        "schema_version": 1,
        "signature_filename": archive_file_name(Path::new(signature_path))?,
        "signature_sha256": sha256_hex(&signature_envelope),
        "signature_size": signature_envelope.len(),
        "tauri_config_sha256": sha256_hex(&config),
    })))
}

fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(Sha256::digest(bytes).as_ref())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
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
        || comment
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
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
mod fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{
        ARCHIVE as FIXTURE_ARCHIVE, ARCHIVE_NAME as FIXTURE_ARCHIVE_NAME,
        PUBLIC_KEY as FIXTURE_PUBLIC_KEY, SIGNATURE as FIXTURE_SIGNATURE,
    };

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
    fn receipt_digests_use_fixed_lowercase_hex() {
        assert_eq!(
            sha256_hex(b"fixture"),
            "f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d"
        );
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
    fn a_trusted_comment_needs_a_bounded_timestamp_and_a_file_field() {
        assert_eq!(
            parse_trusted_comment("timestamp:123456789012345678901\tfile:archive.tar.gz"),
            Err("updater signature timestamp field is too long".into())
        );
        for comment in [
            "timestamp:1784639874",
            "timestamp:1784639874\tname:archive.tar.gz",
        ] {
            assert_eq!(
                parse_trusted_comment(comment),
                Err("updater signature trusted comment lacks a canonical file field".into()),
                "{comment:?}"
            );
        }
    }

    #[test]
    fn a_staged_path_without_a_utf8_file_name_is_refused() {
        use std::os::unix::ffi::OsStrExt as _;

        for path in [
            Path::new("/"),
            Path::new(std::ffi::OsStr::from_bytes(b"/tmp/archive-\xff.tar.gz")),
        ] {
            let error = archive_file_name(path).expect_err("no UTF-8 file name");
            assert!(
                error.starts_with("updater archive path has no canonical UTF-8 file name: "),
                "{error}"
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
        let diagnostic =
            parse_trusted_comment(&oversized).expect_err("oversized comment must fail");
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

    /// A private staging directory with a configuration, an archive and its
    /// signature, removed at the end of the test.
    struct Staging(std::path::PathBuf);

    impl Staging {
        fn new(label: &str) -> Self {
            use std::os::unix::fs::PermissionsExt as _;

            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "cfw-release-verifier-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&root).expect("staging directory");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private");
            let staging = Self(root);
            staging.write_config(FIXTURE_PUBLIC_KEY);
            fs::write(staging.archive(), FIXTURE_ARCHIVE).expect("archive");
            fs::write(staging.signature(), FIXTURE_SIGNATURE).expect("signature");
            staging
        }

        fn write_config(&self, public_key: &str) {
            let config = json!({ "plugins": { "updater": { "pubkey": public_key } } });
            fs::write(self.config(), config.to_string()).expect("configuration");
        }

        fn config(&self) -> std::path::PathBuf {
            self.0.join("tauri.conf.json")
        }

        fn archive(&self) -> std::path::PathBuf {
            self.0.join(FIXTURE_ARCHIVE_NAME)
        }

        fn signature(&self) -> std::path::PathBuf {
            self.0.join(format!("{FIXTURE_ARCHIVE_NAME}.sig"))
        }

        fn arguments(&self, extra: &[&str]) -> Vec<OsString> {
            [self.config(), self.archive(), self.signature()]
                .into_iter()
                .map(OsString::from)
                .chain(extra.iter().map(OsString::from))
                .collect()
        }

        fn rejection(&self) -> String {
            run(&self.arguments(&[])).expect_err("verification must fail")
        }
    }

    impl Drop for Staging {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove staging directory");
        }
    }

    #[test]
    fn a_signed_archive_verifies_and_reports_every_digest() {
        let staging = Staging::new("verified");
        assert_eq!(run(&staging.arguments(&[])), Ok(None));

        let receipt = run(&staging.arguments(&["--json"]))
            .expect("verified")
            .expect("a receipt");
        let config = fs::read(staging.config()).expect("configuration");
        let public_key = decode_base64_utf8(FIXTURE_PUBLIC_KEY, "public key").expect("key");
        assert_eq!(
            receipt,
            json!({
                "archive_filename": FIXTURE_ARCHIVE_NAME,
                "archive_sha256": sha256_hex(FIXTURE_ARCHIVE),
                "archive_size": FIXTURE_ARCHIVE.len(),
                "document": "cfw-updater-embedded-pubkey-verification-v1",
                "embedded_public_key_sha256": sha256_hex(public_key.as_bytes()),
                "result": "verified",
                "schema_version": 1,
                "signature_filename": format!("{FIXTURE_ARCHIVE_NAME}.sig"),
                "signature_sha256": sha256_hex(FIXTURE_SIGNATURE.as_bytes()),
                "signature_size": FIXTURE_SIGNATURE.len(),
                "tauri_config_sha256": sha256_hex(&config),
            })
        );
    }

    #[test]
    fn usage_is_three_paths_and_an_optional_json_flag() {
        let staging = Staging::new("usage");
        let usage =
            "usage: cfw-release-verifier <tauri.conf.json> <archive> <archive.sig> [--json]";
        assert_eq!(run(&[]), Err(usage.into()));
        assert_eq!(run(&staging.arguments(&["--text"])), Err(usage.into()));
        assert_eq!(
            run(&staging.arguments(&["--json", "--json"])),
            Err(usage.into())
        );
    }

    #[test]
    fn altered_bytes_or_a_renamed_archive_fail_verification() {
        let staging = Staging::new("altered");
        fs::write(staging.archive(), b"cfw-release-verifier fixture archivE\n").expect("tamper");
        let error = staging.rejection();
        assert!(
            error.starts_with("updater signature does not match the embedded public key: "),
            "{error}"
        );

        let staging = Staging::new("renamed");
        let renamed = staging.0.join("Clash.for.Mac_9.9.8_aarch64.app.tar.gz");
        fs::rename(staging.archive(), &renamed).expect("rename");
        let arguments = [staging.config(), renamed, staging.signature()].map(OsString::from);
        assert_eq!(
            run(&arguments),
            Err("updater signature names a different archive".into())
        );
    }

    #[test]
    fn a_signature_by_another_key_cannot_start_verification() {
        let staging = Staging::new("other-key");
        fs::write(staging.signature(), V035_SIGNATURE).expect("signature by the product key");
        let error = staging.rejection();
        assert!(
            error.starts_with("cannot initialize updater signature verification: "),
            "{error}"
        );
    }

    #[test]
    fn malformed_keys_and_signatures_are_refused() {
        let staging = Staging::new("malformed");
        staging.write_config("%%%");
        assert!(
            staging
                .rejection()
                .starts_with("public key envelope is invalid base64: ")
        );
        staging.write_config(&STANDARD.encode("not a minisign key"));
        assert!(
            staging
                .rejection()
                .starts_with("embedded updater public key is invalid: ")
        );
        staging.write_config(FIXTURE_PUBLIC_KEY);

        fs::write(staging.signature(), b"\xff").expect("signature");
        assert!(
            staging
                .rejection()
                .starts_with("signature envelope is not UTF-8: ")
        );
        fs::write(staging.signature(), "%%%").expect("signature");
        assert!(
            staging
                .rejection()
                .starts_with("signature envelope is invalid base64: ")
        );
        fs::write(staging.signature(), STANDARD.encode("not a signature")).expect("signature");
        assert!(
            staging
                .rejection()
                .starts_with("updater signature is invalid: ")
        );
    }

    #[test]
    fn every_input_must_be_a_bounded_single_link_regular_file() {
        let staging = Staging::new("inputs");
        fs::write(staging.signature(), b"").expect("empty signature");
        assert_eq!(
            staging.rejection(),
            format!(
                "{} size is outside the accepted 1..=16384 byte range",
                staging.signature().display()
            )
        );
        fs::write(staging.signature(), FIXTURE_SIGNATURE).expect("signature");

        let oversized = vec![b' '; MAX_CONFIG_BYTES as usize + 1];
        fs::write(staging.config(), &oversized).expect("oversized configuration");
        assert_eq!(
            staging.rejection(),
            format!(
                "{} size is outside the accepted 1..=1048576 byte range",
                staging.config().display()
            )
        );
        staging.write_config(FIXTURE_PUBLIC_KEY);

        let linked = staging.0.join("linked.json");
        fs::rename(staging.config(), &linked).expect("move the configuration");
        std::os::unix::fs::symlink(&linked, staging.config()).expect("link");
        assert_eq!(
            staging.rejection(),
            format!("{} is not a regular file", staging.config().display())
        );
        fs::remove_file(staging.config()).expect("remove link");
        fs::rename(&linked, staging.config()).expect("restore the configuration");

        let second = staging.0.join("second-link.tar.gz");
        fs::hard_link(staging.archive(), &second).expect("hard link");
        assert_eq!(
            staging.rejection(),
            format!(
                "{} must have exactly one hard link",
                staging.archive().display()
            )
        );
        fs::remove_file(&second).expect("remove hard link");

        fs::remove_file(staging.archive()).expect("remove the archive");
        let error = staging.rejection();
        assert!(
            error.starts_with(&format!("inspect {}: ", staging.archive().display())),
            "{error}"
        );
    }
}
