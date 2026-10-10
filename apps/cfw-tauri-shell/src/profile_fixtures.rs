//! Stored-profile fixtures shared by the shell's tests.

use std::fs;
use std::path::Path;

use cfw_profiles::ProfileRepository;
use cfw_singbox_config::{ValidatedSingBoxProfile, sha256_hex};

/// Stores and selects a VLESS Reality node, then rewrites it without its
/// uTLS fingerprint the way a build before Reality required uTLS stored it:
/// the digest is the SHA-256 of the stored document and the selection follows
/// that digest. Current validation rejects the result. Returns its id.
pub(crate) fn store_selected_reality_without_utls(
    profiles_dir: &Path,
    repository: &ProfileRepository,
) -> String {
    let profile = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"vless","tag":"proxy","server":"vless.example.com","server_port":443,"credential_ref":{"id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","kind":"vless_uuid"},"tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}}}]}"#,
    )
    .expect("Reality with uTLS");
    let imported = repository
        .import(Some("Reality node"), &profile)
        .expect("import Reality node");
    repository
        .select(&imported.id)
        .expect("select Reality node");
    let earlier =
        profile
            .as_json()
            .replacen(r#","utls":{"enabled":true,"fingerprint":"chrome"}"#, "", 1);
    assert_ne!(earlier, profile.as_json());
    let earlier_digest = sha256_hex(earlier.as_bytes());
    let entries = [
        (
            format!("{}.profile.json", imported.id),
            vec![
                (profile.as_json(), earlier.as_str()),
                (profile.digest(), earlier_digest.as_str()),
            ],
        ),
        (
            "selected-profile-v1.json".to_owned(),
            vec![(profile.digest(), earlier_digest.as_str())],
        ),
    ];
    for (name, replacements) in entries {
        let path = profiles_dir.join(name);
        let mut stored = fs::read_to_string(&path).expect("read stored entry");
        for (from, to) in replacements {
            assert!(stored.contains(from), "stored entry holds the original");
            stored = stored.replacen(from, to, 1);
        }
        // Overwriting keeps the private mode the repository created.
        fs::write(&path, stored).expect("rewrite stored entry");
    }
    imported.id
}
