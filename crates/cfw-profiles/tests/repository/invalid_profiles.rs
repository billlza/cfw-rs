//! Stored profiles that no longer pass validation, modelled on a Reality
//! node an earlier 0.5 build stored before Reality required uTLS.

use std::path::PathBuf;

use cfw_profiles::{ProfileError, ProfileLabel};
use cfw_singbox_config::{ConfigError, sha256_hex};

use crate::private_file_fixture::write_private;
use crate::support::{selection_path, stored_path};

mod damaged;
mod listing;
mod refusals;
mod reimport;
mod selected;

/// A subscription VLESS Reality node without a uTLS fingerprint, exactly as
/// the 0.5 line stored and selected it before Reality required uTLS (bytes
/// written by commit 8415a1b).
pub(crate) const EARLIER_REALITY_ID: &str = "3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d";
pub(crate) const EARLIER_REALITY_DIGEST: &str =
    "0a212f0622cc414ed98a9a138233c8b6224b7625fc6e7d6f9ab1db756d5bc5fa";
pub(crate) const EARLIER_REALITY_ENVELOPE: &str = r#"{"schema_version":1,"id":"3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d","name":"Reality node","profile":{"outbounds":[{"credential_ref":{"id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","kind":"vless_uuid"},"flow":"xtls-rprx-vision","server":"vless.example.com","server_port":443,"tag":"proxy","tls":{"enabled":true,"reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"},"server_name":"www.example.com"},"type":"vless"}],"route":{"final":"proxy"}},"digest":"0a212f0622cc414ed98a9a138233c8b6224b7625fc6e7d6f9ab1db756d5bc5fa","created_epoch_secs":1791415969,"source_url":"https://subscription.example/profile?token=private-test-value"}"#;
pub(crate) const EARLIER_REALITY_SELECTION: &str = r#"{"schema_version":1,"profile_id":"3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d","profile_digest":"0a212f0622cc414ed98a9a138233c8b6224b7625fc6e7d6f9ab1db756d5bc5fa"}"#;

/// Places the earlier envelope in an existing repository, optionally with
/// the selection record the earlier build wrote for it.
pub(crate) fn store_earlier_reality_profile(root: &std::path::Path, selected: bool) -> PathBuf {
    let path = stored_path(root, EARLIER_REALITY_ID);
    write_private(&path, EARLIER_REALITY_ENVELOPE.as_bytes());
    if selected {
        write_private(&selection_path(root), EARLIER_REALITY_SELECTION.as_bytes());
    }
    path
}

/// The document text inside the earlier envelope.
pub(crate) fn earlier_document() -> &'static str {
    EARLIER_REALITY_ENVELOPE
        .split_once(r#""profile":"#)
        .and_then(|(_, rest)| rest.split_once(r#","digest":"#))
        .map(|(document, _)| document)
        .expect("earlier envelope has a document")
}

/// The earlier envelope for an edited document, with the digest an earlier
/// build would have stored for that document.
pub(crate) fn earlier_envelope_with_document(edit: impl FnOnce(&str) -> String) -> String {
    let edited = edit(earlier_document());
    EARLIER_REALITY_ENVELOPE
        .replacen(earlier_document(), &edited, 1)
        .replacen(EARLIER_REALITY_DIGEST, &sha256_hex(edited.as_bytes()), 1)
}

pub(crate) fn reality_requires_utls() -> ConfigError {
    ConfigError::UnsupportedPolicyShape {
        path: "$.outbounds[0].tls.utls".into(),
        reason: "Reality requires uTLS".into(),
    }
}

pub(crate) fn earlier_label() -> ProfileLabel {
    ProfileLabel {
        id: EARLIER_REALITY_ID.into(),
        name: "Reality node".into(),
    }
}

pub(crate) fn is_earlier_invalid(error: &ProfileError) -> bool {
    matches!(
        error,
        ProfileError::StoredProfileInvalid { id, name, source }
            if id == EARLIER_REALITY_ID && name == "Reality node" && *source == reality_requires_utls()
    )
}
