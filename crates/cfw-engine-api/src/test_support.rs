//! Identities, references and profiles shared by the crate's unit tests.

use cfw_singbox_config::{
    CredentialAudience, CredentialKind, CredentialRef, ValidatedSingBoxProfile,
};

use crate::EngineCommandContext;

pub(crate) const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
pub(crate) const CREDENTIAL_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
pub(crate) const VAULT_REVISION: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
pub(crate) const INSTALLATION_ID: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

pub(crate) fn context() -> EngineCommandContext {
    EngineCommandContext {
        installation_id: INSTALLATION_ID.into(),
        config_epoch: 1,
        generation: 2,
    }
}

/// A canonical version-4 UUID whose last group carries `n`.
pub(crate) fn uuid(n: usize) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

pub(crate) fn trojan_reference(id: &str) -> CredentialRef {
    CredentialRef::new(id, CredentialKind::TrojanPassword).expect("canonical reference")
}

pub(crate) fn audience(profile_id: &str) -> CredentialAudience {
    CredentialAudience::new(profile_id, "ef".repeat(32)).expect("canonical audience")
}

/// One Trojan node on `server_port` whose password is the credential `id`.
pub(crate) fn trojan_profile(id: &str, server_port: u16) -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":{server_port},"credential_ref":{{"id":"{id}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"proxy.example.com"}}}}]}}"#
    ))
    .expect("typed profile")
}
