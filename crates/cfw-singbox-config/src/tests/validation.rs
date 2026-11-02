use serde_json::Value;

use crate::{
    ConfigError, CredentialKind, CredentialSecret, MAX_OUTBOUNDS, MAX_PROFILE_BYTES,
    MAX_PROFILE_NODES, ProfileParseError, ValidatedSingBoxProfile,
};

const SS_ID: &str = "11111111-1111-4111-8111-111111111111";
const VMESS_ID: &str = "22222222-2222-4222-8222-222222222222";
const VLESS_ID: &str = "33333333-3333-4333-8333-333333333333";
const TROJAN_ID: &str = "44444444-4444-4444-8444-444444444444";
const HYSTERIA_ID: &str = "55555555-5555-4555-8555-555555555555";
const HYSTERIA_OBFS_ID: &str = "66666666-6666-4666-8666-666666666666";
const ANYTLS_ID: &str = "88888888-8888-4888-8888-888888888888";
const TUIC_UUID_ID: &str = "99999999-9999-4999-8999-999999999999";
const TUIC_PASSWORD_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab";

mod credential_refs;
mod endpoints;
mod parsing;
mod quic;
mod tls;
mod transports;
