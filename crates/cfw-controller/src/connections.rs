//! Connection snapshots and their lenient Clash field decoding.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionsSnapshot {
    #[serde(alias = "uploadTotal", alias = "upload_total")]
    pub upload: u64,
    #[serde(alias = "downloadTotal", alias = "download_total")]
    pub download: u64,
    #[serde(default, deserialize_with = "null_as_empty_vec")]
    pub connections: Vec<Connection>,
}

fn null_as_empty_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

/// clash-rs emits ports as integers; mihomo often emits strings. Accept either.
fn string_or_number<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or number")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(value.to_string())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(value)
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(value.to_string())
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(value.to_string())
        }

        fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.fract() == 0.0 && value >= 0.0 && value <= u64::MAX as f64 {
                Ok((value as u64).to_string())
            } else {
                Ok(value.to_string())
            }
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(String::new())
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(String::new())
        }
    }

    deserializer.deserialize_any(Visitor)
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Connection {
    pub id: String,
    pub upload: u64,
    pub download: u64,
    pub start: String,
    pub chains: Vec<String>,
    pub rule: String,
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,
    pub metadata: ConnectionMetadata,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionMetadata {
    pub network: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "sourceIP", alias = "source_ip")]
    pub source_ip: String,
    #[serde(rename = "destinationIP", alias = "destination_ip")]
    pub destination_ip: String,
    #[serde(
        rename = "sourcePort",
        alias = "source_port",
        deserialize_with = "string_or_number"
    )]
    pub source_port: String,
    #[serde(
        rename = "destinationPort",
        alias = "destination_port",
        deserialize_with = "string_or_number"
    )]
    pub destination_port: String,
    pub host: String,
    #[serde(rename = "dnsMode", alias = "dns_mode")]
    pub dns_mode: String,
    #[serde(rename = "processPath", alias = "process_path")]
    pub process_path: String,
}

#[cfg(test)]
mod tests;
