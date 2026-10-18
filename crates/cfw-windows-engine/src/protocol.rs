use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, ResolvedProjection, configuration::serialize_bounded};

const PROTOCOL: u32 = 1;
const MAX_REQUEST: usize = cfw_singbox_config::MAX_ENGINE_CONFIG_BYTES + 4096;
const MAX_RESPONSE: usize = 4096;

#[derive(Serialize)]
struct Request<'a> {
    protocol: u32,
    session: &'a str,
    id: u64,
    op: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<&'a serde_json::value::RawValue>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Response {
    protocol: u32,
    session: String,
    id: u64,
    pid: u32,
    version: String,
    state: String,
    digest: String,
    error: String,
}

pub(crate) fn request(
    session: &str,
    id: u64,
    op: &str,
    digest: Option<&str>,
    config: Option<&ResolvedProjection>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let config = config
        .map(|value| serde_json::from_slice::<&serde_json::value::RawValue>(&value.bytes))
        .transpose()
        .map_err(|_| Error::Configuration("invalid prepared configuration"))?;
    serialize_bounded(
        &Request {
            protocol: PROTOCOL,
            session,
            id,
            op,
            digest,
            config,
        },
        MAX_REQUEST,
    )
}

pub(crate) fn exchange(
    writer: &mut impl Write,
    reader: &mut impl Read,
    request: &[u8],
) -> Result<Response, Error> {
    let length = u32::try_from(request.len()).map_err(|_| Error::Protocol("request size"))?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(request)?;
    writer.flush()?;
    let mut header = [0u8; 4];
    reader.read_exact(&mut header)?;
    let size = u32::from_le_bytes(header) as usize;
    if size == 0 || size > MAX_RESPONSE {
        return Err(Error::Protocol("response size"));
    }
    let mut bytes = Zeroizing::new(vec![0; size]);
    reader.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::Protocol("response schema"))
}

impl Response {
    pub(crate) fn validate(
        &self,
        session: &str,
        id: u64,
        pid: u32,
        version: &str,
        state: &str,
        digest: &str,
    ) -> Result<(), Error> {
        if self.protocol != PROTOCOL
            || self.session != session
            || self.id != id
            || self.pid != pid
            || self.version != version
        {
            return Err(Error::Protocol("response identity"));
        }
        if !self.error.is_empty() {
            // Never surface untrusted free-form engine output or config text.
            return Err(Error::Rejected(match self.error.as_str() {
                "invalid_request" => "invalid_request",
                "invalid_start" => "invalid_start",
                "invalid_check" => "invalid_check",
                "invalid_config" => "invalid_config",
                "invalid_log_output" => "invalid_log_output",
                "construct_failed" => "construct_failed",
                "start_failed" => "start_failed",
                "invalid_observation" => "invalid_observation",
                "invalid_stop" => "invalid_stop",
                "close_failed" => "close_failed",
                "invalid_operation" => "invalid_operation",
                _ => return Err(Error::Protocol("unknown rejection code")),
            }));
        }
        if self.state != state || self.digest != digest {
            return Err(Error::Protocol("response state"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;

    fn reply() -> serde_json::Value {
        json!({"protocol":1,"session":"session","id":1,"pid":123,"version":"1.14.2","state":"running","digest":"digest","error":""})
    }

    fn decode(bytes: &[u8]) -> Result<Response, Error> {
        let mut input = (bytes.len() as u32).to_le_bytes().to_vec();
        input.extend_from_slice(bytes);
        exchange(&mut Vec::new(), &mut Cursor::new(input), b"request")
    }

    #[test]
    fn every_response_identity_field_is_checked() {
        let original = reply();
        for (field, changed) in [
            ("protocol", json!(2)),
            ("session", json!("stale")),
            ("id", json!(2)),
            ("pid", json!(124)),
            ("version", json!("wrong")),
            ("state", json!("stopped")),
            ("digest", json!("other")),
        ] {
            let mut value = original.clone();
            value[field] = changed;
            let response = decode(&serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(
                response
                    .validate("session", 1, 123, "1.14.2", "running", "digest")
                    .is_err(),
                "{field}"
            );
        }
        decode(&serde_json::to_vec(&original).unwrap())
            .unwrap()
            .validate("session", 1, 123, "1.14.2", "running", "digest")
            .unwrap();
    }

    #[test]
    fn malformed_duplicate_extra_and_oversized_responses_fail() {
        for bytes in [
            b"{}".as_slice(),
            b"not-json",
            b"{\"protocol\":1,\"protocol\":1}",
            &[0xff],
            b"{} {}",
        ] {
            assert!(decode(bytes).is_err());
        }
        let mut value = reply();
        value["unexpected"] = json!(true);
        assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(
            exchange(
                &mut Vec::new(),
                &mut Cursor::new(4097u32.to_le_bytes()),
                b"r"
            )
            .is_err()
        );
        assert!(exchange(&mut Vec::new(), &mut Cursor::new(1u32.to_le_bytes()), b"r").is_err());
    }

    #[test]
    fn remote_error_text_cannot_leak_through_error_display() {
        let mut value = reply();
        value["error"] = json!("secret-config-value");
        let error = decode(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .validate("session", 1, 123, "1.14.2", "running", "digest")
            .unwrap_err();
        assert!(!error.to_string().contains("secret-config-value"));
        value["error"] = json!("start_failed");
        assert!(matches!(
            decode(&serde_json::to_vec(&value).unwrap())
                .unwrap()
                .validate("session", 1, 123, "1.14.2", "running", "digest"),
            Err(Error::Rejected("start_failed"))
        ));
    }

    #[test]
    fn request_has_a_closed_nonsecret_identity() {
        let bytes = request("0123", 2, "observe", Some("digest"), None).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value,
            json!({"protocol":1,"session":"0123","id":2,"op":"observe","digest":"digest"})
        );
    }
}
