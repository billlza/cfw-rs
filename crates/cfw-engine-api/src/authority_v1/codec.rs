//! The canonical, bounded JSON codec of requests and wire models.

use super::*;

pub fn encode_request(envelope: &RequestEnvelope) -> Result<Vec<u8>, CodecError> {
    envelope.command.validate()?;
    let command = match &envelope.command {
        Command::Handshake(value) => tagged("handshake", value)?,
        Command::PrepareStart(value) => tagged("prepare_start", value)?,
        Command::BindProxyOwner(value) => json!({
            "kind": "bind_proxy_owner",
            "payload": {
                "capability": value.capability.0.transport_copy(),
                "lease_id": value.lease_id,
                "operation": value.operation,
            }
        }),
        Command::RedeemTunnelTicket(value) => json!({
            "kind": "redeem_tunnel_ticket",
            "payload": {
                "lease_id": value.lease_id,
                "operation": value.operation,
                "ticket": value.ticket.0.transport_copy(),
            }
        }),
        Command::AttestReady(value) => tagged("attest_ready", value)?,
        Command::BeginStop(value) => tagged("begin_stop", value)?,
        Command::AttestStopped(value) => tagged("attest_stopped", value)?,
        Command::CancelPrepared(value) => tagged("cancel_prepared", value)?,
        Command::Snapshot(value) => tagged("snapshot", value)?,
    };
    canonical_bytes(&json!({
        "command": command,
        "major": envelope.major,
        "minor": envelope.minor,
        "request_id": envelope.request_id,
        "required_feature_bits": envelope.required_feature_bits,
    }))
}

pub fn decode_request(data: &[u8]) -> Result<RequestEnvelope, CodecError> {
    let root = parse_canonical(data)?;
    exact_keys(
        &root,
        &[
            "command",
            "major",
            "minor",
            "request_id",
            "required_feature_bits",
        ],
    )?;
    let major = integer::<u16>(&root, "major")?;
    if major != MAJOR {
        return Err(CodecError::UnsupportedMajor(major));
    }
    let minor = integer::<u16>(&root, "minor")?;
    if minor != MINOR {
        return Err(CodecError::UnsupportedMinor(minor));
    }
    let required = integer::<u64>(&root, "required_feature_bits")?;
    let unsupported = required & !SUPPORTED_FEATURE_BITS;
    if unsupported != 0 {
        return Err(CodecError::UnsupportedRequiredFeatures(unsupported));
    }
    let request_id = decode_field::<Uuid>(&root, "request_id")?;
    let command_value = root.get("command").ok_or(CodecError::Malformed)?;
    let command_object = command_value.as_object().ok_or(CodecError::InvalidType)?;
    if command_object
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != BTreeSet::from(["kind", "payload"])
    {
        return Err(CodecError::Malformed);
    }
    let kind = command_object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(CodecError::InvalidType)?;
    let payload = command_object.get("payload").ok_or(CodecError::Malformed)?;
    let command = match kind {
        "handshake" => Command::Handshake(decode_value(payload)?),
        "prepare_start" => Command::PrepareStart(decode_value(payload)?),
        "bind_proxy_owner" => Command::BindProxyOwner(decode_capability(payload)?),
        "redeem_tunnel_ticket" => Command::RedeemTunnelTicket(decode_ticket(payload)?),
        "attest_ready" => Command::AttestReady(decode_value(payload)?),
        "begin_stop" => Command::BeginStop(decode_value(payload)?),
        "attest_stopped" => Command::AttestStopped(decode_value(payload)?),
        "cancel_prepared" => Command::CancelPrepared(decode_value(payload)?),
        "snapshot" => Command::Snapshot(decode_value(payload)?),
        _ => return Err(CodecError::UnknownCommand),
    };
    let envelope = RequestEnvelope::new(request_id, required, command)?;
    if encode_request(&envelope)? != data {
        return Err(CodecError::Noncanonical);
    }
    Ok(envelope)
}

pub fn encode_canonical<T: Serialize + WireValidate>(value: &T) -> Result<Vec<u8>, CodecError> {
    value.validate()?;
    let value = serde_json::to_value(value).map_err(|_| CodecError::InvalidType)?;
    canonical_bytes(&value)
}

pub fn decode_canonical<T: DeserializeOwned + Serialize + WireValidate>(
    data: &[u8],
) -> Result<T, CodecError> {
    let value = parse_canonical(data)?;
    let decoded: T = serde_json::from_value(value).map_err(|_| CodecError::InvalidType)?;
    decoded.validate()?;
    if encode_canonical(&decoded)? != data {
        return Err(CodecError::Noncanonical);
    }
    Ok(decoded)
}

pub fn verify_canonical_fixture<T: DeserializeOwned + Serialize + WireValidate>(
    data: &[u8],
) -> Result<(), CodecError> {
    let value: T = decode_canonical(data)?;
    if encode_canonical(&value)? == data {
        Ok(())
    } else {
        Err(CodecError::Noncanonical)
    }
}

pub(super) fn parse_canonical(data: &[u8]) -> Result<Value, CodecError> {
    if data.is_empty() {
        return Err(CodecError::Malformed);
    }
    if data.len() > MAX_ENVELOPE_BYTES {
        return Err(CodecError::MessageTooLarge {
            actual: data.len(),
            maximum: MAX_ENVELOPE_BYTES,
        });
    }
    let value: Value = serde_json::from_slice(data).map_err(|_| CodecError::Malformed)?;
    if !value.is_object() {
        return Err(CodecError::InvalidType);
    }
    validate_shape(&value, 1)?;
    if canonical_bytes(&value)? != data {
        return Err(CodecError::Noncanonical);
    }
    Ok(value)
}

fn validate_shape(value: &Value, depth: usize) -> Result<(), CodecError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(CodecError::BoundViolation);
    }
    match value {
        Value::Object(object) => {
            for child in object.values() {
                validate_shape(child, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_shape(child, depth + 1)?;
            }
        }
        Value::Number(number) if !number.is_u64() && !number.is_i64() => {
            return Err(CodecError::InvalidType);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn canonical_bytes(value: &Value) -> Result<Vec<u8>, CodecError> {
    validate_shape(value, 1)?;
    let data = serde_json::to_vec(value).map_err(|_| CodecError::InvalidType)?;
    if data.len() > MAX_ENVELOPE_BYTES {
        return Err(CodecError::MessageTooLarge {
            actual: data.len(),
            maximum: MAX_ENVELOPE_BYTES,
        });
    }
    Ok(data)
}

fn exact_keys(root: &Value, expected: &[&str]) -> Result<(), CodecError> {
    let object = root.as_object().ok_or(CodecError::InvalidType)?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(CodecError::Malformed)
    }
}

fn integer<T>(root: &Value, key: &str) -> Result<T, CodecError>
where
    T: TryFrom<u64>,
{
    root.get(key)
        .and_then(Value::as_u64)
        .ok_or(CodecError::InvalidType)
        .and_then(|value| T::try_from(value).map_err(|_| CodecError::InvalidType))
}

fn decode_field<T: DeserializeOwned>(root: &Value, key: &str) -> Result<T, CodecError> {
    let value = root.get(key).cloned().ok_or(CodecError::Malformed)?;
    serde_json::from_value(value).map_err(|_| CodecError::InvalidType)
}

fn decode_value<T: DeserializeOwned + WireValidate>(value: &Value) -> Result<T, CodecError> {
    let decoded: T = serde_json::from_value(value.clone()).map_err(|_| CodecError::InvalidType)?;
    decoded.validate()?;
    Ok(decoded)
}

fn decode_capability(value: &Value) -> Result<BindProxyOwnerRequest, CodecError> {
    exact_keys(value, &["capability", "lease_id", "operation"])?;
    let operation = decode_field::<OperationContext>(value, "operation")?;
    operation.validate()?;
    if !matches!(
        operation.mode,
        AuthorityMode::LocalProxy | AuthorityMode::SystemProxy
    ) {
        return Err(CodecError::BoundViolation);
    }
    let bytes = decode_exact_bytes(value, "capability", CAPABILITY_BYTES)?;
    Ok(BindProxyOwnerRequest {
        operation,
        lease_id: decode_field(value, "lease_id")?,
        capability: OwnerCapability::new(&bytes)?,
    })
}

fn decode_ticket(value: &Value) -> Result<RedeemTunnelTicketRequest, CodecError> {
    exact_keys(value, &["lease_id", "operation", "ticket"])?;
    let operation = decode_field::<OperationContext>(value, "operation")?;
    operation.validate()?;
    if operation.mode != AuthorityMode::Tunnel {
        return Err(CodecError::BoundViolation);
    }
    let bytes = decode_exact_bytes(value, "ticket", TICKET_BYTES)?;
    Ok(RedeemTunnelTicketRequest {
        operation,
        lease_id: decode_field(value, "lease_id")?,
        ticket: StartTicket::new(&bytes)?,
    })
}

fn decode_exact_bytes(root: &Value, key: &str, count: usize) -> Result<Vec<u8>, CodecError> {
    let values = root
        .get(key)
        .and_then(Value::as_array)
        .ok_or(CodecError::InvalidType)?;
    if values.len() != count {
        return Err(CodecError::BoundViolation);
    }
    values
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or(CodecError::InvalidType)
        })
        .collect()
}

fn tagged<T: Serialize + WireValidate>(kind: &str, value: &T) -> Result<Value, CodecError> {
    value.validate()?;
    Ok(json!({"kind": kind, "payload": value}))
}

#[cfg(test)]
mod tests;
