//! Bounded decoding of controller HTTP responses.

use futures_util::StreamExt;
use serde::Deserialize;

use crate::{
    ConnectionsSnapshot, ControllerError, MAX_CONTROLLER_CONNECTIONS, MAX_CONTROLLER_ERROR_BYTES,
    MAX_CONTROLLER_JSON_BYTES,
};

pub(crate) fn validate_connections(snapshot: &ConnectionsSnapshot) -> Result<(), ControllerError> {
    if snapshot.connections.len() > MAX_CONTROLLER_CONNECTIONS {
        return Err(ControllerError::PayloadLimit {
            resource: "connection set",
            maximum: MAX_CONTROLLER_CONNECTIONS,
        });
    }
    Ok(())
}

pub(crate) async fn decode_response<T>(response: reqwest::Response) -> Result<T, ControllerError>
where
    T: for<'de> Deserialize<'de>,
{
    let status = response.status();
    if !status.is_success() {
        let status = status.as_u16();
        let body = read_bounded_body(response, status, MAX_CONTROLLER_ERROR_BYTES).await?;
        let body = String::from_utf8_lossy(&body).into_owned();
        return Err(ControllerError::Status { status, body });
    }
    let status = status.as_u16();
    let body = read_bounded_body(response, status, MAX_CONTROLLER_JSON_BYTES).await?;
    Ok(serde_json::from_slice(&body)?)
}

pub(crate) async fn decode_empty(response: reqwest::Response) -> Result<(), ControllerError> {
    let status = response.status();
    let status_code = status.as_u16();
    let body = read_bounded_body(response, status_code, MAX_CONTROLLER_ERROR_BYTES).await?;
    if !status.is_success() {
        let body = String::from_utf8_lossy(&body).into_owned();
        let status = status_code;
        return Err(ControllerError::Status { status, body });
    }
    Ok(())
}

async fn read_bounded_body(
    response: reqwest::Response,
    status: u16,
    maximum: usize,
) -> Result<Vec<u8>, ControllerError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(ControllerError::ResponseTooLarge { status, maximum });
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|source| ControllerError::ResponseBodyRead { status, source })?;
        if body.len().saturating_add(chunk.len()) > maximum {
            return Err(ControllerError::ResponseTooLarge { status, maximum });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests;
