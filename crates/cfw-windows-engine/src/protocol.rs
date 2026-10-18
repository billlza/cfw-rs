use std::{
    io::{Read, Write},
    sync::mpsc::{self, Receiver, SyncSender, TrySendError},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, ResolvedProjection, configuration::serialize_bounded};

const PROTOCOL: u32 = 1;
const MAX_REQUEST: usize = cfw_singbox_config::MAX_ENGINE_CONFIG_BYTES + 4096;
const MAX_RESPONSE: usize = 4096;

pub(crate) struct Exchange {
    pub bytes: Zeroizing<Vec<u8>>,
    pub result: SyncSender<Result<Response, Error>>,
}

pub(crate) fn submit(
    sender: &SyncSender<Exchange>,
    sequence: &mut u64,
    session: &str,
    operation: &str,
    digest: Option<&str>,
    config: Option<&ResolvedProjection>,
    deadline: Instant,
) -> Result<Receiver<Result<Response, Error>>, Error> {
    let next = sequence
        .checked_add(1)
        .ok_or(Error::Protocol("request sequence exhausted"))?;
    let bytes = request(session, next, operation, digest, config)?;
    let (result, receiver) = mpsc::sync_channel(1);
    let mut pending = Exchange { bytes, result };
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(Error::Timeout)?;
        match sender.try_send(pending) {
            Ok(()) => {
                // The worker requires contiguous IDs. Neither serialization
                // failure nor queue refusal is a request on that wire.
                *sequence = next;
                return Ok(receiver);
            }
            Err(TrySendError::Full(request)) => {
                // A preceding expired waiter may still occupy the bounded
                // queue. Wait for capacity within this same RPC deadline;
                // retry only admission, never an already admitted operation.
                pending = request;
                thread::sleep(remaining.min(Duration::from_millis(1)));
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(Error::Protocol("control channel disconnected"));
            }
        }
    }
}

pub(crate) fn run_control(
    input: &mut impl Write,
    output: &mut impl Read,
    receiver: Receiver<Exchange>,
) {
    let mut transport_failed = false;
    while let Ok(work) = receiver.recv() {
        let result = if transport_failed {
            Err(Error::Protocol("control transport requires owner recovery"))
        } else {
            exchange(input, output, &work.bytes)
        };
        transport_failed |= result.is_err();
        // An expired per-operation waiter is not owner loss. The owner must
        // restore proxy settings before closing pipes or terminating its job.
        // A late response is retired, never admitted to another request.
        if let Err(retired_response) = work.result.send(result) {
            drop(retired_response);
        }
    }
    // Only channel closure from the process owner releases the control pipes.
}

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

    #[test]
    fn full_queue_timeout_does_not_consume_a_protocol_sequence() {
        let (sender, requests) = mpsc::sync_channel(1);
        let mut sequence = 0;
        let first = submit(
            &sender,
            &mut sequence,
            "session",
            "hello",
            None,
            None,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        drop(first);
        let result = submit(
            &sender,
            &mut sequence,
            "session",
            "observe",
            Some("digest"),
            None,
            Instant::now(),
        );
        assert_eq!(sequence, 1, "an unqueued request must not consume an ID");
        assert!(matches!(result, Err(Error::Timeout)));
        let expired = requests.try_recv().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&expired.bytes).unwrap();
        assert_eq!(value["id"], 1);
        assert!(expired.result.send(Err(Error::Timeout)).is_err());
        assert!(matches!(
            requests.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        let _response = submit(
            &sender,
            &mut sequence,
            "session",
            "stop",
            Some("digest"),
            None,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&requests.try_recv().unwrap().bytes).unwrap();
        assert_eq!(sequence, 2);
        assert_eq!(
            value["id"], 2,
            "the real worker rejects a gap in request IDs"
        );
        assert_eq!(value["op"], "stop");
    }

    #[test]
    fn expired_response_and_queue_pressure_preserve_the_control_stream() {
        struct GatedReader {
            bytes: Cursor<Vec<u8>>,
            gate: Option<(SyncSender<()>, Receiver<()>)>,
        }
        impl Read for GatedReader {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                if let Some((entered, resume)) = self.gate.take() {
                    entered.send(()).unwrap();
                    resume.recv_timeout(Duration::from_secs(2)).unwrap();
                }
                self.bytes.read(output)
            }
        }
        let mut bytes = Vec::new();
        for id in 1..=3 {
            let mut value = reply();
            value["id"] = json!(id);
            if id == 3 {
                value["state"] = json!("stopped");
            }
            let encoded = serde_json::to_vec(&value).unwrap();
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&encoded);
        }
        let (sender, requests) = mpsc::sync_channel(1);
        let (entered, entered_waiter) = mpsc::sync_channel(1);
        let (resume, resumed) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let mut writer = Vec::new();
            let mut reader = GatedReader {
                bytes: Cursor::new(bytes),
                gate: Some((entered, resumed)),
            };
            run_control(&mut writer, &mut reader, requests);
            writer
        });
        let mut sequence = 0;
        let first = submit(
            &sender,
            &mut sequence,
            "session",
            "observe",
            Some("digest"),
            None,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        entered_waiter.recv_timeout(Duration::from_secs(2)).unwrap();
        // The accepted request reaches the transport, but its caller expires
        // before the gated response can arrive. The real control loop is used.
        assert!(matches!(
            first.recv_timeout(Duration::ZERO),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(first);
        let second = submit(
            &sender,
            &mut sequence,
            "session",
            "observe",
            Some("digest"),
            None,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        let wait = Duration::from_millis(20);
        let start = Instant::now();
        let refused = submit(
            &sender,
            &mut sequence,
            "session",
            "observe",
            Some("digest"),
            None,
            start + wait,
        );
        assert!(matches!(refused, Err(Error::Timeout)));
        assert!(start.elapsed() >= wait);
        assert_eq!(sequence, 2);
        let pending_sender = sender.clone();
        let (admitted, admitted_waiter) = mpsc::sync_channel(1);
        let admission = thread::spawn(move || {
            let mut sequence = sequence;
            let last = submit(
                &pending_sender,
                &mut sequence,
                "session",
                "stop",
                Some("digest"),
                None,
                Instant::now() + Duration::from_secs(2),
            );
            admitted.send((sequence, last)).unwrap();
        });
        assert!(matches!(
            admitted_waiter.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        resume.send(()).unwrap();
        second
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap()
            .validate("session", 2, 123, "1.14.2", "running", "digest")
            .unwrap();
        let (sequence, last) = admitted_waiter
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert_eq!(sequence, 3);
        let last = last.unwrap();
        last.recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap()
            .validate("session", 3, 123, "1.14.2", "stopped", "digest")
            .unwrap();
        admission.join().unwrap();
        drop(sender);
        let mut wire = Cursor::new(worker.join().unwrap());
        for id in 1..=3 {
            let mut length = [0; 4];
            wire.read_exact(&mut length).unwrap();
            let mut bytes = vec![0; u32::from_le_bytes(length) as usize];
            wire.read_exact(&mut bytes).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["id"], id);
        }
        assert_eq!(wire.position() as usize, wire.get_ref().len());
    }

    #[test]
    fn expired_disconnected_and_exhausted_admission_never_enqueues() {
        let (sender, requests) = mpsc::sync_channel(1);
        let mut sequence = 0;
        assert!(matches!(
            submit(
                &sender,
                &mut sequence,
                "session",
                "start",
                None,
                None,
                Instant::now(),
            ),
            Err(Error::Timeout)
        ));
        assert_eq!(sequence, 0);
        assert!(matches!(
            requests.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        sequence = u64::MAX;
        assert!(matches!(
            submit(
                &sender,
                &mut sequence,
                "session",
                "observe",
                None,
                None,
                Instant::now() + Duration::from_secs(2),
            ),
            Err(Error::Protocol("request sequence exhausted"))
        ));
        assert_eq!(sequence, u64::MAX);
        assert!(matches!(
            requests.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        drop(requests);
        sequence = 0;
        assert!(matches!(
            submit(
                &sender,
                &mut sequence,
                "session",
                "observe",
                None,
                None,
                Instant::now() + Duration::from_secs(2),
            ),
            Err(Error::Protocol("control channel disconnected"))
        ));
        assert_eq!(sequence, 0);
    }
}
