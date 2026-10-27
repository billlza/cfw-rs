//! Bounded, nonsecret fixture diagnostics. Never changes a product deadline.
use serde::Serialize;
use std::{collections::VecDeque, io::Write, path::Path, time::Instant};
use uuid::Uuid;

const MAX_EVENTS: usize = 64;
const MAX_BYTES: usize = 16384;
type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Received,
    LockAcquired,
    DispatchFinished,
    DispatchFailed,
    ReplyFinished,
    ReplyFailed,
}

#[derive(Serialize)]
struct Event {
    request: u64,
    command: &'static str,
    role: &'static str,
    phase: Phase,
    since_start_ms: u64,
    request_elapsed_ms: u64,
}

pub(super) struct Request {
    id: u64,
    command: &'static str,
    role: &'static str,
    started: Instant,
}

pub(super) struct Trace {
    source: String,
    trace_id: Uuid,
    started: Instant,
    requests: u64,
    event_count: u64,
    events: VecDeque<Event>,
}
impl Trace {
    pub(super) fn new(source: String) -> Result<Self> {
        if source.len() != 40
            || !source
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("request timing source is invalid".into());
        }
        Ok(Self {
            source,
            trace_id: Uuid::new_v4(),
            started: Instant::now(),
            requests: 0,
            event_count: 0,
            events: VecDeque::new(),
        })
    }

    pub(super) fn begin(&mut self, command: &'static str, role: &'static str) -> Result<Request> {
        // Only static command names and role labels enter this recorder. No
        // request body, credential, ticket, SID or configuration is accepted.
        if command.is_empty()
            || command.len() > 32
            || !command.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            || !matches!(role, "desktop" | "user-agent")
        {
            return Err("request timing label is invalid".into());
        }
        self.requests = self
            .requests
            .checked_add(1)
            .ok_or("request timing counter overflow")?;
        let request = Request {
            id: self.requests,
            command,
            role,
            started: Instant::now(),
        };
        self.mark(&request, Phase::Received)?;
        Ok(request)
    }

    pub(super) fn mark(&mut self, request: &Request, phase: Phase) -> Result<()> {
        let event = Event {
            request: request.id,
            command: request.command,
            role: request.role,
            phase,
            since_start_ms: self
                .started
                .elapsed()
                .as_millis()
                .try_into()
                .map_err(|_| "request timing clock overflow")?,
            request_elapsed_ms: request
                .started
                .elapsed()
                .as_millis()
                .try_into()
                .map_err(|_| "request timing clock overflow")?,
        };
        self.event_count = self
            .event_count
            .checked_add(1)
            .ok_or("request timing event counter overflow")?;
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
        Ok(())
    }

    pub(super) fn encode(&self, process_id: u32) -> Result<Vec<u8>> {
        if process_id == 0 {
            return Err("request timing process identity is invalid".into());
        }
        let bytes = serde_json::to_vec(&serde_json::json!({
            "document":"cfw-native-authority-request-timing-v2",
            "source":self.source,"trace_id":self.trace_id,
            "process_id":process_id,"requests":self.requests,
            "event_count":self.event_count,"omitted_events":self.event_count-self.events.len() as u64,
            "events":self.events,
        })).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_BYTES {
            return Err("request timing record exceeds its bound".into());
        }
        Ok(bytes)
    }

    pub(super) fn persist(&self, root: &Path, process_id: u32) -> Result<()> {
        let bytes = self.encode(process_id)?;
        // SCM can reuse a PID for a later fixture process. Each service run
        // needs its own receipt even when independent roots share an archive.
        let path = root.join(format!(
            "service-request-timing-{}-{process_id}.txt",
            self.trace_id
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| format!("create request timing receipt {}: {e}", path.display()))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("write request timing receipt {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_retains_a_bounded_tail_and_reports_omitted_events() {
        let mut trace = Trace::new("a".repeat(40)).unwrap();
        for _ in 0..100 {
            let request = trace.begin("ready", "user-agent").unwrap();
            for phase in [
                Phase::LockAcquired,
                Phase::DispatchFinished,
                Phase::ReplyFinished,
            ] {
                trace.mark(&request, phase).unwrap();
            }
        }
        let bytes = trace.encode(1).unwrap();
        assert!(bytes.len() <= MAX_BYTES);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["requests"], 100);
        assert_eq!(value["event_count"], 400);
        assert_eq!(value["omitted_events"], 336);
        assert_eq!(value["events"].as_array().unwrap().len(), MAX_EVENTS);
        assert_eq!(value["events"][0]["request"], 85);
        assert_eq!(value["events"][63]["phase"], "reply_finished");
        assert_eq!(value["events"][0].as_object().unwrap().len(), 6);
    }

    #[test]
    fn timing_records_failure_phases_and_validates_only_public_labels() {
        assert!(Trace::new("unknown".into()).is_err());
        let mut trace = Trace::new("b".repeat(40)).unwrap();
        assert!(trace.begin("body with spaces", "desktop").is_err());
        assert!(trace.begin("ready", "unknown-role").is_err());
        let request = trace.begin("ready", "user-agent").unwrap();
        trace.mark(&request, Phase::DispatchFailed).unwrap();
        trace.mark(&request, Phase::ReplyFailed).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&trace.encode(123).unwrap()).unwrap();
        assert_eq!(value["events"][1]["phase"], "dispatch_failed");
        assert_eq!(value["events"][2]["phase"], "reply_failed");
        assert!(trace.encode(0).is_err());
    }
}
