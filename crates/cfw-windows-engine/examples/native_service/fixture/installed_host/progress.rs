use super::*;
use serde::{Deserialize, Serialize};
use std::io::Write;

const MAX_PHASES: usize = 96;
const PHASES: &[&str] = &[
    "open_desktop",
    "configuration_checks",
    "configuration_checks_complete",
    "host_start",
    "host_ready",
    "host_query",
    "host_query_complete",
    "host_stop",
    "host_off",
    "backend_open",
    "backend_check",
    "backend_check_complete",
    "backend_rejected_prepare",
    "backend_rejection_received",
    "backend_rejection_retired",
    "backend_start",
    "backend_ready",
    "backend_queries",
    "backend_queries_complete",
    "backend_traffic_complete",
    "backend_stop",
    "backend_off",
    "backend_engine_exit",
    "backend_exited_query_rejected",
    "backend_failed_stop",
    "backend_recovery_off",
    "complete",
];
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Phase {
    kind: String,
    source: String,
    ordinal: u32,
    phase: String,
    generation: u64,
    elapsed_millis: u64,
}
pub(super) struct Progress {
    started: Instant,
    ordinal: u32,
    source: String,
}
fn source() -> Result<String> {
    let value = std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e| e.to_string())?;
    if value.len() != 40
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid installed trace source".into());
    }
    Ok(value)
}
impl Progress {
    pub(super) fn new() -> Result<Self> {
        Ok(Self {
            started: Instant::now(),
            ordinal: 0,
            source: source()?,
        })
    }
    pub(super) fn record(&mut self, phase: &'static str, generation: u64) -> Result<()> {
        if !PHASES.contains(&phase) || self.ordinal as usize >= MAX_PHASES {
            return Err("installed trace phase exceeds its contract".into());
        }
        self.ordinal += 1;
        let record = Phase {
            kind: "installed_runtime_phase".into(),
            source: self.source.clone(),
            ordinal: self.ordinal,
            phase: phase.into(),
            generation,
            elapsed_millis: self
                .started
                .elapsed()
                .as_millis()
                .try_into()
                .map_err(|_| "trace clock overflow")?,
        };
        let mut line = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
        if line.len() > 256 {
            return Err("installed trace phase exceeds its bound".into());
        }
        line.push(b'\n');
        let mut output = std::io::stdout().lock();
        output
            .write_all(&line)
            .and_then(|()| output.flush())
            .map_err(|e| e.to_string())
    }
}
pub(super) fn decode(bytes: &[u8]) -> Result<(serde_json::Value, Vec<Phase>)> {
    let expected = source()?;
    let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    let mut phases: Vec<Phase> = Vec::new();
    let mut final_report = None;
    for line in text.lines() {
        if final_report.is_some() || line.is_empty() {
            return Err("unexpected line after installed report".into());
        }
        let value: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
        if value.get("kind").is_some() {
            let phase: Phase = serde_json::from_value(value).map_err(|e| e.to_string())?;
            if line.len() > 256
                || phases.len() >= MAX_PHASES
                || phase.kind != "installed_runtime_phase"
                || phase.source != expected
                || phase.ordinal as usize != phases.len() + 1
                || !PHASES.contains(&phase.phase.as_str())
                || phases
                    .last()
                    .is_some_and(|prior| prior.elapsed_millis > phase.elapsed_millis)
            {
                return Err("installed phase trace is unrelated or malformed".into());
            }
            phases.push(phase);
        } else {
            if line.len() > 16384 {
                return Err("installed final report exceeds its original bound".into());
            }
            final_report = Some(value);
        }
    }
    if phases
        .first()
        .is_none_or(|phase| phase.phase != "open_desktop")
        || phases.last().is_none_or(|phase| phase.phase != "complete")
    {
        return Err("installed runtime phase trace is incomplete".into());
    }
    Ok((
        final_report.ok_or("installed runtime final report is missing")?,
        phases,
    ))
}
