//! Non-sensitive, product-owned observations for physical release validation.
//!
//! The signed Host writes a closed event shape to Apple Unified Logging.  The
//! physical collector may read these events, but it cannot ask the product to
//! report an arbitrary value or execute an operation.  Credentials, profile
//! documents, controller secrets, migration tickets and native error text have
//! no field in this schema.

use std::ffi::{CString, c_char, c_void};
use std::mem::{MaybeUninit, size_of};
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(test, feature = "physical-release-evidence"))]
use cfw_engine_api::EngineMode;
use cfw_engine_api::{EngineOwner, EngineSnapshot, EngineState};
#[cfg(any(test, feature = "physical-release-evidence"))]
use cfw_singbox_config::ReleaseDnsEvidenceCase;
use serde::Serialize;
use serde_json::{Map, Value, json};

const DOCUMENT: &str = "cfw-product-observation-event-v1";
const MESSAGE_PREFIX: &str = "cfw-release-observation-v1 ";
const SUBSYSTEM: &[u8] = b"com.bill.clashformac\0";
const CATEGORY: &[u8] = b"release-observation\0";
const MAX_MESSAGE_BYTES: usize = 8 * 1024;

static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static BUNDLE_CANDIDATE: OnceLock<Result<CandidateObservation, String>> = OnceLock::new();
static PROCESS_OBSERVATION: OnceLock<Result<ProcessObservation, String>> = OnceLock::new();
static RELEASE_LOG: OnceLock<Result<usize, String>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CandidateObservation {
    version: String,
    build_number: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct ProcessObservation {
    pid: u32,
    start_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ProductStateObservation {
    desired_mode: cfw_engine_api::EngineMode,
    generation: u64,
    config_digest: Option<String>,
    phase: &'static str,
    owner: Option<EngineOwner>,
    ready: bool,
    ipv6_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg(any(test, feature = "physical-release-evidence"))]
pub struct DnsEvidenceSnapshotReceipt {
    generation: u64,
    config_digest: String,
    phase: &'static str,
    owner: EngineOwner,
    ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "physical-release-evidence")]
pub struct DnsEvidenceTransactionReceipt {
    pub role: &'static str,
    pub baseline: DnsEvidenceSnapshotReceipt,
    pub test: DnsEvidenceSnapshotReceipt,
    pub restore: DnsEvidenceSnapshotReceipt,
    pub candidate_observation_sequence: u64,
}

#[cfg(any(test, feature = "physical-release-evidence"))]
impl DnsEvidenceSnapshotReceipt {
    pub(crate) fn from_ready_tunnel(snapshot: &EngineSnapshot) -> Result<Self, String> {
        let Some(config_digest) = snapshot.config_digest.as_ref() else {
            return Err("DNS evidence snapshot has no configuration digest".to_owned());
        };
        let EngineState::TunnelActive { runtime } = &snapshot.state else {
            return Err("DNS evidence snapshot is not TunnelActive".to_owned());
        };
        if snapshot.desired_mode != EngineMode::Tunnel
            || snapshot.generation == 0
            || config_digest.len() != 64
            || !config_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || runtime.owner != EngineOwner::PacketTunnelSystemExtension
            || runtime.context.generation != snapshot.generation
            || runtime.config_digest != *config_digest
            || !runtime.ready
        {
            return Err("DNS evidence snapshot identity is not exact and ready".to_owned());
        }
        Ok(Self {
            generation: snapshot.generation,
            config_digest: config_digest.clone(),
            phase: "tunnel_active",
            owner: runtime.owner,
            ready: runtime.ready,
        })
    }
}

fn product_state(snapshot: &EngineSnapshot, ipv6_enabled: bool) -> ProductStateObservation {
    let (phase, owner, ready) = match &snapshot.state {
        EngineState::Off => ("off", None, false),
        EngineState::ProxyStarting { .. } => ("proxy_starting", None, false),
        EngineState::ProxyActive { runtime } => {
            ("proxy_active", Some(runtime.owner), runtime.ready)
        }
        EngineState::ProxyStopping { .. } => ("proxy_stopping", None, false),
        EngineState::TunnelInstalling { .. } => ("tunnel_installing", None, false),
        EngineState::AwaitingApproval { .. } => ("awaiting_approval", None, false),
        EngineState::TunnelStarting { .. } => ("tunnel_starting", None, false),
        EngineState::TunnelActive { runtime } => {
            ("tunnel_active", Some(runtime.owner), runtime.ready)
        }
        EngineState::TunnelStopping { .. } => ("tunnel_stopping", None, false),
        // Native error text may contain environmental or path information.  A
        // stable phase and the public target/generation in EngineSnapshot are
        // sufficient for release observation; the free-form error is omitted.
        EngineState::Failed { .. } => ("failed", None, false),
    };
    ProductStateObservation {
        desired_mode: snapshot.desired_mode,
        generation: snapshot.generation,
        config_digest: snapshot.config_digest.clone(),
        phase,
        owner,
        ready,
        ipv6_enabled,
    }
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect::<std::collections::BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect::<Map<_, _>>())
        }
        scalar => scalar,
    }
}

fn build_engine_snapshot_message(
    snapshot: &EngineSnapshot,
    ipv6_enabled: bool,
    candidate: &CandidateObservation,
    process: ProcessObservation,
    sequence: u64,
    recorded_unix_ms: u64,
) -> Result<String, String> {
    if sequence == 0 {
        return Err("release observation sequence must be positive".to_owned());
    }
    let value = canonicalize(json!({
        "schema_version": 1,
        "document": DOCUMENT,
        "component": "host",
        "event": "engine_snapshot",
        "sequence": sequence,
        "recorded_unix_ms": recorded_unix_ms,
        "process": process,
        "candidate": candidate,
        "payload": {
            "state": product_state(snapshot, ipv6_enabled),
        },
    }));
    let encoded = serde_json::to_string(&value)
        .map_err(|error| format!("release observation JSON encoding failed: {error}"))?;
    let message = format!("{MESSAGE_PREFIX}{encoded}");
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(format!(
            "release observation exceeds the {MAX_MESSAGE_BYTES}-byte limit"
        ));
    }
    Ok(message)
}

#[cfg(any(test, feature = "physical-release-evidence"))]
fn dns_role(case: ReleaseDnsEvidenceCase) -> &'static str {
    match case {
        ReleaseDnsEvidenceCase::PrimaryIpv4 => "primary_ipv4",
        ReleaseDnsEvidenceCase::PrimaryIpv6 => "primary_ipv6",
        ReleaseDnsEvidenceCase::SecondaryIpv4 => "secondary_ipv4",
        ReleaseDnsEvidenceCase::SecondaryIpv6 => "secondary_ipv6",
    }
}

#[derive(Clone, Copy)]
#[cfg(any(test, feature = "physical-release-evidence"))]
struct ObservationMetadata<'a> {
    candidate: &'a CandidateObservation,
    process: ProcessObservation,
    sequence: u64,
    recorded_unix_ms: u64,
}

#[cfg(any(test, feature = "physical-release-evidence"))]
fn build_dns_evidence_transaction_message(
    case: ReleaseDnsEvidenceCase,
    baseline: &DnsEvidenceSnapshotReceipt,
    test: &DnsEvidenceSnapshotReceipt,
    restore: &DnsEvidenceSnapshotReceipt,
    metadata: ObservationMetadata<'_>,
) -> Result<String, String> {
    if metadata.sequence == 0 {
        return Err("release observation sequence must be positive".to_owned());
    }
    if !(baseline.generation < test.generation && test.generation < restore.generation)
        || baseline.config_digest != restore.config_digest
        || baseline.config_digest == test.config_digest
        || baseline.phase != "tunnel_active"
        || test.phase != "tunnel_active"
        || restore.phase != "tunnel_active"
        || baseline.owner != EngineOwner::PacketTunnelSystemExtension
        || test.owner != EngineOwner::PacketTunnelSystemExtension
        || restore.owner != EngineOwner::PacketTunnelSystemExtension
        || !baseline.ready
        || !test.ready
        || !restore.ready
    {
        return Err("DNS evidence transaction identity is inconsistent".to_owned());
    }
    let value = canonicalize(json!({
        "schema_version": 1,
        "document": DOCUMENT,
        "component": "host",
        "event": "dns_evidence_transaction",
        "sequence": metadata.sequence,
        "recorded_unix_ms": metadata.recorded_unix_ms,
        "process": metadata.process,
        "candidate": metadata.candidate,
        "payload": {
            "receipt": {
                "role": dns_role(case),
                "baseline": baseline,
                "test": test,
                "restore": restore,
                "candidate_observation_sequence": metadata.sequence,
            },
        },
    }));
    let encoded = serde_json::to_string(&value)
        .map_err(|error| format!("release observation JSON encoding failed: {error}"))?;
    let message = format!("{MESSAGE_PREFIX}{encoded}");
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(format!(
            "release observation exceeds the {MAX_MESSAGE_BYTES}-byte limit"
        ));
    }
    Ok(message)
}

fn read_bundle_candidate(executable: &Path) -> Result<CandidateObservation, String> {
    let contents = executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "release observation cannot locate the app Contents directory".to_owned())?;
    let info_path = contents.join("Info.plist");
    let info = plist::Value::from_file(&info_path)
        .map_err(|error| format!("release observation cannot read Info.plist: {error}"))?;
    let dictionary = info
        .as_dictionary()
        .ok_or_else(|| "release observation Info.plist is not a dictionary".to_owned())?;
    let version = dictionary
        .get("CFBundleShortVersionString")
        .and_then(plist::Value::as_string)
        .ok_or_else(|| "release observation version is unavailable".to_owned())?;
    let build_number = dictionary
        .get("CFBundleVersion")
        .and_then(plist::Value::as_string)
        .ok_or_else(|| "release observation build number is unavailable".to_owned())?;
    if version != env!("CARGO_PKG_VERSION") {
        return Err("release observation bundle/package versions differ".to_owned());
    }
    if build_number.is_empty()
        || build_number.len() > 18
        || build_number.starts_with('0')
        || !build_number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("release observation build number is not canonical".to_owned());
    }
    Ok(CandidateObservation {
        version: version.to_owned(),
        build_number: build_number.to_owned(),
    })
}

fn current_process_observation() -> Result<ProcessObservation, String> {
    let pid = std::process::id();
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = size_of::<libc::proc_bsdinfo>();
    let returned = unsafe {
        // SAFETY: `info` points to a writable `proc_bsdinfo` allocation of the
        // exact byte count passed to libproc, and the current PID remains valid
        // for the duration of this call.
        libc::proc_pidinfo(
            i32::try_from(pid).map_err(|_| "release observation PID exceeds i32")?,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            i32::try_from(size).map_err(|_| "proc_bsdinfo size exceeds i32")?,
        )
    };
    if returned != i32::try_from(size).map_err(|_| "proc_bsdinfo size exceeds i32")? {
        return Err("release observation cannot read the current process identity".to_owned());
    }
    let info = unsafe {
        // SAFETY: libproc returned the exact `proc_bsdinfo` size above.
        info.assume_init()
    };
    let start_unix_ms = info
        .pbi_start_tvsec
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(info.pbi_start_tvusec / 1_000))
        .ok_or_else(|| "release observation process start time overflowed".to_owned())?;
    Ok(ProcessObservation { pid, start_unix_ms })
}

fn now_unix_ms() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "release observation system clock predates the Unix epoch".to_owned())?;
    u64::try_from(duration.as_millis())
        .map_err(|_| "release observation timestamp exceeds u64".to_owned())
}

fn release_log() -> Result<usize, String> {
    RELEASE_LOG
        .get_or_init(|| {
            let log = unsafe {
                // SAFETY: both byte strings are static, NUL-terminated C
                // strings. `os_log_create` retains the subsystem/category.
                os_log_create(SUBSYSTEM.as_ptr().cast(), CATEGORY.as_ptr().cast())
            };
            if log.is_null() {
                Err("release observation logger is unavailable".to_owned())
            } else {
                Ok(log as usize)
            }
        })
        .clone()
}

fn observation_identity() -> Result<(CandidateObservation, ProcessObservation, u64), String> {
    let candidate = BUNDLE_CANDIDATE
        .get_or_init(|| {
            std::env::current_exe()
                .map_err(|error| format!("release observation cannot resolve executable: {error}"))
                .and_then(|path| read_bundle_candidate(&path))
        })
        .as_ref()
        .map_err(Clone::clone)?
        .clone();
    let process = *PROCESS_OBSERVATION
        .get_or_init(current_process_observation)
        .as_ref()
        .map_err(Clone::clone)?;
    let sequence = EVENT_SEQUENCE
        .fetch_add(1, Ordering::Relaxed)
        .checked_add(1)
        .ok_or_else(|| "release observation sequence overflowed".to_owned())?;
    Ok((candidate, process, sequence))
}

fn emit_message(message: String) -> Result<(), String> {
    let message = CString::new(message)
        .map_err(|_| "release observation unexpectedly contains NUL".to_owned())?;
    let log = release_log()? as *mut c_void;
    unsafe {
        // SAFETY: `log` is the non-null object returned by `os_log_create` and
        // `message` is live and NUL-terminated for this call. The C shim owns a
        // fixed compile-time `%{public}s` format and accepts no format input.
        cfw_release_observation_log(log, message.as_ptr());
    }
    Ok(())
}

pub(crate) fn emit_engine_snapshot(
    snapshot: &EngineSnapshot,
    ipv6_enabled: bool,
) -> Result<(), String> {
    emit_engine_snapshot_with_sequence(snapshot, ipv6_enabled).map(|_| ())
}

/// Publishes an exact product-state observation and returns the source-owned
/// sequence embedded in that same log record. Physical Packet transactions use
/// the sequence only as a receipt binding; callers cannot choose or reset it.
pub(crate) fn emit_engine_snapshot_with_sequence(
    snapshot: &EngineSnapshot,
    ipv6_enabled: bool,
) -> Result<u64, String> {
    let (candidate, process, sequence) = observation_identity()?;
    let message = build_engine_snapshot_message(
        snapshot,
        ipv6_enabled,
        &candidate,
        process,
        sequence,
        now_unix_ms()?,
    )?;
    emit_message(message)?;
    Ok(sequence)
}

#[cfg(feature = "physical-release-evidence")]
pub(crate) fn emit_dns_evidence_transaction(
    case: ReleaseDnsEvidenceCase,
    baseline: DnsEvidenceSnapshotReceipt,
    test: DnsEvidenceSnapshotReceipt,
    restore: DnsEvidenceSnapshotReceipt,
) -> Result<DnsEvidenceTransactionReceipt, String> {
    let (candidate, process, sequence) = observation_identity()?;
    let message = build_dns_evidence_transaction_message(
        case,
        &baseline,
        &test,
        &restore,
        ObservationMetadata {
            candidate: &candidate,
            process,
            sequence,
            recorded_unix_ms: now_unix_ms()?,
        },
    )?;
    emit_message(message)?;
    Ok(DnsEvidenceTransactionReceipt {
        role: dns_role(case),
        baseline,
        test,
        restore,
        candidate_observation_sequence: sequence,
    })
}

#[link(name = "System")]
unsafe extern "C" {
    fn os_log_create(subsystem: *const c_char, category: *const c_char) -> *mut c_void;
    fn cfw_release_observation_log(log: *mut c_void, message: *const c_char);
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfw_engine_api::{EngineCommandContext, EngineMode, EngineOwner, RuntimeIdentity};

    fn candidate() -> CandidateObservation {
        CandidateObservation {
            version: "0.4.0".to_owned(),
            build_number: "40005".to_owned(),
        }
    }

    fn process() -> ProcessObservation {
        ProcessObservation {
            pid: 123,
            start_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn active_snapshot_is_a_canonical_closed_public_event() {
        let snapshot = EngineSnapshot {
            desired_mode: EngineMode::Tunnel,
            state: EngineState::TunnelActive {
                runtime: RuntimeIdentity {
                    owner: EngineOwner::PacketTunnelSystemExtension,
                    context: EngineCommandContext {
                        installation_id: "must-not-be-logged".to_owned(),
                        config_epoch: 7,
                        generation: 11,
                    },
                    config_digest: "a".repeat(64),
                    ready: true,
                },
            },
            generation: 11,
            config_digest: Some("a".repeat(64)),
        };
        let message = build_engine_snapshot_message(
            &snapshot,
            true,
            &candidate(),
            process(),
            9,
            1_700_000_001_000,
        )
        .expect("closed observation");
        assert!(message.starts_with(MESSAGE_PREFIX));
        assert!(!message.contains("must-not-be-logged"));
        let json = &message[MESSAGE_PREFIX.len()..];
        let value: Value = serde_json::from_str(json).expect("strict event JSON");
        assert_eq!(
            serde_json::to_string(&canonicalize(value.clone())).unwrap(),
            json
        );
        assert_eq!(value["document"], DOCUMENT);
        assert_eq!(value["component"], "host");
        assert_eq!(value["payload"]["state"]["phase"], "tunnel_active");
        assert_eq!(
            value["payload"]["state"]["owner"],
            "packet_tunnel_system_extension"
        );
        assert_eq!(value["payload"]["state"]["ready"], true);
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                "candidate",
                "component",
                "document",
                "event",
                "payload",
                "process",
                "recorded_unix_ms",
                "schema_version",
                "sequence",
            ]
        );
    }

    #[test]
    fn failed_snapshot_does_not_log_native_error_text() {
        let snapshot = EngineSnapshot {
            desired_mode: cfw_engine_api::EngineMode::SystemProxy,
            state: EngineState::Failed {
                generation: 4,
                target: cfw_engine_api::EngineMode::SystemProxy,
                error: "secret-bearing injected failure".to_owned(),
            },
            generation: 4,
            config_digest: None,
        };
        let message =
            build_engine_snapshot_message(&snapshot, false, &candidate(), process(), 1, 1)
                .expect("failed observation");
        assert!(!message.contains("secret-bearing"));
        assert!(message.contains("\"phase\":\"failed\""));
    }

    #[test]
    fn zero_sequence_is_rejected() {
        let error = build_engine_snapshot_message(
            &EngineSnapshot::default(),
            true,
            &candidate(),
            process(),
            0,
            1,
        )
        .expect_err("zero sequence");
        assert_eq!(error, "release observation sequence must be positive");
    }

    fn tunnel_snapshot(generation: u64, digest: char) -> EngineSnapshot {
        let config_digest = digest.to_string().repeat(64);
        EngineSnapshot {
            desired_mode: EngineMode::Tunnel,
            state: EngineState::TunnelActive {
                runtime: RuntimeIdentity {
                    owner: EngineOwner::PacketTunnelSystemExtension,
                    context: EngineCommandContext {
                        installation_id: "not-in-receipt".to_owned(),
                        config_epoch: 7,
                        generation,
                    },
                    config_digest: config_digest.clone(),
                    ready: true,
                },
            },
            generation,
            config_digest: Some(config_digest),
        }
    }

    #[test]
    fn dns_transaction_receipt_is_closed_canonical_and_strictly_ordered() {
        let baseline = DnsEvidenceSnapshotReceipt::from_ready_tunnel(&tunnel_snapshot(7, 'a'))
            .expect("baseline receipt");
        let test = DnsEvidenceSnapshotReceipt::from_ready_tunnel(&tunnel_snapshot(8, 'b'))
            .expect("test receipt");
        let restore = DnsEvidenceSnapshotReceipt::from_ready_tunnel(&tunnel_snapshot(9, 'a'))
            .expect("restore receipt");
        let message = build_dns_evidence_transaction_message(
            ReleaseDnsEvidenceCase::PrimaryIpv4,
            &baseline,
            &test,
            &restore,
            ObservationMetadata {
                candidate: &candidate(),
                process: process(),
                sequence: 12,
                recorded_unix_ms: 1_700_000_001_000,
            },
        )
        .expect("closed receipt");
        assert!(message.starts_with(MESSAGE_PREFIX));
        assert!(!message.contains("not-in-receipt"));
        assert!(!message.contains("dns-query"));
        assert!(!message.contains("controller"));
        let json = &message[MESSAGE_PREFIX.len()..];
        let value: Value = serde_json::from_str(json).expect("strict event JSON");
        assert_eq!(
            serde_json::to_string(&canonicalize(value.clone())).unwrap(),
            json
        );
        assert_eq!(value["event"], "dns_evidence_transaction");
        assert_eq!(value["payload"]["receipt"]["role"], "primary_ipv4");
        assert_eq!(
            value["payload"]["receipt"]["candidate_observation_sequence"],
            12
        );
        assert_eq!(value["payload"]["receipt"]["baseline"]["generation"], 7);
        assert_eq!(value["payload"]["receipt"]["test"]["generation"], 8);
        assert_eq!(value["payload"]["receipt"]["restore"]["generation"], 9);
    }

    #[test]
    fn dns_transaction_receipt_rejects_digest_or_generation_drift() {
        let baseline = DnsEvidenceSnapshotReceipt::from_ready_tunnel(&tunnel_snapshot(7, 'a'))
            .expect("baseline receipt");
        let test = DnsEvidenceSnapshotReceipt::from_ready_tunnel(&tunnel_snapshot(8, 'b'))
            .expect("test receipt");
        let wrong_restore = DnsEvidenceSnapshotReceipt::from_ready_tunnel(&tunnel_snapshot(8, 'c'))
            .expect("restore receipt shape");
        assert!(
            build_dns_evidence_transaction_message(
                ReleaseDnsEvidenceCase::SecondaryIpv6,
                &baseline,
                &test,
                &wrong_restore,
                ObservationMetadata {
                    candidate: &candidate(),
                    process: process(),
                    sequence: 1,
                    recorded_unix_ms: 1,
                },
            )
            .is_err()
        );
    }
}
