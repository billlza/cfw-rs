use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use cfw_core::LegacyControlSession;
use cfw_platform::{LegacyServiceRetirement, MacOsPlatformService};
use serde::{Deserialize, Serialize};

const LEGACY_HELPER_BINARY: &str = "/Library/PrivilegedHelperTools/com.bill.clashformac.helper";
const PROCESS_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const LEGACY_CORE_NAMES: [&str; 3] = ["clash-darwin", "clash-rs", "mihomo"];

pub(super) async fn wait_for_managed_process_to_exit(
    cores_dir: &Path,
    expected: &ProcessRecord,
) -> Result<(), String> {
    let deadline = Instant::now() + PROCESS_EXIT_TIMEOUT;
    loop {
        let remaining = managed_processes(cores_dir)?;
        if remaining.is_empty() {
            return Ok(());
        }
        if remaining.len() != 1 || remaining.first() != Some(expected) {
            return Err(format!(
                "legacy core identity changed or respawned while stopping; expected uid={} pid={} started={} executable={}",
                expected.uid,
                expected.pid,
                expected.start_identity,
                expected.executable.display()
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the exact legacy core remains after its stop request: {}",
                remaining
                    .iter()
                    .map(|process| {
                        format!(
                            "uid={} pid={} started={} executable={}",
                            process.uid,
                            process.pid,
                            process.start_identity,
                            process.executable.display()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessRecord {
    pub(super) uid: u32,
    pub(super) pid: u32,
    pub(super) start_identity: String,
    pub(super) executable: PathBuf,
    pub(super) command: String,
}

pub(super) fn managed_processes(cores_dir: &Path) -> Result<Vec<ProcessRecord>, String> {
    let output = command_output("/bin/ps", &["-axo", "uid=,pid=,lstart=,command="])?;
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| parse_managed_process(line, cores_dir))
        .filter_map(Result::transpose)
        .collect::<Result<Vec<_>, _>>()
        .and_then(|records| {
            if records.len() > 8 {
                Err("more than eight legacy managed core processes were observed; ownership is ambiguous".into())
            } else {
                Ok(records)
            }
        })
}

pub(super) fn require_unique_root_managed_process(
    cores_dir: &Path,
    app_home: &Path,
    config_file: &Path,
) -> Result<ProcessRecord, String> {
    let records = managed_processes(cores_dir)?;
    validate_unique_root_managed_process(&records, app_home, config_file)
}

pub(super) fn validate_unique_root_managed_process(
    records: &[ProcessRecord],
    app_home: &Path,
    config_file: &Path,
) -> Result<ProcessRecord, String> {
    let record = match records {
        [record] => record.clone(),
        [] => return Err("no exact managed legacy core process was observed".into()),
        _ => {
            return Err(
                "more than one managed legacy core process was observed; ownership is ambiguous"
                    .into(),
            );
        }
    };
    if record.uid != 0 {
        return Err(format!(
            "managed legacy core pid {} is not running as root",
            record.pid
        ));
    }
    let expected_command = format!(
        "{} -d {} -f {}",
        record.executable.display(),
        app_home.display(),
        config_file.display()
    );
    if record.command != expected_command {
        return Err(format!(
            "managed legacy core pid {} arguments do not bind the fixed app home and config",
            record.pid
        ));
    }
    Ok(record)
}

pub(super) fn verify_process_listens_on_ports(
    process: &ProcessRecord,
    ports: &[u16],
) -> Result<(), String> {
    if ports.is_empty() || ports.iter().any(|port| *port == 0) {
        return Err("legacy listener ownership requires non-zero ports".into());
    }
    let output = command_output("/usr/sbin/netstat", &["-anv", "-p", "tcp"])?;
    let expected_process = format!(
        "{}:{}",
        process
            .executable
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "legacy core executable basename is not UTF-8".to_owned())?,
        process.pid
    );
    for port in ports {
        let owners = parse_loopback_listener_owners(&output, *port)?;
        if owners.as_slice() != [expected_process.as_str()] {
            return Err(format!(
                "expected exactly one 127.0.0.1:{port} TCP listener owned by {expected_process}, observed {}",
                if owners.is_empty() {
                    "none".into()
                } else {
                    owners.join(", ")
                }
            ));
        }
    }
    Ok(())
}

pub(super) fn parse_managed_process(
    line: &str,
    cores_dir: &Path,
) -> Result<Option<ProcessRecord>, String> {
    let mut fields = line.split_ascii_whitespace();
    let uid = fields
        .next()
        .ok_or_else(|| "ps process record is missing uid".to_owned())?
        .parse::<u32>()
        .map_err(|error| format!("ps process record has invalid uid: {error}"))?;
    let pid = fields
        .next()
        .ok_or_else(|| "ps process record is missing pid".to_owned())?
        .parse::<u32>()
        .map_err(|error| format!("ps process record has invalid pid: {error}"))?;
    let start_identity = (0..5)
        .map(|_| {
            fields
                .next()
                .ok_or_else(|| "ps process record has incomplete start identity".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?
        .join(" ");
    let command = fields.collect::<Vec<_>>().join(" ");
    let executable = LEGACY_CORE_NAMES
        .iter()
        .map(|name| cores_dir.join(name))
        .find(|path| command_uses_exact_executable(&command, path));
    Ok(executable.map(|executable| ProcessRecord {
        uid,
        pid,
        start_identity,
        executable,
        command,
    }))
}

pub(super) fn parse_loopback_listener_owners(
    output: &str,
    expected_port: u16,
) -> Result<Vec<&str>, String> {
    let expected_endpoint = format!("127.0.0.1.{expected_port}");
    let mut owners = Vec::new();
    for line in output.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.first().is_some_and(|protocol| *protocol == "tcp4")
            && fields.get(3) == Some(&expected_endpoint.as_str())
            && fields.get(5) == Some(&"LISTEN")
        {
            let owner = fields
                .get(10)
                .copied()
                .ok_or_else(|| "netstat listener row has no process identity".to_owned())?;
            if !owner.rsplit_once(':').is_some_and(|(name, pid)| {
                !name.is_empty()
                    && pid.parse::<u32>().is_ok_and(|value| value != 0)
                    && !name.chars().any(char::is_whitespace)
            }) {
                return Err("netstat listener row has an invalid process token".into());
            }
            owners.push(owner);
        }
    }
    Ok(owners)
}

fn command_uses_exact_executable(command: &str, executable: &Path) -> bool {
    let executable = executable.to_string_lossy();
    command
        .strip_prefix(executable.as_ref())
        .is_some_and(|remaining| remaining.is_empty() || remaining.starts_with(' '))
}

fn command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("failed to execute {program}: {error}"))?;
    if output.stdout.len() > 1024 * 1024 || output.stderr.len() > 64 * 1024 {
        return Err(format!("{program} output exceeded its safety bound"));
    }
    if !output.status.success() {
        return Err(format!(
            "{program} failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(super) fn verify_privileged_artifacts_are_gone(cores_dir: &Path) -> Result<(), String> {
    let remaining = managed_processes(cores_dir)?;
    if !remaining.is_empty() {
        return Err("legacy core process identity still exists after retirement".into());
    }
    if LegacyControlSession::exists().map_err(|error| error.to_string())? {
        return Err("legacy privileged control session still exists".into());
    }
    MacOsPlatformService
        .verify_legacy_service_retired()
        .map_err(|error| format!("legacy Service Mode verification failed: {error}"))?;
    require_path_absent(Path::new(LEGACY_HELPER_BINARY), "legacy privileged helper")
}

pub(super) fn require_path_absent(path: &Path, label: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!("{label} remains at {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to verify removal of {}: {error}",
            path.display()
        )),
    }
}
