use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};
use cfw_core::SettingsStore;
use serde::{Deserialize, Serialize};

const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const ROUTE: &str = "/sbin/route";
const LAUNCHCTL: &str = "/bin/launchctl";
const ID: &str = "/usr/bin/id";
const CODESIGN: &str = "/usr/bin/codesign";
const PROXY_HOST: &str = "127.0.0.1";
const PRIVILEGED_HELPER_TOOLS: &str = "/Library/PrivilegedHelperTools";
const SYSTEM_PROXY_SNAPSHOT_FILE: &str = "system-proxy-snapshot.json";
/// Name of the privileged helper daemon plist embedded in the app bundle at
/// `Contents/Library/LaunchDaemons/`. Registered via `SMAppService` so launchd
/// runs `cfw-helper serve` as root, which is what lets mihomo open a utun device
/// for TUN mode. Must match the plist filename staged into the bundle.
pub const HELPER_DAEMON_PLIST_NAME: &str = "com.bill.clashformac.helper.plist";
pub const DEFAULT_BYPASS_DOMAINS: &[&str] = &[
    "127.0.0.1",
    "localhost",
    "*.local",
    "169.254/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlatformTarget {
    MacOsArm64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemProxyState {
    Enabled,
    Disabled,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemProxyMode {
    Off,
    GlobalHttp,
    RulePacLike,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LaunchdDomain {
    GuiAgent,
    SystemDaemon,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunDriverKind {
    /// TUN via SMAppService-registered privileged helper running mihomo as root.
    /// (Not Apple NetworkExtension — that name was an early planning placeholder.)
    #[serde(alias = "NetworkExtensionPacketTunnel")]
    SmAppServiceRootHelper,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperInstallRequest {
    pub label: String,
    pub domain: LaunchdDomain,
    pub binary_relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchAgentSpec {
    pub label: String,
    pub program: PathBuf,
    pub program_arguments: Vec<String>,
    pub run_at_load: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsPlatformDesign {
    pub target: PlatformTarget,
    pub system_proxy_strategy: &'static str,
    pub helper_strategy: &'static str,
    pub launchd_strategy: &'static str,
    pub tun_strategy: TunDriverKind,
    pub intel_supported: bool,
    pub minimum_macos: &'static str,
}

impl MacOsPlatformDesign {
    pub fn arm64_baseline() -> Self {
        Self {
            target: PlatformTarget::MacOsArm64,
            system_proxy_strategy: "macOS network service proxy manager with explicit snapshot/restore",
            helper_strategy: "SMAppService privileged helper (Login Items approval required)",
            launchd_strategy: "typed launchd contract, no ad-hoc shell scripts in product logic",
            tun_strategy: TunDriverKind::SmAppServiceRootHelper,
            intel_supported: false,
            minimum_macos: "13.0",
        }
    }
}

pub trait SystemProxyService {
    fn read_system_proxy_state(&self) -> Result<SystemProxyState>;
    fn set_system_proxy_mode(&self, mode: SystemProxyMode, port: u16, bypass: &[String]) -> Result<()>;
    fn restore_original_system_proxy_state(&self) -> Result<()>;
}

pub trait HelperService {
    fn install_helper(&self, request: &HelperInstallRequest) -> Result<()>;
    fn uninstall_helper(&self, label: &str) -> Result<()>;
}

pub trait LaunchdService {
    fn bootstrap(&self, label: &str, domain: LaunchdDomain) -> Result<()>;
    fn bootout(&self, label: &str, domain: LaunchdDomain) -> Result<()>;
}

pub trait TunService {
    fn install_tun_runtime(&self) -> Result<()>;
    fn start_tun(&self) -> Result<()>;
    fn stop_tun(&self) -> Result<()>;
}

/// Registration state of the privileged helper daemon, mirroring
/// `SMAppServiceStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceModeStatus {
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
    Unknown,
}

/// Privileged "Service Mode": registers a bundled root launchd daemon via
/// `SMAppService` so the Clash core can run with the privileges TUN requires.
pub trait ServiceModeService {
    fn service_mode_status(&self) -> ServiceModeStatus;
    fn enable_service_mode(&self) -> Result<ServiceModeStatus>;
    fn disable_service_mode(&self) -> Result<()>;
}

pub struct MacOsPlatformService;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDiagnostics {
    pub default_route_interface: Option<String>,
    pub service_order: Vec<String>,
    pub services: Vec<NetworkServiceDiagnostics>,
    pub recommended_clash_proxy_services: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkServiceDiagnostics {
    pub service: String,
    pub service_order: Option<usize>,
    pub hardware_port: Option<String>,
    pub bsd_device: Option<String>,
    pub service_type: NetworkServiceType,
    pub is_default_route: bool,
    pub proxy: NetworkServiceProxyDiagnostics,
    pub bypass_domains: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkServiceType {
    #[serde(rename = "Wi-Fi")]
    WiFi,
    Ethernet,
    #[serde(rename = "USB")]
    Usb,
    #[serde(rename = "VPN")]
    Vpn,
    Utun,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkServiceProxyDiagnostics {
    pub web: ProxyProtocolDiagnostics,
    pub secure_web: ProxyProtocolDiagnostics,
    pub socks: ProxyProtocolDiagnostics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyProtocolDiagnostics {
    pub enabled: bool,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub managed_by_clash: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkServiceOrderEntry {
    service: String,
    service_order: usize,
    hardware_port: Option<String>,
    bsd_device: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SystemProxySnapshot {
    services: Vec<NetworkServiceProxySnapshot>,
    #[serde(default)]
    target_services: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NetworkServiceProxySnapshot {
    service: String,
    web: ProxyProtocolState,
    secure_web: ProxyProtocolState,
    socks: ProxyProtocolState,
    bypass_domains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProxyProtocolState {
    enabled: bool,
    server: Option<String>,
    port: Option<u16>,
}

impl SystemProxySnapshot {
    fn services_for_restore(&self) -> Vec<&NetworkServiceProxySnapshot> {
        if self.target_services.is_empty() {
            return self.services.iter().collect();
        }

        self.services
            .iter()
            .filter(|service| {
                self.target_services
                    .iter()
                    .any(|target| target == &service.service)
            })
            .collect()
    }
}

impl MacOsPlatformService {
    fn active_network_services(&self) -> Result<Vec<String>> {
        let output = run_networksetup(&["-listallnetworkservices"])?;
        Ok(parse_network_services(&output))
    }

    fn network_service_order(&self) -> Result<Vec<NetworkServiceOrderEntry>> {
        let output = run_networksetup(&["-listnetworkserviceorder"])?;
        Ok(parse_network_service_order(&output))
    }

    fn proxy_target_services(&self) -> Result<Vec<String>> {
        let active_services = self.active_network_services()?;
        let service_order = self.network_service_order().unwrap_or_default();
        let default_route_interface = default_route_interface().unwrap_or_default();
        Ok(recommended_proxy_services(
            &active_services,
            &service_order,
            default_route_interface.as_deref(),
        ))
    }

    fn read_proxy_snapshot(&self) -> Result<SystemProxySnapshot> {
        let services = self
            .active_network_services()?
            .into_iter()
            .map(|service| self.read_service_proxy_snapshot(service))
            .collect::<Result<Vec<_>>>()?;
        Ok(SystemProxySnapshot {
            services,
            target_services: Vec::new(),
        })
    }

    fn read_service_proxy_snapshot(&self, service: String) -> Result<NetworkServiceProxySnapshot> {
        Ok(NetworkServiceProxySnapshot {
            web: read_protocol_state(&service, "-getwebproxy")?,
            secure_web: read_protocol_state(&service, "-getsecurewebproxy")?,
            socks: read_protocol_state(&service, "-getsocksfirewallproxy")?,
            bypass_domains: read_bypass_domains(&service)?,
            service,
        })
    }

    fn snapshot_path() -> Result<PathBuf> {
        let store = SettingsStore::default_for_current_user()?;
        store.ensure_layout()?;
        Ok(store.paths().helpers_dir.join(SYSTEM_PROXY_SNAPSHOT_FILE))
    }

    fn capture_snapshot_for_targets(&self, target_services: &[String]) -> Result<()> {
        let path = Self::snapshot_path()?;
        if !path.exists() {
            let mut snapshot = self.read_proxy_snapshot()?;
            snapshot.target_services = target_services.to_vec();
            let json = serde_json::to_vec_pretty(&snapshot)?;
            fs::write(path, json)?;
            return Ok(());
        }

        let raw = fs::read(&path)?;
        let mut snapshot: SystemProxySnapshot = serde_json::from_slice(&raw)?;
        let mut changed = false;

        for target_service in target_services {
            if !snapshot
                .services
                .iter()
                .any(|service| &service.service == target_service)
            {
                snapshot.services.push(
                    self.read_service_proxy_snapshot(target_service.clone())
                        .with_context(|| {
                            format!("failed to extend system proxy snapshot for {target_service}")
                        })?,
                );
                changed = true;
            }

            if !snapshot.target_services.is_empty()
                && !snapshot
                    .target_services
                    .iter()
                    .any(|service| service == target_service)
            {
                snapshot.target_services.push(target_service.clone());
                changed = true;
            }
        }

        if changed {
            let json = serde_json::to_vec_pretty(&snapshot)?;
            fs::write(path, json)?;
        }
        Ok(())
    }

    fn apply_snapshot(&self, snapshot: &SystemProxySnapshot) -> Result<()> {
        for service in snapshot.services_for_restore() {
            apply_protocol_state(&service.service, ProxyProtocol::Web, &service.web)?;
            apply_protocol_state(
                &service.service,
                ProxyProtocol::SecureWeb,
                &service.secure_web,
            )?;
            apply_protocol_state(&service.service, ProxyProtocol::Socks, &service.socks)?;
            set_bypass_domains(&service.service, &service.bypass_domains)?;
        }
        Ok(())
    }

    fn apply_clash_proxy(&self, port: u16, target_services: &[String], bypass: &[String]) -> Result<()> {
        let mut rollback_snapshot = self.read_proxy_snapshot()?;
        rollback_snapshot.target_services = target_services.to_vec();
        let result = (|| -> Result<()> {
            for service in target_services {
                set_protocol_proxy(service, ProxyProtocol::Web, PROXY_HOST, port)?;
                set_protocol_proxy(service, ProxyProtocol::SecureWeb, PROXY_HOST, port)?;
                set_protocol_proxy(service, ProxyProtocol::Socks, PROXY_HOST, port)?;
                let domains = if bypass.is_empty() {
                    DEFAULT_BYPASS_DOMAINS
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                } else {
                    bypass.to_vec()
                };
                set_bypass_domains(service, &domains)?;
            }
            Ok(())
        })();

        if let Err(error) = result {
            if let Err(rollback_error) = self.apply_snapshot(&rollback_snapshot) {
                bail!(
                    "failed to apply Clash system proxy: {error}; rollback also failed: {rollback_error}"
                );
            }
            return Err(error.context(
                "failed to apply Clash system proxy; restored previous macOS proxy state",
            ));
        }
        Ok(())
    }

    pub fn network_diagnostics(&self) -> Result<NetworkDiagnostics> {
        let active_services = self.active_network_services()?;
        let service_order = self.network_service_order()?;
        let default_route_interface = default_route_interface()?;
        let expected_port = SettingsStore::default_for_current_user()
            .ok()
            .and_then(|store| store.read_or_default().ok())
            .map(|settings| settings.mixed_port);

        let mut diagnostics = Vec::with_capacity(active_services.len());
        let mut seen = Vec::<String>::with_capacity(active_services.len());
        for entry in service_order.iter().filter(|entry| {
            active_services
                .iter()
                .any(|service| service == &entry.service)
        }) {
            diagnostics.push(self.read_service_network_diagnostics(
                &entry.service,
                Some(entry),
                default_route_interface.as_deref(),
                expected_port,
            )?);
            seen.push(entry.service.clone());
        }

        for service in active_services
            .iter()
            .filter(|service| !seen.iter().any(|seen| seen == *service))
        {
            diagnostics.push(self.read_service_network_diagnostics(
                service,
                None,
                default_route_interface.as_deref(),
                expected_port,
            )?);
        }

        Ok(NetworkDiagnostics {
            default_route_interface: default_route_interface.clone(),
            service_order: diagnostics
                .iter()
                .map(|service| service.service.clone())
                .collect(),
            recommended_clash_proxy_services: recommended_proxy_services(
                &active_services,
                &service_order,
                default_route_interface.as_deref(),
            ),
            services: diagnostics,
        })
    }

    fn read_service_network_diagnostics(
        &self,
        service: &str,
        order_entry: Option<&NetworkServiceOrderEntry>,
        default_route_interface: Option<&str>,
        expected_port: Option<u16>,
    ) -> Result<NetworkServiceDiagnostics> {
        let proxy_snapshot = self.read_service_proxy_snapshot(service.to_string())?;
        let hardware_port = order_entry.and_then(|entry| entry.hardware_port.clone());
        let bsd_device = order_entry.and_then(|entry| entry.bsd_device.clone());
        let is_default_route = matches!(
            (default_route_interface, bsd_device.as_deref()),
            (Some(default_route_interface), Some(bsd_device))
                if default_route_interface == bsd_device
        );

        Ok(NetworkServiceDiagnostics {
            service: service.to_string(),
            service_order: order_entry.map(|entry| entry.service_order),
            service_type: classify_network_service(
                service,
                hardware_port.as_deref(),
                bsd_device.as_deref(),
            ),
            hardware_port,
            bsd_device,
            is_default_route,
            proxy: NetworkServiceProxyDiagnostics {
                web: protocol_diagnostics(&proxy_snapshot.web, expected_port),
                secure_web: protocol_diagnostics(&proxy_snapshot.secure_web, expected_port),
                socks: protocol_diagnostics(&proxy_snapshot.socks, expected_port),
            },
            bypass_domains: proxy_snapshot.bypass_domains,
        })
    }

    fn disable_clash_owned_proxies(&self, expected_port: u16) -> Result<()> {
        for service in self.active_network_services()? {
            for protocol in [
                ProxyProtocol::Web,
                ProxyProtocol::SecureWeb,
                ProxyProtocol::Socks,
            ] {
                let state = read_protocol_state(&service, protocol.get_arg())?;
                if state_is_managed_clash_proxy(&state, Some(expected_port), false) {
                    set_protocol_state(&service, protocol, false)?;
                }
            }
        }
        Ok(())
    }

    pub fn install_launch_agent(&self, spec: &LaunchAgentSpec) -> Result<PathBuf> {
        if spec.label.trim().is_empty() {
            bail!("launch agent label must not be empty");
        }
        if !spec.program.is_absolute() {
            bail!(
                "launch agent program must be absolute: {}",
                spec.program.display()
            );
        }

        let path = launch_agent_path(&spec.label)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, render_launch_agent_plist(spec))?;
        Ok(path)
    }

    pub fn uninstall_launch_agent(&self, label: &str) -> Result<()> {
        let path = launch_agent_path(label)?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}

impl SystemProxyService for MacOsPlatformService {
    fn read_system_proxy_state(&self) -> Result<SystemProxyState> {
        let snapshot = self.read_proxy_snapshot()?;
        let expected_port = SettingsStore::default_for_current_user()
            .ok()
            .and_then(|store| store.read_or_default().ok())
            .map(|settings| settings.mixed_port);
        let has_snapshot = Self::snapshot_path()
            .map(|path| path.exists())
            .unwrap_or(false);
        let states = snapshot
            .services
            .iter()
            .flat_map(|service| [&service.web, &service.secure_web, &service.socks])
            .collect::<Vec<_>>();

        let managed = has_snapshot
            && states
                .iter()
                .any(|state| state_is_managed_clash_proxy(state, expected_port, true));
        let external = states.iter().any(|state| state.enabled);

        Ok(if managed {
            SystemProxyState::Enabled
        } else if external {
            SystemProxyState::External
        } else {
            SystemProxyState::Disabled
        })
    }

    fn set_system_proxy_mode(&self, mode: SystemProxyMode, port: u16, bypass: &[String]) -> Result<()> {
        match mode {
            SystemProxyMode::Off => self.restore_original_system_proxy_state(),
            SystemProxyMode::GlobalHttp | SystemProxyMode::RulePacLike => {
                if port == 0 {
                    bail!("mixed-port must be greater than 0 before enabling system proxy")
                }
                let target_services = self.proxy_target_services()?;
                self.capture_snapshot_for_targets(&target_services)?;
                self.apply_clash_proxy(port, &target_services, bypass)
            }
        }
    }

    fn restore_original_system_proxy_state(&self) -> Result<()> {
        let path = Self::snapshot_path()?;
        if !path.exists() {
            let settings = SettingsStore::default_for_current_user()?.read_or_default()?;
            return self.disable_clash_owned_proxies(settings.mixed_port);
        }

        let raw = fs::read(&path)?;
        let snapshot: SystemProxySnapshot = serde_json::from_slice(&raw)?;
        self.apply_snapshot(&snapshot)?;
        fs::remove_file(path)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum ProxyProtocol {
    Web,
    SecureWeb,
    Socks,
}

impl ProxyProtocol {
    fn get_arg(self) -> &'static str {
        match self {
            Self::Web => "-getwebproxy",
            Self::SecureWeb => "-getsecurewebproxy",
            Self::Socks => "-getsocksfirewallproxy",
        }
    }

    fn set_arg(self) -> &'static str {
        match self {
            Self::Web => "-setwebproxy",
            Self::SecureWeb => "-setsecurewebproxy",
            Self::Socks => "-setsocksfirewallproxy",
        }
    }

    fn state_arg(self) -> &'static str {
        match self {
            Self::Web => "-setwebproxystate",
            Self::SecureWeb => "-setsecurewebproxystate",
            Self::Socks => "-setsocksfirewallproxystate",
        }
    }
}

fn run_networksetup(args: &[&str]) -> Result<String> {
    let output = Command::new(NETWORKSETUP)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {NETWORKSETUP} {}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "networksetup {} failed: {}{}",
            args.join(" "),
            stderr.trim(),
            stdout.trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("An asterisk")
                && !line.starts_with('*')
                && !line.starts_with("There")
        })
        .map(ToString::to_string)
        .collect()
}

fn parse_network_service_order(output: &str) -> Vec<NetworkServiceOrderEntry> {
    let mut entries = Vec::new();
    let mut current = None;

    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if let Some((service_order, service)) = parse_network_service_order_line(line) {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            current = Some(NetworkServiceOrderEntry {
                service,
                service_order,
                hardware_port: None,
                bsd_device: None,
            });
            continue;
        }

        if let Some((hardware_port, bsd_device)) = parse_network_service_hardware_line(line)
            && let Some(entry) = current.as_mut()
        {
            entry.hardware_port = hardware_port;
            entry.bsd_device = bsd_device;
        }
    }

    if let Some(entry) = current {
        entries.push(entry);
    }

    entries
}

fn parse_network_service_order_line(line: &str) -> Option<(usize, String)> {
    let line = line.trim();
    let close = line.strip_prefix('(')?.find(')')? + 1;
    let service_order = line.get(1..close)?.trim().parse::<usize>().ok()?;
    let service = line.get(close + 1..)?.trim().trim_start_matches('*').trim();

    if service.is_empty() {
        return None;
    }

    Some((service_order, service.to_string()))
}

fn parse_network_service_hardware_line(line: &str) -> Option<(Option<String>, Option<String>)> {
    let line = line
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    let value = line.strip_prefix("Hardware Port:")?.trim();
    let (hardware_port, bsd_device) = value
        .split_once(", Device:")
        .map(|(hardware_port, bsd_device)| (hardware_port.trim(), bsd_device.trim()))
        .unwrap_or((value, ""));

    Some((
        normalize_optional_network_value(hardware_port),
        normalize_optional_network_value(bsd_device),
    ))
}

fn normalize_optional_network_value(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.eq_ignore_ascii_case("(null)")
        || value.eq_ignore_ascii_case("none")
    {
        None
    } else {
        Some(value.to_string())
    }
}

fn default_route_interface() -> Result<Option<String>> {
    let ipv4_default = read_default_route_interface(&["-n", "get", "default"])?;
    if ipv4_default.is_some() {
        return Ok(ipv4_default);
    }

    read_default_route_interface(&["-n", "get", "-inet6", "default"])
}

fn read_default_route_interface(args: &[&str]) -> Result<Option<String>> {
    let output = Command::new(ROUTE)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {ROUTE} {}", args.join(" ")))?;

    if !output.status.success() {
        return Ok(None);
    }

    Ok(parse_default_route_interface(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn parse_default_route_interface(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("interface:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

fn recommended_proxy_services(
    active_services: &[String],
    service_order: &[NetworkServiceOrderEntry],
    default_route_interface: Option<&str>,
) -> Vec<String> {
    if let Some(default_route_interface) = default_route_interface {
        let default_route_services = service_order
            .iter()
            .filter(|entry| entry.bsd_device.as_deref() == Some(default_route_interface))
            .filter(|entry| {
                active_services
                    .iter()
                    .any(|service| service == &entry.service)
            })
            .map(|entry| entry.service.clone())
            .collect::<Vec<_>>();

        if !default_route_services.is_empty() {
            return default_route_services;
        }
    }

    let ordered_services = service_order
        .iter()
        .filter(|entry| {
            active_services
                .iter()
                .any(|service| service == &entry.service)
        })
        .map(|entry| entry.service.clone())
        .collect::<Vec<_>>();

    if ordered_services.is_empty() {
        active_services.to_vec()
    } else {
        ordered_services
    }
}

fn classify_network_service(
    service: &str,
    hardware_port: Option<&str>,
    bsd_device: Option<&str>,
) -> NetworkServiceType {
    let service = service.to_ascii_lowercase();
    let hardware_port = hardware_port
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let bsd_device = bsd_device.map(str::to_ascii_lowercase).unwrap_or_default();
    let label = format!("{service} {hardware_port}");

    if contains_any(
        &label,
        &[
            "vpn",
            "tunnel",
            "wireguard",
            "openvpn",
            "tailscale",
            "zerotier",
            "ipsec",
            "l2tp",
            "ppp",
        ],
    ) {
        return NetworkServiceType::Vpn;
    }

    if bsd_device.starts_with("utun") {
        return NetworkServiceType::Utun;
    }

    if contains_any(&label, &["wi-fi", "wifi", "airport"]) {
        return NetworkServiceType::WiFi;
    }

    if contains_any(&label, &["usb", "iphone", "ipad", "android"]) {
        return NetworkServiceType::Usb;
    }

    if contains_any(
        &label,
        &[
            "ethernet",
            "lan",
            "thunderbolt",
            "bridge",
            "gigabit",
            "10/100",
        ],
    ) || bsd_device.starts_with("en")
    {
        return NetworkServiceType::Ethernet;
    }

    NetworkServiceType::Other
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn read_protocol_state(service: &str, get_arg: &str) -> Result<ProxyProtocolState> {
    let output = run_networksetup(&[get_arg, service])?;
    Ok(parse_protocol_state(&output))
}

fn parse_protocol_state(output: &str) -> ProxyProtocolState {
    let mut enabled = false;
    let mut server = None;
    let mut port = None;
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("Enabled:") {
            enabled = value.trim().eq_ignore_ascii_case("yes");
        }
        if let Some(value) = line.strip_prefix("Server:") {
            let value = value.trim();
            if !value.is_empty() {
                server = Some(value.to_string());
            }
        }
        if let Some(value) = line.strip_prefix("Port:") {
            port = value.trim().parse::<u16>().ok().filter(|value| *value > 0);
        }
    }
    ProxyProtocolState {
        enabled,
        server,
        port,
    }
}

fn state_is_managed_clash_proxy(
    state: &ProxyProtocolState,
    expected_port: Option<u16>,
    allow_unknown_port: bool,
) -> bool {
    if !state.enabled {
        return false;
    }

    if !state
        .server
        .as_deref()
        .map(is_local_proxy_host)
        .unwrap_or(false)
    {
        return false;
    }

    match (expected_port, state.port) {
        (Some(expected), Some(actual)) => expected == actual,
        _ => allow_unknown_port,
    }
}

fn is_local_proxy_host(server: &str) -> bool {
    matches!(server, PROXY_HOST | "localhost" | "::1")
}

fn protocol_diagnostics(
    state: &ProxyProtocolState,
    expected_port: Option<u16>,
) -> ProxyProtocolDiagnostics {
    ProxyProtocolDiagnostics {
        enabled: state.enabled,
        server: state.server.clone(),
        port: state.port,
        managed_by_clash: state_is_managed_clash_proxy(state, expected_port, true),
    }
}

fn launch_agent_path(label: &str) -> Result<PathBuf> {
    validate_launchd_label(label)?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is required to resolve LaunchAgents directory")?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{label}.plist")))
}

fn launch_daemon_path(label: &str) -> Result<PathBuf> {
    validate_launchd_label(label)?;
    Ok(PathBuf::from("/Library")
        .join("LaunchDaemons")
        .join(format!("{label}.plist")))
}

fn launchd_plist_path(label: &str, domain: LaunchdDomain) -> Result<PathBuf> {
    match domain {
        LaunchdDomain::GuiAgent => launch_agent_path(label),
        LaunchdDomain::SystemDaemon => launch_daemon_path(label),
    }
}

fn helper_program_path(binary_relative_path: &str) -> Result<PathBuf> {
    let requested = PathBuf::from(binary_relative_path);
    let program = if requested.is_absolute() {
        requested
    } else {
        SettingsStore::default_for_current_user()?
            .paths()
            .helpers_dir
            .join(requested)
    };
    if !program.is_absolute() {
        bail!(
            "helper program must resolve to an absolute path: {}",
            program.display()
        );
    }
    if !program.is_file() {
        bail!("helper program is missing: {}", program.display());
    }
    Ok(program)
}

fn validate_privileged_helper_program(program: &PathBuf) -> Result<()> {
    let privileged_root = PathBuf::from(PRIVILEGED_HELPER_TOOLS);
    if !program.starts_with(&privileged_root) {
        bail!(
            "privileged helpers must be installed under {}: {}",
            privileged_root.display(),
            program.display()
        );
    }
    let metadata = fs::metadata(program)?;
    if metadata.uid() != 0 || metadata.gid() != 0 {
        bail!(
            "privileged helper must be owned by root:wheel: {}",
            program.display()
        );
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "privileged helper must not be writable by group/others: {}",
            program.display()
        );
    }
    verify_codesign(program)?;
    Ok(())
}

fn verify_codesign(program: &PathBuf) -> Result<()> {
    let output = Command::new(CODESIGN)
        .args(["--verify", "--strict"])
        .arg(program)
        .output()
        .with_context(|| format!("failed to run {CODESIGN} --verify {}", program.display()))?;
    if !output.status.success() {
        bail!(
            "privileged helper code signature verification failed for {}: {}{}",
            program.display(),
            String::from_utf8_lossy(&output.stderr).trim(),
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
    Ok(())
}

fn validate_launchd_label(label: &str) -> Result<()> {
    if label.trim().is_empty() || label.contains('/') {
        bail!("invalid launch agent label: {label}");
    }
    Ok(())
}

fn launchd_domain_target(domain: LaunchdDomain) -> Result<String> {
    match domain {
        LaunchdDomain::GuiAgent => Ok(format!("gui/{}", current_uid()?)),
        LaunchdDomain::SystemDaemon => Ok("system".into()),
    }
}

fn launchd_service_target(label: &str, domain: LaunchdDomain) -> Result<String> {
    validate_launchd_label(label)?;
    Ok(format!("{}/{}", launchd_domain_target(domain)?, label))
}

fn current_uid() -> Result<String> {
    let output = Command::new(ID)
        .arg("-u")
        .output()
        .with_context(|| format!("failed to run {ID} -u"))?;
    if !output.status.success() {
        bail!(
            "{ID} -u failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if uid.is_empty() {
        bail!("{ID} -u returned an empty uid");
    }
    Ok(uid)
}

fn run_launchctl(args: &[String]) -> Result<String> {
    let output = Command::new(LAUNCHCTL)
        .args(args.iter().map(|arg| OsStr::new(arg.as_str())))
        .output()
        .with_context(|| format!("failed to run {LAUNCHCTL} {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "{LAUNCHCTL} {} failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim(),
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_launchctl_allow_absent(args: &[String]) -> Result<()> {
    match run_launchctl(args) {
        Ok(_) => Ok(()),
        Err(error) if launchctl_absent_error(&error.to_string()) => Ok(()),
        Err(error) => Err(error),
    }
}

fn launchctl_absent_error(message: &str) -> bool {
    [
        "No such process",
        "No such file or directory",
        "Could not find specified service",
        "service is not loaded",
        "Load failed: 5",
        "Boot-out failed: 5",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

fn render_launch_agent_plist(spec: &LaunchAgentSpec) -> String {
    let mut arguments = Vec::with_capacity(1 + spec.program_arguments.len());
    arguments.push(spec.program.display().to_string());
    arguments.extend(spec.program_arguments.iter().cloned());
    let arguments = arguments
        .iter()
        .map(|argument| format!("    <string>{}</string>", xml_escape(argument)))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{arguments}
  </array>
  <key>RunAtLoad</key>
  <{run_at_load}/>
  <key>KeepAlive</key>
  <false/>
</dict>
</plist>
"#,
        label = xml_escape(&spec.label),
        arguments = arguments,
        run_at_load = if spec.run_at_load { "true" } else { "false" },
    )
}

fn xml_escape(value: impl AsRef<str>) -> String {
    value
        .as_ref()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn read_bypass_domains(service: &str) -> Result<Vec<String>> {
    let output = run_networksetup(&["-getproxybypassdomains", service])?;
    Ok(output
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("There aren't any")
                && !line.starts_with("There are no")
        })
        .map(ToString::to_string)
        .collect())
}

fn set_bypass_domains(service: &str, domains: &[String]) -> Result<()> {
    if domains.is_empty() {
        run_networksetup(&["-setproxybypassdomains", service, "Empty"])?;
        return Ok(());
    }

    let mut args = vec!["-setproxybypassdomains", service];
    args.extend(domains.iter().map(String::as_str));
    run_networksetup(&args)?;
    Ok(())
}

fn set_protocol_proxy(
    service: &str,
    protocol: ProxyProtocol,
    server: &str,
    port: u16,
) -> Result<()> {
    let port = port.to_string();
    run_networksetup(&[protocol.set_arg(), service, server, &port])?;
    set_protocol_state(service, protocol, true)
}

fn set_protocol_state(service: &str, protocol: ProxyProtocol, enabled: bool) -> Result<()> {
    run_networksetup(&[
        protocol.state_arg(),
        service,
        if enabled { "on" } else { "off" },
    ])?;
    Ok(())
}

fn apply_protocol_state(
    service: &str,
    protocol: ProxyProtocol,
    state: &ProxyProtocolState,
) -> Result<()> {
    if state.enabled
        && let (Some(server), Some(port)) = (state.server.as_deref(), state.port)
    {
        return set_protocol_proxy(service, protocol, server, port);
    }

    set_protocol_state(service, protocol, false)
}

impl HelperService for MacOsPlatformService {
    fn install_helper(&self, request: &HelperInstallRequest) -> Result<()> {
        let program = helper_program_path(&request.binary_relative_path)?;
        if request.domain == LaunchdDomain::SystemDaemon {
            validate_privileged_helper_program(&program)?;
        }
        let store = SettingsStore::default_for_current_user()?;
        let spec = LaunchAgentSpec {
            label: request.label.clone(),
            program,
            program_arguments: vec![
                "serve".into(),
                "--app-home".into(),
                store.paths().app_home.display().to_string(),
            ],
            run_at_load: true,
        };
        let plist_path = launchd_plist_path(&request.label, request.domain)?;
        if let Some(parent) = plist_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(&plist_path, render_launch_agent_plist(&spec))
            .with_context(|| format!("failed to write {}", plist_path.display()))?;
        let mut permissions = fs::metadata(&plist_path)?.permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&plist_path, permissions)
            .with_context(|| format!("failed to chmod {}", plist_path.display()))?;
        self.bootstrap(&request.label, request.domain)
    }

    fn uninstall_helper(&self, label: &str) -> Result<()> {
        let mut errors = Vec::new();
        for domain in [LaunchdDomain::SystemDaemon, LaunchdDomain::GuiAgent] {
            if let Err(error) = self.bootout(label, domain) {
                errors.push(error.to_string());
            }
            let plist_path = launchd_plist_path(label, domain)?;
            if plist_path.exists()
                && let Err(error) = fs::remove_file(&plist_path)
            {
                errors.push(format!("{}: {error}", plist_path.display()));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("failed to uninstall helper {label}: {}", errors.join("; "))
        }
    }
}

impl LaunchdService for MacOsPlatformService {
    fn bootstrap(&self, label: &str, domain: LaunchdDomain) -> Result<()> {
        let plist_path = launchd_plist_path(label, domain)?;
        if !plist_path.exists() {
            bail!("launchd plist is missing: {}", plist_path.display());
        }
        let domain_target = launchd_domain_target(domain)?;
        let service_target = launchd_service_target(label, domain)?;
        let plist = plist_path.display().to_string();

        run_launchctl_allow_absent(&["bootout".into(), domain_target.clone(), plist.clone()])?;
        run_launchctl(&["bootstrap".into(), domain_target, plist])?;
        run_launchctl(&["enable".into(), service_target])?;
        Ok(())
    }

    fn bootout(&self, label: &str, domain: LaunchdDomain) -> Result<()> {
        let domain_target = launchd_domain_target(domain)?;
        let service_target = launchd_service_target(label, domain)?;
        let plist = launchd_plist_path(label, domain)?.display().to_string();

        run_launchctl_allow_absent(&["disable".into(), service_target])?;
        run_launchctl_allow_absent(&["bootout".into(), domain_target, plist])?;
        Ok(())
    }
}

impl ServiceModeService for MacOsPlatformService {
    fn service_mode_status(&self) -> ServiceModeStatus {
        #[cfg(target_os = "macos")]
        {
            sm_app_service::status()
        }
        #[cfg(not(target_os = "macos"))]
        {
            ServiceModeStatus::Unknown
        }
    }

    fn enable_service_mode(&self) -> Result<ServiceModeStatus> {
        #[cfg(target_os = "macos")]
        {
            sm_app_service::register().map_err(|err| anyhow::anyhow!(err))
        }
        #[cfg(not(target_os = "macos"))]
        {
            bail!("Service Mode is only available on macOS")
        }
    }

    fn disable_service_mode(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            sm_app_service::unregister().map_err(|err| anyhow::anyhow!(err))
        }
        #[cfg(not(target_os = "macos"))]
        {
            bail!("Service Mode is only available on macOS")
        }
    }
}

impl TunService for MacOsPlatformService {
    fn install_tun_runtime(&self) -> Result<()> {
        // TUN on macOS needs the core to run as root so mihomo can open a utun
        // device and install routes. We deliver that by registering the bundled
        // privileged helper daemon (Service Mode) via SMAppService; launchd then
        // runs `cfw-helper serve` as root. mihomo's `tun:` config block is
        // injected separately when settings.tun_mode is on. No false success:
        // an unsigned/unapproved build surfaces an actionable error instead.
        match self.enable_service_mode()? {
            ServiceModeStatus::Enabled => Ok(()),
            ServiceModeStatus::RequiresApproval => bail!(
                "Service Mode needs approval: open System Settings \u{203a} General \u{203a} Login Items & Extensions, enable the \"Clash for Mac\" helper, then turn TUN on again"
            ),
            other => bail!(
                "Service Mode could not be enabled (status: {other:?}); a Developer ID-signed build with the bundled helper daemon is required"
            ),
        }
    }

    fn start_tun(&self) -> Result<()> {
        match self.service_mode_status() {
            ServiceModeStatus::Enabled => Ok(()),
            ServiceModeStatus::RequiresApproval => bail!(
                "Service Mode is awaiting approval in System Settings \u{203a} General \u{203a} Login Items & Extensions"
            ),
            other => bail!(
                "Service Mode is not active (status: {other:?}); enable it before starting TUN"
            ),
        }
    }

    fn stop_tun(&self) -> Result<()> {
        // Leave the helper daemon registered. TUN is turned off by regenerating
        // the core config without the `tun:` block and restarting the core;
        // unregister the daemon only when the user disables Service Mode entirely.
        Ok(())
    }
}

/// `SMAppService` (macOS 13+) bindings for registering the bundled privileged
/// helper daemon. The plist named [`HELPER_DAEMON_PLIST_NAME`] must ship in the
/// app bundle's `Contents/Library/LaunchDaemons/` directory and the app must be
/// Developer ID-signed for registration to succeed.
#[cfg(target_os = "macos")]
mod sm_app_service {
    use super::{HELPER_DAEMON_PLIST_NAME, ServiceModeStatus};
    use objc2::rc::Retained;
    use objc2_foundation::NSString;
    use objc2_service_management::{SMAppService, SMAppServiceStatus};

    fn daemon() -> Retained<SMAppService> {
        let name = NSString::from_str(HELPER_DAEMON_PLIST_NAME);
        // SAFETY: `daemonServiceWithPlistName:` returns a non-null SMAppService
        // describing the named daemon; it performs no privileged action on its own.
        unsafe { SMAppService::daemonServiceWithPlistName(&name) }
    }

    fn map_status(value: SMAppServiceStatus) -> ServiceModeStatus {
        if value == SMAppServiceStatus::Enabled {
            ServiceModeStatus::Enabled
        } else if value == SMAppServiceStatus::RequiresApproval {
            ServiceModeStatus::RequiresApproval
        } else if value == SMAppServiceStatus::NotRegistered {
            ServiceModeStatus::NotRegistered
        } else if value == SMAppServiceStatus::NotFound {
            ServiceModeStatus::NotFound
        } else {
            ServiceModeStatus::Unknown
        }
    }

    pub(super) fn status() -> ServiceModeStatus {
        // SAFETY: `status` only reads the current registration state.
        map_status(unsafe { daemon().status() })
    }

    pub(super) fn register() -> Result<ServiceModeStatus, String> {
        let daemon = daemon();
        // SAFETY: `registerAndReturnError:` submits the bundled daemon to launchd
        // and returns an NSError on failure (unsigned, needs approval, …) rather
        // than exhibiting UB.
        unsafe { daemon.registerAndReturnError() }
            .map_err(|err| format!("SMAppService register failed: {err:?}"))?;
        Ok(map_status(unsafe { daemon.status() }))
    }

    pub(super) fn unregister() -> Result<(), String> {
        // SAFETY: see `register`.
        unsafe { daemon().unregisterAndReturnError() }
            .map_err(|err| format!("SMAppService unregister failed: {err:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_enabled_networksetup_proxy_state() {
        let output = "\
Enabled: Yes
Server: 127.0.0.1
Port: 7890
Authenticated Proxy Enabled: 0
";
        let state = parse_protocol_state(output);
        assert!(state.enabled);
        assert_eq!(state.server.as_deref(), Some("127.0.0.1"));
        assert_eq!(state.port, Some(7890));
    }

    #[test]
    fn filters_disabled_and_header_network_services() {
        let output = "\
An asterisk (*) denotes that a network service is disabled.
Wi-Fi
*Thunderbolt Bridge
USB 10/100/1000 LAN
";
        assert_eq!(
            parse_network_services(output),
            vec!["Wi-Fi".to_string(), "USB 10/100/1000 LAN".to_string()]
        );
    }

    #[test]
    fn parses_network_service_order_with_devices() {
        let output = "\
An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en7)

(3) VPN
(Hardware Port: VPN, Device: utun4)
";
        let services = parse_network_service_order(output);
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].service, "Wi-Fi");
        assert_eq!(services[0].service_order, 1);
        assert_eq!(services[0].hardware_port.as_deref(), Some("Wi-Fi"));
        assert_eq!(services[0].bsd_device.as_deref(), Some("en0"));
        assert_eq!(services[1].service, "USB 10/100/1000 LAN");
        assert_eq!(services[1].bsd_device.as_deref(), Some("en7"));
        assert_eq!(services[2].service, "VPN");
        assert_eq!(services[2].bsd_device.as_deref(), Some("utun4"));
    }

    #[test]
    fn parses_default_route_interface() {
        let output = "\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
";
        assert_eq!(
            parse_default_route_interface(output).as_deref(),
            Some("en0")
        );
    }

    #[test]
    fn recommends_default_route_service_before_ordered_fallback() {
        let active_services = vec![
            "Wi-Fi".to_string(),
            "USB 10/100/1000 LAN".to_string(),
            "VPN".to_string(),
        ];
        let service_order = vec![
            NetworkServiceOrderEntry {
                service: "VPN".into(),
                service_order: 1,
                hardware_port: Some("VPN".into()),
                bsd_device: Some("utun4".into()),
            },
            NetworkServiceOrderEntry {
                service: "Wi-Fi".into(),
                service_order: 2,
                hardware_port: Some("Wi-Fi".into()),
                bsd_device: Some("en0".into()),
            },
        ];

        assert_eq!(
            recommended_proxy_services(&active_services, &service_order, Some("en0")),
            vec!["Wi-Fi".to_string()]
        );
        assert_eq!(
            recommended_proxy_services(&active_services, &service_order, Some("en9")),
            vec!["VPN".to_string(), "Wi-Fi".to_string()]
        );
    }

    #[test]
    fn classifies_common_mac_network_service_types() {
        assert_eq!(
            classify_network_service("Wi-Fi", Some("Wi-Fi"), Some("en0")),
            NetworkServiceType::WiFi
        );
        assert_eq!(
            classify_network_service("USB 10/100/1000 LAN", Some("USB LAN"), Some("en7")),
            NetworkServiceType::Usb
        );
        assert_eq!(
            classify_network_service("Tailscale", Some("VPN"), Some("utun4")),
            NetworkServiceType::Vpn
        );
        assert_eq!(
            classify_network_service("Private Tunnel", None, Some("utun6")),
            NetworkServiceType::Vpn
        );
        assert_eq!(
            classify_network_service("Anonymous Adapter", None, Some("utun8")),
            NetworkServiceType::Utun
        );
    }

    #[test]
    fn snapshot_restore_uses_recorded_targets_and_keeps_legacy_full_restore() {
        let services = vec![
            NetworkServiceProxySnapshot {
                service: "Wi-Fi".into(),
                web: disabled_proxy_state(),
                secure_web: disabled_proxy_state(),
                socks: disabled_proxy_state(),
                bypass_domains: Vec::new(),
            },
            NetworkServiceProxySnapshot {
                service: "Ethernet".into(),
                web: disabled_proxy_state(),
                secure_web: disabled_proxy_state(),
                socks: disabled_proxy_state(),
                bypass_domains: Vec::new(),
            },
        ];

        let targeted = SystemProxySnapshot {
            services: services.clone(),
            target_services: vec!["Wi-Fi".into()],
        };
        let legacy = SystemProxySnapshot {
            services,
            target_services: Vec::new(),
        };

        assert_eq!(
            targeted
                .services_for_restore()
                .iter()
                .map(|service| service.service.as_str())
                .collect::<Vec<_>>(),
            vec!["Wi-Fi"]
        );
        assert_eq!(legacy.services_for_restore().len(), 2);
    }

    #[test]
    fn managed_proxy_detection_requires_matching_local_port() {
        let clash_state = ProxyProtocolState {
            enabled: true,
            server: Some("127.0.0.1".into()),
            port: Some(7890),
        };
        let charles_state = ProxyProtocolState {
            enabled: true,
            server: Some("127.0.0.1".into()),
            port: Some(8888),
        };
        let remote_state = ProxyProtocolState {
            enabled: true,
            server: Some("proxy.example.com".into()),
            port: Some(7890),
        };

        assert!(state_is_managed_clash_proxy(
            &clash_state,
            Some(7890),
            false
        ));
        assert!(!state_is_managed_clash_proxy(
            &charles_state,
            Some(7890),
            false
        ));
        assert!(!state_is_managed_clash_proxy(
            &remote_state,
            Some(7890),
            true
        ));
    }

    #[test]
    fn launch_agent_plist_escapes_program_arguments() {
        let spec = LaunchAgentSpec {
            label: "com.bill.clashformac".into(),
            program: PathBuf::from("/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac"),
            program_arguments: vec!["--profile=A&B".into()],
            run_at_load: true,
        };
        let plist = render_launch_agent_plist(&spec);
        assert!(plist.contains("<string>com.bill.clashformac</string>"));
        assert!(plist.contains("<string>--profile=A&amp;B</string>"));
        assert!(plist.contains("<true/>"));
    }

    #[test]
    fn launchd_paths_validate_labels_and_domains() {
        assert_eq!(
            launchd_plist_path("com.bill.clashformac", LaunchdDomain::SystemDaemon)
                .unwrap()
                .display()
                .to_string(),
            "/Library/LaunchDaemons/com.bill.clashformac.plist"
        );
        assert_eq!(
            launchd_domain_target(LaunchdDomain::SystemDaemon).unwrap(),
            "system"
        );
        assert!(launchd_plist_path("bad/label", LaunchdDomain::SystemDaemon).is_err());
    }

    #[test]
    fn helper_program_path_accepts_existing_absolute_binary() {
        let path = std::env::temp_dir().join(format!(
            "cfw-helper-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, "#!/bin/sh\n").unwrap();
        assert_eq!(
            helper_program_path(path.to_string_lossy().as_ref()).unwrap(),
            path
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn privileged_helper_rejects_user_writable_locations() {
        let path = std::env::temp_dir().join(format!(
            "cfw-helper-unsafe-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, "#!/bin/sh\n").unwrap();
        let error = validate_privileged_helper_program(&path).unwrap_err();
        assert!(error.to_string().contains(PRIVILEGED_HELPER_TOOLS));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn launchctl_absent_errors_are_idempotent() {
        assert!(launchctl_absent_error(
            "Boot-out failed: 5: No such process"
        ));
        assert!(launchctl_absent_error("Could not find specified service"));
        assert!(!launchctl_absent_error(
            "Bootstrap failed: 5: Input/output error"
        ));
    }

    fn disabled_proxy_state() -> ProxyProtocolState {
        ProxyProtocolState {
            enabled: false,
            server: None,
            port: None,
        }
    }
}
