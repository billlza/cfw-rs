//! Installed Windows runtime entrypoints. Publisher/package admission belongs
//! to installation; these hosts require its protected, fixed-location manifest
//! and retain every admitted file identity throughout their lifetime.
#[cfg(windows)]
mod agent;
#[cfg(windows)]
mod desktop;
#[cfg(windows)]
mod installation;
mod manifest;
#[cfg(windows)]
mod service;
#[cfg(windows)]
pub use agent::run_agent;
#[cfg(windows)]
pub use desktop::InstalledDesktop;
#[cfg(windows)]
pub use installation::{InstalledRuntime, UserPaths};
#[cfg(windows)]
pub use service::run_service;

pub const SERVICE_NAME: &str = "CFWAuthority";
pub const PACKAGE_DIRECTORY: &str = "Clash for Windows";
pub const RUNTIME_FILE: &str = "cfw-windows-runtime.exe";
pub const DESKTOP_FILE: &str = "Clash for Windows.exe";
pub const ENGINE_FILE: &str = "cfw-engine-host.exe";
pub const MANIFEST_FILE: &str = "runtime-installation-v1.json";

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("Windows runtime installation manifest is invalid")]
    Manifest,
    #[error("Windows runtime installation ownership or write access is unsafe")]
    InstallationSecurity,
    #[error("Windows runtime known-folder lookup failed ({0:#x})")]
    KnownFolder(i32),
    #[error("Windows runtime I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Windows runtime executable: {0}")]
    Executable(#[from] crate::Error),
    #[cfg(windows)]
    #[error("Windows runtime private storage: {0}")]
    Storage(#[from] cfw_windows_storage::Error),
    #[cfg(windows)]
    #[error("Windows runtime peer identity: {0}")]
    Peer(#[from] crate::PeerIdentityError),
    #[cfg(windows)]
    #[error("Windows runtime service identity: {0}")]
    ServicePeer(#[from] crate::ServicePeerError),
    #[cfg(windows)]
    #[error("Windows runtime transport: {0}")]
    Transport(#[from] crate::ServiceTransportError),
    #[error("Windows runtime authority: {0}")]
    Authority(#[from] crate::authority::AuthorityError),
    #[cfg(windows)]
    #[error("Windows runtime Agent: {0}")]
    Agent(#[from] crate::user_agent::UserAgentError),
    #[cfg(windows)]
    #[error("Windows runtime Desktop: {0}")]
    Desktop(#[from] crate::user_agent::desktop::DesktopError),
    #[cfg(windows)]
    #[error("Windows runtime credentials: {0}")]
    Credentials(#[from] crate::credential_lifecycle::CredentialLifecycleError),
    #[cfg(windows)]
    #[error("Windows runtime lineage: {0}")]
    Lineage(#[from] crate::LineageError),
    #[cfg(windows)]
    #[error("Windows runtime handoff: {0}")]
    Handoff(#[from] crate::user_agent::launch_channel::LaunchChannelError),
    #[cfg(windows)]
    #[error("Windows runtime launch plan: {0}")]
    Plan(#[from] crate::user_agent::handoff::HandoffError),
    #[cfg(windows)]
    #[error("Windows runtime launcher: {0}")]
    Launcher(#[from] crate::user_agent::launcher::LaunchError),
    #[error("Windows runtime state: {0}")]
    State(&'static str),
    #[error("Windows runtime failed ({operation}); cleanup failed ({cleanup})")]
    Cleanup {
        operation: Box<Self>,
        cleanup: Box<Self>,
    },
}
type Result<T> = std::result::Result<T, HostError>;
