//! Windows tunnel device primitives. They do not authorize a user, publish
//! global readiness or change routing. The authority owns those decisions.
#[cfg(windows)]
mod driver;
mod packet;
#[cfg(windows)]
mod session;
#[cfg(windows)]
pub use driver::{Adapter, Library, Session, interface_identity, observe};
#[cfg(all(windows, feature = "native-service-validation"))]
pub(crate) use driver::{absence_within_deadline, wait_absent};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Windows tunnel contract: {0}")]
    Contract(String),
    #[error("Windows tunnel {operation}: {source}")]
    Native {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("Windows tunnel image: {0}")]
    Image(#[from] crate::Error),
    #[error("Windows tunnel installation: {0}")]
    Installation(#[from] crate::runtime_host::HostError),
    #[error("Windows tunnel packet ring is full")]
    RingFull,
    #[error("Windows tunnel packet length or IP header is invalid")]
    Packet,
}
impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self::Contract(value.to_owned())
    }
}
impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::Contract(value)
    }
}
pub type Result<T> = std::result::Result<T, Error>;
/// Wintun allocates one ring of this capacity in each direction.
pub const RING_CAPACITY_BYTES: u32 = 128 * 1024;

#[cfg(windows)]
fn native_error(operation: &'static str) -> Error {
    Error::Native {
        operation,
        source: std::io::Error::last_os_error(),
    }
}
