//! Windows tunnel device primitives. They do not authorize a user, publish
//! global readiness or change routing. The authority owns those decisions.
#[cfg(windows)]
mod channel;
#[cfg(windows)]
mod device;
#[cfg(windows)]
mod driver;
mod endpoint;
#[cfg(windows)]
mod host;
#[cfg(windows)]
mod network;
mod packet;
mod plan;
mod policy;
#[cfg(windows)]
mod pump;
#[cfg(windows)]
mod session;
#[cfg(all(windows, feature = "native-service-validation"))]
pub use channel::{AdoptedEndpointProbe, PacketHandoffProbe};
#[cfg(windows)]
pub use channel::{
    ENDPOINT_ACCESS, EndpointHandoff, HandoffError, PacketCancellation, PacketClient, PacketServer,
};
#[cfg(windows)]
pub use device::interface_luid;
#[cfg(windows)]
pub(crate) use device::{
    WintunDevice, absent as adapter_absent, wait_until_absent as wait_until_adapter_absent,
};
#[cfg(windows)]
pub use driver::{Adapter, Library, Session, interface_identity, observe};
#[cfg(all(windows, feature = "native-service-validation"))]
pub(crate) use driver::{InterfaceCounters, absence_within_deadline, counters, wait_absent};
pub use endpoint::{EndpointOffer, HANDOFF_MTU};
#[cfg(windows)]
pub use host::{PumpSummary, TunnelHost, TunnelRetirement};
#[cfg(windows)]
pub use network::{NetworkPhase, NetworkReceipt};
pub use plan::{FamilyPlan, Ipv4Prefix, Ipv6Prefix, TunnelNetworkPlan, adapter_guid};
pub use policy::{DeliveryPolicy, Refusal, RefusalReason};
#[cfg(windows)]
pub use pump::{
    DirectionCounters, PacketPump, PumpControl, PumpReport, PumpRetirement, RefusedClass,
    RefusedPackets,
};

use std::{fmt, time::Duration};

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
    #[cfg(windows)]
    #[error("Windows tunnel packet transport: {0}")]
    Transport(#[from] crate::ServiceTransportError),
    #[error(
        "Windows tunnel packet endpoint peer closed before retirement was requested (native code {code})"
    )]
    PeerClosed { code: i32 },
    #[error("Windows tunnel {direction} packet transfer exceeded its bound")]
    Stalled { direction: PumpDirection },
    #[error(
        "Windows tunnel packet endpoint closure was not observed before its retirement deadline"
    )]
    PeerCloseUnobserved,
    #[error("Windows tunnel {direction} packet worker panicked: {message}")]
    WorkerPanicked {
        direction: PumpDirection,
        message: String,
    },
    #[error("Windows tunnel operation failed ({operation}); cleanup failed ({cleanup})")]
    Cleanup {
        operation: Box<Self>,
        cleanup: Box<Self>,
    },
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

/// The bounds a Windows Tunnel Ready attests for SYSTEM's packet pump: in
/// user space it holds one packet of the endpoint MTU per direction and reads
/// one at a time. The Wintun rings and the endpoint pipe are kernel buffers,
/// bounded by `RING_CAPACITY_BYTES` and the pipe capacity, not pump queues.
pub fn packet_pump_limits(mtu: u16) -> cfw_engine_api::authority_v1::PacketPumpLimits {
    cfw_engine_api::authority_v1::PacketPumpLimits {
        maximum_packet_bytes: mtu,
        maximum_queued_bytes: 2 * u32::from(mtu),
        maximum_queued_packets: 2,
        maximum_read_batch: 1,
    }
}

/// How long SYSTEM may take to create and configure a tunnel adapter, which
/// includes the first installation of the pinned Wintun driver.
pub const OPEN_LIMIT: Duration = Duration::from_secs(45);

/// Longest one packet may wait for the engine endpoint or the system send
/// ring. Shorter than the engine's own five-second write deadline, so a full
/// system ring is reported by the pump instead of as an engine failure.
pub const PACKET_TRANSFER_BOUND: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PumpDirection {
    /// Packets the Windows IP stack routed into the adapter.
    ToEngine,
    /// Packets the engine produced for the Windows IP stack.
    ToSystem,
}
impl fmt::Display for PumpDirection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ToEngine => "system-to-engine",
            Self::ToSystem => "engine-to-system",
        })
    }
}

/// ERROR_BROKEN_PIPE and ERROR_NO_DATA: the codes the server end of a packet
/// pipe reports after its client end closes. ERROR_PIPE_NOT_CONNECTED follows
/// only this side's own disconnect, so it is not a peer observation.
const PEER_CLOSE_CODES: [i32; 2] = [109, 232];

pub(crate) fn peer_close_code(error: &std::io::Error) -> Option<i32> {
    error
        .raw_os_error()
        .filter(|code| PEER_CLOSE_CODES.contains(code))
}

/// The first failure stays the operation; a later one is kept as cleanup.
pub(crate) fn merge_failures(first: Option<Error>, second: Option<Error>) -> Option<Error> {
    match (first, second) {
        (None, None) => None,
        (Some(error), None) | (None, Some(error)) => Some(error),
        (Some(operation), Some(cleanup)) => Some(Error::Cleanup {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
}

#[cfg(windows)]
fn native_error(operation: &'static str) -> Error {
    Error::Native {
        operation,
        source: std::io::Error::last_os_error(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_transfer_bound_stays_below_the_engine_write_deadline() {
        const ENGINE: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../native/windows/engine-host/packet_windows.go"
        ));
        let declarations: Vec<_> = ENGINE
            .lines()
            .filter_map(|line| line.strip_prefix("const packetWriteTimeout = "))
            .collect();
        assert_eq!(declarations, ["5 * time.Second"]);
        assert!(PACKET_TRANSFER_BOUND < Duration::from_secs(5));
        assert!(PACKET_TRANSFER_BOUND >= Duration::from_secs(1));
    }

    #[test]
    fn only_the_peer_closing_codes_count_as_a_closed_endpoint() {
        for code in [109, 232] {
            assert_eq!(
                peer_close_code(&std::io::Error::from_raw_os_error(code)),
                Some(code)
            );
        }
        // Cancellation, a full pipe, our own disconnect and timeouts are not a
        // peer observation.
        for code in [0, 5, 6, 233, 258, 995, 997, 1460] {
            assert_eq!(
                peer_close_code(&std::io::Error::from_raw_os_error(code)),
                None
            );
        }
        assert_eq!(peer_close_code(&std::io::Error::other("peer")), None);
    }

    #[test]
    fn the_first_failure_remains_the_operation() {
        assert!(merge_failures(None, None).is_none());
        assert!(matches!(
            merge_failures(Some(Error::Packet), None),
            Some(Error::Packet)
        ));
        assert!(matches!(
            merge_failures(None, Some(Error::RingFull)),
            Some(Error::RingFull)
        ));
        let merged = merge_failures(
            Some(Error::PeerClosed { code: 109 }),
            Some(Error::Stalled {
                direction: PumpDirection::ToSystem,
            }),
        );
        assert!(matches!(
            merged,
            Some(Error::Cleanup { operation, cleanup })
                if matches!(*operation, Error::PeerClosed { code: 109 })
                    && matches!(*cleanup, Error::Stalled { direction: PumpDirection::ToSystem })
        ));
        assert_eq!(PumpDirection::ToEngine.to_string(), "system-to-engine");
        assert_eq!(PumpDirection::ToSystem.to_string(), "engine-to-system");
    }
}
