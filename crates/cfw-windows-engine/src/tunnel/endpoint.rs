//! The terms on which a SYSTEM-created packet endpoint may reach a user
//! process: who may receive it, and what SYSTEM tells the recipient.
use serde::{Deserialize, Serialize};

/// The packet MTUs an Authority may attest for a Tunnel run. They match the
/// shared Authority protocol's `PacketPumpLimits`, as on macOS; the data plane
/// itself accepts more, but no larger endpoint is handed over.
pub const HANDOFF_MTU: std::ops::RangeInclusive<u16> = 1280..=1500;

/// What SYSTEM tells the recipient over its authenticated connection: the
/// handle value SYSTEM placed in the recipient's handle table, and the
/// endpoint's adapter and MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointOffer {
    pub handle: u64,
    pub adapter: uuid::Uuid,
    pub mtu: u16,
}

impl EndpointOffer {
    pub fn is_well_formed(&self) -> bool {
        handle_value_is_well_formed(self.handle)
            && !self.adapter.is_nil()
            && HANDOFF_MTU.contains(&self.mtu)
    }
}

/// A non-zero, pointer-sized, four-aligned value, as Windows handle values are.
pub(crate) fn handle_value_is_well_formed(value: u64) -> bool {
    value != 0 && value <= isize::MAX as u64 && value & 3 == 0
}

/// Medium or high integrity in an interactive session, and neither SYSTEM,
/// an AppContainer nor a restricted token. Low and untrusted integrity are
/// sandboxes; system integrity is never an ordinary user's process.
pub(crate) fn admits_recipient(
    local_system: bool,
    session_id: u32,
    integrity_rid: u32,
    app_container: bool,
    restricted: bool,
) -> bool {
    !local_system
        && session_id != 0
        && (0x2000..0x4000).contains(&integrity_rid)
        && !app_container
        && !restricted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> EndpointOffer {
        EndpointOffer {
            handle: 0x1a4,
            adapter: uuid::Uuid::from_u128(0x6f1c_2d4e_8a90_4b7c_9e3f_1a2b_3c4d_5e6f),
            mtu: 1500,
        }
    }

    #[test]
    fn packet_handoff_admits_medium_and_high_integrity_users_only() {
        // Medium, medium-plus and high integrity in an interactive session.
        for integrity in [0x2000, 0x2100, 0x3000, 0x3fff] {
            assert!(
                admits_recipient(false, 1, integrity, false, false),
                "{integrity:#x}"
            );
        }
        // Untrusted, low, system and protected-process integrity.
        for integrity in [0, 0x1000, 0x1fff, 0x4000, 0x5000] {
            assert!(
                !admits_recipient(false, 1, integrity, false, false),
                "{integrity:#x}"
            );
        }
        assert!(!admits_recipient(true, 1, 0x3000, false, false));
        assert!(!admits_recipient(false, 0, 0x2000, false, false));
        assert!(!admits_recipient(false, 1, 0x2000, true, false));
        assert!(!admits_recipient(false, 1, 0x2000, false, true));
    }

    #[test]
    fn packet_handoff_offers_only_well_formed_endpoints_within_the_wire_mtu() {
        assert!(offer().is_well_formed());
        for mtu in [1280, 1500] {
            assert!(EndpointOffer { mtu, ..offer() }.is_well_formed());
        }
        for mtu in [0, 1279, 1501, 9000] {
            assert!(!EndpointOffer { mtu, ..offer() }.is_well_formed(), "{mtu}");
        }
        for handle in [0, 2, 0x1a5, isize::MAX as u64 + 1, u64::MAX] {
            assert!(
                !EndpointOffer { handle, ..offer() }.is_well_formed(),
                "{handle:#x}"
            );
        }
        assert!(handle_value_is_well_formed(4));
        assert!(
            !EndpointOffer {
                adapter: uuid::Uuid::nil(),
                ..offer()
            }
            .is_well_formed()
        );
    }

    #[test]
    fn packet_handoff_mtu_is_the_authority_packet_pump_bound() {
        use cfw_engine_api::authority_v1::{PacketPumpLimits, WireValidate};
        let limits = |maximum_packet_bytes| PacketPumpLimits {
            maximum_packet_bytes,
            maximum_queued_bytes: 1_048_576,
            maximum_queued_packets: 256,
            maximum_read_batch: 32,
        };
        for mtu in [*HANDOFF_MTU.start(), *HANDOFF_MTU.end()] {
            limits(mtu).validate().unwrap();
        }
        for mtu in [HANDOFF_MTU.start() - 1, HANDOFF_MTU.end() + 1] {
            assert!(limits(mtu).validate().is_err(), "{mtu}");
        }
    }

    #[test]
    fn packet_handoff_offer_decodes_only_its_exact_fields() {
        let encoded = serde_json::to_string(&offer()).unwrap();
        assert_eq!(
            serde_json::from_str::<EndpointOffer>(&encoded).unwrap(),
            offer()
        );
        let mut extra: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        extra["access"] = serde_json::json!(0x1f01ff);
        assert!(serde_json::from_value::<EndpointOffer>(extra).is_err());
        let mut missing: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        missing.as_object_mut().unwrap().remove("mtu");
        assert!(serde_json::from_value::<EndpointOffer>(missing).is_err());
    }
}
