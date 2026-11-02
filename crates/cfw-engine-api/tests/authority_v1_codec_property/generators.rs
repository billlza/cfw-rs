//! Seeded random cases: the SplitMix64 stream, the choices of one case and the
//! value generators.

use cfw_engine_api::{
    CredentialAudience, CredentialKind, CredentialRef, CredentialSlot, CredentialTarget,
    DirectIpv4HostRoutes, TunnelNetworkOptions, authority_v1::*,
};
use uuid::Uuid;

/// Deterministic, seedable value source (SplitMix64), reproducible across runs
/// and platforms so a printed seed replays the exact generated case.
pub(crate) struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub(crate) fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub(crate) fn in_range(&mut self, lo: u64, hi: u64) -> u64 {
        debug_assert!(hi >= lo);
        lo + self.next_u64() % (hi - lo + 1)
    }
}

/// Numeric choices that fully determine a generated case. Every field is kept
/// as a small value derived from the seed so a counterexample can be shrunk by
/// reducing each choice toward its minimal-valid value and re-deriving
/// deterministically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaseChoices {
    /// Selects the command kind (0..=8).
    pub(crate) command_index: u64,
    /// Seeds all UUIDs and digests for the case.
    pub(crate) entropy: u64,
    /// RootContext epoch (>= 1).
    pub(crate) epoch: u64,
    /// RootContext generation (>= 1).
    pub(crate) generation: u64,
    /// OperationContext authority revision (>= 1).
    pub(crate) revision: u64,
    /// Added to `revision` for begin_stop / cancel expected_revision.
    pub(crate) revision_delta: u64,
    /// Credential slot count for prepare_start configurations (0..=3).
    pub(crate) slot_count: u64,
    /// Tunnel MTU (1280..=1500) when the case is a Tunnel mode.
    pub(crate) mtu: u64,
    /// Ready attestation monotonic timestamp (>= 1).
    pub(crate) ready_ts: u64,
    /// Stopped attestation monotonic timestamp (>= 1).
    pub(crate) stopped_ts: u64,
    /// Configuration descriptor declared byte count (1..=MAX_CONFIGURATION_BYTES).
    pub(crate) byte_count: u64,
    /// Selects Tunnel vs System Proxy for commands that allow either mode.
    pub(crate) mode_is_tunnel: bool,
}

pub(crate) const COMMAND_COUNT: u64 = 9;

pub(crate) fn random_choices(rng: &mut SplitMix64) -> CaseChoices {
    CaseChoices {
        command_index: rng.in_range(0, COMMAND_COUNT - 1),
        entropy: rng.next_u64(),
        epoch: rng.in_range(1, 1_000_000),
        generation: rng.in_range(1, 1_000_000),
        revision: rng.in_range(1, 1_000_000),
        revision_delta: rng.in_range(0, 8),
        slot_count: rng.in_range(0, 3),
        mtu: rng.in_range(1_280, 1_500),
        ready_ts: rng.in_range(1, u64::MAX / 2),
        stopped_ts: rng.in_range(1, u64::MAX / 2),
        byte_count: rng.in_range(1, MAX_CONFIGURATION_BYTES as u64),
        mode_is_tunnel: rng.next_u64() & 1 == 0,
    }
}

pub(crate) fn uuid_from(seed: u64, salt: u64) -> Uuid {
    let mut rng = SplitMix64::new(seed ^ salt.wrapping_mul(0x1000_0000_0000_0001));
    let hi = rng.next_u64();
    let lo = rng.next_u64();
    Uuid::from_u128(((hi as u128) << 64) | lo as u128)
}

pub(crate) fn digest_from(seed: u64, salt: u64) -> String {
    let mut rng = SplitMix64::new(seed ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xABCD);
    let mut out = String::with_capacity(64);
    for _ in 0..32 {
        out.push_str(&format!("{:02x}", (rng.next_u64() & 0xFF) as u8));
    }
    out
}

/// Mode forced by command kind, if any; otherwise the caller's choice.
pub(crate) fn mode_for(choices: &CaseChoices) -> AuthorityMode {
    match choices.command_index {
        2 => AuthorityMode::SystemProxy, // bind_proxy_owner
        3 => AuthorityMode::Tunnel,      // redeem_tunnel_ticket
        _ if choices.mode_is_tunnel => AuthorityMode::Tunnel,
        _ => AuthorityMode::SystemProxy,
    }
}

fn root_of(choices: &CaseChoices) -> RootContext {
    RootContext {
        epoch: choices.epoch,
        generation: choices.generation,
        installation_id: uuid_from(choices.entropy, 1),
    }
}

pub(crate) fn operation_of(choices: &CaseChoices, mode: AuthorityMode) -> OperationContext {
    OperationContext {
        authority_revision: choices.revision,
        config_sha256: digest_from(choices.entropy, 2),
        identity_sha256: digest_from(choices.entropy, 3),
        mode,
        operation_id: uuid_from(choices.entropy, 4),
        owner_uid: 501,
        root: root_of(choices),
    }
}

fn credential_slots(choices: &CaseChoices) -> Vec<CredentialSlot> {
    (0..choices.slot_count)
        .map(|index| {
            let reference = CredentialRef::new(
                uuid_from(choices.entropy, 100 + index)
                    .hyphenated()
                    .to_string(),
                CredentialKind::TrojanPassword,
            )
            .expect("canonical credential reference");
            CredentialSlot::new(reference, CredentialTarget::TrojanPassword, index as usize)
                .expect("valid credential slot")
        })
        .collect()
}

pub(crate) fn configuration_of(
    choices: &CaseChoices,
    operation: &OperationContext,
) -> ConfigurationDescriptor {
    let tunnel_options = if operation.mode == AuthorityMode::Tunnel {
        Some(TunnelNetworkOptions {
            ipv6_enabled: true,
            bypass_private_networks: false,
            direct_ipv4_hosts: DirectIpv4HostRoutes::none(),
            mtu: choices.mtu as u16,
            system_proxy_port: None,
        })
    } else {
        None
    };
    ConfigurationDescriptor {
        byte_count: choices.byte_count as u32,
        config_sha256: operation.config_sha256.clone(),
        credential_audience: CredentialAudience::new(
            operation.root.installation_id.hyphenated().to_string(),
            operation.identity_sha256.clone(),
        )
        .expect("canonical credential audience"),
        credential_slots: credential_slots(choices),
        identity_sha256: operation.identity_sha256.clone(),
        tunnel_options,
    }
}

pub(crate) fn packet_pump_limits() -> PacketPumpLimits {
    PacketPumpLimits {
        maximum_packet_bytes: 1_400,
        maximum_queued_bytes: 1_048_576,
        maximum_queued_packets: 512,
        maximum_read_batch: 32,
    }
}
