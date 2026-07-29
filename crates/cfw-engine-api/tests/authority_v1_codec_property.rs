//! Property 2: Canonical bounded protocol round trip.
//!
//! For all valid v1 authority models within command-specific bounds, canonical
//! encoding followed by decoding produces an equivalent value; for all
//! encodings with an unknown required field/command, noncanonical
//! representation, unsupported version, invalid type, or any exceeded bound,
//! decoding fails before state mutation.
//!
//! This is a deterministic, seeded generative property test. It builds valid
//! `RequestEnvelope`s across every command kind plus a spread of standalone
//! canonical models, proves canonical encode → decode → re-encode is stable
//! (an equivalent value), then subjects each valid encoding to a battery of
//! malformed / noncanonical / oversize / version-incompatible / out-of-bound
//! mutations and proves the codec rejects every one before yielding a value.
//! The generator is a reproducible SplitMix64 stream; on failure the seed and
//! the shrunk counterexample are printed so the exact case replays.
//!
//! **Validates: Requirements 2.2, 2.7, 6.4, 7.1**

use cfw_engine_api::authority_v1::*;
use cfw_engine_api::{
    CredentialAudience, CredentialKind, CredentialRef, CredentialSlot, CredentialTarget,
    TunnelNetworkOptions,
};
use uuid::Uuid;

// MARK: - Deterministic seed source

/// Deterministic, seedable value source (SplitMix64), reproducible across runs
/// and platforms so a printed seed replays the exact generated case.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn in_range(&mut self, lo: u64, hi: u64) -> u64 {
        debug_assert!(hi >= lo);
        lo + self.next_u64() % (hi - lo + 1)
    }
}

// MARK: - Generated case

/// Numeric choices that fully determine a generated case. Every field is kept
/// as a small value derived from the seed so a counterexample can be shrunk by
/// reducing each choice toward its minimal-valid value and re-deriving
/// deterministically.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CaseChoices {
    /// Selects the command kind (0..=8).
    command_index: u64,
    /// Seeds all UUIDs and digests for the case.
    entropy: u64,
    /// RootContext epoch (>= 1).
    epoch: u64,
    /// RootContext generation (>= 1).
    generation: u64,
    /// OperationContext authority revision (>= 1).
    revision: u64,
    /// Added to `revision` for begin_stop / cancel expected_revision.
    revision_delta: u64,
    /// Credential slot count for prepare_start configurations (0..=3).
    slot_count: u64,
    /// Tunnel MTU (1280..=1500) when the case is a Tunnel mode.
    mtu: u64,
    /// Ready attestation monotonic timestamp (>= 1).
    ready_ts: u64,
    /// Stopped attestation monotonic timestamp (>= 1).
    stopped_ts: u64,
    /// Configuration descriptor declared byte count (1..=MAX_CONFIGURATION_BYTES).
    byte_count: u64,
    /// Selects Tunnel vs System Proxy for commands that allow either mode.
    mode_is_tunnel: bool,
}

const COMMAND_COUNT: u64 = 9;

fn random_choices(rng: &mut SplitMix64) -> CaseChoices {
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

// MARK: - Value generators

fn uuid_from(seed: u64, salt: u64) -> Uuid {
    let mut rng = SplitMix64::new(seed ^ salt.wrapping_mul(0x1000_0000_0000_0001));
    let hi = rng.next_u64();
    let lo = rng.next_u64();
    Uuid::from_u128(((hi as u128) << 64) | lo as u128)
}

fn digest_from(seed: u64, salt: u64) -> String {
    let mut rng = SplitMix64::new(seed ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xABCD);
    let mut out = String::with_capacity(64);
    for _ in 0..32 {
        out.push_str(&format!("{:02x}", (rng.next_u64() & 0xFF) as u8));
    }
    out
}

/// Mode forced by command kind, if any; otherwise the caller's choice.
fn mode_for(choices: &CaseChoices) -> AuthorityMode {
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

fn operation_of(choices: &CaseChoices, mode: AuthorityMode) -> OperationContext {
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

fn configuration_of(
    choices: &CaseChoices,
    operation: &OperationContext,
) -> ConfigurationDescriptor {
    let tunnel_options = if operation.mode == AuthorityMode::Tunnel {
        Some(TunnelNetworkOptions {
            ipv6_enabled: true,
            bypass_private_networks: false,
            mtu: choices.mtu as u16,
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

fn packet_pump_limits() -> PacketPumpLimits {
    PacketPumpLimits {
        maximum_packet_bytes: 1_400,
        maximum_queued_bytes: 1_048_576,
        maximum_queued_packets: 512,
        maximum_read_batch: 32,
    }
}

/// Builds the valid command selected by `choices`. Every produced command
/// satisfies its `WireValidate` contract.
fn build_command(choices: &CaseChoices) -> Command {
    let mode = mode_for(choices);
    let operation = operation_of(choices, mode);
    let lease_id = uuid_from(choices.entropy, 5);
    match choices.command_index {
        0 => Command::Handshake(HandshakeRequest {
            version: ProtocolVersion::v1(),
        }),
        1 => {
            let configuration = configuration_of(choices, &operation);
            Command::PrepareStart(PrepareStartRequest {
                configuration,
                expected_revision: operation.authority_revision,
                operation,
            })
        }
        2 => Command::BindProxyOwner(BindProxyOwnerRequest {
            operation,
            lease_id,
            capability: OwnerCapability::new(&[0x5a; CAPABILITY_BYTES]).expect("capability"),
        }),
        3 => Command::RedeemTunnelTicket(RedeemTunnelTicketRequest {
            operation,
            lease_id,
            ticket: StartTicket::new(&[0x5a; TICKET_BYTES]).expect("ticket"),
        }),
        4 => {
            let (owner_role, packet_pump_limits) = match mode {
                AuthorityMode::Tunnel => (AuthorityRole::Provider, Some(packet_pump_limits())),
                AuthorityMode::SystemProxy => (AuthorityRole::ProxyAgent, None),
            };
            Command::AttestReady(ReadyAttestation {
                lease_id,
                monotonic_timestamp_ms: choices.ready_ts,
                operation,
                owner_role,
                packet_pump_limits,
                ready_flags: 0b111,
                runtime_digest: digest_from(choices.entropy, 6),
            })
        }
        5 => Command::BeginStop(BeginStopRequest {
            expected_revision: choices.revision + choices.revision_delta,
            lease_id,
            operation,
        }),
        6 => Command::AttestStopped(StoppedAttestation {
            lease_id,
            libbox_stopped: true,
            monotonic_timestamp_ms: choices.stopped_ts,
            operation,
            os_restored: true,
            transport_closed: true,
        }),
        7 => Command::CancelPrepared(CancelPreparedRequest {
            expected_revision: choices.revision + choices.revision_delta,
            operation,
        }),
        _ => Command::Snapshot(SnapshotRequest {}),
    }
}

fn command_kind(choices: &CaseChoices) -> &'static str {
    match choices.command_index {
        0 => "handshake",
        1 => "prepare_start",
        2 => "bind_proxy_owner",
        3 => "redeem_tunnel_ticket",
        4 => "attest_ready",
        5 => "begin_stop",
        6 => "attest_stopped",
        7 => "cancel_prepared",
        _ => "snapshot",
    }
}

// MARK: - Malformation battery

/// Replaces the first occurrence of `needle` in the UTF-8 bytes with
/// `replacement`, returning `None` when the needle is absent.
fn replace_once(data: &[u8], needle: &str, replacement: &str) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    if !text.contains(needle) {
        return None;
    }
    Some(text.replacen(needle, replacement, 1).into_bytes())
}

/// Every malformed / incompatible / out-of-bound derivative of a valid canonical
/// envelope. Each entry is `(label, bytes)`; the codec must reject all of them.
fn malformed_envelopes(choices: &CaseChoices, canonical: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut cases: Vec<(String, Vec<u8>)> = vec![
        // Empty and truncated inputs are structurally malformed.
        ("empty".into(), Vec::new()),
        (
            "truncated".into(),
            canonical[..canonical.len() / 2].to_vec(),
        ),
        // Trailing / leading whitespace is a noncanonical representation.
        ("trailing_space".into(), [canonical, b" "].concat()),
        ("leading_space".into(), [b" ", canonical].concat()),
        // Oversize exceeds the envelope bound before parsing.
        ("oversize".into(), vec![b' '; MAX_ENVELOPE_BYTES + 1]),
    ];

    // Duplicate key and unknown extra field.
    if let Some(bytes) = replace_once(canonical, "\"major\":", "\"major\":1,\"major\":") {
        cases.push(("duplicate_key".into(), bytes));
    }
    if let Some(bytes) = replace_once(canonical, "\"major\":", "\"extra\":0,\"major\":") {
        cases.push(("unknown_field".into(), bytes));
    }

    // Unsupported protocol version and required feature bits.
    if let Some(bytes) = replace_once(canonical, "\"major\":1", "\"major\":9") {
        cases.push(("unsupported_major".into(), bytes));
    }
    if let Some(bytes) = replace_once(canonical, "\"minor\":0", "\"minor\":7") {
        cases.push(("unsupported_minor".into(), bytes));
    }
    if let Some(bytes) = replace_once(
        canonical,
        "\"required_feature_bits\":0",
        "\"required_feature_bits\":1",
    ) {
        cases.push(("unsupported_feature".into(), bytes));
    }

    // Invalid type: a fractional number where an integer is required.
    if let Some(bytes) = replace_once(canonical, "\"minor\":0", "\"minor\":0.0") {
        cases.push(("float_number".into(), bytes));
    }

    // Unknown command kind.
    let kind = command_kind(choices);
    if let Some(bytes) = replace_once(
        canonical,
        &format!("\"kind\":\"{kind}\""),
        "\"kind\":\"nope_unknown_command\"",
    ) {
        cases.push(("unknown_command".into(), bytes));
    }

    // Exceeded command-specific bound: an oversized configuration byte count.
    if choices.command_index == 1
        && let Some(bytes) = replace_once(
            canonical,
            &format!("\"byte_count\":{}", choices.byte_count),
            "\"byte_count\":999999999",
        )
    {
        cases.push(("byte_count_bound".into(), bytes));
    }

    cases
}

// MARK: - Standalone canonical models

fn replay_cursor_of(choices: &CaseChoices) -> ReplayCursor {
    ReplayCursor {
        accepted_epoch: choices.epoch,
        accepted_generation: choices.generation,
        installation_id: uuid_from(choices.entropy, 7),
        previous_record_sha256: digest_from(choices.entropy, 8),
        revision: choices.revision,
        schema_version: 1,
    }
}

fn snapshot_of(choices: &CaseChoices) -> AuthoritySnapshot {
    AuthoritySnapshot {
        console_uid: None,
        last_failure: None,
        lease_view: None,
        protocol_version: ProtocolVersion::v1(),
        replay_cursor: replay_cursor_of(choices),
        revision: choices.revision + choices.revision_delta,
        state: AuthorityState::Off,
    }
}

fn global_lease_of(choices: &CaseChoices) -> GlobalLease {
    let mode = if choices.mode_is_tunnel {
        AuthorityMode::Tunnel
    } else {
        AuthorityMode::SystemProxy
    };
    GlobalLease {
        expiry_monotonic_ms: choices.ready_ts + 1,
        issued_monotonic_ms: choices.ready_ts,
        lease_id: uuid_from(choices.entropy, 9),
        operation: operation_of(choices, mode),
        owner_connection_nonce_sha256: digest_from(choices.entropy, 10),
        state: LeaseState::Active,
    }
}

fn preference_receipt_of(choices: &CaseChoices) -> PreferenceMutationReceipt {
    PreferenceMutationReceipt {
        created_manager: true,
        operation_id: uuid_from(choices.entropy, 11),
        prior_values: None,
        written_descriptor_sha256: digest_from(choices.entropy, 12),
    }
}

/// Round-trips a standalone canonical model and asserts value equivalence,
/// returning a violation description on any failure.
fn check_canonical_round_trip<T>(label: &str, value: &T) -> Option<String>
where
    T: serde::Serialize + serde::de::DeserializeOwned + WireValidate + PartialEq,
{
    let bytes = match encode_canonical(value) {
        Ok(bytes) => bytes,
        Err(error) => return Some(format!("{label}: valid model failed to encode: {error:?}")),
    };
    let decoded = match decode_canonical::<T>(&bytes) {
        Ok(decoded) => decoded,
        Err(error) => {
            return Some(format!(
                "{label}: canonical bytes failed to decode: {error:?}"
            ));
        }
    };
    if &decoded != value {
        return Some(format!(
            "{label}: decoded value is not equivalent to the original"
        ));
    }
    match encode_canonical(&decoded) {
        Ok(reencoded) if reencoded == bytes => None,
        Ok(_) => Some(format!(
            "{label}: re-encoding decoded value is not byte-stable"
        )),
        Err(error) => Some(format!(
            "{label}: decoded value failed to re-encode: {error:?}"
        )),
    }
}

// MARK: - Property evaluation

/// Returns `None` when the case satisfies Property 2, or a description of the
/// first violation otherwise.
fn evaluate(choices: &CaseChoices) -> Option<String> {
    // 1. Valid envelope round trip: encode → decode → re-encode is byte stable,
    //    which is the canonical form's notion of an equivalent value (the
    //    envelope holds non-cloneable secret material, so byte stability is the
    //    equivalence witness).
    let command = build_command(choices);
    let envelope = match RequestEnvelope::new(uuid_from(choices.entropy, 0), 0, command) {
        Ok(envelope) => envelope,
        Err(error) => {
            return Some(format!(
                "valid command rejected by RequestEnvelope::new: {error:?}"
            ));
        }
    };
    let canonical = match encode_request(&envelope) {
        Ok(bytes) => bytes,
        Err(error) => return Some(format!("valid envelope failed to encode: {error:?}")),
    };
    let decoded = match decode_request(&canonical) {
        Ok(decoded) => decoded,
        Err(error) => return Some(format!("canonical envelope failed to decode: {error:?}")),
    };
    match encode_request(&decoded) {
        Ok(reencoded) if reencoded == canonical => {}
        Ok(_) => return Some("decoded envelope re-encodes to different bytes".into()),
        Err(error) => return Some(format!("decoded envelope failed to re-encode: {error:?}")),
    }

    // 2. Every malformed / incompatible / out-of-bound derivative must be
    //    rejected before a value (and therefore any state mutation) is produced.
    for (label, mutated) in malformed_envelopes(choices, &canonical) {
        if decode_request(&mutated).is_ok() {
            return Some(format!(
                "malformed envelope '{label}' decoded instead of being rejected"
            ));
        }
    }

    // 3. Standalone canonical models round-trip with true value equality.
    let snapshot = snapshot_of(choices);
    if let Some(reason) = check_canonical_round_trip("AuthoritySnapshot", &snapshot) {
        return Some(reason);
    }
    let cursor = replay_cursor_of(choices);
    if let Some(reason) = check_canonical_round_trip("ReplayCursor", &cursor) {
        return Some(reason);
    }
    let lease = global_lease_of(choices);
    if let Some(reason) = check_canonical_round_trip("GlobalLease", &lease) {
        return Some(reason);
    }
    let receipt = preference_receipt_of(choices);
    if let Some(reason) = check_canonical_round_trip("PreferenceMutationReceipt", &receipt) {
        return Some(reason);
    }

    // 4. An out-of-bound standalone model must be rejected on decode. A valid
    //    ReplayCursor with its revision forced to the illegal value 0 keeps a
    //    canonical shape yet must fail validation before yielding a value.
    let cursor_bytes = encode_canonical(&cursor).expect("valid cursor encodes");
    if let Some(zeroed) = replace_once(
        &cursor_bytes,
        &format!("\"revision\":{}", choices.revision),
        "\"revision\":0",
    ) && decode_canonical::<ReplayCursor>(&zeroed).is_ok()
    {
        return Some(
            "out-of-bound ReplayCursor (revision=0) decoded instead of being rejected".into(),
        );
    }

    None
}

// MARK: - Shrinking

fn shrink_candidates(choices: &CaseChoices) -> Vec<CaseChoices> {
    let mut candidates = Vec::new();
    let mut push_if = |c: CaseChoices| {
        if &c != choices {
            candidates.push(c);
        }
    };
    if choices.entropy != 0 {
        let mut c = choices.clone();
        c.entropy = 0;
        push_if(c);
    }
    if choices.epoch != 1 {
        let mut c = choices.clone();
        c.epoch = 1;
        push_if(c);
    }
    if choices.generation != 1 {
        let mut c = choices.clone();
        c.generation = 1;
        push_if(c);
    }
    if choices.revision != 1 {
        let mut c = choices.clone();
        c.revision = 1;
        push_if(c);
    }
    if choices.revision_delta != 0 {
        let mut c = choices.clone();
        c.revision_delta = 0;
        push_if(c);
    }
    if choices.slot_count != 0 {
        let mut c = choices.clone();
        c.slot_count = 0;
        push_if(c);
    }
    if choices.mtu != 1_280 {
        let mut c = choices.clone();
        c.mtu = 1_280;
        push_if(c);
    }
    if choices.ready_ts != 1 {
        let mut c = choices.clone();
        c.ready_ts = 1;
        push_if(c);
    }
    if choices.stopped_ts != 1 {
        let mut c = choices.clone();
        c.stopped_ts = 1;
        push_if(c);
    }
    if choices.byte_count != 1 {
        let mut c = choices.clone();
        c.byte_count = 1;
        push_if(c);
    }
    if choices.mode_is_tunnel {
        let mut c = choices.clone();
        c.mode_is_tunnel = false;
        push_if(c);
    }
    candidates
}

/// Greedily reduces choices while the failure persists, terminating at a local
/// minimum that still reproduces the violation.
fn shrink(choices: &CaseChoices) -> CaseChoices {
    let mut current = choices.clone();
    let mut improved = true;
    while improved {
        improved = false;
        for candidate in shrink_candidates(&current) {
            if evaluate(&candidate).is_some() {
                current = candidate;
                improved = true;
                break;
            }
        }
    }
    current
}

// MARK: - Property test

/// Base seed. Override with `CFW_PBT_SEED_PROP2` to replay a printed failure.
fn base_seed() -> u64 {
    std::env::var("CFW_PBT_SEED_PROP2")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(0xC0FF_EE13_A5A5_0002)
}

#[test]
fn canonical_bounded_protocol_round_trips_and_rejects_malformed() {
    let seed = base_seed();
    let iterations = 200;

    let mut successful_cases = 0;
    let mut tunnel_cases = 0;
    let mut proxy_cases = 0;
    let mut covered_commands = std::collections::BTreeSet::new();
    let mut failure: Option<(u64, CaseChoices, String)> = None;

    for index in 0..iterations {
        let iteration_seed = seed.wrapping_add(index as u64);
        let mut rng = SplitMix64::new(iteration_seed);

        // Deterministically cycle through every command kind so each is
        // exercised, then let the seed spread the remaining dimensions.
        let mut choices = random_choices(&mut rng);
        choices.command_index = index as u64 % COMMAND_COUNT;

        if let Some(reason) = evaluate(&choices) {
            let shrunk = shrink(&choices);
            let shrunk_reason = evaluate(&shrunk).unwrap_or(reason);
            failure = Some((iteration_seed, shrunk, shrunk_reason));
            break;
        }

        covered_commands.insert(choices.command_index);
        match mode_for(&choices) {
            AuthorityMode::Tunnel => tunnel_cases += 1,
            AuthorityMode::SystemProxy => proxy_cases += 1,
        }
        successful_cases += 1;
    }

    if let Some((failure_seed, shrunk, reason)) = &failure {
        panic!(
            "Property 2 counterexample found.\n\
             reproduce with: CFW_PBT_SEED_PROP2={failure_seed}\n\
             shrunk choices: {shrunk:?}\n\
             violation: {reason}"
        );
    }

    assert!(
        successful_cases >= 100,
        "expected at least 100 successful generated cases, ran {successful_cases}"
    );
    assert_eq!(
        covered_commands.len() as u64,
        COMMAND_COUNT,
        "generated batch did not exercise every command kind: {covered_commands:?}"
    );
    assert!(
        tunnel_cases > 0,
        "generated batch never exercised a Tunnel case"
    );
    assert!(
        proxy_cases > 0,
        "generated batch never exercised a System Proxy case"
    );
}
