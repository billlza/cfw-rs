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

use crate::{
    generators::{COMMAND_COUNT, CaseChoices, SplitMix64, mode_for, random_choices},
    round_trip::evaluate,
    shrinking::shrink,
};

mod commands;
mod generators;
mod malformed;
mod records;
mod round_trip;
mod shrinking;

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
            AuthorityMode::LocalProxy | AuthorityMode::SystemProxy => proxy_cases += 1,
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
