//! Shrinking a failing case to a minimal counterexample.

use crate::{generators::CaseChoices, round_trip::evaluate};

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
pub(crate) fn shrink(choices: &CaseChoices) -> CaseChoices {
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
