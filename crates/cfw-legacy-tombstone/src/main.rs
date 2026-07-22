//! Non-operational descriptor target for unregistering the historical Service
//! Mode registration through `SMAppService`.
//!
//! This binary deliberately performs no filesystem, process, launchd, proxy,
//! DNS, route, interface, or network mutation. The signed application owns the
//! separately verified false-first retirement transaction. If launchd or a
//! user executes this placeholder unexpectedly, it rejects execution.

const RETIRED_EXIT_CODE: i32 = 78;

fn main() {
    eprintln!(
        "legacy Service Mode is retired; this non-operational descriptor cannot modify networking"
    );
    std::process::exit(RETIRED_EXIT_CODE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_is_a_fixed_non_successful_refusal() {
        assert_ne!(RETIRED_EXIT_CODE, 0);
    }
}
