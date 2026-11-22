//! How the owner of a run reads the Authority: one observation and, while the
//! observed state carries a lease, the Authority's word that the lease is this
//! connection's. The Authority answers the two requests one at a time. When
//! the Agent ends a run itself, SYSTEM can commit global Off and release the
//! lease between them; the proof is then refused with `Identity`, as for a
//! lease another owner holds. A fresh observation tells the two apart.
use crate::authority::AuthoritySnapshot;
use cfw_engine_api::authority_v1::AuthorityState;

/// The two reads, on the owner's own Authority connection.
pub(super) trait OwnerReads {
    type Error;
    /// One observation of the owner's run.
    fn observe(&mut self) -> Result<AuthoritySnapshot, Self::Error>;
    /// The Authority's word that the observed lease is this connection's.
    fn prove_lease(&mut self) -> Result<(), Self::Error>;
    /// Whether the Authority refused that proof because it holds no lease of
    /// this connection.
    fn is_lease_refusal(error: &Self::Error) -> bool;
}

/// Observe the owner's run and prove its lease while the observed state
/// carries one. A refused proof stands unless a fresh observation finds the
/// run past every state with a lease; that observation is then the answer.
pub(super) fn observe_owned<R: OwnerReads>(reads: &mut R) -> Result<AuthoritySnapshot, R::Error> {
    let snapshot = reads.observe()?;
    if !carries_lease(snapshot.state) {
        return Ok(snapshot);
    }
    match reads.prove_lease() {
        Ok(()) => Ok(snapshot),
        Err(refusal) if R::is_lease_refusal(&refusal) => {
            let after = reads.observe()?;
            if carries_lease(after.state) {
                Err(refusal)
            } else {
                Ok(after)
            }
        }
        Err(error) => Err(error),
    }
}

/// The states of a run that may still execute, whose lease the owner proves.
const fn carries_lease(state: AuthorityState) -> bool {
    matches!(
        state,
        AuthorityState::Preparing
            | AuthorityState::Starting
            | AuthorityState::Active
            | AuthorityState::Stopping
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Refused {
        /// The Authority holds no lease of this connection.
        Lease,
        /// Any other failure.
        Other,
    }

    /// The Authority's answers, in the order the owner asks for them.
    struct Script {
        observations: VecDeque<Result<AuthorityState, Refused>>,
        proof: Option<Result<(), Refused>>,
        reads: Vec<&'static str>,
    }
    impl Script {
        fn new(
            observations: impl IntoIterator<Item = Result<AuthorityState, Refused>>,
            proof: Option<Result<(), Refused>>,
        ) -> Self {
            Self {
                observations: observations.into_iter().collect(),
                proof,
                reads: Vec::new(),
            }
        }
    }
    impl OwnerReads for Script {
        type Error = Refused;
        fn observe(&mut self) -> Result<AuthoritySnapshot, Refused> {
            self.reads.push("observe");
            let state = self
                .observations
                .pop_front()
                .expect("the owner asked for an observation the script does not have")?;
            Ok(AuthoritySnapshot {
                state,
                revision: Some(7),
                root: None,
            })
        }
        fn prove_lease(&mut self) -> Result<(), Refused> {
            self.reads.push("prove");
            self.proof
                .take()
                .expect("the owner asked for a proof the script does not have")
        }
        fn is_lease_refusal(error: &Refused) -> bool {
            *error == Refused::Lease
        }
    }

    fn observed(script: &mut Script) -> Result<AuthorityState, Refused> {
        observe_owned(script).map(|snapshot| snapshot.state)
    }

    #[test]
    fn a_lease_released_between_the_two_reads_is_read_as_the_state_that_followed() {
        // The Agent ended its run: SYSTEM committed Off, or quarantined or
        // began recovering the run, after the first observation.
        for (before, after) in [
            (AuthorityState::Stopping, AuthorityState::Off),
            (AuthorityState::Active, AuthorityState::Off),
            (AuthorityState::Starting, AuthorityState::Quarantined),
            (AuthorityState::Preparing, AuthorityState::Recovering),
        ] {
            let mut script = Script::new([Ok(before), Ok(after)], Some(Err(Refused::Lease)));
            assert_eq!(
                observed(&mut script),
                Ok(after),
                "{before:?} then {after:?}"
            );
            assert_eq!(script.reads, ["observe", "prove", "observe"]);
        }
    }

    #[test]
    fn a_refusal_while_the_run_still_holds_a_lease_stands() {
        for state in [
            AuthorityState::Preparing,
            AuthorityState::Starting,
            AuthorityState::Active,
            AuthorityState::Stopping,
        ] {
            let mut script = Script::new([Ok(state), Ok(state)], Some(Err(Refused::Lease)));
            assert_eq!(observed(&mut script), Err(Refused::Lease), "{state:?}");
            assert_eq!(script.reads, ["observe", "prove", "observe"]);
        }
    }

    #[test]
    fn a_failed_second_observation_is_the_answer() {
        let mut script = Script::new(
            [Ok(AuthorityState::Stopping), Err(Refused::Other)],
            Some(Err(Refused::Lease)),
        );
        assert_eq!(observed(&mut script), Err(Refused::Other));
        assert_eq!(script.reads, ["observe", "prove", "observe"]);
    }

    #[test]
    fn only_a_lease_refusal_is_observed_again() {
        let mut script = Script::new([Ok(AuthorityState::Stopping)], Some(Err(Refused::Other)));
        assert_eq!(observed(&mut script), Err(Refused::Other));
        assert_eq!(script.reads, ["observe", "prove"]);
    }

    #[test]
    fn a_proven_lease_keeps_the_first_observation() {
        for state in [
            AuthorityState::Preparing,
            AuthorityState::Starting,
            AuthorityState::Active,
            AuthorityState::Stopping,
        ] {
            let mut script = Script::new([Ok(state)], Some(Ok(())));
            assert_eq!(observed(&mut script), Ok(state), "{state:?}");
            assert_eq!(script.reads, ["observe", "prove"]);
        }
    }

    #[test]
    fn a_run_past_its_lease_needs_no_proof() {
        for state in [
            AuthorityState::Off,
            AuthorityState::Recovering,
            AuthorityState::Quarantined,
        ] {
            let mut script = Script::new([Ok(state)], None);
            assert_eq!(observed(&mut script), Ok(state), "{state:?}");
            assert_eq!(script.reads, ["observe"]);
        }
        let mut script = Script::new([Err(Refused::Other)], None);
        assert_eq!(observed(&mut script), Err(Refused::Other));
        assert_eq!(script.reads, ["observe"]);
    }
}
