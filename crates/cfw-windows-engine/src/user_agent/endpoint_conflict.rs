//! A start the engine refused because another program holds one of the two
//! local endpoints the application moves: the loopback proxy listener or the
//! controller. The UserAgent reports such a refusal by an exit code of its
//! own, and only when its local cleanup and the Authority's Stopped
//! acknowledgement both succeeded. The Desktop still proves global Off for the
//! run before the backend names the endpoint.
use super::UserAgentError;
use crate::protocol::rejection::{CONTROLLER_ENDPOINT_IN_USE, MIXED_ENDPOINT_IN_USE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointConflict {
    /// The loopback proxy listener.
    Mixed,
    /// The controller.
    Controller,
}

impl EndpointConflict {
    /// The conflict a run's own error names. A refusal that came with a
    /// failed cleanup or acknowledgement is not a conflict.
    pub fn of_agent_error(error: &UserAgentError) -> Option<Self> {
        match error {
            UserAgentError::Engine(crate::Error::Rejected(MIXED_ENDPOINT_IN_USE)) => {
                Some(Self::Mixed)
            }
            UserAgentError::Engine(crate::Error::Rejected(CONTROLLER_ENDPOINT_IN_USE)) => {
                Some(Self::Controller)
            }
            _ => None,
        }
    }
    /// The UserAgent's exit code for this refusal. A completed run exits
    /// with 0 and any other failure with 1. Small codes are not used: 3 is
    /// also what the C runtime's abort() and some terminations leave.
    pub fn exit_code(self) -> u16 {
        match self {
            Self::Mixed => 0xCF31,
            Self::Controller => 0xCF32,
        }
    }
    /// The refusal an exited UserAgent reported, as its Desktop reads it.
    pub fn of_exit_code(code: u32) -> Option<Self> {
        [Self::Mixed, Self::Controller]
            .into_iter()
            .find(|conflict| u32::from(conflict.exit_code()) == code)
    }
}

impl std::fmt::Display for EndpointConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Mixed => "proxy listener",
            Self::Controller => "controller",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_bare_engine_refusal_of_a_held_endpoint_is_a_conflict() {
        let refused = |code| UserAgentError::Engine(crate::Error::Rejected(code));
        assert_eq!(
            EndpointConflict::of_agent_error(&refused(MIXED_ENDPOINT_IN_USE)),
            Some(EndpointConflict::Mixed)
        );
        assert_eq!(
            EndpointConflict::of_agent_error(&refused(CONTROLLER_ENDPOINT_IN_USE)),
            Some(EndpointConflict::Controller)
        );
        for error in [
            refused("start_failed"),
            // A refusal whose cleanup failed was not completed by the run.
            UserAgentError::Cleanup {
                operation: Box::new(refused(MIXED_ENDPOINT_IN_USE)),
                cleanup: Box::new(UserAgentError::WorkerEnded),
            },
            UserAgentError::Engine(crate::Error::CleanupFailed {
                operation: Box::new(crate::Error::Rejected(CONTROLLER_ENDPOINT_IN_USE)),
                cleanup: Box::new(crate::Error::Cleanup),
            }),
            UserAgentError::Cancelled,
        ] {
            assert_eq!(EndpointConflict::of_agent_error(&error), None, "{error}");
        }
    }

    #[test]
    fn refusal_exit_codes_differ_from_completion_and_failure() {
        for conflict in [EndpointConflict::Mixed, EndpointConflict::Controller] {
            assert_eq!(
                EndpointConflict::of_exit_code(u32::from(conflict.exit_code())),
                Some(conflict)
            );
        }
        assert_ne!(
            EndpointConflict::Mixed.exit_code(),
            EndpointConflict::Controller.exit_code()
        );
        // Completion, failure, the engine host's failure, the C runtime's
        // abort(), a panic, an exit not yet recorded, a fast-fail abort and
        // a forced end.
        for code in [0, 1, 2, 3, 101, 0x103, 0xC000_0409, u32::MAX] {
            assert_eq!(EndpointConflict::of_exit_code(code), None);
        }
    }
}
