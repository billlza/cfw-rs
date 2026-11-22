//! A start the engine refused, which the UserAgent reports by an exit code of
//! its own, and only when its local cleanup and the Authority's Stopped
//! acknowledgement both succeeded. The Desktop still proves global Off for the
//! run before the backend reports the refusal. Two refusals name a local
//! endpoint that another program holds and that the application moves: the
//! loopback proxy listener and the controller. The third is an engine that
//! could not build the configuration or could not start it, a LAN listener
//! another program holds among them: an ordinary start failure, as macOS
//! reports an engine it could not create or start. Any other refusal is no
//! refused start, and the UserAgent exits with 1.
use super::UserAgentError;
use crate::protocol::rejection::{
    CONSTRUCT_FAILED, CONTROLLER_ENDPOINT_IN_USE, MIXED_ENDPOINT_IN_USE, START_FAILED,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartRefusal {
    /// The engine could not build the configuration or could not start it.
    Engine,
    /// Another program holds the loopback proxy listener's address.
    MixedEndpoint,
    /// Another program holds the controller's address.
    ControllerEndpoint,
}

impl StartRefusal {
    const ALL: [Self; 3] = [Self::Engine, Self::MixedEndpoint, Self::ControllerEndpoint];

    /// The refusal a run's own error names. A refusal that came with a
    /// failed cleanup or acknowledgement is not one.
    pub fn of_agent_error(error: &UserAgentError) -> Option<Self> {
        let UserAgentError::Engine(crate::Error::Rejected(code)) = error else {
            return None;
        };
        match *code {
            CONSTRUCT_FAILED | START_FAILED => Some(Self::Engine),
            MIXED_ENDPOINT_IN_USE => Some(Self::MixedEndpoint),
            CONTROLLER_ENDPOINT_IN_USE => Some(Self::ControllerEndpoint),
            _ => None,
        }
    }
    /// The UserAgent's exit code for this refusal. A completed run exits
    /// with 0 and any other failure with 1. Small codes are not used: 3 is
    /// also what the C runtime's abort() and some terminations leave.
    pub fn exit_code(self) -> u16 {
        match self {
            Self::Engine => 0xCF30,
            Self::MixedEndpoint => 0xCF31,
            Self::ControllerEndpoint => 0xCF32,
        }
    }
    /// The refusal an exited UserAgent reported, as its Desktop reads it.
    pub fn of_exit_code(code: u32) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|refusal| u32::from(refusal.exit_code()) == code)
    }
}

impl std::fmt::Display for StartRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Engine => "the engine could not start",
            Self::MixedEndpoint => "another program holds the address of the proxy listener",
            Self::ControllerEndpoint => "another program holds the address of the controller",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_bare_engine_refusal_of_the_start_is_a_refused_start() {
        let refused = |code| UserAgentError::Engine(crate::Error::Rejected(code));
        for (code, refusal) in [
            (CONSTRUCT_FAILED, StartRefusal::Engine),
            (START_FAILED, StartRefusal::Engine),
            (MIXED_ENDPOINT_IN_USE, StartRefusal::MixedEndpoint),
            (CONTROLLER_ENDPOINT_IN_USE, StartRefusal::ControllerEndpoint),
        ] {
            assert_eq!(
                StartRefusal::of_agent_error(&refused(code)),
                Some(refusal),
                "{code}"
            );
        }
        for error in [
            // A configuration the engine could not read, and refusals of
            // another request and of the stop.
            refused("invalid_config"),
            refused("probe_failed"),
            refused("close_failed"),
            // A refusal whose cleanup failed was not completed by the run.
            UserAgentError::Cleanup {
                operation: Box::new(refused(START_FAILED)),
                cleanup: Box::new(UserAgentError::WorkerEnded),
            },
            UserAgentError::Engine(crate::Error::CleanupFailed {
                operation: Box::new(crate::Error::Rejected(MIXED_ENDPOINT_IN_USE)),
                cleanup: Box::new(crate::Error::Cleanup),
            }),
            UserAgentError::Engine(crate::Error::Exited),
            UserAgentError::Cancelled,
        ] {
            assert_eq!(StartRefusal::of_agent_error(&error), None, "{error}");
        }
    }

    #[test]
    fn refusal_exit_codes_differ_from_each_other_completion_and_failure() {
        for refusal in StartRefusal::ALL {
            assert_eq!(
                StartRefusal::of_exit_code(u32::from(refusal.exit_code())),
                Some(refusal)
            );
        }
        let codes: std::collections::BTreeSet<u16> = StartRefusal::ALL
            .into_iter()
            .map(StartRefusal::exit_code)
            .collect();
        assert_eq!(codes.len(), StartRefusal::ALL.len());
        // Completion, failure, the engine host's failure, the C runtime's
        // abort(), a panic, an exit not yet recorded, a fast-fail abort and
        // a forced end.
        for code in [0, 1, 2, 3, 101, 0x103, 0xC000_0409, u32::MAX] {
            assert_eq!(StartRefusal::of_exit_code(code), None);
        }
    }
}
