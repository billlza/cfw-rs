use super::*;
use crate::user_agent::{
    EndpointConflict, UserAgentSession, UserRuntimeStorage, launch_channel::LaunchReceiver,
};
use std::{
    os::windows::io::AsHandle,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

/// `started` is the process start and `images` were verified once by the entry
/// point. Admission is announced before the launch frame is read, so the
/// Desktop prepares the lease only when Bind can follow at once.
pub fn run_agent(
    installation: InstalledRuntime,
    images: AdmittedImages,
    started: Instant,
) -> Result<()> {
    let AdmittedImages {
        runtime,
        desktop,
        engine,
        wintun: _wintun,
    } = images;
    let paths = installation.user_paths()?;
    let input = std::io::stdin().as_handle().try_clone_to_owned()?;
    let launch_receiver = LaunchReceiver::from_inherited(input, Arc::new(desktop))?;
    let storage = UserRuntimeStorage::open(&paths.runtime)?;
    let cancel = AtomicBool::new(false);
    let admitted = started.elapsed();
    launch_receiver.announce_admitted(Instant::now() + Duration::from_secs(15), &cancel)?;
    let (launch, observation) =
        launch_receiver.receive_observed(Instant::now() + Duration::from_secs(15), &cancel)?;
    let launched = started.elapsed();
    let context = launch.context().clone();
    let plan = launch.into_plan(cfw_windows_credentials::WindowsCredentialStore::new(
        paths.credentials.join("vault"),
    ))?;
    let mut session = UserAgentSession::new(
        plan,
        SERVICE_NAME.to_owned(),
        Arc::new(runtime),
        storage.runtime(engine, context.operation.mode)?,
    )?;
    let stop = AtomicBool::new(false);
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::scope(|scope| -> Result<()> {
        let worker = scope.spawn(|| session.run_observed(&stop, sender, observation));
        let ready_limit = if context.operation.mode.owns_tunnel() {
            Duration::from_secs(20) + crate::tunnel::OPEN_LIMIT
        } else {
            Duration::from_secs(20)
        };
        let readiness = match receiver.recv_timeout(ready_limit) {
            Ok(ready)
                if ready.context() == &context
                    && ready.authority().state
                        == cfw_engine_api::authority_v1::AuthorityState::Active =>
            {
                // Non-secret start timing for the installation-owned diagnostic
                // sink: how long admission, the launch handoff and Ready took.
                eprintln!(
                    "installed Agent timing: admitted {} ms, launch received {} ms, ready {} ms after process start",
                    admitted.as_millis(),
                    launched.as_millis(),
                    started.elapsed().as_millis()
                );
                Readiness::Ready
            }
            Ok(_) => Readiness::Failed(HostError::State(
                "installed Agent readiness changed its operation",
            )),
            Err(mpsc::RecvTimeoutError::Timeout) => Readiness::Failed(HostError::State(
                "installed Agent readiness was not delivered",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Readiness::Ended,
        };
        if !matches!(readiness, Readiness::Ready) {
            stop.store(true, Ordering::Release);
        }
        let result = worker
            .join()
            .map_err(|_| HostError::State("installed Agent worker panicked"))?
            .map(|_| ())
            .map_err(HostError::from);
        readiness.outcome(result)
    })
}

/// What the wait for the run's readiness observed.
enum Readiness {
    Ready,
    /// The run ended before Ready.
    Ended,
    Failed(HostError),
}
impl Readiness {
    /// A run that ended before Ready failed for a reason of its own, which is
    /// then the Agent's whole result: its exit code names a start the engine
    /// refused only when nothing else failed.
    fn outcome(self, run: Result<()>) -> Result<()> {
        match (self, run) {
            (Self::Ready, run) => run,
            (Self::Ended, Ok(())) => Err(HostError::State(
                "installed Agent readiness was not delivered",
            )),
            (Self::Ended, Err(error)) | (Self::Failed(error), Ok(())) => Err(error),
            (Self::Failed(operation), Err(cleanup)) => Err(HostError::Cleanup {
                operation: Box::new(operation),
                cleanup: Box::new(cleanup),
            }),
        }
    }
}

/// The UserAgent's exit code after `error`: 1, or the code of a start the
/// engine refused because another program holds an endpoint.
pub fn agent_exit_code(error: &HostError) -> i32 {
    match error {
        HostError::Agent(error) => EndpointConflict::of_agent_error(error)
            .map_or(1, |conflict| i32::from(conflict.exit_code())),
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user_agent::UserAgentError;

    fn refused(code: &'static str) -> Result<()> {
        Err(UserAgentError::Engine(crate::Error::Rejected(code)).into())
    }

    #[test]
    fn a_run_that_ended_before_ready_exits_with_its_own_refusal() {
        let mixed = Readiness::Ended.outcome(refused("mixed_endpoint_in_use"));
        assert_eq!(agent_exit_code(&mixed.unwrap_err()), 0xCF31);
        let controller = Readiness::Ended.outcome(refused("controller_endpoint_in_use"));
        assert_eq!(agent_exit_code(&controller.unwrap_err()), 0xCF32);
        let other = Readiness::Ended.outcome(refused("start_failed"));
        assert_eq!(agent_exit_code(&other.unwrap_err()), 1);
        assert!(matches!(
            Readiness::Ended.outcome(Ok(())),
            Err(HostError::State(
                "installed Agent readiness was not delivered"
            ))
        ));
    }

    #[test]
    fn a_readiness_failure_of_its_own_is_never_a_refusal() {
        let late = || Readiness::Failed(HostError::State("late"));
        let both = late()
            .outcome(refused("mixed_endpoint_in_use"))
            .unwrap_err();
        assert!(matches!(both, HostError::Cleanup { .. }));
        assert_eq!(agent_exit_code(&both), 1);
        assert!(matches!(
            late().outcome(Ok(())),
            Err(HostError::State("late"))
        ));
        assert!(Readiness::Ready.outcome(Ok(())).is_ok());
        assert_eq!(agent_exit_code(&HostError::State("other")), 1);
    }
}
