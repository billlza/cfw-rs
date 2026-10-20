use super::*;
use crate::user_agent::{UserAgentSession, UserRuntimeStorage, launch_channel::LaunchReceiver};
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

pub fn run_agent(installation: InstalledRuntime) -> Result<()> {
    installation.require_runtime_process()?;
    let paths = installation.user_paths()?;
    let expected = Arc::new(installation.desktop()?);
    let input = std::io::stdin().as_handle().try_clone_to_owned()?;
    let (launch, observation) = LaunchReceiver::from_inherited(input, expected)?.receive_observed(
        Instant::now() + Duration::from_secs(15),
        &AtomicBool::new(false),
    )?;
    let context = launch.context().clone();
    let storage = UserRuntimeStorage::open(&paths.runtime)?;
    let plan = launch.into_plan(cfw_windows_credentials::WindowsCredentialStore::new(
        paths.credentials.join("vault"),
    ))?;
    let mut session = UserAgentSession::new(
        plan,
        SERVICE_NAME.to_owned(),
        Arc::new(installation.runtime()?),
        storage.runtime(installation.engine()?, context.operation.mode)?,
    )?;
    let stop = AtomicBool::new(false);
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::scope(|scope| -> Result<()> {
        let worker = scope.spawn(|| session.run_observed(&stop, sender, observation));
        let readiness = match receiver.recv_timeout(Duration::from_secs(20)) {
            Ok(ready)
                if ready.context() == &context
                    && ready.authority().state
                        == cfw_engine_api::authority_v1::AuthorityState::Active =>
            {
                Ok(())
            }
            Ok(_) => Err(HostError::State(
                "installed Agent readiness changed its operation",
            )),
            Err(_) => Err(HostError::State(
                "installed Agent readiness was not delivered",
            )),
        };
        if readiness.is_err() {
            stop.store(true, Ordering::Release);
        }
        let result = worker
            .join()
            .map_err(|_| HostError::State("installed Agent worker panicked"))?
            .map(|_| ())
            .map_err(HostError::from);
        match (readiness, result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(operation), Err(cleanup)) => Err(HostError::Cleanup {
                operation: Box::new(operation),
                cleanup: Box::new(cleanup),
            }),
        }
    })
}
