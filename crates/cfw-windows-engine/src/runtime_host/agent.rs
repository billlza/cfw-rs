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
        let ready_limit =
            if context.operation.mode == cfw_engine_api::authority_v1::AuthorityMode::Tunnel {
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
