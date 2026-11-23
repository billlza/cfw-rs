//! Retiring a run once global Off has been observed for it, including a
//! start the engine refused because another program holds an endpoint.
use super::*;

impl State {
    /// Retire the retained run once global Off has been observed for it.
    pub(super) fn retire_active(&mut self, deadline: Instant) -> Result<()> {
        let active = self
            .active
            .as_mut()
            .ok_or_else(|| fail(Kind::Internal, "no retained runtime to retire"))?;
        active.retire_until(deadline)?;
        self.retired = Some(Retired {
            context: active.context.clone(),
            mode: active.mode,
            prepared: active.owner_prepared != Some(false),
        });
        self.active.take();
        Ok(())
    }
}

/// A cleanup failure after `result`: the cleanup's alone after a success,
/// both after a failure.
pub(super) fn cleanup_failed(result: Result<()>, cleanup: BackendError) -> BackendError {
    match result {
        Ok(()) => cleanup,
        Err(operation) => combined(operation, cleanup),
    }
}

/// Whether the engine refused a start because another program holds one of
/// its endpoints. Its owner has then proven global Off for the run.
pub(super) fn endpoint_conflict(error: &BackendError) -> bool {
    matches!(
        error.kind,
        Kind::MixedEndpointInUse | Kind::ControllerEndpointInUse
    )
}

/// Observe Off for the refused run once more and retire it, so that the
/// coordinator's stop and Off proof that follow find nothing left to stop.
/// The refusal stands only then; otherwise the start failed with its cleanup
/// unproven and the run stays retained.
pub(super) fn refused_start(
    shared: &Shared,
    state: &mut State,
    refusal: BackendError,
    deadline: Instant,
) -> BackendError {
    let off = state
        .active
        .as_ref()
        .map(|active| active.context.clone())
        .ok_or_else(|| fail(Kind::Internal, "runtime owner was not retained"))
        .and_then(|context| {
            let snapshot = shared
                .desktop
                .observe_authority(deadline)
                .map_err(host_error)?;
            if off_matches(&snapshot, &context) {
                Ok(())
            } else {
                Err(fail(
                    Kind::CleanupUnproven,
                    "Authority has not verified global Off",
                ))
            }
        });
    match off.and_then(|()| state.retire_active(deadline)) {
        Ok(()) => refusal,
        Err(error) => combined(refusal, error),
    }
}
