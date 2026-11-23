//! Retiring a run once global Off has been observed for it, including a
//! start the engine refused.
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

/// Whether the Desktop reported that the engine refused a start, which its
/// Agent ended after its cleanup and Stopped acknowledgement: another program
/// holds an endpoint, or the engine could not start. No other failure of this
/// backend has these kinds. The owner has then proven global Off for the run.
pub(super) fn reported_refusal(error: &BackendError) -> bool {
    matches!(
        error.kind,
        Kind::MixedEndpointInUse | Kind::ControllerEndpointInUse | Kind::SystemProxyRuntimeFailed
    )
}

/// A refused start in the kind macOS gives it in `mode`: an engine its
/// ProxyAgent could not start is `SystemProxyRuntimeFailed`, one its Packet
/// Tunnel, which runs both tunnel modes, could not start is `Unavailable`.
fn in_mode(refusal: BackendError, mode: ProjectionMode) -> BackendError {
    match refusal.kind {
        Kind::SystemProxyRuntimeFailed if mode.has_tunnel() => BackendError {
            kind: Kind::Unavailable,
            ..refusal
        },
        _ => refusal,
    }
}

/// Observe Off for the refused run once more and retire it, so that the
/// coordinator's stop and Off proof that follow find nothing left to stop.
/// The refusal stands only then; otherwise the start failed with its cleanup
/// unproven and the run stays retained.
pub(super) fn refused_start(
    shared: &Shared,
    state: &mut State,
    refusal: BackendError,
    mode: ProjectionMode,
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
        Ok(()) => in_mode(refusal, mode),
        Err(error) => combined(refusal, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_engine_that_could_not_start_is_named_as_macos_names_it_in_each_mode() {
        let refusal = |kind| fail(kind, "Windows Desktop start: refused");
        for (mode, kind) in [
            (ProjectionMode::LocalProxy, Kind::SystemProxyRuntimeFailed),
            (ProjectionMode::SystemProxy, Kind::SystemProxyRuntimeFailed),
            (ProjectionMode::Tunnel, Kind::Unavailable),
            (ProjectionMode::TunnelSystemProxy, Kind::Unavailable),
        ] {
            let reported = in_mode(refusal(Kind::SystemProxyRuntimeFailed), mode);
            assert_eq!(reported.kind, kind, "{mode:?}");
            assert_eq!(reported.message, "Windows Desktop start: refused");
            // A held endpoint keeps its kind in every mode.
            for held in [Kind::MixedEndpointInUse, Kind::ControllerEndpointInUse] {
                assert_eq!(in_mode(refusal(held), mode).kind, held, "{mode:?}");
            }
        }
    }
}
