use std::{future::Future, pin::Pin};

use cfw_engine_api::{EngineCommandContext, EngineMode, EngineSnapshot};
use cfw_singbox_config::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};

use crate::runtime::{CoordinatorState, TransitionContext, backend_error, call_backend};
use crate::{EngineCoordinatorError as Error, EngineOperation, EngineRestartSpec};

/// A prepared storage change. Preparation may provision immutable credential
/// audiences, but must leave the active catalog and runtime intact. The actor
/// checks and starts an active candidate before invoking the atomic commit.
pub struct ProfileChange<T> {
    pub profile_id: String,
    pub profile: ValidatedSingBoxProfile,
    pub activate: bool,
    /// Current saved manual selections for the prior profile. Its document
    /// digest must still match the actor-owned source; only selections may vary.
    pub previous_profile: Option<(String, ValidatedSingBoxProfile)>,
    pub commit: Box<dyn FnOnce() -> Result<T, String> + Send>,
}

pub(crate) type Preparation =
    Pin<Box<dyn Future<Output = Result<ProfileChange<()>, Error>> + Send>>;

pub(crate) async fn apply(
    context: TransitionContext<'_>,
    state: &mut CoordinatorState,
    settings: EngineSettings,
    prepare: Preparation,
) -> Result<EngineSnapshot, Error> {
    // The whole operation runs inside the coordinator actor, so observation
    // polling and other mode changes cannot interleave with native preparation.
    let mode = state.snapshot.desired_mode;
    let candidate = prepare.await?;
    if !candidate.activate || mode == EngineMode::Off {
        (candidate.commit)().map_err(Error::ProfileCommit)?;
        return Ok(state.snapshot.clone());
    }
    let mut previous = if mode == EngineMode::Off {
        None
    } else {
        Some(state.restart_spec.clone().filter(|spec| spec.matches_ready_snapshot(&state.snapshot))
            .ok_or_else(|| Error::ProfilePreparation("the current runtime is not ready for an online change; cancel or recover the pending operation first".into()))?)
    };
    if let (Some(prior), Some((id, profile))) = (&mut previous, &candidate.previous_profile) {
        if id != prior.profile_id() || profile.digest() != prior.profile().digest() {
            return Err(Error::ProfilePreparation(
                "the selected profile differs from the active runtime; no change was applied"
                    .into(),
            ));
        }
        prior.replace_saved_selections(profile.clone());
    }
    if previous.as_ref().is_some_and(|prior| {
        prior.profile_id() == candidate.profile_id
            && prior.profile().digest() == candidate.profile.digest()
            && prior.profile().proxy_selections() == candidate.profile.proxy_selections()
            && prior.settings() == &settings
    }) {
        (candidate.commit)().map_err(Error::ProfileCommit)?;
        state.restart_spec = Some(EngineRestartSpec::accepted(
            mode,
            candidate.profile_id,
            candidate.profile,
            settings,
            &state.snapshot,
        ));
        return Ok(state.snapshot.clone());
    }
    let projected_mode = match mode {
        EngineMode::LocalProxy => ProjectionMode::LocalProxy,
        EngineMode::SystemProxy => ProjectionMode::SystemProxy,
        EngineMode::Tunnel => ProjectionMode::Tunnel,
        EngineMode::TunnelSystemProxy => ProjectionMode::TunnelSystemProxy,
        EngineMode::Off => unreachable!("offline changes commit without a runtime"),
    };
    let projected = candidate
        .profile
        .project(&candidate.profile_id, projected_mode, &settings)?;
    let next_generation = state
        .snapshot
        .generation
        .checked_add(1)
        .ok_or(Error::GenerationExhausted)?;
    let request = crate::cutover::start_request(
        &projected,
        &settings,
        EngineCommandContext::new(context.session, next_generation),
    );
    call_backend(
        context.operation_timeout,
        EngineOperation::CheckConfiguration,
        context.backend.check_configuration(request),
    )
    .await
    .map_err(|source| backend_error(EngineOperation::CheckConfiguration, source))?;

    let result = crate::transition::transition(
        context,
        state,
        mode,
        &candidate.profile_id,
        &candidate.profile,
        &settings,
    )
    .await;
    if let Err(error) = result {
        return restore(context, state, previous.as_ref(), error, false).await;
    }
    if let Err(error) = (candidate.commit)() {
        return restore(
            context,
            state,
            previous.as_ref(),
            Error::ProfileCommit(error),
            true,
        )
        .await;
    }
    state.restart_spec = Some(EngineRestartSpec::accepted(
        mode,
        candidate.profile_id,
        candidate.profile,
        settings,
        &state.snapshot,
    ));
    Ok(state.snapshot.clone())
}

async fn restore(
    context: TransitionContext<'_>,
    state: &mut CoordinatorState,
    previous: Option<&EngineRestartSpec>,
    source: Error,
    candidate_started: bool,
) -> Result<EngineSnapshot, Error> {
    let Some(previous) = previous else {
        return Err(source);
    };
    if previous.matches_ready_snapshot(&state.snapshot) {
        return Err(source);
    }
    // A failed start may have an unproven owner. Only a completed cleanup, or
    // an exactly active candidate whose commit failed, permits bounded restore.
    if state.quarantine.is_some() || (!candidate_started && state.native_lease.is_some()) {
        return Err(Error::ProfileChangeRecoveryRequired {
            source: Box::new(source),
        });
    }
    match crate::transition::transition(
        context,
        state,
        previous.mode(),
        previous.profile_id(),
        previous.profile(),
        previous.settings(),
    )
    .await
    {
        Ok(snapshot) => {
            state.restart_spec = Some(EngineRestartSpec::accepted(
                previous.mode(),
                previous.profile_id().into(),
                previous.profile().clone(),
                previous.settings().clone(),
                &snapshot,
            ));
            Err(Error::ProfileChangeRolledBack {
                source: Box::new(source),
            })
        }
        Err(rollback) => Err(Error::ProfileChangeRollbackFailed {
            source: Box::new(source),
            rollback: Box::new(rollback),
        }),
    }
}
