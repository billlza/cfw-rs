//! Completion of a run that owned this user's proxy settings. SYSTEM proves
//! that the run's processes are gone, but it cannot read or restore another
//! account's WinINet options. A Desktop of that account restores what the run
//! left applied and proves it, and only then is the run recorded Off.
//!
//! The Desktop that started the run does this on its original connection for
//! a stop its UserAgent acknowledged. A run that SYSTEM took into recovery,
//! because its UserAgent or its Desktop was lost, has no owner any more: any
//! Desktop of the same account completes it.
//!
//! A run that also owned a tunnel is recorded Off only once SYSTEM has seen
//! its own adapter gone. The settings are not kept waiting for that: they are
//! restored as soon as the processes are gone, and the proof is given again
//! until SYSTEM accepts it.
use super::desktop::{DesktopError, Result, send};
use crate::{
    WindowsSystemProxy,
    authority::{
        AuthorityChannel, LeaseContext, ProxyRecoveryTarget,
        wire::{Command, ProxyCleanupReceipt, ProxyRecoveryGrant, Rejection, Response, WireError},
    },
    service_transport::check_deadline,
};
use cfw_engine_api::authority_v1::AuthorityState;
use std::{
    thread,
    time::{Duration, Instant},
};

/// How often to ask again while the run's last processes are still exiting.
const RETIREMENT_POLL: Duration = Duration::from_millis(50);
/// How long a Desktop that only found the run waits for those processes. It
/// did not see them end, so it does not wait out a status query for them: the
/// refusal is its answer, and the next query asks again.
const FOUND_RUN_PATIENCE: Duration = Duration::from_secs(3);

/// `owner` is the lease of the Desktop that started the run, when that Desktop
/// is the caller: it has seen its UserAgent exit and waits until `deadline`
/// for SYSTEM to see the same. Returns `None` when the recorded run is not
/// this account's or does not own the proxy settings: SYSTEM completes such a
/// run by itself.
///
/// Only a typed refusal is asked again, because it records nothing; a
/// command whose delivery is uncertain is never repeated.
pub(crate) fn complete(
    authority: &mut AuthorityChannel,
    proxy: &WindowsSystemProxy,
    owner: Option<&LeaseContext>,
    deadline: Instant,
) -> Result<Option<ProxyCleanupReceipt>> {
    let patience = match owner {
        Some(_) => deadline,
        None => deadline.min(Instant::now() + FOUND_RUN_PATIENCE),
    };
    loop {
        let grant = grant(authority, owner, deadline, patience)?;
        let Some(grant) = grant else {
            return Ok(None);
        };
        let report = grant.restore_and_observe(proxy)?;
        match send(authority, Command::ReconcileProxyCleanup(report), deadline) {
            Ok(Response::ProxyCleanupReconciled(receipt)) => return Ok(Some(receipt)),
            Ok(_) => return Err(DesktopError::Response),
            // The settings are restored and proven, and SYSTEM is still
            // retiring what it owns of the run: give the proof again.
            Err(
                refused @ DesktopError::Authority(WireError::Rejected(Rejection::CleanupUnproven)),
            ) => {
                if Instant::now() + RETIREMENT_POLL >= patience {
                    return Err(refused);
                }
            }
            Err(error) => return Err(error),
        }
        thread::sleep(RETIREMENT_POLL);
    }
}

/// SYSTEM's challenge for the recorded run, once it has seen the processes of
/// that run gone. `None` when the run is not this account's to complete.
fn grant(
    authority: &mut AuthorityChannel,
    owner: Option<&LeaseContext>,
    deadline: Instant,
    patience: Instant,
) -> Result<Option<ProxyRecoveryGrant>> {
    loop {
        check_deadline(deadline)?;
        let scope = match send(authority, Command::ReadRuntimeScope, deadline) {
            Ok(Response::RuntimeScope(scope)) => scope,
            Ok(_) => return Err(DesktopError::Response),
            // The recorded run belongs to another account.
            Err(DesktopError::Authority(WireError::Rejected(Rejection::Identity))) => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if scope
            .operation()
            .is_none_or(|operation| !operation.mode().owns_system_proxy())
        {
            return Ok(None);
        }
        let target = match scope.snapshot().state {
            AuthorityState::Stopping => ProxyRecoveryTarget::from_stopped(
                &scope,
                owner.ok_or(DesktopError::State(
                    "the stop belongs to the Desktop that started the run",
                ))?,
            )?,
            AuthorityState::Recovering => match owner {
                Some(owner) => ProxyRecoveryTarget::from_lost(&scope, owner)?,
                None => ProxyRecoveryTarget::from_recorded(&scope)?,
            },
            _ => {
                return Err(DesktopError::State(
                    "the run is not waiting for its proxy settings",
                ));
            }
        };
        match send(authority, Command::BeginProxyCleanup(target), deadline) {
            Ok(Response::ProxyRecoveryGranted(grant)) => return Ok(Some(grant)),
            Ok(_) => return Err(DesktopError::Response),
            // Processes of the run are still exiting, or SYSTEM has since
            // moved the run into recovery: read the record again. A refusal
            // that outlasts the wait is the result.
            Err(
                refused @ DesktopError::Authority(WireError::Rejected(
                    Rejection::CleanupUnproven | Rejection::Stale,
                )),
            ) => {
                if Instant::now() + RETIREMENT_POLL >= patience {
                    return Err(refused);
                }
            }
            Err(error) => return Err(error),
        }
        thread::sleep(RETIREMENT_POLL);
    }
}
