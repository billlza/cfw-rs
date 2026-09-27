use cfw_engine_api::{EngineMode, EngineSnapshot, EngineState};
use serde::Serialize;

use crate::engine_controls::EngineControl;

#[derive(Clone, Debug, Serialize)]
pub(super) struct Switch {
    pub enabled: bool,
    pub available: bool,
    pub retry: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Controls {
    pub core: Switch,
    pub system_proxy: Switch,
    pub tunnel: Switch,
}

impl Controls {
    pub fn unavailable() -> Self {
        let switch = Switch {
            enabled: false,
            available: false,
            retry: false,
            reason: Some("Native controls require an admitted application session.".into()),
        };
        Self {
            core: switch.clone(),
            system_proxy: switch.clone(),
            tunnel: switch,
        }
    }

    fn get(&self, control: EngineControl) -> &Switch {
        match control {
            EngineControl::Core => &self.core,
            EngineControl::SystemProxy => &self.system_proxy,
            EngineControl::Tunnel => &self.tunnel,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Completion {
    pub request_id: u64,
    pub pending: bool,
    pub error: Option<String>,
}

pub(super) struct Displayed {
    pub revision: u64,
    pub snapshot: EngineSnapshot,
    pub controls: Controls,
}

#[derive(Default)]
pub(super) struct ControlGate {
    pub closed: bool,
    displayed: Option<Displayed>,
    completion: Option<Completion>,
}

impl ControlGate {
    pub fn display(&mut self, displayed: Displayed) {
        self.displayed = Some(displayed);
    }

    pub fn completion(&self) -> Option<Completion> {
        self.completion.clone()
    }

    pub fn reserve(
        &mut self,
        revision: u64,
        request_id: u64,
        control: EngineControl,
        enabled: bool,
    ) -> Result<EngineSnapshot, i32> {
        if self.closed {
            return Err(2);
        }
        if self.completion.as_ref().is_some_and(|value| value.pending) {
            return Err(4);
        }
        if request_id == 0
            || self
                .completion
                .as_ref()
                .is_some_and(|value| request_id <= value.request_id)
        {
            return Err(0);
        }
        let displayed = self.displayed.as_ref().ok_or(0)?;
        if displayed.revision != revision {
            return Err(0);
        }
        let switch = displayed.controls.get(control);
        if !switch.available || (switch.enabled == enabled && !(enabled && switch.retry)) {
            return Err(0);
        }
        let snapshot = displayed.snapshot.clone();
        self.completion = Some(Completion {
            request_id,
            pending: true,
            error: None,
        });
        Ok(snapshot)
    }

    pub fn finish(&mut self, request_id: u64, error: Option<String>) -> Result<(), &'static str> {
        let result = self
            .completion
            .as_mut()
            .ok_or("native request completion had no pending request")?;
        if result.request_id != request_id || !result.pending {
            return Err("native request completion identity differs");
        }
        result.pending = false;
        result.error = error;
        Ok(())
    }
}

/// A retry keeps the desired mode and is only offered for a recoverable
/// observation. A ready or in-flight mode must not acquire another generation.
pub(super) fn retry_target(
    snapshot: &EngineSnapshot,
    control: EngineControl,
) -> Option<EngineMode> {
    let mode = snapshot.desired_mode;
    let owns_mode = match control {
        EngineControl::Core => mode != EngineMode::Off,
        EngineControl::SystemProxy => mode.system_proxy_enabled(),
        EngineControl::Tunnel => mode.tunnel_enabled(),
    };
    if !owns_mode {
        return None;
    }
    if control != EngineControl::Core {
        let switch = if control == EngineControl::SystemProxy {
            EngineMode::SystemProxy
        } else {
            EngineMode::Tunnel
        };
        return crate::engine::switch_transition(snapshot, switch, true)
            .filter(|target| *target == mode);
    }
    let retryable = match &snapshot.state {
        EngineState::Off => true,
        EngineState::Failed { target, .. } => *target == mode,
        EngineState::AwaitingApproval { .. } => mode.tunnel_enabled(),
        EngineState::LocalProxyActive { runtime }
        | EngineState::ProxyActive { runtime }
        | EngineState::TunnelActive { runtime }
        | EngineState::TunnelSystemProxyActive { runtime } => !runtime.ready,
        _ => false,
    };
    retryable.then_some(mode)
}

pub(super) fn needs_approval_settings(requested_retry: bool, result: &EngineSnapshot) -> bool {
    requested_retry
        && result.desired_mode.tunnel_enabled()
        && matches!(result.state, EngineState::AwaitingApproval { .. })
}

pub(super) fn control_from_wire(value: u32) -> Option<EngineControl> {
    match value {
        1 => Some(EngineControl::Core),
        2 => Some(EngineControl::SystemProxy),
        3 => Some(EngineControl::Tunnel),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn gate() -> ControlGate {
        let mut controls = Controls::unavailable();
        controls.core.available = true;
        controls.core.reason = None;
        let mut gate = ControlGate::default();
        gate.display(Displayed {
            revision: 8,
            snapshot: EngineSnapshot::default(),
            controls,
        });
        gate
    }

    #[test]
    fn stale_unavailable_duplicate_and_overlapping_intents_never_enter_the_worker() {
        let mut gate = gate();
        assert!(gate.reserve(7, 1, EngineControl::Core, true).is_err());
        assert!(gate.reserve(8, 1, EngineControl::Tunnel, true).is_err());
        assert!(gate.reserve(8, 0, EngineControl::Core, true).is_err());
        assert!(gate.reserve(8, 1, EngineControl::Core, false).is_err());
        assert!(gate.reserve(8, 1, EngineControl::Core, true).is_ok());
        assert_eq!(
            gate.reserve(8, 2, EngineControl::Core, true).unwrap_err(),
            4
        );
        gate.finish(1, Some("approval denied".into())).unwrap();
        assert!(gate.reserve(8, 1, EngineControl::Core, true).is_err());
        assert_eq!(
            gate.completion().unwrap().error.as_deref(),
            Some("approval denied")
        );
    }

    #[test]
    fn close_rejects_new_work_but_preserves_an_accepted_completion() {
        let mut gate = gate();
        let seen = gate.reserve(8, 1, EngineControl::Core, true).unwrap();
        gate.closed = true;
        assert_eq!(
            gate.reserve(8, 2, EngineControl::Core, true).unwrap_err(),
            2
        );
        gate.finish(1, None).unwrap();
        assert!(!gate.completion().unwrap().pending);
        assert_eq!(seen, EngineSnapshot::default());
        assert!(gate.finish(1, None).is_err());
    }

    #[test]
    fn foreign_completion_cannot_clear_an_active_request() {
        let mut gate = gate();
        gate.reserve(8, 2, EngineControl::Core, true).unwrap();
        assert!(gate.finish(1, None).is_err());
        assert!(gate.completion().unwrap().pending);
        assert!(control_from_wire(0).is_none());
        assert!(control_from_wire(4).is_none());
    }

    #[test]
    fn only_matching_failed_or_approval_modes_admit_same_value_retries() {
        for mode in [
            EngineMode::LocalProxy,
            EngineMode::SystemProxy,
            EngineMode::Tunnel,
            EngineMode::TunnelSystemProxy,
        ] {
            let mut snapshot = EngineSnapshot {
                desired_mode: mode,
                state: EngineState::Failed {
                    generation: 4,
                    target: mode,
                    error: "denied".into(),
                },
                generation: 4,
                config_digest: None,
            };
            assert_eq!(retry_target(&snapshot, EngineControl::Core), Some(mode));
            for (control, owns) in [
                (EngineControl::SystemProxy, mode.system_proxy_enabled()),
                (EngineControl::Tunnel, mode.tunnel_enabled()),
            ] {
                assert_eq!(retry_target(&snapshot, control), owns.then_some(mode));
            }
            snapshot.state = EngineState::Failed {
                generation: 4,
                target: EngineMode::Off,
                error: "denied".into(),
            };
            assert_eq!(retry_target(&snapshot, EngineControl::Core), None);
            snapshot.state = EngineState::AwaitingApproval { generation: 4 };
            assert_eq!(
                retry_target(&snapshot, EngineControl::Core),
                mode.tunnel_enabled().then_some(mode)
            );
            snapshot.state = EngineState::TunnelStarting { generation: 4 };
            assert_eq!(retry_target(&snapshot, EngineControl::Core), None);
        }
        let mut gate = gate();
        let displayed = gate.displayed.as_mut().unwrap();
        displayed.controls.core.enabled = true;
        assert!(gate.reserve(8, 1, EngineControl::Core, true).is_err());
        gate.displayed.as_mut().unwrap().controls.core.retry = true;
        assert!(gate.reserve(8, 1, EngineControl::Core, true).is_ok());
        gate.finish(1, None).unwrap();
        // Losing admission still refuses a stale advertised retry.
        gate.displayed.as_mut().unwrap().controls.core.available = false;
        assert!(gate.reserve(8, 2, EngineControl::Core, true).is_err());
    }

    #[test]
    fn only_explicit_retry_that_still_needs_approval_opens_settings() {
        let mut result = EngineSnapshot {
            desired_mode: EngineMode::Tunnel,
            state: EngineState::AwaitingApproval { generation: 4 },
            ..EngineSnapshot::default()
        };
        assert!(needs_approval_settings(true, &result));
        assert!(!needs_approval_settings(false, &result));
        result.desired_mode = EngineMode::Off;
        assert!(!needs_approval_settings(true, &result));
        result.desired_mode = EngineMode::Tunnel;
        result.state = EngineState::TunnelStarting { generation: 4 };
        assert!(!needs_approval_settings(true, &result));
        result.state = EngineState::Failed {
            generation: 4,
            target: EngineMode::Tunnel,
            error: "denied".into(),
        };
        assert!(!needs_approval_settings(true, &result));
    }
}
