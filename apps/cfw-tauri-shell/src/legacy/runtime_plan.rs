use cfw_platform::{
    LegacyServiceJobObservation, LegacyServiceJobProgram, LegacyServiceRetirement,
    MacOsPlatformService, ServiceModeStatus,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum LegacyRuntimePlanKind {
    LiveOwned {
        service_job: LegacyServiceJobObservation,
    },
    DormantRegistered {
        service_job: LegacyServiceJobObservation,
    },
    OfflineUpgrade,
    FreshInstall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LegacyServiceRetirementBoundary {
    RegisteredInactive,
    AlreadyRetired,
}

impl LegacyRuntimePlanKind {
    pub(super) const fn requires_legacy_gui(self) -> bool {
        matches!(self, Self::LiveOwned { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LegacyRuntimeEvidence {
    pub(super) retirement_completed: bool,
    pub(super) legacy_settings_present: bool,
    pub(super) service_status: ServiceModeStatus,
    pub(super) service_job: LegacyServiceJobObservation,
    pub(super) control_session_present: bool,
    pub(super) managed_process_count: usize,
}

pub(super) fn classify_legacy_runtime(
    evidence: LegacyRuntimeEvidence,
) -> Result<LegacyRuntimePlanKind, String> {
    if evidence.retirement_completed {
        return Err(
            "legacy retirement is already complete; a second network cutover is not permitted"
                .into(),
        );
    }
    match evidence.service_status {
        ServiceModeStatus::Enabled => match (
            evidence.service_job,
            evidence.control_session_present,
            evidence.managed_process_count,
        ) {
            (
                observation @ LegacyServiceJobObservation::LoadedActive {
                    program: LegacyServiceJobProgram::LegacyHelper,
                },
                true,
                1,
            ) => Ok(LegacyRuntimePlanKind::LiveOwned {
                service_job: observation,
            }),
            (
                observation @ LegacyServiceJobObservation::LoadedInactive {
                    program: LegacyServiceJobProgram::LegacyHelper
                        | LegacyServiceJobProgram::RetirementTombstone,
                },
                false,
                0,
            ) => Ok(LegacyRuntimePlanKind::DormantRegistered {
                service_job: observation,
            }),
            _ => Err(
                "legacy Service Mode registration, fixed launchd job, control session, and managed core form a partial or inconsistent runtime; nothing was changed"
                    .into(),
            ),
        },
        ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound => {
            if evidence.service_job != LegacyServiceJobObservation::Unloaded
                || evidence.control_session_present
                || evidence.managed_process_count != 0
            {
                return Err(
                    "legacy Service Mode is unregistered but a launchd job, session, or managed core remains; nothing was changed"
                        .into(),
                );
            }
            if evidence.legacy_settings_present {
                Ok(LegacyRuntimePlanKind::OfflineUpgrade)
            } else {
                Ok(LegacyRuntimePlanKind::FreshInstall)
            }
        }
        status => Err(format!(
            "legacy Service Mode has non-authoritative status {status:?}; nothing was changed"
        )),
    }
}

pub(super) fn classify_service_retirement_boundary(
    status: ServiceModeStatus,
    service_job: LegacyServiceJobObservation,
) -> Result<LegacyServiceRetirementBoundary, String> {
    match (status, service_job) {
        (
            ServiceModeStatus::Enabled,
            LegacyServiceJobObservation::LoadedInactive {
                program: LegacyServiceJobProgram::LegacyHelper
                    | LegacyServiceJobProgram::RetirementTombstone,
            },
        ) => Ok(LegacyServiceRetirementBoundary::RegisteredInactive),
        (
            ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound,
            LegacyServiceJobObservation::Unloaded,
        ) => Ok(LegacyServiceRetirementBoundary::AlreadyRetired),
        _ => Err(
            "legacy service retirement boundary is partial, active, untrusted, or has the wrong fixed program identity"
                .into(),
        ),
    }
}

pub(super) fn complete_service_retirement<Observe, Retire, VerifyAbsence>(
    mut observe: Observe,
    mut retire: Retire,
    verify_absence: VerifyAbsence,
) -> Result<(), String>
where
    Observe: FnMut() -> Result<(ServiceModeStatus, LegacyServiceJobObservation), String>,
    Retire: FnMut() -> Result<(), String>,
    VerifyAbsence: FnOnce() -> Result<(), String>,
{
    let initial = observe()?;
    match classify_service_retirement_boundary(initial.0, initial.1)? {
        LegacyServiceRetirementBoundary::RegisteredInactive => {
            let adjacent = observe()?;
            if classify_service_retirement_boundary(adjacent.0, adjacent.1)?
                != LegacyServiceRetirementBoundary::RegisteredInactive
            {
                return Err(
                    "legacy service/job state changed at the actual unregister boundary".into(),
                );
            }
            retire()?;
        }
        LegacyServiceRetirementBoundary::AlreadyRetired => {}
    }

    let completed = observe()?;
    if classify_service_retirement_boundary(completed.0, completed.1)?
        != LegacyServiceRetirementBoundary::AlreadyRetired
    {
        return Err("legacy service unregister did not reach the exact retired state".into());
    }
    verify_absence()
}

pub(super) fn observe_service_retirement_boundary()
-> Result<(ServiceModeStatus, LegacyServiceJobObservation), String> {
    let status = MacOsPlatformService.service_mode_status();
    let job = MacOsPlatformService
        .legacy_service_job_observation()
        .map_err(|error| {
            format!("the fixed legacy launchd job could not be observed authoritatively: {error}")
        })?;
    Ok((status, job))
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use super::*;

    type ServiceObservation = (ServiceModeStatus, LegacyServiceJobObservation);

    fn registered_inactive() -> ServiceObservation {
        (
            ServiceModeStatus::Enabled,
            LegacyServiceJobObservation::LoadedInactive {
                program: LegacyServiceJobProgram::LegacyHelper,
            },
        )
    }

    fn registered_tombstone() -> ServiceObservation {
        (
            ServiceModeStatus::Enabled,
            LegacyServiceJobObservation::LoadedInactive {
                program: LegacyServiceJobProgram::RetirementTombstone,
            },
        )
    }

    fn retired(status: ServiceModeStatus) -> ServiceObservation {
        (status, LegacyServiceJobObservation::Unloaded)
    }

    fn evidence() -> LegacyRuntimeEvidence {
        LegacyRuntimeEvidence {
            retirement_completed: false,
            legacy_settings_present: true,
            service_status: ServiceModeStatus::Enabled,
            service_job: LegacyServiceJobObservation::LoadedInactive {
                program: LegacyServiceJobProgram::LegacyHelper,
            },
            control_session_present: false,
            managed_process_count: 0,
        }
    }

    #[test]
    fn classifier_distinguishes_live_dormant_offline_and_fresh_installations() {
        assert!(matches!(
            classify_legacy_runtime(evidence()).expect("dormant"),
            LegacyRuntimePlanKind::DormantRegistered { .. }
        ));
        assert!(matches!(
            classify_legacy_runtime(LegacyRuntimeEvidence {
                service_job: LegacyServiceJobObservation::LoadedInactive {
                    program: LegacyServiceJobProgram::RetirementTombstone,
                },
                ..evidence()
            })
            .expect("tombstone dormant"),
            LegacyRuntimePlanKind::DormantRegistered { .. }
        ));

        let mut live = evidence();
        live.service_job = LegacyServiceJobObservation::LoadedActive {
            program: LegacyServiceJobProgram::LegacyHelper,
        };
        live.control_session_present = true;
        live.managed_process_count = 1;
        assert!(matches!(
            classify_legacy_runtime(live).expect("live"),
            LegacyRuntimePlanKind::LiveOwned { .. }
        ));

        let mut offline = evidence();
        offline.service_status = ServiceModeStatus::NotRegistered;
        offline.service_job = LegacyServiceJobObservation::Unloaded;
        assert_eq!(
            classify_legacy_runtime(offline).expect("offline"),
            LegacyRuntimePlanKind::OfflineUpgrade
        );
        offline.legacy_settings_present = false;
        assert_eq!(
            classify_legacy_runtime(offline).expect("fresh"),
            LegacyRuntimePlanKind::FreshInstall
        );
    }

    #[test]
    fn every_partial_or_unverifiable_runtime_combination_fails_closed() {
        let mut active_without_session = evidence();
        active_without_session.service_job = LegacyServiceJobObservation::LoadedActive {
            program: LegacyServiceJobProgram::LegacyHelper,
        };
        assert!(classify_legacy_runtime(active_without_session).is_err());

        let mut session_without_process = evidence();
        session_without_process.control_session_present = true;
        assert!(classify_legacy_runtime(session_without_process).is_err());

        let mut multiple_processes = evidence();
        multiple_processes.managed_process_count = 2;
        assert!(classify_legacy_runtime(multiple_processes).is_err());

        let mut active_tombstone = evidence();
        active_tombstone.service_job = LegacyServiceJobObservation::LoadedActive {
            program: LegacyServiceJobProgram::RetirementTombstone,
        };
        active_tombstone.control_session_present = true;
        active_tombstone.managed_process_count = 1;
        assert!(classify_legacy_runtime(active_tombstone).is_err());

        let mut unregistered_loaded = evidence();
        unregistered_loaded.service_status = ServiceModeStatus::NotRegistered;
        assert!(classify_legacy_runtime(unregistered_loaded).is_err());

        let mut retired = evidence();
        retired.retirement_completed = true;
        assert!(classify_legacy_runtime(retired).is_err());

        let mut unknown = evidence();
        unknown.service_status = ServiceModeStatus::Unknown;
        assert!(classify_legacy_runtime(unknown).is_err());

        let mut enabled_but_unloaded = evidence();
        enabled_but_unloaded.service_job = LegacyServiceJobObservation::Unloaded;
        assert!(classify_legacy_runtime(enabled_but_unloaded).is_err());
    }

    #[test]
    fn retirement_boundary_accepts_only_the_closed_status_job_matrix() {
        let statuses = [
            ServiceModeStatus::NotRegistered,
            ServiceModeStatus::Enabled,
            ServiceModeStatus::RequiresApproval,
            ServiceModeStatus::NotFound,
            ServiceModeStatus::Unknown,
        ];
        let jobs = [
            LegacyServiceJobObservation::Unloaded,
            LegacyServiceJobObservation::LoadedInactive {
                program: LegacyServiceJobProgram::LegacyHelper,
            },
            LegacyServiceJobObservation::LoadedActive {
                program: LegacyServiceJobProgram::LegacyHelper,
            },
            LegacyServiceJobObservation::LoadedInactive {
                program: LegacyServiceJobProgram::RetirementTombstone,
            },
            LegacyServiceJobObservation::LoadedActive {
                program: LegacyServiceJobProgram::RetirementTombstone,
            },
        ];

        for status in statuses {
            for job in jobs {
                let result = classify_service_retirement_boundary(status, job);
                let expected = match (status, job) {
                    (
                        ServiceModeStatus::Enabled,
                        LegacyServiceJobObservation::LoadedInactive {
                            program:
                                LegacyServiceJobProgram::LegacyHelper
                                | LegacyServiceJobProgram::RetirementTombstone,
                        },
                    ) => Some(LegacyServiceRetirementBoundary::RegisteredInactive),
                    (
                        ServiceModeStatus::NotRegistered | ServiceModeStatus::NotFound,
                        LegacyServiceJobObservation::Unloaded,
                    ) => Some(LegacyServiceRetirementBoundary::AlreadyRetired),
                    _ => None,
                };
                assert_eq!(result.ok(), expected, "status={status:?}, job={job:?}");
            }
        }
    }

    #[test]
    fn service_retirement_is_idempotent_for_registered_and_completed_states() {
        let observations = RefCell::new(VecDeque::from([
            registered_inactive(),
            registered_inactive(),
            retired(ServiceModeStatus::NotRegistered),
        ]));
        let unregister_calls = Cell::new(0);
        let absence_checks = Cell::new(0);
        complete_service_retirement(
            || {
                observations
                    .borrow_mut()
                    .pop_front()
                    .ok_or_else(|| "unexpected observation".into())
            },
            || {
                unregister_calls.set(unregister_calls.get() + 1);
                Ok(())
            },
            || {
                absence_checks.set(absence_checks.get() + 1);
                Ok(())
            },
        )
        .expect("registered retirement");
        assert_eq!(unregister_calls.get(), 1);
        assert_eq!(absence_checks.get(), 1);
        assert!(observations.borrow().is_empty());

        let observations = RefCell::new(VecDeque::from([
            registered_tombstone(),
            registered_tombstone(),
            retired(ServiceModeStatus::NotFound),
        ]));
        complete_service_retirement(
            || {
                observations
                    .borrow_mut()
                    .pop_front()
                    .ok_or_else(|| "unexpected observation".into())
            },
            || Ok(()),
            || Ok(()),
        )
        .expect("tombstone retirement");
        assert!(observations.borrow().is_empty());

        let observations = RefCell::new(VecDeque::from([
            retired(ServiceModeStatus::NotFound),
            retired(ServiceModeStatus::NotRegistered),
        ]));
        complete_service_retirement(
            || {
                observations
                    .borrow_mut()
                    .pop_front()
                    .ok_or_else(|| "unexpected observation".into())
            },
            || Err("idempotent recovery must not unregister again".into()),
            || Ok(()),
        )
        .expect("already retired recovery");
        assert!(observations.borrow().is_empty());
    }

    #[test]
    fn service_retirement_faults_never_reach_the_absence_release_boundary() {
        let cases = [
            (
                VecDeque::from([
                    registered_inactive(),
                    (
                        ServiceModeStatus::Enabled,
                        LegacyServiceJobObservation::LoadedInactive {
                            program: LegacyServiceJobProgram::RetirementTombstone,
                        },
                    ),
                ]),
                false,
                "adjacent identity change",
            ),
            (
                VecDeque::from([registered_inactive(), registered_inactive()]),
                true,
                "unregister failure",
            ),
            (
                VecDeque::from([
                    registered_inactive(),
                    registered_inactive(),
                    registered_inactive(),
                ]),
                false,
                "unregister claimed success without retirement",
            ),
        ];

        for (observations, fail_unregister, label) in cases {
            let observations = RefCell::new(observations);
            let absence_checks = Cell::new(0);
            let result = complete_service_retirement(
                || {
                    observations
                        .borrow_mut()
                        .pop_front()
                        .ok_or_else(|| "unexpected observation".into())
                },
                || {
                    if fail_unregister {
                        Err("injected unregister failure".into())
                    } else {
                        Ok(())
                    }
                },
                || {
                    absence_checks.set(absence_checks.get() + 1);
                    Ok(())
                },
            );
            assert!(result.is_err(), "{label}");
            assert_eq!(absence_checks.get(), 0, "{label}");
        }

        for missing_component in ["session", "core", "network", "proxy", "GUI"] {
            let observations = RefCell::new(VecDeque::from([
                retired(ServiceModeStatus::NotRegistered),
                retired(ServiceModeStatus::NotFound),
            ]));
            let result = complete_service_retirement(
                || {
                    observations
                        .borrow_mut()
                        .pop_front()
                        .ok_or_else(|| "unexpected observation".into())
                },
                || Err("already-retired recovery must not unregister".into()),
                || Err(format!("injected {missing_component} absence failure")),
            );
            assert!(
                result
                    .expect_err("absence fault must block release")
                    .contains(missing_component)
            );
        }
    }
}
