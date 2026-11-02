use std::{sync::Arc, time::Duration};

use cfw_engine_api::{
    BackendError, BackendErrorKind, EngineMode, EngineOwner, EngineSnapshot, EngineState,
    NativeEngineStatus,
};
use cfw_singbox_config::{
    EngineSettings, RELEASE_PACKET_TRANSPORT_IPV4, ReleasePacketEvidenceCase,
    ValidatedSingBoxProfile,
};

use crate::{CoordinatorOptions, EngineCoordinatorError, EngineModeCoordinator, EngineOperation};

use super::support::{FakeBackend, coordinator, test_session};

mod identity;
mod reconciliation;
mod start_failures;
mod starts;
mod status_recovery;
mod tunnel;

async fn wait_for_failed(coordinator: &EngineModeCoordinator) -> EngineSnapshot {
    let mut snapshots = coordinator.subscribe();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let snapshot = snapshots.borrow().clone();
            if matches!(snapshot.state, EngineState::Failed { .. }) {
                return snapshot;
            }
            snapshots
                .changed()
                .await
                .expect("coordinator remains available while awaiting failure");
        }
    })
    .await
    .expect("active runtime reconciliation publishes failure before the deadline")
}
