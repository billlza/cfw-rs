use std::cell::RefCell;

use super::complete_legacy_data_retirement;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultAfter {
    Prepare(usize),
    SourceRemoval,
    MarkerCommit,
    Cleanup(usize),
}

#[derive(Debug)]
struct DurableCleanupState {
    prepared: [bool; 3],
    source_present: bool,
    marker_present: bool,
    cleanup_present: [bool; 4],
    marker_commits: usize,
}

impl Default for DurableCleanupState {
    fn default() -> Self {
        Self {
            prepared: [false; 3],
            source_present: true,
            marker_present: false,
            cleanup_present: [true; 4],
            marker_commits: 0,
        }
    }
}

fn run_cleanup_transaction(
    state: &RefCell<DurableCleanupState>,
    fault: Option<FaultAfter>,
) -> Result<(), String> {
    let marker_present = state.borrow().marker_present;
    complete_legacy_data_retirement(
        marker_present,
        || {
            for index in 0..3 {
                state.borrow_mut().prepared[index] = true;
                if fault == Some(FaultAfter::Prepare(index)) {
                    return Err(format!("fault after prepare step {index}"));
                }
            }
            Ok(())
        },
        || {
            state.borrow_mut().source_present = false;
            if fault == Some(FaultAfter::SourceRemoval) {
                Err("fault after source removal".into())
            } else {
                Ok(())
            }
        },
        || {
            let mut state = state.borrow_mut();
            state.marker_present = true;
            state.marker_commits += 1;
            if fault == Some(FaultAfter::MarkerCommit) {
                Err("fault after marker commit".into())
            } else {
                Ok(())
            }
        },
        || {
            for index in 0..4 {
                state.borrow_mut().cleanup_present[index] = false;
                if fault == Some(FaultAfter::Cleanup(index)) {
                    return Err(format!("fault after cleanup step {index}"));
                }
            }
            Ok(())
        },
    )
}

#[test]
fn retirement_marker_is_committed_only_after_legacy_source_removal() {
    let operations = RefCell::new(Vec::new());
    complete_legacy_data_retirement(
        false,
        || {
            operations.borrow_mut().push("prepare");
            Ok(())
        },
        || {
            operations.borrow_mut().push("remove-source");
            Ok(())
        },
        || {
            operations.borrow_mut().push("commit-marker");
            Ok(())
        },
        || {
            operations.borrow_mut().push("finish-cleanup");
            Ok(())
        },
    )
    .expect("retirement sequence");
    assert_eq!(
        operations.into_inner(),
        [
            "prepare",
            "remove-source",
            "commit-marker",
            "finish-cleanup"
        ]
    );
}

#[test]
fn every_cleanup_fault_converges_on_retry_without_marker_source_split_brain() {
    let faults = [
        FaultAfter::Prepare(0),
        FaultAfter::Prepare(1),
        FaultAfter::Prepare(2),
        FaultAfter::SourceRemoval,
        FaultAfter::MarkerCommit,
        FaultAfter::Cleanup(0),
        FaultAfter::Cleanup(1),
        FaultAfter::Cleanup(2),
        FaultAfter::Cleanup(3),
    ];

    for fault in faults {
        let state = RefCell::new(DurableCleanupState::default());
        assert!(
            run_cleanup_transaction(&state, Some(fault)).is_err(),
            "{fault:?} must interrupt the first attempt"
        );
        {
            let durable = state.borrow();
            assert!(
                !durable.marker_present || !durable.source_present,
                "the marker must never be committed ahead of source removal after {fault:?}"
            );
        }

        run_cleanup_transaction(&state, None)
            .unwrap_or_else(|error| panic!("retry after {fault:?} failed: {error}"));
        let durable = state.borrow();
        assert_eq!(durable.prepared, [true; 3], "{fault:?}");
        assert!(!durable.source_present, "{fault:?}");
        assert!(durable.marker_present, "{fault:?}");
        assert_eq!(durable.cleanup_present, [false; 4], "{fault:?}");
        assert_eq!(durable.marker_commits, 1, "{fault:?}");
    }
}

#[test]
fn marker_present_retry_repairs_legacy_source_and_remaining_cleanup() {
    let state = RefCell::new(DurableCleanupState {
        marker_present: true,
        ..DurableCleanupState::default()
    });

    run_cleanup_transaction(&state, None).expect("repair old marker-first state");
    let durable = state.borrow();
    assert_eq!(durable.prepared, [true; 3]);
    assert!(!durable.source_present);
    assert!(durable.marker_present);
    assert_eq!(durable.cleanup_present, [false; 4]);
    assert_eq!(durable.marker_commits, 0);
}
