#[cfg(target_os = "macos")]
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_os = "macos")]
use std::time::Duration;

use super::*;

#[test]
fn failed_initial_window_presentation_can_be_retried_without_representing_success() {
    let launch = LaunchContext::dashboard();
    let calls = AtomicUsize::new(0);
    assert!(
        launch
            .present_initial_with(|| {
                calls.fetch_add(1, Ordering::Relaxed);
                Err("window unavailable".into())
            })
            .is_err()
    );
    launch
        .present_initial_with(|| {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();
    launch
        .present_initial_with(|| panic!("already presented"))
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[cfg(target_os = "macos")]
fn challenges() -> Vec<RendererReadyChallenge> {
    (1..=3)
        .map(|generation| RendererReadyChallenge {
            generation,
            challenge: format!("00000000-0000-4000-8000-{generation:012x}"),
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn active_challenge(gate: &RendererReadyGate) -> RendererReadyChallenge {
    let MigrationHandoffRendererReady::Challenge {
        generation,
        challenge,
    } = gate.boot_state(&challenges()).expect("issue challenge")
    else {
        panic!("expected challenge");
    };
    RendererReadyChallenge {
        generation,
        challenge,
    }
}

#[test]
#[cfg(target_os = "macos")]
fn native_setup_does_not_publish_or_issue_a_renderer_challenge() {
    let gate = RendererReadyGate::default();
    assert!(gate.boot_state(&challenges()).is_err());
    assert!(gate.require_post_parent_window_ready().is_err());
    let publications = AtomicUsize::new(0);
    assert!(
        gate.acknowledge_with(
            MAIN_WINDOW_LABEL,
            challenges()[0].clone(),
            || Ok(()),
            |_| {
                publications.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        )
        .is_err()
    );
    assert_eq!(publications.load(Ordering::Acquire), 0);
    gate.mark_native_ready().expect("native ready");
    assert!(gate.require_post_parent_window_ready().is_err());
}

#[test]
#[cfg(target_os = "macos")]
fn exhausting_parent_bound_generations_is_terminal() {
    let gate = RendererReadyGate::default();
    gate.mark_native_ready().expect("native ready");
    let only = vec![challenges()[0].clone()];
    assert!(gate.boot_state(&only).is_ok());
    assert!(gate.boot_state(&only).is_err());
    assert!(gate.boot_state(&only).is_err());
    assert!(gate.require_post_parent_window_ready().is_err());
}

#[test]
#[cfg(target_os = "macos")]
fn stale_and_wrong_window_acknowledgements_do_not_poison_the_current_generation() {
    let gate = RendererReadyGate::default();
    gate.mark_native_ready().expect("native ready");
    let stale = active_challenge(&gate);
    let current = active_challenge(&gate);
    assert!(
        gate.acknowledge_with(MAIN_WINDOW_LABEL, stale, || Ok(()), |_| Ok(()))
            .is_err()
    );
    assert!(
        gate.acknowledge_with("other", current.clone(), || Ok(()), |_| Ok(()))
            .is_err()
    );
    gate.acknowledge_with(MAIN_WINDOW_LABEL, current, || Ok(()), |_| Ok(()))
        .expect("current main-window acknowledgement");
    assert!(gate.require_post_parent_window_ready().is_err());
    gate.mark_post_parent_window_ready()
        .expect("post-parent window ready");
    gate.require_post_parent_window_ready()
        .expect("final migration window readiness");
    assert!(gate.mark_post_parent_window_ready().is_err());
}

#[test]
#[cfg(target_os = "macos")]
fn replay_and_publish_failure_are_terminal_and_never_republish() {
    let gate = RendererReadyGate::default();
    gate.mark_native_ready().expect("native ready");
    let proof = active_challenge(&gate);
    let calls = AtomicUsize::new(0);
    gate.acknowledge_with(
        MAIN_WINDOW_LABEL,
        proof.clone(),
        || Ok(()),
        |_| {
            calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        },
    )
    .expect("publish");
    assert!(
        gate.acknowledge_with(
            MAIN_WINDOW_LABEL,
            proof,
            || Ok(()),
            |_| {
                calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(calls.load(Ordering::Acquire), 1);

    let failed = RendererReadyGate::default();
    failed.mark_native_ready().expect("native ready");
    let proof = active_challenge(&failed);
    assert!(
        failed
            .acknowledge_with(
                MAIN_WINDOW_LABEL,
                proof.clone(),
                || Ok(()),
                |_| { Err("injected persistence failure".into()) }
            )
            .is_err()
    );
    assert!(
        failed
            .acknowledge_with(MAIN_WINDOW_LABEL, proof, || Ok(()), |_| Ok(()))
            .is_err()
    );
    assert!(failed.require_post_parent_window_ready().is_err());
}

#[test]
#[cfg(target_os = "macos")]
fn concurrent_acknowledgements_have_exactly_one_publication_side_effect() {
    let gate = Arc::new(RendererReadyGate::default());
    gate.mark_native_ready().expect("native ready");
    let proof = active_challenge(&gate);
    let publications = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for _ in 0..16 {
        let gate = gate.clone();
        let proof = proof.clone();
        let publications = publications.clone();
        workers.push(std::thread::spawn(move || {
            gate.acknowledge_with(
                MAIN_WINDOW_LABEL,
                proof,
                || Ok(()),
                |_| {
                    publications.fetch_add(1, Ordering::AcqRel);
                    std::thread::sleep(Duration::from_millis(20));
                    Ok(())
                },
            )
        }));
    }
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(publications.load(Ordering::Acquire), 1);
}

#[test]
#[cfg(target_os = "macos")]
fn dashboard_and_inconsistent_handoff_roles_have_no_acknowledgement_path() {
    let dashboard = LaunchContext::dashboard();
    assert!(dashboard.require_handoff_ticket().is_err());

    let inconsistent = LaunchContext {
        migration_handoff: true,
        handoff_ticket: None,
        _handoff_lease: None,
        initial_window_presented: AtomicBool::new(false),
        requested_visibility: AtomicU8::new(WINDOW_VISIBILITY_DEFAULT),
        renderer_ready: RendererReadyGate::default(),
    };
    assert!(inconsistent.require_handoff_ticket().is_err());
}

#[tokio::test]
#[cfg(target_os = "macos")]
async fn parent_exit_wait_is_bounded_and_preserves_observation_errors() {
    let checks = AtomicUsize::new(0);
    let sleeps = AtomicUsize::new(0);
    wait_for_parent_absence_with(
        || Ok(checks.fetch_add(1, Ordering::AcqRel) >= 2),
        || {
            sleeps.fetch_add(1, Ordering::AcqRel);
            std::future::ready(())
        },
        4,
    )
    .await
    .expect("third observation sees parent exit");
    assert_eq!(checks.load(Ordering::Acquire), 3);
    assert_eq!(sleeps.load(Ordering::Acquire), 2);

    let error = wait_for_parent_absence_with(
        || Err("kernel observation failed".into()),
        || std::future::ready(()),
        4,
    )
    .await
    .expect_err("observation failure remains terminal");
    assert_eq!(error, "kernel observation failed");

    let error = wait_for_parent_absence_with(|| Ok(false), || std::future::ready(()), 2)
        .await
        .expect_err("bounded wait times out");
    assert_eq!(
        error,
        "migration dashboard parent did not exit within 20 seconds"
    );
    assert!(
        wait_for_parent_absence_with(|| Ok(true), || std::future::ready(()), 0,)
            .await
            .is_err()
    );
}
