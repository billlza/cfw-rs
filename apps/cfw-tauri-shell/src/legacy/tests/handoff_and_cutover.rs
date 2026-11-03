//! The app-owned hand-off task, the cutover's explicit confirmation, and the
//! replacement's exact Active proof.

use super::*;

#[tokio::test]
async fn renderer_response_cancellation_cannot_cancel_the_app_owned_task() {
    let (release, released) = tokio::sync::oneshot::channel();
    let completed = Arc::new(AtomicBool::new(false));
    let after_response = Arc::new(AtomicBool::new(false));
    let operation_completed = completed.clone();
    let response_completed = after_response.clone();
    let receiver = spawn_supervised_app_result(
        async move {
            released.await.expect("release app task");
            operation_completed.store(true, Ordering::Release);
        },
        |operation| operation,
        move || response_completed.store(true, Ordering::Release),
    );
    drop(receiver);
    release.send(()).expect("release sender");

    tokio::time::timeout(Duration::from_secs(1), async {
        while !completed.load(Ordering::Acquire) || !after_response.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached task must reach terminal side effects");
}

#[tokio::test]
async fn supervised_app_task_turns_worker_panic_into_a_terminal_error() {
    let receiver = spawn_supervised_app_result(
        async move {
            panic!("injected migration worker panic");
        },
        |operation| operation,
        || {},
    );
    let error = receiver
        .await
        .expect("supervisor response")
        .expect_err("worker panic must fail");
    assert_eq!(error, "migration handoff application task panicked");
}

#[test]
fn destructive_cutover_requires_an_explicit_positive_confirmation() {
    assert!(require_explicit_cutover_confirmation(true).is_ok());
    assert!(
        require_explicit_cutover_confirmation(false)
            .expect_err("missing confirmation")
            .contains("left unchanged")
    );
}

#[test]
fn start_handoff_requires_exact_active_target_and_digest() {
    let digest = "01".repeat(32);
    let runtime = RuntimeIdentity {
        owner: EngineOwner::ProxyAgent,
        context: EngineCommandContext {
            installation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            config_epoch: 1,
            generation: 7,
        },
        config_digest: digest.clone(),
        ready: true,
    };
    let context = runtime.context.clone();
    let active = EngineSnapshot {
        desired_mode: EngineMode::SystemProxy,
        state: EngineState::ProxyActive { runtime },
        generation: 7,
        config_digest: Some(digest.clone()),
    };
    require_replacement_active(active.clone(), EngineMode::SystemProxy, &digest, &context)
        .expect("exact Active proof");
    assert!(require_replacement_active(active, EngineMode::Tunnel, &digest, &context).is_err());
}
