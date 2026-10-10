use super::*;

#[tokio::test]
async fn cancelled_preparation_can_never_install_or_become_ready() {
    let startup = NativeStartup::default();
    assert!(startup.cancel_uninstalled().unwrap());
    assert!(startup.install(|| panic!("late installation")).is_err());
    assert!(startup.finish(Ok(())).is_err());
    assert_eq!(
        startup.wait().await,
        Err("native startup was cancelled".into())
    );
}

#[tokio::test]
async fn installed_engine_requires_normal_shutdown_even_if_startup_fails() {
    let startup = NativeStartup::default();
    startup.install(|| Ok(())).unwrap();
    assert!(!startup.cancel_uninstalled().unwrap());
    startup.finish(Err("preflight failed".into())).unwrap();
    assert!(!startup.cancel_uninstalled().unwrap());
    assert_eq!(startup.wait().await, Err("preflight failed".into()));
    assert!(startup.require_ready().is_err());
}

#[tokio::test]
async fn readiness_is_published_only_after_installation_and_initialization() {
    let startup = NativeStartup::default();
    assert!(startup.finish(Ok(())).is_err());
    assert!(startup.require_ready().is_err());
    startup.install(|| Ok(())).unwrap();
    assert!(startup.require_ready().is_err());
    assert!(startup.install(|| panic!("second installation")).is_err());
    startup.finish(Ok(())).unwrap();
    startup.wait().await.unwrap();
    startup.require_ready().unwrap();
}

#[tokio::test]
async fn preparation_preserves_failures_and_supervises_worker_panics() {
    assert_eq!(
        prepare_off_main(|| Err::<(), _>("access denied".into())).await,
        Err("access denied".into())
    );
    assert!(
        prepare_off_main(|| -> Result<(), String> { panic!("injected preparation panic") })
            .await
            .unwrap_err()
            .contains("preparation task failed")
    );
}
