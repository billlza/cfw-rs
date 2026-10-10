#[cfg(target_os = "macos")]
#[path = "../src/main_run_loop_driver.rs"]
mod main_run_loop_driver;
#[cfg(target_os = "macos")]
#[path = "../src/startup_state.rs"]
mod startup_state;

#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "macos")]
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use cfw_core::{MacOsAppPaths, SettingsStore, UiPreferences};
#[cfg(target_os = "macos")]
use dispatch2::DispatchQueue;
#[cfg(target_os = "macos")]
use startup_state::{NativeStartup, prepare_off_main};

#[cfg(target_os = "macos")]
fn main() {
    assert_eq!(unsafe { libc::pthread_main_np() }, 1);
    let root = tempfile::tempdir().unwrap();
    let store = SettingsStore::new(MacOsAppPaths::from_app_home(root.path().join("app")));
    store.write(&UiPreferences::default()).unwrap();
    let lock = std::fs::File::open(&store.paths().app_home).unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let entered = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let callbacks = Arc::new(AtomicUsize::new(0));
    let installations = Arc::new(AtomicUsize::new(0));
    let startup = Arc::new(NativeStartup::default());
    let start = Instant::now();
    let callback_seen = callbacks.clone();
    let prepared = entered.clone();
    let control = std::env::args().any(|arg| arg == "--synchronous-control");
    let callback_thread = std::thread::spawn(move || {
        while !prepared.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        }
        DispatchQueue::main().exec_async(move || {
            assert_eq!(unsafe { libc::pthread_main_np() }, 1);
            callback_seen.fetch_add(1, Ordering::AcqRel);
        });
    });
    if control {
        // The pre-fix setup used this exact blocking settings read on AppKit.
        // A bounded external release keeps the failing control test finite.
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(800));
            drop(lock);
        });
        entered.store(true, Ordering::Release);
        store.read_or_default().unwrap();
        release.join().unwrap();
        main_run_loop_driver::pump_until_deadline(
            || callbacks.load(Ordering::Acquire) != 0,
            Instant::now() + Duration::from_secs(1),
        );
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "AppKit callback was blocked by synchronous startup I/O"
        );
        return;
    }
    let worker_startup = startup.clone();
    let worker_finished = finished.clone();
    let worker_installations = installations.clone();
    tauri::async_runtime::spawn(async move {
        let result = prepare_off_main(move || {
            assert_eq!(unsafe { libc::pthread_main_np() }, 0);
            entered.store(true, Ordering::Release);
            store.read_or_default().map_err(|error| error.to_string())
        })
        .await;
        assert!(
            result.is_ok(),
            "the real settings read should finish after lock release"
        );
        assert!(
            worker_startup
                .install(|| {
                    worker_installations.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                })
                .is_err()
        );
        assert!(worker_startup.finish(Ok(())).is_err());
        assert!(worker_startup.wait().await.is_err());
        worker_finished.store(true, Ordering::Release);
    });
    assert!(
        main_run_loop_driver::pump_until_deadline(
            || callbacks.load(Ordering::Acquire) != 0,
            start + Duration::from_millis(500),
        ),
        "main queue must respond while the real settings lock is held"
    );
    let callback_latency = start.elapsed();
    assert!(!finished.load(Ordering::Acquire));
    assert!(startup.require_ready().is_err());
    assert!(startup.cancel_uninstalled().unwrap());
    drop(lock);
    assert!(main_run_loop_driver::pump_until_deadline(
        || finished.load(Ordering::Acquire),
        Instant::now() + Duration::from_secs(2),
    ));
    callback_thread.join().unwrap();
    assert_eq!(installations.load(Ordering::Acquire), 0);
    println!(
        "main_queue_callback_ms={} late_engine_installations=0",
        callback_latency.as_millis()
    );
}

#[cfg(not(target_os = "macos"))]
fn main() {}
