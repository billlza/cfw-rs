#[cfg(target_os = "macos")]
#[path = "../src/main_run_loop_driver.rs"]
mod main_run_loop_driver;

#[cfg(target_os = "macos")]
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use dispatch2::DispatchQueue;

#[cfg(target_os = "macos")]
fn main() {
    // SAFETY: pthread_main_np only observes the calling thread identity.
    assert_eq!(unsafe { libc::pthread_main_np() }, 1);

    let completed = Arc::new(AtomicBool::new(false));
    let completion_count = Arc::new(AtomicUsize::new(0));
    let callback_completed = Arc::clone(&completed);
    let callback_count = Arc::clone(&completion_count);
    std::thread::spawn(move || {
        // SAFETY: pthread_main_np only observes the calling thread identity.
        assert_eq!(unsafe { libc::pthread_main_np() }, 0);
        DispatchQueue::main().exec_async(move || {
            // SAFETY: pthread_main_np only observes the calling thread identity.
            assert_eq!(unsafe { libc::pthread_main_np() }, 1);
            callback_count.fetch_add(1, Ordering::AcqRel);
            callback_completed.store(true, Ordering::Release);
        });
    })
    .join()
    .expect("the worker must enqueue its main-queue completion");

    assert!(main_run_loop_driver::pump_until_deadline(
        || completed.load(Ordering::Acquire),
        Instant::now() + Duration::from_secs(2),
    ));
    assert_eq!(completion_count.load(Ordering::Acquire), 1);
}

#[cfg(not(target_os = "macos"))]
fn main() {}
