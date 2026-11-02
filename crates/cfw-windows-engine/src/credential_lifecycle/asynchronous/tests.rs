use super::*;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize},
        mpsc,
    },
    task::Poll,
};
use tokio::sync::oneshot;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap()
}
async fn poll_pending<F: Future>(future: &mut Pin<Box<F>>) {
    poll_fn(|context| {
        assert!(future.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await
}
async fn retired(capacity: &Semaphore) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while capacity.available_permits() != MAX_OPERATIONS {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
/// A payload that records when it retires and whether its task still held
/// its capacity permit at that moment.
struct Dropped {
    dropped: Arc<AtomicBool>,
    capacity: Arc<Semaphore>,
    capacity_held_at_drop: Arc<AtomicBool>,
}
impl Drop for Dropped {
    fn drop(&mut self) {
        self.capacity_held_at_drop.store(
            self.capacity.available_permits() < MAX_OPERATIONS,
            Ordering::Release,
        );
        self.dropped.store(true, Ordering::Release);
    }
}

#[test]
fn worker_admission_is_bounded_and_requires_an_async_runtime() {
    let capacity = Arc::new(Semaphore::new(MAX_OPERATIONS));
    assert!(matches!(
        Worker::reserve(&capacity),
        Err(VaultError::Unavailable)
    ));
    runtime().block_on(async {
        let held = (0..MAX_OPERATIONS)
            .map(|_| Worker::reserve(&capacity).unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            Worker::reserve(&capacity),
            Err(VaultError::ConcurrentModification)
        ));
        drop(held);
        assert_eq!(capacity.available_permits(), MAX_OPERATIONS);
    });
}

#[test]
fn an_impersonating_caller_cannot_escape_the_identity_check_by_offloading() {
    use windows_sys::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};
    runtime().block_on(async {
        let capacity = Arc::new(Semaphore::new(MAX_OPERATIONS));
        assert_ne!(unsafe { ImpersonateSelf(SecurityImpersonation) }, 0);
        let outcome = Worker::reserve(&capacity);
        // Revert on this same thread before another future can be polled.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
        assert!(matches!(outcome, Err(VaultError::AccessDenied)));
        assert_eq!(capacity.available_permits(), MAX_OPERATIONS);
    });
}

#[test]
fn cancelled_queued_work_drops_its_payload_and_never_reaches_the_vault() {
    runtime().block_on(async {
        let capacity = Arc::new(Semaphore::new(MAX_OPERATIONS));
        let (entered, entering) = oneshot::channel();
        let (release, held) = mpsc::sync_channel(1);
        let blocker = tokio::task::spawn_blocking(move || {
            entered.send(()).unwrap();
            held.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        entering.await.unwrap();
        let changed = Arc::new(AtomicBool::new(false));
        let wrote = Arc::clone(&changed);
        let dropped = Arc::new(AtomicBool::new(false));
        let capacity_held_at_drop = Arc::new(AtomicBool::new(false));
        let payload = Dropped {
            dropped: Arc::clone(&dropped),
            capacity: Arc::clone(&capacity),
            capacity_held_at_drop: Arc::clone(&capacity_held_at_drop),
        };
        let worker = Worker::reserve(&capacity).unwrap();
        let mut request = Box::pin(worker.run(move |admission| {
            let _payload = payload;
            admission.begin()?;
            wrote.store(true, Ordering::Release);
            Ok(())
        }));
        poll_pending(&mut request).await;
        // The async executor remains live even though its only blocking worker is occupied.
        tokio::task::yield_now().await;
        drop(request);
        release.send(()).unwrap();
        blocker.await.unwrap();
        retired(&capacity).await;
        assert!(!changed.load(Ordering::Acquire));
        // The payload retires before the task's capacity permit, so capacity
        // returning is proof that the buffers are gone.
        assert!(dropped.load(Ordering::Acquire));
        assert!(capacity_held_at_drop.load(Ordering::Acquire));
    });
}

#[test]
fn cancellation_while_waiting_for_a_native_mutex_is_checked_after_acquisition() {
    runtime().block_on(async {
        let purpose = format!("async-test-{}", uuid::Uuid::new_v4());
        let lock = cfw_windows_storage::PrivateUserMutex::acquire(&purpose, Duration::from_secs(3))
            .unwrap();
        let capacity = Arc::new(Semaphore::new(MAX_OPERATIONS));
        let worker = Worker::reserve(&capacity).unwrap();
        let (entered, entering) = oneshot::channel();
        let (finished, finishing) = oneshot::channel();
        let changed = Arc::new(AtomicBool::new(false));
        let wrote = Arc::clone(&changed);
        let mut request = Box::pin(worker.run(move |admission| {
            entered.send(()).unwrap();
            let lock =
                cfw_windows_storage::PrivateUserMutex::acquire(&purpose, Duration::from_secs(3))?;
            let admitted = admission.begin();
            if admitted.is_ok() {
                wrote.store(true, Ordering::Release);
            }
            lock.release()?;
            finished.send(()).unwrap();
            admitted
        }));
        poll_pending(&mut request).await;
        entering.await.unwrap();
        drop(request);
        lock.release().unwrap();
        tokio::time::timeout(Duration::from_secs(5), finishing)
            .await
            .unwrap()
            .unwrap();
        retired(&capacity).await;
        assert!(!changed.load(Ordering::Acquire));
    });
}

#[test]
fn abandoning_admitted_work_retains_capacity_until_the_operation_retires() {
    runtime().block_on(async {
        let capacity = Arc::new(Semaphore::new(MAX_OPERATIONS));
        let worker = Worker::reserve(&capacity).unwrap();
        let admission = Arc::clone(&worker.admission);
        let (entered, entering) = oneshot::channel();
        let (release, held) = mpsc::sync_channel(1);
        let (finished, finishing) = oneshot::channel();
        let changed = Arc::new(AtomicUsize::new(0));
        let wrote = Arc::clone(&changed);
        let mut request = Box::pin(worker.run(move |admission| {
            admission.begin()?;
            entered.send(()).unwrap();
            held.recv_timeout(Duration::from_secs(5)).unwrap();
            wrote.fetch_add(1, Ordering::AcqRel);
            finished.send(()).unwrap();
            Ok(())
        }));
        poll_pending(&mut request).await;
        entering.await.unwrap();
        assert_eq!(admission.timeout_error(), VaultError::OutcomeUnknown);
        drop(request);
        assert_eq!(capacity.available_permits(), MAX_OPERATIONS - 1);
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), finishing)
            .await
            .unwrap()
            .unwrap();
        retired(&capacity).await;
        assert_eq!(changed.load(Ordering::Acquire), 1);
    });
}

#[test]
fn watchdog_cancels_queued_work_without_waiting_for_the_blocking_pool() {
    runtime().block_on(async {
        let capacity = Arc::new(Semaphore::new(MAX_OPERATIONS));
        let (entered, entering) = oneshot::channel();
        let (release, held) = mpsc::sync_channel(1);
        let blocker = tokio::task::spawn_blocking(move || {
            entered.send(()).unwrap();
            held.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        entering.await.unwrap();
        let mut worker = Worker::reserve(&capacity).unwrap();
        worker.completion_deadline = Instant::now() + Duration::from_millis(100);
        let changed = Arc::new(AtomicBool::new(false));
        let wrote = Arc::clone(&changed);
        let result = worker
            .run(move |admission| {
                admission.begin()?;
                wrote.store(true, Ordering::Release);
                Ok(())
            })
            .await;
        assert_eq!(result, Err(VaultError::Unavailable));
        assert!(!changed.load(Ordering::Acquire));
        release.send(()).unwrap();
        blocker.await.unwrap();
        retired(&capacity).await;
        assert!(!changed.load(Ordering::Acquire));
    });
}

#[test]
fn expired_queue_admission_cannot_run_a_late_operation() {
    runtime().block_on(async {
        let capacity = Arc::new(Semaphore::new(MAX_OPERATIONS));
        let mut worker = Worker::reserve(&capacity).unwrap();
        worker.admission = Arc::new(Admission::new(Instant::now() - Duration::from_secs(1)));
        let changed = Arc::new(AtomicBool::new(false));
        let wrote = Arc::clone(&changed);
        assert_eq!(
            worker
                .run(move |_| {
                    wrote.store(true, Ordering::Release);
                    Ok(())
                })
                .await,
            Err(VaultError::Unavailable)
        );
        assert!(!changed.load(Ordering::Acquire));
        retired(&capacity).await;
    });
}

#[test]
fn a_panicked_admitted_worker_has_an_unknown_outcome_and_releases_its_capacity() {
    runtime().block_on(async {
        let capacity = Arc::new(Semaphore::new(MAX_OPERATIONS));
        let worker = Worker::reserve(&capacity).unwrap();
        let result: std::result::Result<(), _> = worker
            .run(|admission| {
                admission.begin()?;
                panic!("receipt lost after admission")
            })
            .await;
        assert_eq!(result, Err(VaultError::OutcomeUnknown));
        retired(&capacity).await;
    });
}

#[test]
fn errors_keep_missing_protected_vault_and_post_admission_cleanup_distinct() {
    assert_eq!(
        map_error(Error::ProtectedVaultMissing, false),
        VaultError::Corrupt
    );
    assert_eq!(
        map_error(Error::Vault(VaultError::MissingVault), true),
        VaultError::MissingVault
    );
    assert_eq!(
        map_error(Error::Vault(VaultError::ImmutableConflict), true),
        VaultError::ImmutableConflict
    );
    assert_eq!(
        map_error(
            Error::Storage(cfw_windows_storage::Error::Io(std::io::Error::other(
                "release failed"
            ))),
            true
        ),
        VaultError::OutcomeUnknown
    );
    assert_eq!(
        map_error(Error::CancelledBeforeAdmission, false),
        VaultError::Unavailable
    );
}
