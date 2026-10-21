use super::*;
use crate::{NativePeerProcess, PeerIdentityError};
use std::cell::RefCell;

fn fixture() -> VerifiedExecutable {
    assert_eq!(
        std::env::var("CFW_NATIVE_PACKAGE_TESTS").as_deref(),
        Ok("1")
    );
    let path = PathBuf::from(std::env::var_os("CFW_NATIVE_PACKAGE_WORKER_FIXTURE").unwrap());
    let bytes = std::fs::read(&path).unwrap();
    VerifiedExecutable::open(&path, Sha256::digest(bytes).into(), "0.5.0").unwrap()
}

fn observed(path: &Path) -> Option<NativePeerProcess> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => panic!("read native child marker: {error}"),
    };
    let identity: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let pid = u32::try_from(identity["pid"].as_u64().unwrap()).unwrap();
    let process = NativePeerProcess::open(pid).expect("retain the live waiting child");
    assert_eq!(
        process.identity().process_creation_time(),
        identity["creation_filetime"].as_u64().unwrap()
    );
    Some(process)
}

fn assert_retired(process: &NativePeerProcess, role: &str) {
    let outcome = process.revalidate();
    assert!(
        matches!(&outcome, Err(PeerIdentityError::Exited)),
        "{role} pid={} creation_filetime={} retirement observation: {outcome:?}",
        process.process_id(),
        process.identity().process_creation_time(),
    );
}

#[test]
fn a_complete_reply_requires_actual_exit_and_preserves_explicit_rejection() {
    for (request, expected, code) in [
        (b"okay".to_vec(), b"verified".as_slice(), 0),
        (b"deny".to_vec(), b"rejected".as_slice(), 2),
    ] {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("校验 进程");
        let reply = run(
            fixture(),
            &directory,
            request,
            Duration::from_secs(10),
            || false,
        )
        .unwrap();
        assert_eq!(reply.bytes, expected);
        assert_eq!(reply.exit_code, code);
        let marker: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("worker.json")).unwrap()).unwrap();
        assert_eq!(u64::from(reply.process_id), marker["pid"].as_u64().unwrap());
        if let Some(process) = NativePeerProcess::open_if_running(reply.process_id).unwrap() {
            assert_ne!(
                process.identity().process_creation_time(),
                marker["creation_filetime"].as_u64().unwrap(),
                "the original worker is still running"
            );
        }
    }
}

#[test]
fn empty_oversized_replies_and_unexpected_exit_do_not_become_success() {
    for request in [b"empt", b"junk", b"exit"] {
        let root = tempfile::tempdir().unwrap();
        let result = run(
            fixture(),
            &root.path().join("worker"),
            request.to_vec(),
            Duration::from_secs(10),
            || false,
        );
        assert!(matches!(result, Err(Error::Protocol(_))), "{request:?}");
    }
}

#[test]
fn deadline_retires_a_worker_that_never_answers_and_its_blocked_read() {
    waiting_counterexample(b"read", false);
}

#[test]
fn deadline_retires_a_worker_with_an_unread_request_and_its_pipe_writer() {
    waiting_counterexample(b"writ", true);
}

fn waiting_counterexample(mode: &[u8; 4], large: bool) {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("worker");
    let child = RefCell::new(None);
    let mut request = mode.to_vec();
    if large {
        request.resize(MAX_REQUEST, b'x');
    }
    let started = Instant::now();
    let result = run(
        fixture(),
        &directory,
        request,
        Duration::from_secs(3),
        || {
            if child.borrow().is_none() {
                *child.borrow_mut() = observed(&directory.join("worker.json"));
            }
            false
        },
    );
    assert!(matches!(result, Err(Error::Timeout)));
    assert!(started.elapsed() < Duration::from_secs(9));
    assert_retired(
        child
            .borrow()
            .as_ref()
            .expect("the fixture entered its waiting mode"),
        "deadline worker",
    );
    if large {
        let marker: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("worker.json")).unwrap()).unwrap();
        let capacity = marker["input_buffer_capacity"].as_u64().unwrap();
        assert!(capacity > 0 && capacity < (MAX_REQUEST - 4) as u64);
    }
}

#[test]
fn cancellation_retires_the_exact_worker_descendant_and_inherited_pipe() {
    // A native CI failure did not retain the observed result or distinguish
    // the root from its descendant. Exercise the unchanged immediate-exit
    // requirement repeatedly and preserve those facts on the first failure.
    for trial in 0..64 {
        cancellation_counterexample(trial);
    }
    println!("native worker cancellation: 64 complete root/descendant retirement trials");
}

fn cancellation_counterexample(trial: usize) {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("worker");
    let children = RefCell::new((None, None));
    let started = Instant::now();
    let result = run(
        fixture(),
        &directory,
        b"tree".to_vec(),
        Duration::from_secs(10),
        || {
            let mut children = children.borrow_mut();
            if children.0.is_none() {
                children.0 = observed(&directory.join("worker.json"));
            }
            if children.1.is_none() {
                children.1 = observed(&directory.join("descendant.json"));
            }
            children.0.is_some() && children.1.is_some()
        },
    );
    assert!(matches!(result, Err(Error::Cancelled)));
    assert!(started.elapsed() < Duration::from_secs(15));
    let children = children.borrow();
    assert_retired(
        children
            .0
            .as_ref()
            .expect("worker observed before cancellation"),
        &format!("cancellation trial {trial} worker"),
    );
    assert_retired(
        children
            .1
            .as_ref()
            .expect("descendant observed before cancellation"),
        &format!("cancellation trial {trial} descendant"),
    );
}

#[test]
fn cancellation_records_job_membership_and_native_process_signals() {
    use windows_sys::Win32::{
        Foundation::{FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{
            GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
        },
    };

    // The public run() counterexample above stays unchanged. Drive the same
    // owner methods here to inspect its Job before it is closed; this probe
    // distinguishes escape from a gap between Job accounting and signaling.
    for trial in 0..64 {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("worker");
        let assets = spawn_assets_for(
            fixture(),
            &directory,
            None,
            child::Program::PackageInspection,
        )
        .unwrap();
        let mut owner = OneShot {
            assets,
            io: None,
            assigned: false,
            closed: false,
        };
        let children = RefCell::new((None, None));
        let operation = owner.exchange(
            b"tree".to_vec(),
            Instant::now() + Duration::from_secs(10),
            &|| {
                let mut children = children.borrow_mut();
                if children.0.is_none() {
                    children.0 = observed(&directory.join("worker.json"));
                }
                if children.1.is_none() {
                    children.1 = observed(&directory.join("descendant.json"));
                }
                children.0.is_some() && children.1.is_some()
            },
        );
        let (worker, descendant) = children.into_inner();
        let before_active = active_processes(&owner.assets.job).unwrap();
        let witnesses = [
            ("worker", worker.unwrap()),
            ("descendant", descendant.unwrap()),
        ]
        .map(|(role, peer)| {
            peer.verify_executable(&owner.assets.executable).unwrap();
            // Retain this exact live fixture process. Termination access is
            // used only to clean a failed probe, after recording failure.
            let raw = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
                    0,
                    peer.process_id(),
                )
            };
            assert!(!raw.is_null(), "{}", std::io::Error::last_os_error());
            let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
            let mut times = [FILETIME::default(); 4];
            assert_ne!(
                unsafe {
                    GetProcessTimes(
                        handle.as_raw_handle(),
                        &mut times[0],
                        &mut times[1],
                        &mut times[2],
                        &mut times[3],
                    )
                },
                0,
                "{}",
                std::io::Error::last_os_error()
            );
            let created =
                u64::from(times[0].dwLowDateTime) | (u64::from(times[0].dwHighDateTime) << 32);
            assert_eq!(created, peer.identity().process_creation_time());
            owner
                .assets
                .executable
                .verify_process_image(&handle)
                .unwrap();
            let mut member = 0;
            assert_ne!(
                unsafe {
                    IsProcessInJob(
                        handle.as_raw_handle(),
                        owner.assets.job.as_raw_handle(),
                        &mut member,
                    )
                },
                0,
                "{}",
                std::io::Error::last_os_error()
            );
            (role, peer, handle, member != 0)
        });
        let retired = owner.retire(true);
        let after_active = active_processes(&owner.assets.job).unwrap();
        drop(owner);
        let mut samples = Vec::new();
        let mut all_signaled = true;
        for (role, peer, handle, member) in &witnesses {
            let wait = unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) };
            assert!(
                matches!(wait, WAIT_OBJECT_0 | WAIT_TIMEOUT),
                "{}",
                std::io::Error::last_os_error()
            );
            let mut exit = 0;
            assert_ne!(
                unsafe { GetExitCodeProcess(handle.as_raw_handle(), &mut exit) },
                0
            );
            all_signaled &= *member && wait == WAIT_OBJECT_0;
            samples.push(serde_json::json!({
                "role": role, "pid": peer.process_id(),
                "creation_filetime": peer.identity().process_creation_time(),
                "owned_job_member_before_cancel": member,
                "wait_after_retire": wait, "exit_code_after_retire": exit,
                "identity_revalidation": format!("{:?}", peer.revalidate())
            }));
        }
        let receipt = serde_json::json!({
            "document": "cfw-worker-job-retirement-probe-v1", "trial": trial,
            "job_active_before_cancel": before_active, "job_active_after_retire": after_active,
            "cleanup_returned_ok": retired.is_ok(), "processes": samples
        });
        println!("{receipt}");
        for (_, _, handle, _) in &witnesses {
            if wait_until(handle, Instant::now()).unwrap() != WaitOutcome::Signaled {
                assert_ne!(unsafe { TerminateProcess(handle.as_raw_handle(), 3) }, 0);
                assert_eq!(
                    wait_until(handle, Instant::now() + CLEANUP).unwrap(),
                    WaitOutcome::Signaled
                );
            }
        }
        assert!(matches!(operation, Err(Error::Cancelled)));
        assert!(
            retired.is_ok() && after_active == 0 && all_signaled,
            "{receipt}"
        );
    }
}

#[test]
fn precreation_cancellation_and_invalid_bounds_create_no_working_directory() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("worker");
    assert!(matches!(
        run(
            fixture(),
            &directory,
            b"okay".to_vec(),
            Duration::from_secs(1),
            || true
        ),
        Err(Error::Cancelled)
    ));
    for (request, timeout) in [
        (Vec::new(), Duration::from_secs(1)),
        (vec![0; MAX_REQUEST + 1], Duration::from_secs(1)),
        (b"okay".to_vec(), Duration::ZERO),
        (b"okay".to_vec(), Duration::from_secs(121)),
    ] {
        assert!(matches!(
            run(fixture(), &directory, request, timeout, || false),
            Err(Error::Protocol(_))
        ));
    }
    assert!(!directory.exists());
}
