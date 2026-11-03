//! The control socket endpoint: its guard unlinks only its own inode, the
//! listener registers from Tauri's synchronous setup, and a failed cleanup
//! stays typed for the next startup.

use super::*;

#[test]
fn endpoint_guard_unlinks_only_the_exact_bound_socket_inode() {
    let root = tempdir().expect("root");
    let path = root.path().join("control.sock");
    let listener = UnixListener::bind(&path).expect("listener");
    let metadata = fs::symlink_metadata(&path).expect("metadata");
    let guard = ControlSocketGuard {
        identity: SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        path: path.clone(),
    };
    drop(listener);
    fs::remove_file(&path).expect("remove original");
    let replacement = UnixListener::bind(&path).expect("replacement");
    drop(guard);
    assert!(path.exists(), "a replacement inode must never be unlinked");
    drop(replacement);
}

#[test]
fn endpoint_guard_unlinks_its_own_socket_on_clean_shutdown() {
    let root = tempdir().expect("root");
    let path = root.path().join("control.sock");
    let listener = UnixListener::bind(&path).expect("listener");
    let metadata = fs::symlink_metadata(&path).expect("metadata");
    let guard = ControlSocketGuard {
        identity: SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        path: path.clone(),
    };
    drop(listener);
    drop(guard);
    assert!(!path.exists(), "the exact endpoint inode must be unlinked");
}

#[test]
fn synchronous_setup_registers_control_listener_inside_tauri_runtime() {
    assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "the regression requires a setup-equivalent thread without a Tokio reactor"
    );
    let root = tempdir().expect("root");
    let path = root.path().join("control.sock");
    let listener = UnixListener::bind(&path).expect("listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");

    let listener = register_control_endpoint(listener)
        .expect("Tauri runtime registration outside a current reactor");
    let client = UnixStream::connect(&path).expect("queued client");
    let accepted = tauri::async_runtime::block_on(async {
        tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("bounded accept")
            .expect("accepted client")
    });

    drop(accepted);
    drop(client);
}

#[test]
fn endpoint_cleanup_failure_remains_typed_for_the_next_startup() {
    let root = tempdir().expect("root");
    let path = root.path().join("control.sock");
    let listener = UnixListener::bind(&path).expect("listener");
    let metadata = fs::symlink_metadata(&path).expect("metadata");
    let stale = SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };

    let result = remove_stale_control_socket_with(&path, stale, |_| {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected exact-inode unlink failure",
        ))
    });

    assert!(matches!(
        result,
        Err(PacketEvidenceTransportError::EndpointCleanupFailed)
    ));
    assert!(
        path.exists(),
        "failed cleanup must retain the exact inode for startup diagnosis"
    );
    drop(listener);
    fs::remove_file(path).expect("remove test socket");
}
