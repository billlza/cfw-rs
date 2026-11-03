//! The durable launcher tickets: a replay after the store restarts, an
//! interrupted pending ticket, and an expired ticket swept before its session
//! is reused.

use super::*;

#[test]
fn durable_launcher_ticket_rejects_replay_after_store_restart() {
    let now = 1_700_000_000_000;
    let session_id = "7".repeat(64);
    let (proxy, _dashboard) = UnixStream::pair().expect("identity pair");
    let peer = validate_connected_unix_stream(proxy.as_raw_fd()).expect("proxy identity");
    let binding = app_ticket_request(now, peer, &session_id).binding;
    let root = tempdir().expect("ticket root");
    {
        let store = ticket_store(root.path());
        store
            .consume(&binding, &"8".repeat(64), now)
            .expect("first durable consumption");
    }
    let restarted = LauncherTicketStore::open(root.path()).expect("restarted ticket store");
    assert!(matches!(
        restarted.consume(&binding, &"9".repeat(64), now + 1),
        Err(PacketEvidenceTransportError::LauncherTicketReplayed)
    ));
    let records = fs::read_dir(root.path().join(LAUNCHER_TICKET_DIRECTORY))
        .expect("ticket records")
        .collect::<Result<Vec<_>, _>>()
        .expect("ticket entries");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].file_name(),
        OsString::from(format!("consumed-{session_id}.json"))
    );
}

#[test]
fn zero_byte_pending_ticket_is_swept_without_poisoning_store() {
    let now = 1_700_000_000_000;
    let (proxy, _dashboard) = UnixStream::pair().expect("identity pair");
    let peer = validate_connected_unix_stream(proxy.as_raw_fd()).expect("proxy identity");
    let root = tempdir().expect("ticket root");
    let store = ticket_store(root.path());
    let pending_id = "a".repeat(64);
    let pending_name = launcher_ticket_pending_filename(&pending_id).expect("pending name");
    let descriptor = unsafe {
        libc::openat(
            store.directory.as_raw_fd(),
            pending_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    assert_ne!(descriptor, -1, "create interrupted pending ticket");
    drop(unsafe { File::from_raw_fd(descriptor) });

    let binding = app_ticket_request(now, peer, &"b".repeat(64)).binding;
    store
        .consume(&binding, &"c".repeat(64), now)
        .expect("pending sweep followed by durable consumption");
    let names = fs::read_dir(root.path().join(LAUNCHER_TICKET_DIRECTORY))
        .expect("ticket records")
        .map(|entry| entry.expect("ticket entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![OsString::from(format!("consumed-{}.json", "b".repeat(64)))]
    );
}

#[test]
fn expired_launcher_ticket_is_durably_swept_before_session_reuse() {
    let now = 1_700_000_000_000;
    let later = now + SESSION_LIFETIME_MS + SESSION_CLOCK_SKEW_MS + 1;
    let session_id = "d".repeat(64);
    let (proxy, _dashboard) = UnixStream::pair().expect("identity pair");
    let peer = validate_connected_unix_stream(proxy.as_raw_fd()).expect("proxy identity");
    let root = tempdir().expect("ticket root");
    let store = ticket_store(root.path());
    let first = app_ticket_request(now, peer, &session_id).binding;
    store
        .consume(&first, &"e".repeat(64), now)
        .expect("first durable ticket");
    let renewed = app_ticket_request(later, peer, &session_id).binding;
    store
        .consume(&renewed, &"f".repeat(64), later)
        .expect("expired tombstone swept before renewed session");
    let name = format!("consumed-{session_id}.json");
    let _lock = store.lock().expect("ticket read lock");
    let record = store
        .read_record_locked(&name)
        .expect("renewed durable ticket");
    assert_eq!(record.binding.issued_at_unix_ms, later);
    assert_eq!(record.ticket_id, "f".repeat(64));
}
