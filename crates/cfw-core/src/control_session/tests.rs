use super::*;

fn fixture() -> &'static [u8] {
    br#"{
          "app_home":"/Users/bill/Library/Application Support/Clash for Mac",
          "config_file":"/Users/bill/Library/Application Support/Clash for Mac/config.yaml",
          "mixed_port":7900,
          "controller_port":9090,
          "secret":null,
          "want_core":true,
          "generation":7,
          "heartbeat_epoch_secs":1700000000
        }"#
}

#[test]
fn legacy_path_is_fixed_and_has_no_starting_api() {
    assert_eq!(
        LegacyControlSession::path(),
        PathBuf::from("/Library/Application Support/com.bill.clashformac/active-session.json")
    );
}

#[test]
fn old_helper_fixture_decodes_strictly() {
    let value: LegacyControlSessionValue =
        serde_json::from_slice(fixture()).expect("historical fixture");
    validate_value(&value).expect("valid old helper request");
    assert!(value.want_core);
    assert_eq!(value.mixed_port, 7900);

    let mut unknown: serde_json::Value = serde_json::from_slice(fixture()).expect("fixture value");
    unknown["binary"] = serde_json::json!("/tmp/attacker");
    assert!(
        serde_json::from_value::<LegacyControlSessionValue>(unknown).is_err(),
        "retirement decoder must never accept a binary field"
    );
}

#[test]
fn retirement_value_changes_only_want_core_and_heartbeat() {
    let original: LegacyControlSessionValue =
        serde_json::from_slice(fixture()).expect("fixture value");
    let mut stopped = original.clone();
    stopped.want_core = false;
    stopped.heartbeat_epoch_secs += 1;
    assert_eq!(stopped.app_home, original.app_home);
    assert_eq!(stopped.config_file, original.config_file);
    assert_eq!(stopped.mixed_port, original.mixed_port);
    assert_eq!(stopped.controller_port, original.controller_port);
    assert_eq!(stopped.secret, original.secret);
    assert_eq!(stopped.generation, original.generation);
}

/// A private session directory, removed with its contents at the end of the test.
struct SessionDirectoryFixture(PathBuf);

impl SessionDirectoryFixture {
    fn new(label: &str) -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "cfw-core-session-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("session directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private directory");
        Self(fs::canonicalize(&root).expect("canonical directory"))
    }

    fn file(&self) -> PathBuf {
        self.0.join(LEGACY_CONTROL_SESSION_FILE)
    }

    fn write(&self, bytes: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;

        fs::write(self.file(), bytes).expect("session file");
        fs::set_permissions(self.file(), fs::Permissions::from_mode(mode)).expect("session mode");
    }

    fn entries(&self) -> Vec<String> {
        let mut names = fs::read_dir(&self.0)
            .expect("list session directory")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        names.sort();
        names
    }
}

impl Drop for SessionDirectoryFixture {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700))
            .expect("writable directory");
        fs::remove_dir_all(&self.0).expect("remove session directory");
    }
}

fn session_with(edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(fixture()).expect("fixture value");
    edit(&mut value);
    serde_json::to_vec(&value).expect("session bytes")
}

fn unsafe_message(error: LegacyControlSessionError) -> String {
    match error {
        LegacyControlSessionError::Unsafe(message) => message,
        other => panic!("expected an unsafe-session error, got {other:?}"),
    }
}

#[test]
fn a_session_is_observed_with_every_field() {
    let directory = SessionDirectoryFixture::new("observe");
    directory.write(fixture(), 0o600);

    let observed = observe_in(&directory.0).expect("observed");
    assert_eq!(
        observed.app_home(),
        Path::new("/Users/bill/Library/Application Support/Clash for Mac")
    );
    assert_eq!(
        observed.config_file(),
        Path::new("/Users/bill/Library/Application Support/Clash for Mac/config.yaml")
    );
    assert_eq!(observed.mixed_port(), 7900);
    assert_eq!(observed.controller_port(), 9090);
    assert_eq!(observed.generation(), 7);
    assert_eq!(observed.heartbeat_epoch_secs(), 1_700_000_000);
    assert!(observed.wants_core());
    assert_eq!(observed.digest, <[u8; 32]>::from(Sha256::digest(fixture())));
}

#[test]
fn presence_is_reported_without_following_a_link_and_failures_are_errors() {
    let directory = SessionDirectoryFixture::new("exists");
    assert!(!session_exists(&directory.file()).expect("absent"));
    std::os::unix::fs::symlink(directory.0.join("missing"), directory.file()).expect("link");
    assert!(session_exists(&directory.file()).expect("a dangling link is present"));

    let below_file = directory.file().join("nested");
    fs::remove_file(directory.file()).expect("remove link");
    directory.write(fixture(), 0o600);
    assert!(matches!(
        session_exists(&below_file),
        Err(LegacyControlSessionError::Io(_))
    ));
}

#[test]
fn only_a_bounded_private_regular_file_of_this_user_is_read() {
    let directory = SessionDirectoryFixture::new("file");
    directory.write(fixture(), 0o620);
    assert_eq!(
        unsafe_message(observe_in(&directory.0).expect_err("group-writable")),
        "fixed session is not a bounded current-user regular file"
    );

    directory.write(b"", 0o600);
    assert_eq!(
        unsafe_message(observe_in(&directory.0).expect_err("empty")),
        "fixed session is not a bounded current-user regular file"
    );

    let oversized = vec![b' '; MAX_SESSION_BYTES as usize + 1];
    directory.write(&oversized, 0o600);
    assert_eq!(
        unsafe_message(observe_in(&directory.0).expect_err("oversized")),
        "fixed session is not a bounded current-user regular file"
    );

    directory.write(fixture(), 0o600);
    let second_link = directory.0.join("second-link.json");
    fs::hard_link(directory.file(), &second_link).expect("hard link");
    assert_eq!(
        unsafe_message(observe_in(&directory.0).expect_err("hard-linked")),
        "fixed session is not a bounded current-user regular file"
    );
    fs::remove_file(&second_link).expect("remove hard link");

    let target = directory.0.join("target.json");
    fs::rename(directory.file(), &target).expect("move the session aside");
    std::os::unix::fs::symlink(&target, directory.file()).expect("link to the session");
    assert!(matches!(
        observe_in(&directory.0).expect_err("a link is never followed"),
        LegacyControlSessionError::Io(_)
    ));
    fs::remove_file(directory.file()).expect("remove link");

    fs::create_dir(directory.file()).expect("a directory in its place");
    assert_eq!(
        unsafe_message(observe_in(&directory.0).expect_err("a directory")),
        "fixed session is not a bounded current-user regular file"
    );
}

#[test]
fn a_session_outside_the_historical_schema_is_refused() {
    let directory = SessionDirectoryFixture::new("schema");
    directory.write(b"{not json", 0o600);
    assert!(matches!(
        observe_in(&directory.0).expect_err("malformed"),
        LegacyControlSessionError::Codec(_)
    ));
    directory.write(
        &session_with(|value| value["binary"] = "/tmp/attacker".into()),
        0o600,
    );
    assert!(matches!(
        observe_in(&directory.0).expect_err("an unknown field"),
        LegacyControlSessionError::Codec(_)
    ));

    let edits: [fn(&mut serde_json::Value); 7] = [
        |value| value["app_home"] = "Library/Clash for Mac".into(),
        |value| value["config_file"] = "config.yaml".into(),
        |value| value["mixed_port"] = 0.into(),
        |value| value["controller_port"] = 0.into(),
        |value| value["generation"] = 0.into(),
        |value| value["heartbeat_epoch_secs"] = 0.into(),
        |value| value["secret"] = "s".repeat(16 * 1024 + 1).into(),
    ];
    for edit in edits {
        directory.write(&session_with(edit), 0o600);
        assert_eq!(
            unsafe_message(observe_in(&directory.0).expect_err("out of bounds")),
            "session fields are outside the historical schema bounds"
        );
    }
    directory.write(
        &session_with(|value| value["secret"] = "s".repeat(16 * 1024).into()),
        0o600,
    );
    observe_in(&directory.0).expect("the longest secret is accepted");
}

#[test]
fn only_this_users_real_directory_is_opened() {
    let directory = SessionDirectoryFixture::new("directory");
    let missing = directory.0.join("missing");
    assert!(matches!(
        observe_in(&missing).expect_err("missing"),
        LegacyControlSessionError::Io(error) if error.kind() == io::ErrorKind::NotFound
    ));

    let linked = directory.0.join("linked");
    std::os::unix::fs::symlink(&directory.0, &linked).expect("directory link");
    assert!(matches!(
        observe_in(&linked).expect_err("a linked directory"),
        LegacyControlSessionError::Io(_)
    ));

    directory.write(fixture(), 0o600);
    assert!(matches!(
        observe_in(&directory.file()).expect_err("a file is not a directory"),
        LegacyControlSessionError::Io(_)
    ));

    assert_eq!(
        unsafe_message(observe_in(Path::new("/tmp/session\0directory")).expect_err("NUL")),
        "fixed session path contains NUL"
    );
}

#[test]
fn stopping_rewrites_only_the_request_and_the_heartbeat() {
    let directory = SessionDirectoryFixture::new("stop");
    directory.write(
        &session_with(|value| value["secret"] = "s3cret".into()),
        0o600,
    );
    let observed = observe_in(&directory.0).expect("observed");

    let stopped = request_stop_in(&directory.0, &observed).expect("stopped");
    assert!(!stopped.wants_core());
    assert!(stopped.heartbeat_epoch_secs() > observed.heartbeat_epoch_secs());
    let mut expected = observed.value.clone();
    expected.want_core = false;
    expected.heartbeat_epoch_secs = stopped.heartbeat_epoch_secs();
    assert_eq!(stopped.value, expected);
    assert_eq!(stopped.value.secret.as_deref(), Some("s3cret"));

    assert_eq!(observe_in(&directory.0).expect("re-read"), stopped);
    assert_eq!(directory.entries(), [LEGACY_CONTROL_SESSION_FILE]);
    let mode = fs::metadata(directory.file()).expect("metadata").mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_session_changed_since_preparation_is_not_stopped() {
    let directory = SessionDirectoryFixture::new("changed");
    directory.write(fixture(), 0o600);
    let observed = observe_in(&directory.0).expect("observed");

    // The same value in other bytes is a change: the request is revalidated
    // byte for byte.
    let reformatted = session_with(|_| ());
    directory.write(&reformatted, 0o600);
    assert!(matches!(
        request_stop_in(&directory.0, &observed).expect_err("other bytes"),
        LegacyControlSessionError::Changed
    ));

    directory.write(&session_with(|value| value["generation"] = 8.into()), 0o600);
    assert!(matches!(
        request_stop_in(&directory.0, &observed).expect_err("another generation"),
        LegacyControlSessionError::Changed
    ));
    assert!(observe_in(&directory.0).expect("unchanged").wants_core());
}

#[test]
fn a_session_that_no_longer_requests_a_core_is_not_rewritten() {
    let directory = SessionDirectoryFixture::new("idle");
    let idle = session_with(|value| value["want_core"] = false.into());
    directory.write(&idle, 0o600);
    let observed = observe_in(&directory.0).expect("observed");
    assert_eq!(
        unsafe_message(request_stop_in(&directory.0, &observed).expect_err("no core")),
        "prepared session no longer requests a core"
    );
    assert_eq!(fs::read(directory.file()).expect("unchanged"), idle);
}

#[test]
fn a_failed_publication_leaves_no_temporary_file() {
    let directory = SessionDirectoryFixture::new("publish");
    fs::create_dir(directory.file()).expect("a directory in the session's place");
    fs::write(directory.file().join("occupied"), b"x").expect("occupy it");
    let session = SessionDirectory::open(&directory.0).expect("directory");
    assert!(matches!(
        session.write_atomic(fixture()),
        Err(LegacyControlSessionError::Io(_))
    ));
    assert_eq!(directory.entries(), [LEGACY_CONTROL_SESSION_FILE]);

    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o500)).expect("read-only");
    }
    assert!(matches!(
        session.write_atomic(fixture()),
        Err(LegacyControlSessionError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
    ));
}

#[test]
fn removal_tolerates_absence_and_reports_other_failures() {
    let directory = SessionDirectoryFixture::new("remove");
    remove_in(&directory.0.join("missing")).expect("no directory");
    remove_in(&directory.0).expect("no session");
    directory.write(fixture(), 0o600);
    remove_in(&directory.0).expect("removed");
    assert!(directory.entries().is_empty());

    directory.write(fixture(), 0o600);
    assert!(matches!(
        remove_in(&directory.file()).expect_err("a file is not a directory"),
        LegacyControlSessionError::Io(_)
    ));
    fs::remove_file(directory.file()).expect("remove the session");
    fs::create_dir(directory.file()).expect("a directory in the session's place");
    assert!(matches!(
        remove_in(&directory.0).expect_err("a directory is not unlinked"),
        LegacyControlSessionError::Io(_)
    ));
}

#[test]
fn the_debug_form_never_shows_the_secret() {
    let value: LegacyControlSessionValue =
        serde_json::from_slice(&session_with(|value| value["secret"] = "s3cret".into()))
            .expect("value");
    let rendered = format!("{value:?}");
    assert!(rendered.contains("[REDACTED]"), "{rendered}");
    assert!(!rendered.contains("s3cret"), "{rendered}");
    assert_eq!(
        LegacyControlSessionError::Changed.to_string(),
        "legacy control session changed after preparation"
    );
}
