use super::*;
use crate::test_support::{
    assert_private_file, create_private_directory, remove_directory_link, symlink, write_private,
};

static TEST_DIRECTORY_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "cfm-diagnostic-test-{}-{}-{}",
        TEST_DIRECTORY_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_private_directory(&path);
    path
}

#[test]
fn journal_survives_reopen_bounds_retention_and_preserves_errors() {
    let root = directory();
    let entries = (0..150)
        .map(|i| {
            DiagnosticEntry::new(
                "request_error",
                &format!("attempt {i}: context deadline exceeded"),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    DiagnosticJournal::new(&root)
        .append(DiagnosticTopic::Network, &entries)
        .unwrap();
    DiagnosticJournal::new(&root)
        .append(
            DiagnosticTopic::Network,
            &[DiagnosticEntry::new("request_error", "peer EOF").unwrap()],
        )
        .unwrap();
    let path = root.join("diagnostics/network-errors.json");
    let read: Vec<DiagnosticEntry> =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(read.len(), MAX_RECORDS);
    assert!(read[0].message.starts_with("attempt 23:"));
    assert_eq!(read.last().unwrap().message, "peer EOF");
    assert_private_file(&path);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn corruption_and_symlinks_fail_without_replacing_evidence() {
    let root = directory();
    let log = root.join("diagnostics");
    create_private_directory(&log);
    let path = log.join("startup.json");
    write_private(&path, "not json");
    let entry = DiagnosticEntry::new("ready", "ready").unwrap();
    assert!(
        DiagnosticJournal::new(&root)
            .append(DiagnosticTopic::Startup, std::slice::from_ref(&entry))
            .is_err()
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "not json");
    std::fs::remove_file(&path).unwrap();
    let external = root.join("external");
    std::fs::write(&external, "untouched").unwrap();
    symlink(&external, &path).unwrap();
    assert!(
        DiagnosticJournal::new(&root)
            .append(DiagnosticTopic::Startup, &[entry])
            .is_err()
    );
    assert_eq!(std::fs::read_to_string(external).unwrap(), "untouched");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn credentials_are_redacted_without_losing_failure_stage() {
    for text in [
        "read tcp: EOF token=do-not-store",
        "Authorization: Bearer do-not-store",
        r#"{"password": "do-not-store with spaces"} context deadline exceeded"#,
        "socks://name:do-not-store@example.com:1080 setup failed",
        "https://example.com/path?custom=do-not-store reset",
        "日本 Password = 'do-not-store' EOF",
    ] {
        let redacted = redact_diagnostic_text(text);
        assert!(!redacted.contains("do-not-store"), "{redacted}");
    }
    assert_eq!(
        redact_diagnostic_text("[123 5.0s] read tcp: context deadline exceeded; EOF"),
        "[123 5.0s] read tcp: context deadline exceeded; EOF"
    );
}

#[test]
fn concurrent_writers_do_not_lose_entries_and_warnings_do_not_evict_errors() {
    let root = directory();
    let workers = (0..2)
        .map(|worker| {
            let root = root.clone();
            std::thread::spawn(move || {
                for index in 0..12 {
                    DiagnosticJournal::new(&root)
                        .append(
                            DiagnosticTopic::Network,
                            &[
                                DiagnosticEntry::new("request_error", &format!("{worker}:{index}"))
                                    .unwrap(),
                            ],
                        )
                        .unwrap();
                }
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().unwrap();
    }
    let warnings = (0..150)
        .map(|_| DiagnosticEntry::new("request_warning", "unsupported ICMP").unwrap())
        .collect::<Vec<_>>();
    DiagnosticJournal::new(&root)
        .append(DiagnosticTopic::NetworkWarnings, &warnings)
        .unwrap();
    let errors: Vec<DiagnosticEntry> = serde_json::from_slice(
        &std::fs::read(root.join("diagnostics/network-errors.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(errors.len(), 24);
    assert_eq!(
        errors
            .iter()
            .map(|e| &e.message)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        24
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unicode_retention_obeys_byte_limit_and_a_redirected_parent_is_rejected() {
    let root = directory();
    let entry = DiagnosticEntry::new("request_error", &"🧭".repeat(2048)).unwrap();
    DiagnosticJournal::new(&root)
        .append(DiagnosticTopic::Network, &vec![entry; 128])
        .unwrap();
    let bytes = std::fs::read(root.join("diagnostics/network-errors.json")).unwrap();
    assert!(bytes.len() <= MAX_FILE_BYTES);
    let parsed: Vec<DiagnosticEntry> = serde_json::from_slice(&bytes).unwrap();
    assert!(!parsed.is_empty());
    let redirected = root.with_extension("link");
    symlink(&root, &redirected).unwrap();
    assert!(
        DiagnosticJournal::new(&redirected)
            .append(
                DiagnosticTopic::Startup,
                &[DiagnosticEntry::new("ready", "").unwrap()]
            )
            .is_err()
    );
    remove_directory_link(&redirected);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_entry_code_is_bounded_lowercase_snake_text() {
    DiagnosticEntry::new("update_check_2", "ok").expect("a valid code");
    DiagnosticEntry::new(&"c".repeat(64), "ok").expect("the longest code");
    for code in [
        "",
        "Update",
        "update-check",
        "update check",
        &"c".repeat(65),
    ] {
        assert!(
            matches!(
                DiagnosticEntry::new(code, "message"),
                Err(SettingsStoreError::InvalidPath)
            ),
            "{code:?}"
        );
    }
}

#[test]
fn an_empty_batch_writes_nothing_and_each_topic_has_its_own_journal() {
    let root = directory();
    DiagnosticJournal::new(&root)
        .append(DiagnosticTopic::Update, &[])
        .unwrap();
    assert!(!root.join("diagnostics").exists());

    for topic in [
        DiagnosticTopic::Startup,
        DiagnosticTopic::Network,
        DiagnosticTopic::NetworkWarnings,
        DiagnosticTopic::Update,
    ] {
        DiagnosticJournal::new(&root)
            .append(topic, &[DiagnosticEntry::new("probe", "written").unwrap()])
            .unwrap();
    }
    let mut journals = std::fs::read_dir(root.join("diagnostics"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    journals.sort();
    assert_eq!(
        journals,
        [
            "network-errors.json",
            "network-warnings.json",
            "startup.json",
            "update.json"
        ]
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_journal_holding_an_invalid_code_is_not_extended() {
    let root = directory();
    let mut stored = DiagnosticEntry::new("probe", "earlier").unwrap();
    stored.code = "Not-Valid".into();
    let journal = root.join("diagnostics/update.json");
    create_private_directory(&root.join("diagnostics"));
    let bytes = serde_json::to_vec_pretty(&[stored]).unwrap();
    write_private(&journal, &bytes);
    assert!(matches!(
        DiagnosticJournal::new(&root).append(
            DiagnosticTopic::Update,
            &[DiagnosticEntry::new("probe", "later").unwrap()]
        ),
        Err(SettingsStoreError::InvalidPath)
    ));
    assert_eq!(std::fs::read(&journal).unwrap(), bytes);
    std::fs::remove_dir_all(root).unwrap();
}
