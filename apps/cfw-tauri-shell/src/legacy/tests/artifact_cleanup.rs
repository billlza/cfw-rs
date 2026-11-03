//! The legacy runtime's processes, listeners and files that a cutover
//! removes: parsing them exactly, and removing paths without following links.

use super::*;

#[test]
fn process_parser_only_accepts_fixed_managed_core_paths() {
    let cores_dir =
        std::path::Path::new("/Users/test/Library/Application Support/Clash for Mac/cores");
    assert_eq!(
        parse_managed_process(
            "0 42 Tue Jul 22 10:11:12 2026 /Users/test/Library/Application Support/Clash for Mac/cores/mihomo -d x",
            cores_dir
        )
        .expect("parse fixed identity"),
        Some(ProcessRecord {
            uid: 0,
            pid: 42,
            start_identity: "Tue Jul 22 10:11:12 2026".into(),
            executable: cores_dir.join("mihomo"),
            command: "/Users/test/Library/Application Support/Clash for Mac/cores/mihomo -d x"
                .into(),
        })
    );
    assert_eq!(
        parse_managed_process(
            "0 42 Tue Jul 22 10:11:12 2026 /tmp/mihomo --config /Users/test/Library/Application Support/Clash for Mac/cores/config.yaml",
            cores_dir
        )
        .expect("unrelated process"),
        None
    );
    assert!(parse_managed_process("root 42 malformed", cores_dir).is_err());
}

#[test]
fn core_ownership_requires_one_root_identity_with_exact_arguments() {
    let app_home = std::path::Path::new("/Users/test/Library/Application Support/Clash for Mac");
    let config = app_home.join("config.yaml");
    let executable = app_home.join("cores/clash-darwin");
    let root = ProcessRecord {
        uid: 0,
        pid: 42,
        start_identity: "Tue Jul 22 10:11:12 2026".into(),
        command: format!(
            "{} -d {} -f {}",
            executable.display(),
            app_home.display(),
            config.display()
        ),
        executable,
    };
    assert_eq!(
        validate_unique_root_managed_process(std::slice::from_ref(&root), app_home, &config)
            .expect("unique root"),
        root
    );

    let mut non_root = root.clone();
    non_root.uid = 501;
    assert!(validate_unique_root_managed_process(&[non_root], app_home, &config).is_err());
    assert!(
        validate_unique_root_managed_process(&[root.clone(), root.clone()], app_home, &config)
            .is_err()
    );
    let mut reused = root;
    reused.command.push_str(" --unexpected");
    assert!(validate_unique_root_managed_process(&[reused], app_home, &config).is_err());
}

#[test]
fn netstat_listener_parser_requires_exact_loopback_rows() {
    let fixture = r#"tcp4 0 0 127.0.0.1.7900 *.* LISTEN 0 0 131072 131072 clash-darwin:67262 00180
tcp4 0 0 *.7900 *.* LISTEN 0 0 131072 131072 attacker:9 00180
tcp4 0 0 127.0.0.1.7901 *.* LISTEN 0 0 131072 131072 other:8 00180
tcp4 0 0 127.0.0.1.7900 127.0.0.1.50000 ESTABLISHED 0 0 1 1 clash-darwin:67262 00180"#;
    assert_eq!(
        parse_loopback_listener_owners(fixture, 7900).expect("owners"),
        ["clash-darwin:67262"]
    );
    let duplicate =
        format!("{fixture}\ntcp4 0 0 127.0.0.1.7900 *.* LISTEN 0 0 131072 131072 attacker:9 00180");
    assert_eq!(
        parse_loopback_listener_owners(&duplicate, 7900).expect("duplicates"),
        ["clash-darwin:67262", "attacker:9"]
    );
}

#[test]
fn managed_cleanup_unlinks_a_symlink_without_touching_target() {
    let root = std::env::temp_dir().join(format!(
        "cfw-managed-cleanup-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let target = root.join("target");
    let link = root.join("managed-link");
    fs::create_dir_all(&target).expect("create target");
    fs::write(target.join("sentinel"), b"keep").expect("write sentinel");
    symlink(&target, &link).expect("create symlink");
    remove_managed_path(&link).expect("unlink managed symlink");
    assert_eq!(fs::read(target.join("sentinel")).expect("read"), b"keep");
    fs::remove_dir_all(root).expect("remove root");
}

#[test]
fn legacy_profile_cleanup_cannot_delete_staged_native_profiles() {
    let root = std::env::temp_dir().join(format!(
        "cfw-profile-cutover-isolation-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let paths = AppPaths::from_app_home(root.join("app"));
    fs::create_dir_all(&paths.legacy_profiles_dir).expect("create legacy profiles");
    fs::create_dir_all(&paths.profiles_dir).expect("create staged profiles");
    fs::write(paths.legacy_profiles_dir.join("legacy.yaml"), b"legacy").expect("legacy");
    let staged = paths.profiles_dir.join("staged-sentinel");
    fs::write(&staged, b"keep staged replacement").expect("staged");
    ProfileRepository::new(paths.legacy_profiles_dir.clone())
        .clear_managed_profiles()
        .expect("clear legacy only");
    remove_managed_path(&paths.legacy_profiles_dir).expect("remove legacy dir");
    assert_eq!(
        fs::read(&staged).expect("read staged"),
        b"keep staged replacement"
    );
    fs::remove_dir_all(root).expect("remove root");
}

#[test]
fn broken_symlink_is_not_treated_as_an_absent_privileged_artifact() {
    let root = std::env::temp_dir().join(format!(
        "cfw-privileged-absence-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    fs::create_dir_all(&root).expect("root");
    let link = root.join("retired-helper");
    symlink(root.join("missing-target"), &link).expect("link");
    assert!(
        require_path_absent(&link, "legacy privileged helper")
            .expect_err("broken link remains")
            .contains("remains")
    );
    fs::remove_file(link).expect("remove link");
    fs::remove_dir(root).expect("remove root");
}
