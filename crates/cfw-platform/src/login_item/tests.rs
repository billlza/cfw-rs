use std::os::unix::fs::symlink;

use super::*;

fn test_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cfw-platform-login-{name}-{}", std::process::id()))
}

#[test]
fn fixed_file_cleanup_unlinks_symlink_without_following_it() {
    let root = test_root("symlink");
    let target = root.join("target");
    let link = root.join("legacy.plist");
    fs::create_dir_all(&root).expect("create root");
    fs::write(&target, b"keep").expect("write target");
    symlink(&target, &link).expect("create symlink");

    remove_fixed_file_if_present(&link).expect("remove link");

    assert_eq!(fs::read(&target).expect("read target"), b"keep");
    fs::remove_file(target).expect("remove target");
    fs::remove_dir(root).expect("remove root");
}

#[test]
fn fixed_file_cleanup_rejects_directories() {
    let root = test_root("directory");
    fs::create_dir_all(&root).expect("create root");
    let error = remove_fixed_file_if_present(&root).expect_err("directory must be rejected");
    assert!(error.to_string().contains("non-file"));
    fs::remove_dir(root).expect("remove root");
}

/// A scratch directory removed at the end of the test, whatever its modes.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let root = test_root(name);
        fs::create_dir_all(&root).expect("create root");
        Self(root)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700)).expect("writable root");
        fs::remove_dir_all(&self.0).expect("remove root");
    }
}

#[test]
fn the_legacy_login_agent_lives_under_the_user_launch_agents() {
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    assert_eq!(
        legacy_login_agent_path().expect("path"),
        home.join("Library/LaunchAgents/com.bill.clashformac.plist")
    );
}

#[test]
fn only_a_file_or_symlink_is_a_login_agent_left_to_retire() {
    let scratch = Scratch::new("present");
    let file = scratch.0.join("file.plist");
    fs::write(&file, b"plist").expect("file");
    let link = scratch.0.join("link.plist");
    symlink(scratch.0.join("missing"), &link).expect("dangling symlink");

    assert!(!legacy_login_agent_present(&scratch.0.join("absent.plist")).expect("absent"));
    assert!(legacy_login_agent_present(&file).expect("file"));
    assert!(legacy_login_agent_present(&link).expect("symlink"));

    let error = legacy_login_agent_present(&scratch.0).expect_err("a directory");
    assert_eq!(
        error.to_string(),
        format!(
            "refusing to retire non-file legacy Login Item path: {}",
            scratch.0.display()
        )
    );
    let below_file = file.join("nested.plist");
    let error = legacy_login_agent_present(&below_file).expect_err("not a directory");
    assert_eq!(
        error.to_string(),
        format!("failed to inspect {}", below_file.display())
    );
}

#[test]
fn fixed_file_cleanup_removes_a_file_and_tolerates_its_absence() {
    let scratch = Scratch::new("remove");
    let file = scratch.0.join("legacy.plist");
    fs::write(&file, b"plist").expect("file");

    remove_fixed_file_if_present(&file).expect("removed");
    assert!(!file.exists());
    remove_fixed_file_if_present(&file).expect("already absent");
    ensure_path_absent(&file).expect("absent");
}

#[test]
fn fixed_file_cleanup_reports_what_it_cannot_inspect_or_remove() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = Scratch::new("refused");
    let file = scratch.0.join("legacy.plist");
    fs::write(&file, b"plist").expect("file");

    let below_file = file.join("nested.plist");
    let error = remove_fixed_file_if_present(&below_file).expect_err("not a directory");
    assert_eq!(
        error.to_string(),
        format!("failed to inspect {}", below_file.display())
    );

    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o500)).expect("read-only root");
    let error = remove_fixed_file_if_present(&file).expect_err("a read-only directory");
    assert_eq!(
        error.to_string(),
        format!("failed to remove {}", file.display())
    );
}

#[test]
fn a_remaining_or_uninspectable_path_is_not_absent() {
    let scratch = Scratch::new("absent");
    let file = scratch.0.join("legacy.plist");
    fs::write(&file, b"plist").expect("file");

    let error = ensure_path_absent(&file).expect_err("still present");
    assert_eq!(
        error.to_string(),
        format!(
            "legacy launchd path remains after retirement: {}",
            file.display()
        )
    );
    let below_file = file.join("nested.plist");
    let error = ensure_path_absent(&below_file).expect_err("not a directory");
    assert_eq!(
        error.to_string(),
        format!("failed to verify {}", below_file.display())
    );
}
