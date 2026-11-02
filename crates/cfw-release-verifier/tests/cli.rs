//! The built verifier as the release tooling runs it: the receipt on standard
//! output and a non-zero exit with a diagnostic on standard error.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

#[path = "../src/fixture.rs"]
mod fixture;

/// A private staging directory with a configuration, the archive and its
/// signature, removed at the end of the test.
struct Staging(PathBuf);

impl Staging {
    fn new(label: &str) -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!(
            "cfw-release-verifier-cli-{label}-{}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("staging directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private");
        let config = format!(
            r#"{{"plugins":{{"updater":{{"pubkey":"{}"}}}}}}"#,
            fixture::PUBLIC_KEY
        );
        fs::write(root.join("tauri.conf.json"), config).expect("configuration");
        fs::write(root.join(fixture::ARCHIVE_NAME), fixture::ARCHIVE).expect("archive");
        fs::write(
            root.join(format!("{}.sig", fixture::ARCHIVE_NAME)),
            fixture::SIGNATURE,
        )
        .expect("signature");
        Self(root)
    }

    fn verify(&self, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_cfw-release-verifier"))
            .arg(self.0.join("tauri.conf.json"))
            .arg(self.0.join(fixture::ARCHIVE_NAME))
            .arg(self.0.join(format!("{}.sig", fixture::ARCHIVE_NAME)))
            .args(extra)
            .output()
            .expect("run the verifier")
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove staging directory");
    }
}

#[test]
fn a_verified_archive_prints_its_receipt_only_when_asked() {
    let staging = Staging::new("receipt");
    let quiet = staging.verify(&[]);
    assert!(quiet.status.success(), "{quiet:?}");
    assert!(
        quiet.stdout.is_empty() && quiet.stderr.is_empty(),
        "{quiet:?}"
    );

    let receipt = staging.verify(&["--json"]);
    assert!(receipt.status.success(), "{receipt:?}");
    assert!(receipt.stderr.is_empty(), "{receipt:?}");
    let stdout = String::from_utf8(receipt.stdout).expect("UTF-8 receipt");
    assert_eq!(stdout.matches('\n').count(), 1, "one line: {stdout}");
    assert!(stdout.contains(r#""result":"verified""#), "{stdout}");
    assert!(
        stdout.contains(&format!(
            r#""archive_filename":"{}""#,
            fixture::ARCHIVE_NAME
        )),
        "{stdout}"
    );
}

#[test]
fn a_refused_archive_exits_non_zero_with_a_diagnostic() {
    let staging = Staging::new("refused");
    fs::write(staging.0.join(fixture::ARCHIVE_NAME), b"altered").expect("tamper");
    let refused = staging.verify(&["--json"]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(refused.stdout.is_empty(), "{refused:?}");
    let stderr = String::from_utf8(refused.stderr).expect("UTF-8 diagnostic");
    assert!(
        stderr.starts_with("error: updater signature does not match the embedded public key: "),
        "{stderr}"
    );

    let usage = Command::new(env!("CARGO_BIN_EXE_cfw-release-verifier"))
        .output()
        .expect("run the verifier");
    assert_eq!(usage.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(usage.stderr).expect("UTF-8 diagnostic"),
        "error: usage: cfw-release-verifier <tauri.conf.json> <archive> <archive.sig> [--json]\n"
    );
}
