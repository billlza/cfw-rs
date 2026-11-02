use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;

use super::*;
use crate::operating_system_version;

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "cfw-app-update-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("scratch directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private scratch");
        Self(fs::canonicalize(&root).expect("canonical scratch"))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove scratch directory");
    }
}

/// One ustar member with an arbitrary name, as a hostile archive would
/// carry it. The system `tar` refuses to create such names itself.
fn single_member_tar(name: &str, contents: &[u8]) -> Vec<u8> {
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", contents.len()).as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    let mut archive = header.to_vec();
    archive.extend_from_slice(contents);
    archive.resize(archive.len().div_ceil(512) * 512, 0);
    archive.extend_from_slice(&[0_u8; 1024]);
    archive
}

#[test]
fn extraction_restores_a_release_shaped_archive_without_recorded_ownership() {
    let scratch = Scratch::new("extract");
    let source = scratch.path("source");
    let bundle = source.join("Sample.app/Contents/MacOS");
    fs::create_dir_all(&bundle).expect("bundle layout");
    fs::write(bundle.join("sample"), b"#!/bin/sh\n").expect("executable");
    fs::set_permissions(bundle.join("sample"), fs::Permissions::from_mode(0o755))
        .expect("executable mode");
    std::os::unix::fs::symlink("MacOS/sample", source.join("Sample.app/Contents/Current"))
        .expect("relative symlink");
    let archive = scratch.path("sample.tar.gz");
    let packed = Command::new(TAR)
        .current_dir(&source)
        .env("COPYFILE_DISABLE", "1")
        .args(["-czf"])
        .arg(&archive)
        .args(["--no-xattrs", "--no-mac-metadata", "Sample.app"])
        .status()
        .expect("pack fixture");
    assert!(packed.success());

    let destination = scratch.path("stage");
    fs::create_dir(&destination).expect("destination");
    extract_update_archive(&archive, &destination).expect("extraction");

    let executable = destination.join("Sample.app/Contents/MacOS/sample");
    assert_eq!(fs::read(&executable).expect("contents"), b"#!/bin/sh\n");
    assert_eq!(
        fs::metadata(&executable)
            .expect("mode")
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        fs::read_link(destination.join("Sample.app/Contents/Current")).expect("symlink"),
        PathBuf::from("MacOS/sample")
    );
}

#[test]
fn extraction_refuses_members_that_leave_the_destination() {
    let scratch = Scratch::new("escape");
    let destination = scratch.path("stage");
    fs::create_dir(&destination).expect("destination");
    for name in ["../escaped", "nested/../../escaped"] {
        let archive = scratch.path("hostile.tar");
        fs::write(&archive, single_member_tar(name, b"escaped")).expect("hostile archive");
        let error = extract_update_archive(&archive, &destination)
            .expect_err("a traversing member must fail extraction");
        assert!(
            matches!(error, AppUpdateToolError::Rejected { tool, .. } if tool == "archive extraction"),
            "{name}: {error}"
        );
        assert!(
            !scratch.path("escaped").exists(),
            "{name} escaped the destination"
        );
    }
}

#[test]
fn extraction_keeps_an_absolute_member_inside_the_destination() {
    let scratch = Scratch::new("absolute");
    let destination = scratch.path("stage");
    fs::create_dir(&destination).expect("destination");
    let outside = PathBuf::from(format!("/tmp/cfw-absolute-member-{}", std::process::id()));
    let archive = scratch.path("absolute.tar");
    fs::write(
        &archive,
        single_member_tar(outside.to_str().expect("UTF-8 path"), b"member"),
    )
    .expect("archive with an absolute member");

    let extracted = extract_update_archive(&archive, &destination);
    let escaped = outside.exists();
    if escaped {
        fs::remove_file(&outside).expect("remove the escaped member");
    }
    assert!(!escaped, "an absolute member left the destination");
    extracted.expect("the member is extracted without its leading separator");
    assert_eq!(
        fs::read(destination.join(outside.strip_prefix("/").expect("absolute path")))
            .expect("member inside the destination"),
        b"member"
    );
}

#[test]
fn extraction_and_verification_refuse_noncanonical_paths() {
    for path in [
        "relative/archive.tar.gz",
        "/tmp/../etc/archive.tar.gz",
        "../archive.tar.gz",
    ] {
        assert!(matches!(
            extract_update_archive(Path::new(path), Path::new("/tmp")),
            Err(AppUpdateToolError::UnsafeArgument("update archive"))
        ));
        assert!(matches!(
            verify_update_application_signature(Path::new(path)),
            Err(AppUpdateToolError::UnsafeArgument(
                "staged application bundle"
            ))
        ));
    }
}

#[test]
fn signature_verification_rejects_validly_signed_code_of_another_identity() {
    // A system application has a valid signature and sealed resources but
    // is neither this product nor signed by its Developer ID.
    let foreign = Path::new("/System/Applications/Calculator.app");
    assert!(foreign.is_dir(), "fixture system application is missing");
    let error = verify_update_application_signature(foreign)
        .expect_err("a foreign identity must not satisfy the release requirement");
    assert!(
        matches!(error, AppUpdateToolError::Rejected { tool, .. } if tool == "code signature verification"),
        "{error}"
    );
}

#[test]
fn signature_verification_rejects_unsigned_bundles() {
    let scratch = Scratch::new("unsigned");
    let executable = scratch.path("Unsigned.app/Contents/MacOS");
    fs::create_dir_all(&executable).expect("bundle layout");
    fs::write(executable.join("unsigned"), b"not code").expect("payload");
    let error = verify_update_application_signature(&scratch.path("Unsigned.app"))
        .expect_err("an unsigned bundle must be rejected");
    assert!(
        matches!(error, AppUpdateToolError::Rejected { .. }),
        "{error}"
    );
}

#[test]
fn operating_system_version_is_a_dotted_decimal() {
    let version = operating_system_version().expect("system version");
    let parts = version.split('.').collect::<Vec<_>>();
    assert!((2..=3).contains(&parts.len()), "{version}");
    assert!(
        parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())),
        "{version}"
    );
}

#[test]
fn installed_host_invocation_refuses_unbounded_or_empty_arguments() {
    let long = "x".repeat(129);
    for arguments in [
        &[][..],
        &["a", "b", "c", "d", "e"][..],
        &[""][..],
        &[long.as_str()][..],
    ] {
        assert!(matches!(
            run_installed_host(arguments, Duration::from_secs(1)),
            Err(AppUpdateToolError::UnsafeArgument(
                "installed Host arguments"
            ))
        ));
    }
}

#[test]
fn the_host_is_given_exactly_the_variables_that_identify_the_user() {
    let ambient = |name: &str| match name {
        "HOME" | "LOGNAME" | "USER" | "PATH" | "DYLD_INSERT_LIBRARIES" => {
            Some(std::ffi::OsString::from(format!("value-of-{name}")))
        }
        _ => None,
    };
    assert_eq!(
        host_user_environment(ambient),
        [
            ("HOME", "value-of-HOME".into()),
            ("LOGNAME", "value-of-LOGNAME".into()),
            ("USER", "value-of-USER".into()),
        ]
    );
    // What this process does not have is not invented for the Host.
    assert_eq!(
        host_user_environment(|name| match name {
            "HOME" => Some("/Users/example".into()),
            "USER" => Some(std::ffi::OsString::new()),
            _ => None,
        }),
        [("HOME", "/Users/example".into())]
    );
}

#[test]
fn each_tool_error_names_its_tool_and_cause() {
    assert_eq!(
        AppUpdateToolError::UnsafeArgument("update archive").to_string(),
        "update archive is outside the accepted argument form"
    );
    assert_eq!(
        AppUpdateToolError::Unavailable {
            tool: "archive extraction",
            detail: "timed out".into(),
        }
        .to_string(),
        "archive extraction could not complete: timed out"
    );
    assert_eq!(
        AppUpdateToolError::Rejected {
            tool: "installed Host",
            status: Some(2),
            diagnostic: "unknown mode".into(),
        }
        .to_string(),
        "installed Host reported failure (status Some(2)): unknown mode"
    );
}

#[test]
fn a_tool_path_must_be_absolute_text_without_a_nul() {
    use std::os::unix::ffi::OsStrExt as _;

    assert_eq!(
        canonical_argument(Path::new("/tmp/archive.tar.gz"), "update archive").expect("canonical"),
        "/tmp/archive.tar.gz"
    );
    for path in [
        Path::new(std::ffi::OsStr::from_bytes(b"/tmp/\xff.tar.gz")),
        Path::new("/tmp/archive\0.tar.gz"),
    ] {
        assert!(matches!(
            canonical_argument(path, "update archive"),
            Err(AppUpdateToolError::UnsafeArgument("update archive"))
        ));
    }
}

#[test]
fn the_host_runs_with_its_arguments_and_returns_its_output() {
    let output = run_host_at("/bin/echo", &["--mode", "status"], Duration::from_secs(5))
        .expect("host output");
    assert_eq!(output.stdout, "--mode status\n");
}

#[test]
fn the_host_sees_only_the_closed_defaults_and_the_user_identity() {
    let output = run_host_at(
        "/usr/bin/env",
        &["-u", "CFW_COVERAGE_UNSET"],
        Duration::from_secs(5),
    )
    .expect("environment listing");
    let mut names = output
        .stdout
        .lines()
        .map(|line| line.split_once('=').expect("NAME=value").0.to_owned())
        .collect::<Vec<_>>();
    names.sort();
    let mut expected = HOST_USER_ENVIRONMENT
        .into_iter()
        .filter(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
        .chain(["LANG", "LC_ALL", "PATH"])
        .map(str::to_owned)
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(names, expected);
}

#[test]
fn a_failing_unreadable_or_missing_host_is_reported() {
    let error = run_host_at("/usr/bin/false", &["status"], Duration::from_secs(5))
        .expect_err("a failing host");
    assert!(
        matches!(
            error,
            AppUpdateToolError::Rejected {
                tool: "installed Host",
                status: Some(1),
                ..
            }
        ),
        "{error}"
    );
    let error = run_host_at("/usr/bin/printf", &["\\377"], Duration::from_secs(5))
        .expect_err("non-UTF-8 output");
    assert_eq!(
        error.to_string(),
        "installed Host could not complete: standard output is not UTF-8"
    );
    let error = run_host_at(
        "/nonexistent/clash-for-mac",
        &["status"],
        Duration::from_secs(5),
    )
    .expect_err("a missing host");
    assert!(
        matches!(
            error,
            AppUpdateToolError::Unavailable {
                tool: "installed Host",
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn launching_a_missing_application_is_rejected_without_opening_anything() {
    let error = open_application_at("/nonexistent/Clash for Mac.app").expect_err("nothing to open");
    assert!(
        matches!(
            error,
            AppUpdateToolError::Rejected {
                tool: "application launch",
                status: Some(1),
                ..
            }
        ),
        "{error}"
    );
}
