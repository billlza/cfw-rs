//! The built descriptor target refuses to run, as launchd or a person would
//! start it: no output, a fixed diagnostic and a configuration-error exit.

use std::process::Command;

#[test]
fn running_the_descriptor_refuses_with_its_fixed_diagnostic() {
    let output = Command::new(env!("CARGO_BIN_EXE_cfw-helper-tombstone"))
        .arg("--any-argument")
        .output()
        .expect("run the tombstone");
    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("UTF-8 diagnostic"),
        "legacy Service Mode is retired; this non-operational descriptor cannot modify networking\n"
    );
}
