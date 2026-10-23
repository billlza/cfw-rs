#![cfg(windows)]
#[path = "../src/updater/install_lease.rs"]
mod install_lease;
#[path = "../src/updater/windows_update/journal.rs"]
mod journal;
#[path = "../src/private_store.rs"]
mod private_store;
#[path = "../src/process_identity.rs"]
mod process_identity;

#[test]
fn update_lease_excludes_a_second_owner_and_process_claims_are_reobserved() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().join("private");
    let first = install_lease::UpdateInstallLease::acquire(&home).unwrap();
    assert!(matches!(
        install_lease::UpdateInstallLease::acquire(&home),
        Err(install_lease::UpdateInstallLeaseError::Held)
    ));
    drop(first);
    let _next = install_lease::UpdateInstallLease::acquire(&home).unwrap();
    let executable = std::env::current_exe().unwrap();
    let current = process_identity::current_process_identity(&executable).unwrap();
    assert!(current.is_this_process());
    assert!(process_identity::process_identity_exists(&current).unwrap());
    assert_eq!(
        process_identity::process_identity(std::process::id(), &executable).unwrap(),
        current
    );
    assert!(
        process_identity::exact_processes(&executable)
            .unwrap()
            .contains(&current)
    );
}
