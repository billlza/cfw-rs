//! A repository that does not exist yet: every read finds it empty, and no
//! read or removal creates it.

use std::fs;

use cfw_profiles::{InvalidSelection, ProfileError};
use uuid::Uuid;

use crate::support::{profile, repository};

#[test]
fn an_absent_repository_reads_as_empty_and_is_never_created() {
    let (root, repository) = repository("absent");
    let id = Uuid::new_v4().hyphenated().to_string();
    assert_eq!(repository.load(&id).expect("load"), None);
    assert_eq!(repository.load_selected().expect("load selected"), None);
    assert!(matches!(
        repository.require_selected(),
        Err(ProfileError::NoSelectedProfile)
    ));
    assert_eq!(
        repository.profile_entry_name(&id).expect("entry name"),
        None
    );
    assert!(matches!(
        repository.source_url(&id),
        Err(ProfileError::ProfileNotFound(missing)) if missing == id
    ));
    assert!(matches!(
        repository.select(&id),
        Err(ProfileError::SelectedProfileMissing(missing)) if missing == id
    ));
    assert!(
        !repository
            .delete(&id, InvalidSelection::Keep)
            .expect("delete")
    );
    assert_eq!(
        repository.clear_managed_profiles().expect("clear profiles"),
        0
    );
    let snapshot = repository.snapshot().expect("snapshot");
    assert!(snapshot.profiles.is_empty() && snapshot.invalid_profiles.is_empty());
    assert_eq!(snapshot.selected_profile_id, None);
    assert!(!root.exists(), "reading never creates the repository");
}

#[test]
fn a_profile_absent_from_an_existing_repository_loads_as_none() {
    let (root, repository) = repository("absent-profile");
    repository
        .import(Some("Present"), &profile())
        .expect("import profile");
    let missing = Uuid::new_v4().hyphenated().to_string();
    assert_eq!(repository.load(&missing).expect("load"), None);
    assert!(
        !repository
            .delete(&missing, InvalidSelection::Keep)
            .expect("delete")
    );
    fs::remove_dir_all(root).expect("remove test directory");
}
