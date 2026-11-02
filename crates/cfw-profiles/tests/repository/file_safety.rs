//! What the repository refuses to read: tampered, oversized, linked or
//! unexpected entries, and ids that are not canonical.

use std::fs;

use cfw_profiles::{InvalidSelection, ProfileError};
use uuid::Uuid;

use crate::private_file_fixture::write_private;
use crate::support::{
    MAX_STORED_BYTES, create_private_directory, listed, profile, repository, stored_path, symlink,
};

#[test]
fn a_non_directory_ancestor_is_not_an_empty_profile_repository() {
    let (root, repository) = repository("invalid-ancestor");
    fs::write(&root, b"preserved ancestor").unwrap();
    assert!(
        repository.snapshot().is_err(),
        "an invalid path must not appear empty"
    );
    assert_eq!(fs::read(&root).unwrap(), b"preserved ancestor");
    fs::remove_file(root).unwrap();
}

#[test]
fn digest_tampering_is_reported_instead_of_skipped() {
    let (root, repository) = repository("digest-tamper");
    let imported = repository.import(None, &profile()).expect("import profile");
    let path = stored_path(&root, &imported.id);
    let raw = fs::read_to_string(&path).expect("read envelope");
    let tampered = raw.replacen(&imported.digest, &"00".repeat(32), 1);
    assert_ne!(tampered, raw);
    fs::write(&path, tampered).expect("tamper envelope");

    assert!(matches!(
        listed(&repository),
        Err(ProfileError::DigestMismatch { .. })
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn oversized_stored_file_is_rejected_before_deserialization() {
    let (root, repository) = repository("oversized");
    let profiles_dir = root.join("profiles");
    create_private_directory(&profiles_dir);
    let id = Uuid::new_v4().hyphenated().to_string();
    let path = stored_path(&root, &id);
    write_private(&path, &vec![b' '; MAX_STORED_BYTES + 1]);

    assert!(matches!(
        listed(&repository),
        Err(ProfileError::StoredProfileTooLarge { .. })
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn traversal_and_noncanonical_ids_are_rejected() {
    let (_root, repository) = repository("invalid-id");
    for id in [
        "../profile",
        "00000000000000000000000000000000",
        "NOT-A-UUID",
    ] {
        assert!(matches!(
            repository.load(id),
            Err(ProfileError::InvalidProfileId(_))
        ));
        assert!(matches!(
            repository.delete(id, InvalidSelection::Keep),
            Err(ProfileError::InvalidProfileId(_))
        ));
    }
}

#[test]
fn symlink_profile_is_rejected_without_reading_target() {
    let (root, repository) = repository("symlink");
    create_private_directory(&root.join("profiles"));
    let outside = root.join("outside.json");
    fs::write(&outside, b"secret").expect("write outside file");
    let id = Uuid::new_v4().hyphenated().to_string();
    symlink(&outside, stored_path(&root, &id)).expect("create symlink");

    assert!(matches!(
        listed(&repository),
        Err(ProfileError::UnsafeProfileFile(_))
    ));
    assert_eq!(fs::read(&outside).expect("outside target"), b"secret");
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn hard_link_profile_is_rejected() {
    let (root, repository) = repository("hard-link");
    let imported = repository.import(None, &profile()).expect("import profile");
    fs::hard_link(
        stored_path(&root, &imported.id),
        root.join("external-link.json"),
    )
    .expect("create hard link");

    assert!(matches!(
        listed(&repository),
        Err(ProfileError::UnsafeProfileFile(_))
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn one_way_cleanup_unlinks_symlinks_without_touching_targets() {
    let (root, repository) = repository("cleanup");
    repository.import(None, &profile()).expect("import profile");
    let outside = root.join("external-profile.json");
    fs::write(&outside, b"external").expect("write external file");
    symlink(&outside, root.join("profiles").join("legacy.yaml")).expect("create legacy symlink");

    assert_eq!(
        repository.clear_managed_profiles().expect("clear profiles"),
        2
    );
    assert!(listed(&repository).expect("empty profile list").is_empty());
    assert_eq!(fs::read(&outside).expect("external target"), b"external");
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn malformed_or_unexpected_entries_are_not_silently_skipped() {
    let (root, repository) = repository("unexpected");
    create_private_directory(&root.join("profiles"));
    fs::write(root.join("profiles").join("legacy.yaml"), b"proxies: []")
        .expect("write legacy entry");
    assert!(matches!(
        listed(&repository),
        Err(ProfileError::UnexpectedEntry(_))
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn profile_entry_name_resolves_only_existing_canonical_ids() {
    let (root, repository) = repository("entry-name");
    let imported = repository
        .import(Some("Local"), &profile())
        .expect("import profile");
    assert_eq!(
        repository
            .profile_entry_name(&imported.id)
            .expect("entry name"),
        Some(format!("{}.profile.json", imported.id))
    );
    assert_eq!(
        repository
            .profile_entry_name("34db18b6-9903-4e9f-8854-15648e19e4f3")
            .expect("absent profile"),
        None
    );
    assert!(repository.profile_entry_name("../escape").is_err());

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn a_stored_name_or_source_url_out_of_normal_form_is_refused() {
    type Expect = fn(&ProfileError) -> bool;
    let cases: [(&str, &str, Expect); 2] = [
        (r#""name":"Remote""#, r#""name":" Remote""#, |error| {
            matches!(error, ProfileError::InvalidName)
        }),
        (
            r#""source_url":"https://subscription.example/profile""#,
            r#""source_url":"http://subscription.example/profile""#,
            |error| matches!(error, ProfileError::InvalidSourceUrl),
        ),
    ];
    for (stored, edited, expected) in cases {
        let (root, repository) = repository("stored-normal-form");
        let imported = repository
            .import_with_source(
                Some("Remote"),
                &profile(),
                Some("https://subscription.example/profile"),
            )
            .expect("import profile");
        let path = stored_path(&root, &imported.id);
        let envelope = fs::read_to_string(&path).expect("read envelope");
        assert!(envelope.contains(stored), "{stored}");
        write_private(&path, envelope.replacen(stored, edited, 1).as_bytes());
        let error = repository.snapshot().expect_err(edited);
        assert!(expected(&error), "{edited}: {error}");
        fs::remove_dir_all(root).expect("remove test directory");
    }
}

#[test]
fn single_profile_reads_refuse_a_linked_entry() {
    let (root, repository) = repository("linked-single-read");
    repository.import(None, &profile()).expect("import profile");
    let outside = root.join("outside.json");
    fs::write(&outside, b"secret").expect("write outside file");
    let id = Uuid::new_v4().hyphenated().to_string();
    symlink(&outside, stored_path(&root, &id)).expect("create symlink");

    assert!(matches!(
        repository.load(&id),
        Err(ProfileError::UnsafeProfileFile(unsafe_id)) if unsafe_id == id
    ));
    assert!(matches!(
        repository.source_url(&id),
        Err(ProfileError::UnsafeProfileFile(unsafe_id)) if unsafe_id == id
    ));
    assert_eq!(fs::read(&outside).expect("outside target"), b"secret");
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn one_way_cleanup_never_descends_into_a_subdirectory() {
    let (root, repository) = repository("cleanup-subdirectory");
    let imported = repository.import(None, &profile()).expect("import profile");
    fs::create_dir(root.join("profiles").join("nested")).expect("create subdirectory");
    assert!(matches!(
        repository.clear_managed_profiles(),
        Err(ProfileError::UnexpectedManagedSubdirectory(name)) if name == "nested"
    ));
    assert!(
        stored_path(&root, &imported.id).exists(),
        "nothing is removed"
    );
    fs::remove_dir_all(root).expect("remove test directory");
}
