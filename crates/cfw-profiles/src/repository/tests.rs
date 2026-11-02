//! Repository tests that need the crate's private envelope, selection and
//! replacement-intent codecs, and the fixtures they share.

use std::fs;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::{
    ProfileRepository, ProfileSourceKind, SelectedProfileReplaceIntent, StoredProfile,
    ensure_credential_reference_capacity, ensure_repository_bytes, sha256_hex,
    stored_envelope_digest,
};
use crate::envelope::{encode_with_timestamp, profile_file_name};
use crate::private_file_fixture::write_private;
use crate::selection::{ProfileSelection, encode as encode_selection};
use crate::{
    MAX_REPOSITORY_BYTES, MAX_REPOSITORY_CREDENTIAL_REFERENCES, ProfileError,
    SELECTED_REPLACE_FILE_NAME, SELECTION_FILE_NAME, ValidatedSingBoxProfile,
};

mod intent_file;
mod limits;
mod recovery;
mod recovery_conflicts;
mod source_kind;

fn repository(name: &str) -> (PathBuf, ProfileRepository) {
    let root = std::env::temp_dir().join(format!(
        "cfw-selected-replace-{name}-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    let repository = ProfileRepository::new(root.join("profiles"));
    (root, repository)
}

fn profile(tag: &str) -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&format!(
        r#"{{"route":{{"final":"{tag}"}},"outbounds":[{{"tag":"{tag}","type":"direct"}}]}}"#
    ))
    .expect("valid profile")
}

fn stage_selected_replace(
    root: &Path,
    original: &StoredProfile,
    replacement: &ValidatedSingBoxProfile,
) -> (SelectedProfileReplaceIntent, Vec<u8>) {
    let replacement_bytes = encode_with_timestamp(
        &original.record.id,
        "Replacement",
        replacement,
        original.source_url.as_deref(),
        original.record.created_epoch_secs + 1,
    )
    .expect("replacement envelope");
    let intent = SelectedProfileReplaceIntent::new(
        &original.record.id,
        &original.record.digest,
        replacement.digest(),
        &stored_envelope_digest(original).expect("original envelope digest"),
        &sha256_hex(&replacement_bytes),
    )
    .expect("replacement intent");
    write_private(
        &root.join("profiles").join(SELECTED_REPLACE_FILE_NAME),
        &intent.encode().expect("intent bytes"),
    );
    (intent, replacement_bytes)
}

fn selected_fixture(name: &str) -> (PathBuf, ProfileRepository, StoredProfile) {
    let (root, repository) = repository(name);
    let imported = repository
        .import(Some("Original"), &profile("direct-original"))
        .expect("import original");
    repository.select(&imported.id).expect("select original");
    let original = repository
        .load_selected()
        .expect("load selected")
        .expect("selected original");
    (root, repository, original)
}
