//! A damaged, linked or oversized invalid entry still fails closed and is
//! never deleted.

use std::fs;

use cfw_profiles::{InvalidSelection, ProfileError};

use crate::invalid_profiles::{
    EARLIER_REALITY_DIGEST, EARLIER_REALITY_ENVELOPE, EARLIER_REALITY_ID,
    store_earlier_reality_profile,
};
use crate::private_file_fixture::write_private;
use crate::support::{
    MAX_STORED_BYTES, profile, repository, stored_path, symlink, weaken_file_privacy,
};

#[test]
fn damaged_invalid_profiles_still_fail_closed_and_are_never_deleted() {
    type Expect = fn(&ProfileError) -> bool;
    let cases: [(&str, String, Expect); 6] = [
        (
            "document edited, digest kept",
            EARLIER_REALITY_ENVELOPE.replacen(r#""server_port":443"#, r#""server_port":444"#, 1),
            |error| matches!(error, ProfileError::DigestMismatch { id } if id == EARLIER_REALITY_ID),
        ),
        (
            "digest edited",
            EARLIER_REALITY_ENVELOPE.replacen(EARLIER_REALITY_DIGEST, &"00".repeat(32), 1),
            |error| matches!(error, ProfileError::DigestMismatch { id } if id == EARLIER_REALITY_ID),
        ),
        (
            "non-canonical",
            format!("{EARLIER_REALITY_ENVELOPE}\n"),
            |error| matches!(error, ProfileError::NonCanonicalEnvelope(id) if id == EARLIER_REALITY_ID),
        ),
        (
            "unknown envelope field",
            format!(
                "{},\"unexpected\":true}}",
                EARLIER_REALITY_ENVELOPE
                    .strip_suffix('}')
                    .expect("envelope object")
            ),
            |error| matches!(error, ProfileError::InvalidEnvelopeJson(_)),
        ),
        (
            "schema version",
            EARLIER_REALITY_ENVELOPE.replacen(r#""schema_version":1"#, r#""schema_version":2"#, 1),
            |error| matches!(error, ProfileError::UnsupportedSchema(2)),
        ),
        (
            "identity",
            EARLIER_REALITY_ENVELOPE.replacen(
                EARLIER_REALITY_ID,
                "4c0e7d3f-5a2b-4f9c-8d8e-3b6a9f2c1d5e",
                1,
            ),
            |error| matches!(error, ProfileError::IdentityMismatch { .. }),
        ),
    ];
    for (case, envelope, expected) in cases {
        let (root, repository) = repository("earlier-damaged");
        repository
            .import(Some("Other"), &profile())
            .expect("import other profile");
        let path = stored_path(&root, EARLIER_REALITY_ID);
        write_private(&path, envelope.as_bytes());
        let error = repository.snapshot().expect_err(case);
        assert!(expected(&error), "{case}: {error}");
        let error = repository
            .delete(EARLIER_REALITY_ID, InvalidSelection::Clear)
            .expect_err(case);
        assert!(expected(&error), "{case}: {error}");
        assert_eq!(
            fs::read_to_string(&path).expect("entry kept"),
            envelope,
            "{case}"
        );
        fs::remove_dir_all(root).expect("remove test directory");
    }

    for case in ["mode", "hard link"] {
        let (root, repository) = repository("earlier-unsafe");
        repository
            .import(Some("Other"), &profile())
            .expect("import other profile");
        let path = store_earlier_reality_profile(&root, false);
        if case == "mode" {
            weaken_file_privacy(&path);
        } else {
            fs::hard_link(&path, root.join("external-link.json")).expect("hard link");
        }
        assert!(
            matches!(repository.snapshot(), Err(ProfileError::UnsafeProfileFile(id)) if id == EARLIER_REALITY_ID),
            "{case}"
        );
        assert!(
            matches!(
                repository.delete(EARLIER_REALITY_ID, InvalidSelection::Clear),
                Err(ProfileError::UnsafeProfileFile(_))
            ),
            "{case}"
        );
        assert!(path.exists(), "{case}");
        fs::remove_dir_all(root).expect("remove test directory");
    }
}

#[test]
fn linked_or_oversized_invalid_profiles_still_fail_closed() {
    for case in ["symlink", "oversized"] {
        let (root, repository) = repository("earlier-linked");
        repository
            .import(Some("Other"), &profile())
            .expect("import other profile");
        let path = stored_path(&root, EARLIER_REALITY_ID);
        let outside = root.join("outside.profile.json");
        if case == "symlink" {
            write_private(&outside, EARLIER_REALITY_ENVELOPE.as_bytes());
            symlink(&outside, &path).expect("create symlink");
        } else {
            write_private(
                &path,
                format!("{EARLIER_REALITY_ENVELOPE}{}", " ".repeat(MAX_STORED_BYTES)).as_bytes(),
            );
        }
        for result in [
            repository.snapshot().map(|_| ()),
            repository
                .delete(EARLIER_REALITY_ID, InvalidSelection::Clear)
                .map(|_| ()),
        ] {
            let error = result.expect_err(case);
            assert!(
                matches!(
                    (case, &error),
                    ("symlink", ProfileError::UnsafeProfileFile(_))
                        | ("oversized", ProfileError::StoredProfileTooLarge { .. })
                ),
                "{case}: {error}"
            );
        }
        assert!(path.symlink_metadata().is_ok(), "{case}: entry kept");
        if case == "symlink" {
            assert_eq!(
                fs::read_to_string(&outside).expect("target untouched"),
                EARLIER_REALITY_ENVELOPE
            );
        }
        fs::remove_dir_all(root).expect("remove test directory");
    }
}
