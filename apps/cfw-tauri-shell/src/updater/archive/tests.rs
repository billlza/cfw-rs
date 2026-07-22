use std::io::Cursor;

use flate2::Compression;
use flate2::write::GzEncoder;
use tar::{Builder, EntryType, Header};

use super::*;

struct TestEntry<'a> {
    path: &'a str,
    kind: EntryType,
    mode: u32,
    body: &'a [u8],
    link: Option<&'a str>,
}

fn archive(entries: &[TestEntry<'_>]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::fast());
    let mut builder = Builder::new(encoder);
    for entry in entries {
        let mut header = Header::new_gnu();
        header.set_entry_type(entry.kind);
        header.set_mode(entry.mode);
        header.set_size(entry.body.len() as u64);
        if let Some(link) = entry.link {
            header.set_link_name(link).expect("link name");
        }
        header.set_cksum();
        builder
            .append_data(&mut header, entry.path, Cursor::new(entry.body))
            .expect("append entry");
    }
    builder
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn minimal_entries() -> Vec<TestEntry<'static>> {
    vec![
        TestEntry {
            path: "Clash for Mac.app/",
            kind: EntryType::Directory,
            mode: 0o755,
            body: b"",
            link: None,
        },
        TestEntry {
            path: "Clash for Mac.app/Contents/",
            kind: EntryType::Directory,
            mode: 0o755,
            body: b"",
            link: None,
        },
        TestEntry {
            path: "Clash for Mac.app/Contents/MacOS/",
            kind: EntryType::Directory,
            mode: 0o755,
            body: b"",
            link: None,
        },
        TestEntry {
            path: "Clash for Mac.app/Contents/Info.plist",
            kind: EntryType::Regular,
            mode: 0o644,
            body: b"plist",
            link: None,
        },
        TestEntry {
            path: "Clash for Mac.app/Contents/MacOS/clash-for-mac",
            kind: EntryType::Regular,
            mode: 0o755,
            body: b"binary",
            link: None,
        },
    ]
}

#[test]
fn accepts_bounded_canonical_bundle_and_extracts_without_entry_unpack() {
    let entries = minimal_entries();
    let bytes = archive(&entries);
    let plan = validate_archive(&bytes, RELEASE_LIMITS).expect("valid plan");
    let destination = tempfile::tempdir().expect("destination");
    extract_archive(&bytes, &plan, destination.path()).expect("safe extraction");
    assert_eq!(
        fs::read(destination.path().join(MAIN_EXECUTABLE)).expect("executable"),
        b"binary"
    );
}

#[test]
fn extraction_never_follows_a_preexisting_directory_symlink() {
    let entries = minimal_entries();
    let bytes = archive(&entries);
    let plan = validate_archive(&bytes, RELEASE_LIMITS).expect("valid plan");
    let destination = tempfile::tempdir().expect("destination");
    let outside = tempfile::tempdir().expect("outside");
    std::os::unix::fs::symlink(outside.path(), destination.path().join("Contents"))
        .expect("preexisting symlink");

    assert!(extract_archive(&bytes, &plan, destination.path()).is_err());
    assert!(
        !outside.path().join("Info.plist").exists(),
        "the extractor must not write through an existing symlink"
    );
}

#[test]
fn rejects_duplicate_conflicting_special_and_escaping_entries() {
    let mut duplicate = minimal_entries();
    duplicate.push(TestEntry {
        path: "Clash for Mac.app/Contents/Info.plist",
        kind: EntryType::Regular,
        mode: 0o644,
        body: b"again",
        link: None,
    });
    assert!(matches!(
        validate_archive(&archive(&duplicate), RELEASE_LIMITS),
        Err(UpdateArchiveError::PathConflict)
    ));

    let mut special = minimal_entries();
    special.push(TestEntry {
        path: "Clash for Mac.app/device",
        kind: EntryType::Fifo,
        mode: 0o600,
        body: b"",
        link: None,
    });
    assert!(matches!(
        validate_archive(&archive(&special), RELEASE_LIMITS),
        Err(UpdateArchiveError::ForbiddenEntryType)
    ));

    let mut escaping = minimal_entries();
    escaping.push(TestEntry {
        path: "Clash for Mac.app/escape",
        kind: EntryType::Symlink,
        mode: 0o777,
        body: b"",
        link: Some("../../outside"),
    });
    assert!(matches!(
        validate_archive(&archive(&escaping), RELEASE_LIMITS),
        Err(UpdateArchiveError::InvalidSymlink)
    ));
}

#[test]
fn rejects_entry_count_single_file_and_total_expansion_limits() {
    let entries = minimal_entries();
    let bytes = archive(&entries);
    assert!(matches!(
        validate_archive(
            &bytes,
            ArchiveLimits {
                entry_count: 4,
                ..RELEASE_LIMITS
            }
        ),
        Err(UpdateArchiveError::TooManyEntries)
    ));
    assert!(matches!(
        validate_archive(
            &bytes,
            ArchiveLimits {
                single_file_bytes: 5,
                ..RELEASE_LIMITS
            }
        ),
        Err(UpdateArchiveError::EntryTooLarge)
    ));
    assert!(matches!(
        validate_archive(
            &bytes,
            ArchiveLimits {
                expanded_bytes: 8,
                ..RELEASE_LIMITS
            }
        ),
        Err(UpdateArchiveError::ExpandedSizeExceeded)
    ));
}

#[test]
fn rejects_an_app_bundle_with_an_unusable_directory_or_main_executable() {
    for (index, mode) in [(1, 0o644), (4, 0o644)] {
        let mut entries = minimal_entries();
        entries[index].mode = mode;
        assert!(matches!(
            validate_archive(&archive(&entries), RELEASE_LIMITS),
            Err(UpdateArchiveError::UnsafePermissions)
        ));
    }
}

#[test]
fn rejects_oversized_extension_metadata_before_the_tar_parser_allocates_it() {
    let metadata = vec![b'a'; MAX_EXTENSION_ENTRY_BYTES as usize + 1];
    let mut entries = vec![TestEntry {
        path: "PaxHeader",
        kind: EntryType::XHeader,
        mode: 0o644,
        body: &metadata,
        link: None,
    }];
    entries.extend(minimal_entries());

    assert!(matches!(
        validate_archive(&archive(&entries), RELEASE_LIMITS),
        Err(UpdateArchiveError::ExtensionMetadataExceeded)
    ));
}

#[test]
fn rejects_symlink_ancestor_path_conflicts_regardless_of_order() {
    for symlink_first in [true, false] {
        let mut entries = minimal_entries();
        let symlink = TestEntry {
            path: "Clash for Mac.app/alias",
            kind: EntryType::Symlink,
            mode: 0o777,
            body: b"",
            link: Some("Contents"),
        };
        let child = TestEntry {
            path: "Clash for Mac.app/alias/payload",
            kind: EntryType::Regular,
            mode: 0o644,
            body: b"x",
            link: None,
        };
        if symlink_first {
            entries.extend([symlink, child]);
        } else {
            entries.extend([child, symlink]);
        }
        assert!(matches!(
            validate_archive(&archive(&entries), RELEASE_LIMITS),
            Err(UpdateArchiveError::PathConflict)
        ));
    }
}
