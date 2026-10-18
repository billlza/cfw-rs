use std::ffi::OsStr;

use uuid::Uuid;

use crate::{MAX_REPOSITORY_ENTRIES, ProfileError};

#[cfg(target_os = "macos")]
#[path = "storage/macos.rs"]
mod platform;
#[cfg(windows)]
#[path = "storage/windows.rs"]
mod platform;
#[cfg(not(any(target_os = "macos", windows)))]
compile_error!("profile storage supports macOS and Windows");

#[cfg(target_os = "macos")]
pub(crate) use platform::relative_c_string;
pub(crate) use platform::{RepositoryDirectory, private_metadata};
#[cfg(all(test, target_os = "macos"))]
pub(crate) use platform::{effective_user_id, repository_directory_is_safe};

pub(super) const MAX_ABANDONED_TEMPORARIES: usize = 64;

pub(crate) fn ensure_entry_capacity(current_entries: usize) -> Result<(), ProfileError> {
    if current_entries >= MAX_REPOSITORY_ENTRIES {
        Err(ProfileError::TooManyEntries)
    } else {
        Ok(())
    }
}

pub(super) fn remaining_directory_entry_capacity(
    current_entries: usize,
) -> Result<usize, ProfileError> {
    // Selection metadata, one selected-replacement intent, and bounded crash
    // temporaries remain enumerable.
    if current_entries >= MAX_REPOSITORY_ENTRIES + 2 + MAX_ABANDONED_TEMPORARIES {
        Err(ProfileError::TooManyEntries)
    } else {
        Ok(MAX_REPOSITORY_ENTRIES + 2 + MAX_ABANDONED_TEMPORARIES - current_entries)
    }
}

pub(super) fn is_owned_temporary_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(id) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    Uuid::parse_str(id).is_ok_and(|parsed| parsed.hyphenated().to_string() == id)
}
