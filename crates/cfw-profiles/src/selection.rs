use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

use serde::{Deserialize, Serialize};

use crate::{
    MAX_SELECTION_BYTES, ProfileError, SELECTION_SCHEMA_VERSION, envelope::validate_profile_id,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileSelection {
    schema_version: u16,
    profile_id: String,
    profile_digest: String,
}

impl ProfileSelection {
    pub(crate) fn new(profile_id: &str, profile_digest: &str) -> Result<Self, ProfileError> {
        validate_profile_id(profile_id)?;
        validate_digest(profile_digest)?;
        Ok(Self {
            schema_version: SELECTION_SCHEMA_VERSION,
            profile_id: profile_id.to_owned(),
            profile_digest: profile_digest.to_owned(),
        })
    }

    pub(crate) fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub(crate) fn profile_digest(&self) -> &str {
        &self.profile_digest
    }
}

pub(crate) fn encode(selection: &ProfileSelection) -> Result<Vec<u8>, ProfileError> {
    let bytes = serde_json::to_vec(selection)
        .map_err(|error| ProfileError::InvalidSelectionJson(error.to_string()))?;
    if bytes.len() > MAX_SELECTION_BYTES {
        return Err(ProfileError::SelectionTooLarge {
            actual: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

pub(crate) fn decode(mut file: File) -> Result<ProfileSelection, ProfileError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_type().is_socket()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != effective_user_id()
    {
        return Err(ProfileError::UnsafeSelectionFile);
    }
    if metadata.len() > MAX_SELECTION_BYTES as u64 {
        return Err(ProfileError::SelectionTooLarge {
            actual: metadata.len(),
        });
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((MAX_SELECTION_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SELECTION_BYTES {
        return Err(ProfileError::SelectionTooLarge {
            actual: bytes.len() as u64,
        });
    }

    let selection: ProfileSelection = serde_json::from_slice(&bytes)
        .map_err(|error| ProfileError::InvalidSelectionJson(error.to_string()))?;
    if selection.schema_version != SELECTION_SCHEMA_VERSION {
        return Err(ProfileError::UnsupportedSelectionSchema(
            selection.schema_version,
        ));
    }
    validate_profile_id(&selection.profile_id)?;
    validate_digest(&selection.profile_digest)?;
    if serde_json::to_vec(&selection)
        .map_err(|error| ProfileError::InvalidSelectionJson(error.to_string()))?
        != bytes
    {
        return Err(ProfileError::NonCanonicalSelection);
    }
    Ok(selection)
}

fn validate_digest(digest: &str) -> Result<(), ProfileError> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ProfileError::InvalidSelectionJson(
            "profile_digest must be a lowercase SHA-256 digest".to_owned(),
        ))
    }
}

fn effective_user_id() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::validate_digest;

    #[test]
    fn selection_digest_is_exact_lowercase_sha256() {
        validate_digest(&"ab".repeat(32)).expect("valid digest");
        assert!(validate_digest(&"AB".repeat(32)).is_err());
        assert!(validate_digest(&"0".repeat(63)).is_err());
        assert!(validate_digest(&format!("{}g", "0".repeat(63))).is_err());
    }
}
