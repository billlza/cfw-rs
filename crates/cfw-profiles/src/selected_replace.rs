use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

use serde::{Deserialize, Serialize};

use crate::envelope::validate_profile_id;
use crate::selection::validate_digest;
use crate::{MAX_SELECTED_REPLACE_BYTES, ProfileError, SELECTED_REPLACE_SCHEMA_VERSION};

/// Durable intent for the only repository mutation that spans two files.
///
/// The replacement profile is committed first and the selected-profile digest
/// second. This record lets recovery distinguish an untouched transaction from
/// the exact intermediate state without treating an arbitrary digest mismatch
/// as repairable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectedProfileReplaceIntent {
    schema_version: u16,
    profile_id: String,
    previous_profile_digest: String,
    replacement_profile_digest: String,
    previous_envelope_digest: String,
    replacement_envelope_digest: String,
}

impl SelectedProfileReplaceIntent {
    pub(crate) fn new(
        profile_id: &str,
        previous_profile_digest: &str,
        replacement_profile_digest: &str,
        previous_envelope_digest: &str,
        replacement_envelope_digest: &str,
    ) -> Result<Self, ProfileError> {
        validate_profile_id(profile_id)?;
        for digest in [
            previous_profile_digest,
            replacement_profile_digest,
            previous_envelope_digest,
            replacement_envelope_digest,
        ] {
            validate_digest(digest)?;
        }
        if previous_profile_digest == replacement_profile_digest {
            return Err(ProfileError::InvalidSelectedReplace(
                "previous and replacement profile digests must differ".into(),
            ));
        }
        if previous_envelope_digest == replacement_envelope_digest {
            return Err(ProfileError::InvalidSelectedReplace(
                "previous and replacement envelope digests must differ".into(),
            ));
        }
        Ok(Self {
            schema_version: SELECTED_REPLACE_SCHEMA_VERSION,
            profile_id: profile_id.to_owned(),
            previous_profile_digest: previous_profile_digest.to_owned(),
            replacement_profile_digest: replacement_profile_digest.to_owned(),
            previous_envelope_digest: previous_envelope_digest.to_owned(),
            replacement_envelope_digest: replacement_envelope_digest.to_owned(),
        })
    }

    pub(crate) fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub(crate) fn previous_profile_digest(&self) -> &str {
        &self.previous_profile_digest
    }

    pub(crate) fn replacement_profile_digest(&self) -> &str {
        &self.replacement_profile_digest
    }

    pub(crate) fn previous_envelope_digest(&self) -> &str {
        &self.previous_envelope_digest
    }

    pub(crate) fn replacement_envelope_digest(&self) -> &str {
        &self.replacement_envelope_digest
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, ProfileError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| ProfileError::InvalidSelectedReplace(error.to_string()))?;
        if bytes.len() > MAX_SELECTED_REPLACE_BYTES {
            return Err(ProfileError::SelectedReplaceTooLarge {
                actual: bytes.len() as u64,
            });
        }
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), ProfileError> {
        if self.schema_version != SELECTED_REPLACE_SCHEMA_VERSION {
            return Err(ProfileError::InvalidSelectedReplace(format!(
                "unsupported schema version {}",
                self.schema_version
            )));
        }
        validate_profile_id(&self.profile_id)?;
        for digest in [
            self.previous_profile_digest.as_str(),
            self.replacement_profile_digest.as_str(),
            self.previous_envelope_digest.as_str(),
            self.replacement_envelope_digest.as_str(),
        ] {
            validate_digest(digest)?;
        }
        if self.previous_profile_digest == self.replacement_profile_digest {
            return Err(ProfileError::InvalidSelectedReplace(
                "previous and replacement profile digests must differ".into(),
            ));
        }
        if self.previous_envelope_digest == self.replacement_envelope_digest {
            return Err(ProfileError::InvalidSelectedReplace(
                "previous and replacement envelope digests must differ".into(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn decode(mut file: File) -> Result<SelectedProfileReplaceIntent, ProfileError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_type().is_socket()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != effective_user_id()
    {
        return Err(ProfileError::UnsafeSelectedReplaceFile);
    }
    if metadata.len() > MAX_SELECTED_REPLACE_BYTES as u64 {
        return Err(ProfileError::SelectedReplaceTooLarge {
            actual: metadata.len(),
        });
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((MAX_SELECTED_REPLACE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SELECTED_REPLACE_BYTES {
        return Err(ProfileError::SelectedReplaceTooLarge {
            actual: bytes.len() as u64,
        });
    }

    let intent: SelectedProfileReplaceIntent = serde_json::from_slice(&bytes)
        .map_err(|error| ProfileError::InvalidSelectedReplace(error.to_string()))?;
    intent.validate()?;
    if intent.encode()? != bytes {
        return Err(ProfileError::InvalidSelectedReplace(
            "intent is not in canonical form".into(),
        ));
    }
    Ok(intent)
}

fn effective_user_id() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_is_closed_to_distinct_canonical_digests() {
        let intent = SelectedProfileReplaceIntent::new(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            &"a1".repeat(32),
            &"b2".repeat(32),
            &"c3".repeat(32),
            &"d4".repeat(32),
        )
        .expect("valid intent");
        assert!(intent.encode().is_ok());
        assert!(
            SelectedProfileReplaceIntent::new(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                &"a1".repeat(32),
                &"a1".repeat(32),
                &"c3".repeat(32),
                &"d4".repeat(32),
            )
            .is_err()
        );
        assert!(
            SelectedProfileReplaceIntent::new(
                "not-a-profile-id",
                &"a1".repeat(32),
                &"b2".repeat(32),
                &"c3".repeat(32),
                &"d4".repeat(32),
            )
            .is_err()
        );
    }
}
