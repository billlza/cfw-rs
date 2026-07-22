use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::time::{SystemTime, UNIX_EPOCH};

use cfw_singbox_config::ValidatedSingBoxProfile;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    MAX_ENVELOPE_BYTES, MAX_PROFILE_NAME_CHARS, PROFILE_FILE_SUFFIX, PROFILE_SCHEMA_VERSION,
    ProfileError,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileEnvelope {
    schema_version: u16,
    id: String,
    name: String,
    profile: Value,
    digest: String,
    created_epoch_secs: u64,
}

pub(crate) struct DecodedEnvelope {
    pub(crate) name: String,
    pub(crate) digest: String,
    pub(crate) created_epoch_secs: u64,
    pub(crate) profile: ValidatedSingBoxProfile,
}

pub(crate) fn encode(
    id: &str,
    name: &str,
    profile: &ValidatedSingBoxProfile,
) -> Result<Vec<u8>, ProfileError> {
    let envelope = ProfileEnvelope {
        schema_version: PROFILE_SCHEMA_VERSION,
        id: id.to_string(),
        name: name.to_string(),
        profile: serde_json::from_str(profile.as_json())?,
        digest: profile.digest().to_string(),
        created_epoch_secs: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    let bytes = serde_json::to_vec(&envelope)?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(ProfileError::StoredProfileTooLarge {
            actual: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

pub(crate) fn decode(expected_id: &str, mut file: File) -> Result<DecodedEnvelope, ProfileError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_type().is_socket()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != effective_user_id()
    {
        return Err(ProfileError::UnsafeProfileFile(expected_id.to_string()));
    }
    if metadata.len() > MAX_ENVELOPE_BYTES as u64 {
        return Err(ProfileError::StoredProfileTooLarge {
            actual: metadata.len(),
        });
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((MAX_ENVELOPE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(ProfileError::StoredProfileTooLarge {
            actual: bytes.len() as u64,
        });
    }

    let envelope: ProfileEnvelope = serde_json::from_slice(&bytes)?;
    if envelope.schema_version != PROFILE_SCHEMA_VERSION {
        return Err(ProfileError::UnsupportedSchema(envelope.schema_version));
    }
    let stored_id = validate_profile_id(&envelope.id)?;
    if stored_id != expected_id {
        return Err(ProfileError::IdentityMismatch {
            expected: expected_id.to_string(),
            stored: envelope.id,
        });
    }
    if normalize_name(&envelope.name)? != envelope.name {
        return Err(ProfileError::InvalidName);
    }
    if serde_json::to_vec(&envelope)? != bytes {
        return Err(ProfileError::NonCanonicalEnvelope(expected_id.to_string()));
    }

    let profile = ValidatedSingBoxProfile::parse(&serde_json::to_string(&envelope.profile)?)?;
    if profile.digest() != envelope.digest {
        return Err(ProfileError::DigestMismatch {
            id: expected_id.to_string(),
        });
    }
    Ok(DecodedEnvelope {
        name: envelope.name,
        digest: envelope.digest,
        created_epoch_secs: envelope.created_epoch_secs,
        profile,
    })
}

fn effective_user_id() -> u32 {
    unsafe { libc::geteuid() }
}

pub(crate) fn normalize_name(name: &str) -> Result<String, ProfileError> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_PROFILE_NAME_CHARS
        || name
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
    {
        return Err(ProfileError::InvalidName);
    }
    Ok(name.to_string())
}

pub(crate) fn validate_profile_id(id: &str) -> Result<&str, ProfileError> {
    let parsed = Uuid::parse_str(id).map_err(|_| ProfileError::InvalidProfileId(id.into()))?;
    if parsed.hyphenated().to_string() != id {
        return Err(ProfileError::InvalidProfileId(id.into()));
    }
    Ok(id)
}

pub(crate) fn profile_file_name(id: &str) -> String {
    format!("{id}{PROFILE_FILE_SUFFIX}")
}

pub(crate) fn profile_id_from_file_name(file_name: &str) -> Result<&str, ProfileError> {
    let id = file_name
        .strip_suffix(PROFILE_FILE_SUFFIX)
        .ok_or_else(|| ProfileError::UnexpectedEntry(file_name.into()))?;
    validate_profile_id(id)
}
