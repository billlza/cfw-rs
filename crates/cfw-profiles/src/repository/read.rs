//! Reading and decoding stored entries and the selected profile.

use super::*;

impl ProfileRepository {
    pub(super) fn read_all(
        &self,
        directory: &RepositoryDirectory,
    ) -> Result<RepositorySnapshot, ProfileError> {
        let profiles = self.read_profiles(directory)?;
        let mut stored_bytes = profiles.stored_bytes;
        let selection = if profiles.has_selection {
            let file = directory.open_selection_file()?;
            stored_bytes = stored_bytes
                .checked_add(file.metadata()?.len())
                .ok_or(ProfileError::RepositoryTooLarge { actual: u64::MAX })?;
            if stored_bytes > MAX_REPOSITORY_BYTES {
                return Err(ProfileError::RepositoryTooLarge {
                    actual: stored_bytes,
                });
            }
            Some(decode_selection(file)?)
        } else {
            None
        };

        if let Some(selection) = &selection {
            // A selection naming an invalid entry is still bound to its stored
            // digest; it is reported as selected and refused by every load.
            let digest = profiles
                .records
                .iter()
                .find(|record| record.id == selection.profile_id())
                .map(|record| &record.digest)
                .or_else(|| {
                    find_invalid(&profiles.invalid, selection.profile_id())
                        .map(|entry| &entry.digest)
                })
                .ok_or_else(|| {
                    ProfileError::SelectedProfileMissing(selection.profile_id().to_owned())
                })?;
            if digest != selection.profile_digest() {
                return Err(ProfileError::SelectedProfileDigestMismatch {
                    id: selection.profile_id().to_owned(),
                    expected: selection.profile_digest().to_owned(),
                    actual: digest.clone(),
                });
            }
        }

        Ok(RepositorySnapshot {
            records: profiles.records,
            invalid: profiles.invalid,
            stored_bytes,
            selection,
            credential_catalog: profiles.credential_catalog,
        })
    }

    pub(super) fn read_profiles(
        &self,
        directory: &RepositoryDirectory,
    ) -> Result<RepositoryProfiles, ProfileError> {
        let mut ids = Vec::new();
        let mut has_selection = false;
        for file_name in directory.entry_names()? {
            let file_name = file_name
                .to_str()
                .ok_or_else(|| ProfileError::UnexpectedEntry("non-UTF-8 filename".into()))?;
            if file_name == SELECTION_FILE_NAME {
                has_selection = true;
            } else {
                ids.push(profile_id_from_file_name(file_name)?.to_string());
            }
        }
        ids.sort_unstable();

        let mut records = Vec::with_capacity(ids.len());
        let mut invalid = Vec::new();
        let mut credential_catalog = Vec::with_capacity(ids.len());
        let mut credential_binding_count = 0_usize;
        let mut stored_bytes = 0_u64;
        for id in ids {
            let file = directory.open_profile_file(&id)?;
            let file_length = file.metadata()?.len();
            stored_bytes = stored_bytes
                .checked_add(file_length)
                .ok_or(ProfileError::RepositoryTooLarge { actual: u64::MAX })?;
            if stored_bytes > MAX_REPOSITORY_BYTES {
                return Err(ProfileError::RepositoryTooLarge {
                    actual: stored_bytes,
                });
            }
            let stored = match self.decode_entry(&id, file)? {
                StoredEntry::Valid(stored) => *stored,
                StoredEntry::Invalid(entry) => {
                    invalid.push(entry);
                    continue;
                }
            };
            let mut references = stored.profile.credential_references();
            references.sort();
            credential_binding_count = credential_binding_count
                .checked_add(references.len())
                .ok_or(ProfileError::TooManyCredentialReferences)?;
            ensure_credential_reference_capacity(credential_binding_count)?;
            let audience = CredentialAudience::new(&stored.record.id, &stored.record.digest)
                .map_err(|_| ProfileError::InvalidCredentialAudience(stored.record.id.clone()))?;
            credential_catalog.push(ProfileCredentialCatalogEntry {
                audience,
                references,
            });
            records.push(stored.record);
        }
        records
            .sort_by(|left, right| listing_order((&left.name, &left.id), (&right.name, &right.id)));
        invalid.sort_by(|left, right| {
            listing_order(
                (&left.record.name, &left.record.id),
                (&right.record.name, &right.record.id),
            )
        });
        credential_catalog.sort_by(|left, right| left.audience.cmp(&right.audience));
        Ok(RepositoryProfiles {
            records,
            invalid,
            stored_bytes,
            has_selection,
            credential_catalog,
        })
    }

    pub fn load(&self, id: &str) -> Result<Option<StoredProfile>, ProfileError> {
        let id = validate_profile_id(id)?;
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Ok(None);
        };
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        match directory.open_profile_file(id) {
            Ok(file) => self.decode(id, file).map(Some),
            Err(ProfileError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Subscription URL of one stored profile, including one that fails
    /// validation, so its source can be imported again before it is deleted.
    /// Like [`Self::load`] it reads a single entry; lists never carry URLs.
    pub fn source_url(&self, id: &str) -> Result<Option<String>, ProfileError> {
        let id = validate_profile_id(id)?;
        let missing = || ProfileError::ProfileNotFound(id.to_owned());
        let directory =
            RepositoryDirectory::open_if_present(&self.profiles_dir)?.ok_or_else(missing)?;
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        let file = match directory.open_profile_file(id) {
            Ok(file) => file,
            Err(ProfileError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(missing());
            }
            Err(error) => return Err(error),
        };
        Ok(match self.decode_entry(id, file)? {
            StoredEntry::Valid(stored) => stored.source_url,
            StoredEntry::Invalid(entry) => entry.source_url,
        })
    }

    pub fn load_selected(&self) -> Result<Option<StoredProfile>, ProfileError> {
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Ok(None);
        };
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        let snapshot = self.read_all(&directory)?;
        let Some(selection) = snapshot.selection else {
            return Ok(None);
        };
        let file = directory.open_profile_file(selection.profile_id())?;
        self.decode(selection.profile_id(), file).map(Some)
    }

    pub fn require_selected(&self) -> Result<StoredProfile, ProfileError> {
        self.load_selected()?.ok_or(ProfileError::NoSelectedProfile)
    }

    pub fn lock_selected(&self) -> Result<LockedSelectedProfile, ProfileError> {
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        let snapshot = self.read_all(&directory)?;
        let selection = snapshot.selection.ok_or(ProfileError::NoSelectedProfile)?;
        let file = directory.open_profile_file(selection.profile_id())?;
        let stored = self.decode(selection.profile_id(), file)?;
        Ok(LockedSelectedProfile {
            stored,
            _directory: directory,
        })
    }

    /// Loads one profile for use; an entry that fails validation is an error.
    pub(super) fn decode(&self, id: &str, file: File) -> Result<StoredProfile, ProfileError> {
        match self.decode_entry(id, file)? {
            StoredEntry::Valid(stored) => Ok(*stored),
            StoredEntry::Invalid(entry) => Err(entry.record.load_error()),
        }
    }

    pub(super) fn decode_entry(&self, id: &str, file: File) -> Result<StoredEntry, ProfileError> {
        Ok(match decode(id, file)? {
            DecodedEntry::Valid(decoded) => {
                let decoded = *decoded;
                StoredEntry::Valid(Box::new(StoredProfile {
                    record: ProfileRecord {
                        id: id.to_string(),
                        name: decoded.name,
                        bytes: decoded.profile.as_json().len(),
                        digest: decoded.digest,
                        created_epoch_secs: decoded.created_epoch_secs,
                        source_kind: ProfileSourceKind::from_source_url(
                            decoded.source_url.as_deref(),
                        ),
                    },
                    profile: decoded.profile,
                    source_url: decoded.source_url,
                }))
            }
            DecodedEntry::Invalid(decoded) => StoredEntry::Invalid(InvalidEntry {
                record: InvalidProfileRecord {
                    id: id.to_string(),
                    name: decoded.name,
                    created_epoch_secs: decoded.created_epoch_secs,
                    source_kind: ProfileSourceKind::from_source_url(decoded.source_url.as_deref()),
                    error: decoded.error,
                },
                digest: decoded.digest,
                envelope_digest: decoded.envelope_digest,
                source_url: decoded.source_url,
            }),
        })
    }
}
