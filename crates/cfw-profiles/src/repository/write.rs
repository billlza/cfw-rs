//! Imports, replacements, restores and metadata updates of profile entries.

use super::*;

impl ProfileRepository {
    pub fn import(
        &self,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
    ) -> Result<ProfileImportResult, ProfileError> {
        self.import_with_source(name, profile, None)
    }

    /// Imports a profile together with the subscription URL it came from.
    ///
    /// The URL is stored as opaque bounded text. This crate never fetches it;
    /// refreshing a subscription is the caller's transport decision.
    pub fn import_with_source(
        &self,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<ProfileImportResult, ProfileError> {
        let id = Uuid::new_v4().hyphenated().to_string();
        self.import_with_id_and_source(&id, name, profile, source_url)
    }

    /// Imports one profile under an exact caller-owned UUID.
    ///
    /// Migration credentials are bound to the profile UUID and digest, so a
    /// retry must reuse the same identity. An exact replay returns the existing
    /// record. Reusing the UUID with any different name, profile, or source URL
    /// is an explicit conflict and never overwrites the durable entry.
    pub fn import_with_id_and_source(
        &self,
        id: &str,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<ProfileImportResult, ProfileError> {
        self.import_with_id_and_source_outcome(id, name, profile, source_url)
            .map(|outcome| outcome.profile)
    }

    /// Exact-ID import with a lock-bound created/replayed disposition.
    /// Callers must use this outcome instead of a separate preflight `load`
    /// when compensating a newly created entry after a surrounding transaction.
    pub fn import_with_id_and_source_outcome(
        &self,
        id: &str,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<ExactProfileImportOutcome, ProfileError> {
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        self.import_with_id_and_source_outcome_in_directory(
            &directory, id, name, profile, source_url,
        )
    }

    pub(super) fn import_with_id_and_source_outcome_in_directory(
        &self,
        directory: &RepositoryDirectory,
        id: &str,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<ExactProfileImportOutcome, ProfileError> {
        let id = validate_profile_id(id)?;
        let name = normalize_name(name.unwrap_or("Local profile"))?;
        // Do not add new state alongside a corrupt, legacy, or interrupted
        // entry. The one-way migration API is the only path that clears those.
        // An intact entry that fails validation does not block other imports,
        // since importing a corrected node is how it is replaced; its own id
        // stays taken, and reported as invalid, until it is deleted.
        let existing = self.read_all(directory)?;
        if let Some(entry) = existing.invalid(id) {
            return Err(entry.record.load_error());
        }
        if existing.records.iter().any(|record| record.id == id) {
            let current = self.decode(id, directory.open_profile_file(id)?)?;
            if current.record.name == name
                && current.profile == *profile
                && current.source_url.as_deref() == source_url
            {
                return Ok(ExactProfileImportOutcome {
                    profile: ProfileImportResult {
                        id: id.to_owned(),
                        name,
                        bytes: profile.as_json().len(),
                        digest: profile.digest().to_string(),
                    },
                    created: false,
                });
            }
            return Err(ProfileError::AlreadyExists(id.to_owned()));
        }
        // The catalog counts validated documents only; the native vault still
        // enforces its own capacity for references an invalid entry kept.
        let prospective_bindings = credential_binding_count(&existing.credential_catalog)?
            .checked_add(profile.credential_references().len())
            .ok_or(ProfileError::TooManyCredentialReferences)?;
        ensure_credential_reference_capacity(prospective_bindings)?;
        // A successful read proves the repository contains at most the
        // documented limit. Import must still reject the next write when it
        // is already full; otherwise the 4,097th entry would be committed and
        // only discovered by a later operation.
        ensure_entry_capacity(existing.records.len() + existing.invalid.len())?;
        let bytes = encode(id, &name, profile, source_url)?;
        ensure_repository_bytes(existing.stored_bytes, bytes.len())?;
        directory.write_new_atomic(&profile_file_name(id), &bytes)?;
        Ok(ExactProfileImportOutcome {
            profile: ProfileImportResult {
                id: id.to_owned(),
                name,
                bytes: profile.as_json().len(),
                digest: profile.digest().to_string(),
            },
            created: true,
        })
    }

    /// Replaces the document of an existing profile in place.
    ///
    /// The identity stays stable so an edited or re-fetched subscription keeps
    /// its credentials and its selection. When the replaced profile is the
    /// selected one, its selection metadata is rebound to the new digest under
    /// the same exclusive lock, so no reader can observe the digest mismatch
    /// that a bare profile rewrite would create.
    pub fn replace(
        &self,
        id: &str,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<ProfileImportResult, ProfileError> {
        self.replace_with_timestamp(id, name, profile, source_url, None, None)
            .map(|(result, _stored)| result)
    }

    /// Replaces a profile only when its complete stored identity still matches
    /// the caller's pre-I/O snapshot.
    ///
    /// Subscription fetches happen outside the repository lock. This compare-
    /// and-swap boundary prevents a delayed response from overwriting a newer
    /// document, name, source URL, or credential-reference set.
    pub fn replace_if_unchanged(
        &self,
        expected: &StoredProfile,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<(ProfileImportResult, StoredProfile), ProfileError> {
        validate_stored_profile(expected)?;
        self.replace_with_timestamp(
            &expected.record.id,
            name,
            profile,
            source_url,
            None,
            Some(expected),
        )
    }

    /// Restores a previously loaded profile after a surrounding transaction
    /// fails. Unlike a normal replacement, rollback preserves the original
    /// timestamp as well as identity, name, profile, source URL, credentials,
    /// and selected digest.
    pub fn restore(&self, stored: &StoredProfile) -> Result<ProfileImportResult, ProfileError> {
        validate_stored_profile(stored)?;
        self.replace_with_timestamp(
            &stored.record.id,
            Some(&stored.record.name),
            &stored.profile,
            stored.source_url.as_deref(),
            Some(stored.record.created_epoch_secs),
            None,
        )
        .map(|(result, _stored)| result)
    }

    /// Restores a prior snapshot only if the transaction's replacement is
    /// still current. A failed vault operation must never roll the repository
    /// back over a newer user edit or subscription response.
    pub fn restore_if_unchanged(
        &self,
        expected_current: &StoredProfile,
        stored: &StoredProfile,
    ) -> Result<ProfileImportResult, ProfileError> {
        validate_stored_profile(expected_current)?;
        validate_stored_profile(stored)?;
        if expected_current.record.id != stored.record.id {
            return Err(ProfileError::ProfileChanged {
                id: stored.record.id.clone(),
            });
        }
        self.replace_with_timestamp(
            &stored.record.id,
            Some(&stored.record.name),
            &stored.profile,
            stored.source_url.as_deref(),
            Some(stored.record.created_epoch_secs),
            Some(expected_current),
        )
        .map(|(result, _stored)| result)
    }

    fn replace_with_timestamp(
        &self,
        id: &str,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
        created_epoch_secs: Option<u64>,
        expected: Option<&StoredProfile>,
    ) -> Result<(ProfileImportResult, StoredProfile), ProfileError> {
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        self.replace_with_timestamp_in_directory(
            &directory,
            ProfileReplacement {
                id,
                name,
                profile,
                source_url,
                created_epoch_secs,
                expected,
            },
        )
    }

    pub(super) fn replace_with_timestamp_in_directory(
        &self,
        directory: &RepositoryDirectory,
        replacement: ProfileReplacement<'_>,
    ) -> Result<(ProfileImportResult, StoredProfile), ProfileError> {
        let ProfileReplacement {
            id,
            name,
            profile,
            source_url,
            created_epoch_secs,
            expected,
        } = replacement;
        let id = validate_profile_id(id)?;
        let existing = self.read_all(directory)?;
        let file = directory.open_profile_file(id)?;
        let replaced_bytes = file.metadata()?.len();
        let current = self.decode(id, file)?;
        if expected.is_some_and(|expected| expected != &current) {
            return Err(ProfileError::ProfileChanged { id: id.to_owned() });
        }
        let existing_bindings = credential_binding_count(&existing.credential_catalog)?;
        let prospective_bindings = existing_bindings
            .checked_sub(current.profile.credential_references().len())
            .and_then(|count| count.checked_add(profile.credential_references().len()))
            .ok_or(ProfileError::TooManyCredentialReferences)?;
        ensure_credential_reference_capacity(prospective_bindings)?;
        let name = match name {
            Some(name) => normalize_name(name)?,
            None => current.record.name.clone(),
        };
        let timestamp = match created_epoch_secs {
            Some(timestamp) => timestamp,
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        let bytes = encode_with_timestamp(id, &name, profile, source_url, timestamp)?;
        ensure_repository_bytes(
            existing.stored_bytes.saturating_sub(replaced_bytes),
            bytes.len(),
        )?;
        let selection = existing
            .selection
            .as_ref()
            .filter(|selection| selection.profile_id() == id)
            .map(|_| ProfileSelection::new(id, profile.digest()))
            .transpose()?;
        let result = ProfileImportResult {
            id: id.to_owned(),
            name: name.clone(),
            bytes: profile.as_json().len(),
            digest: profile.digest().to_string(),
        };
        let stored = StoredProfile {
            record: ProfileRecord {
                id: id.to_owned(),
                name,
                bytes: profile.as_json().len(),
                digest: profile.digest().to_string(),
                created_epoch_secs: timestamp,
                source_kind: ProfileSourceKind::from_source_url(source_url),
            },
            profile: profile.clone(),
            source_url: source_url.map(ToOwned::to_owned),
        };

        let replacement_changes_selected_digest =
            selection.is_some() && current.record.digest != stored.record.digest;
        if replacement_changes_selected_digest {
            let intent = SelectedProfileReplaceIntent::new(
                id,
                &current.record.digest,
                &stored.record.digest,
                &stored_envelope_digest(&current)?,
                &sha256_hex(&bytes),
            )?;
            let intent_bytes = intent.encode()?;
            let prospective_bytes = existing
                .stored_bytes
                .saturating_sub(replaced_bytes)
                .saturating_add(bytes.len() as u64);
            ensure_repository_bytes(prospective_bytes, intent_bytes.len())?;
            if let Err(operation) =
                directory.write_new_atomic(SELECTED_REPLACE_FILE_NAME, &intent_bytes)
            {
                return match self.recover_after_selected_replace_error(directory, &operation)? {
                    SelectedReplaceRecovery::None | SelectedReplaceRecovery::Aborted => {
                        Err(operation)
                    }
                    SelectedReplaceRecovery::Committed => {
                        Err(ProfileError::SelectedReplaceRecovery {
                            operation: operation.to_string(),
                            recovery:
                                "an unstarted replacement was unexpectedly reported committed"
                                    .into(),
                        })
                    }
                };
            }

            if let Err(operation) = directory.write_replace_atomic(&profile_file_name(id), &bytes) {
                return match self.recover_after_selected_replace_error(directory, &operation)? {
                    SelectedReplaceRecovery::Committed => Ok((result, stored)),
                    SelectedReplaceRecovery::Aborted => Err(operation),
                    SelectedReplaceRecovery::None => Err(ProfileError::SelectedReplaceRecovery {
                        operation: operation.to_string(),
                        recovery: "replacement intent disappeared before recovery".into(),
                    }),
                };
            }

            let selection = selection.expect("selected digest change has selection metadata");
            if let Err(operation) =
                directory.write_replace_atomic(SELECTION_FILE_NAME, &encode_selection(&selection)?)
            {
                return match self.recover_after_selected_replace_error(directory, &operation)? {
                    SelectedReplaceRecovery::Committed => Ok((result, stored)),
                    SelectedReplaceRecovery::Aborted | SelectedReplaceRecovery::None => {
                        Err(ProfileError::SelectedReplaceRecovery {
                            operation: operation.to_string(),
                            recovery:
                                "profile replacement committed but selection did not roll forward"
                                    .into(),
                        })
                    }
                };
            }

            if let Err(operation) = self.finish_selected_replace(directory) {
                return match self.recover_after_selected_replace_error(directory, &operation)? {
                    SelectedReplaceRecovery::Committed | SelectedReplaceRecovery::None => {
                        Ok((result, stored))
                    }
                    SelectedReplaceRecovery::Aborted => {
                        Err(ProfileError::SelectedReplaceRecovery {
                            operation: operation.to_string(),
                            recovery: "replacement cleanup reverted after both commits".into(),
                        })
                    }
                };
            }
        } else {
            directory.write_replace_atomic(&profile_file_name(id), &bytes)?;
        }
        Ok((result, stored))
    }

    /// Renames a profile and/or rebinds its subscription URL without touching
    /// the validated document, so neither the digest nor the selection changes.
    pub fn update_metadata(
        &self,
        id: &str,
        name: Option<&str>,
        source_url: Option<&str>,
    ) -> Result<ProfileRecord, ProfileError> {
        let id = validate_profile_id(id)?;
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        let existing = self.read_all(&directory)?;
        let file = directory.open_profile_file(id)?;
        let replaced_bytes = file.metadata()?.len();
        let current = self.decode(id, file)?;
        let name = match name {
            Some(name) => normalize_name(name)?,
            None => current.record.name.clone(),
        };
        // The document and its creation time are preserved: renaming or
        // rebinding a subscription URL is not an update of the profile itself.
        let bytes = encode_with_timestamp(
            id,
            &name,
            &current.profile,
            source_url,
            current.record.created_epoch_secs,
        )?;
        ensure_repository_bytes(
            existing.stored_bytes.saturating_sub(replaced_bytes),
            bytes.len(),
        )?;
        directory.write_replace_atomic(&profile_file_name(id), &bytes)?;
        let mut record = current.record;
        record.name = name;
        record.source_kind = ProfileSourceKind::from_source_url(source_url);
        Ok(record)
    }
}
