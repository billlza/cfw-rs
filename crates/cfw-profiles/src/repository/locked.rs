//! Reads and writes of a credential profile mutation, made under the lock it
//! retains through online preparation.

use super::*;

impl LockedCredentialProfileMutation {
    /// Reads selection under the lock retained through online preparation.
    pub fn selected_profile(&self) -> Result<ProfileSelectionState, ProfileError> {
        let snapshot = self.repository.read_all(&self.directory)?;
        let Some(selection) = snapshot.selection else {
            return Ok(ProfileSelectionState::Unselected);
        };
        let file = self.directory.open_profile_file(selection.profile_id())?;
        Ok(
            match self.repository.decode_entry(selection.profile_id(), file)? {
                StoredEntry::Valid(stored) => ProfileSelectionState::Valid(stored),
                StoredEntry::Invalid(entry) => ProfileSelectionState::Invalid(entry.record),
            },
        )
    }

    pub fn profile(&self, id: &str) -> Result<StoredProfile, ProfileError> {
        let id = validate_profile_id(id)?;
        self.repository
            .decode(id, self.directory.open_profile_file(id)?)
    }

    /// Selection is committed only after a candidate runtime is ready. A failed
    /// durable write restores the prior selection before releasing the lock.
    pub fn commit_selection(self, id: &str) -> Result<ProfileRecord, ProfileError> {
        self.select_recovering(id)
    }

    pub fn commit_exact_import_and_select(
        self,
        id: &str,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
        activate: bool,
    ) -> Result<ExactProfileImportOutcome, ProfileError> {
        let imported = self
            .repository
            .import_with_id_and_source_outcome_in_directory(
                &self.directory,
                id,
                name,
                profile,
                source_url,
            )?;
        if activate && imported.created {
            self.select_recovering(id)?;
        }
        Ok(imported)
    }

    fn select_recovering(&self, id: &str) -> Result<ProfileRecord, ProfileError> {
        let previous = self.repository.read_all(&self.directory)?.selection;
        match self.repository.select_in_directory(&self.directory, id) {
            Ok(record) => Ok(record),
            Err(operation) => {
                let recovery = (|| {
                    if let Some(previous) = previous {
                        self.directory.write_replace_atomic(
                            SELECTION_FILE_NAME,
                            &encode_selection(&previous)?,
                        )?;
                    } else if self.directory.entry_exists(SELECTION_FILE_NAME)? {
                        self.directory.unlink(SELECTION_FILE_NAME)?;
                        self.directory.sync_committed(SELECTION_FILE_NAME)?;
                    }
                    Ok::<_, ProfileError>(())
                })();
                match recovery {
                    Ok(()) => Err(operation),
                    Err(recovery) => Err(ProfileError::SelectedReplaceRecovery {
                        operation: operation.to_string(),
                        recovery: recovery.to_string(),
                    }),
                }
            }
        }
    }

    /// Commits one exact-ID import and then releases the repository lock.
    pub fn commit_exact_import(
        self,
        id: &str,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<ExactProfileImportOutcome, ProfileError> {
        self.repository
            .import_with_id_and_source_outcome_in_directory(
                &self.directory,
                id,
                name,
                profile,
                source_url,
            )
    }

    /// Commits one compare-and-swap replacement and then releases the lock.
    pub fn commit_replace_if_unchanged(
        self,
        expected: &StoredProfile,
        name: Option<&str>,
        profile: &ValidatedSingBoxProfile,
        source_url: Option<&str>,
    ) -> Result<(ProfileImportResult, StoredProfile), ProfileError> {
        validate_stored_profile(expected)?;
        let selection = self.repository.read_all(&self.directory)?.selection;
        let result = self.repository.replace_with_timestamp_in_directory(
            &self.directory,
            ProfileReplacement {
                id: &expected.record.id,
                name,
                profile,
                source_url,
                created_epoch_secs: None,
                expected: Some(expected),
            },
        );
        match result {
            Ok(committed) => Ok(committed),
            Err(operation) => {
                if matches!(&operation, ProfileError::ProfileChanged { .. }) {
                    return Err(operation);
                }
                // A post-rename durability failure may have exposed the new
                // file. Under the retained lock, compensate only the exact
                // old/candidate states; never overwrite an unrelated edit.
                let recovery = (|| {
                    let current = self.profile(&expected.record.id)?;
                    if current == *expected
                        && !self.directory.entry_exists(SELECTED_REPLACE_FILE_NAME)?
                    {
                        return Ok(());
                    }
                    if current != *expected {
                        let candidate_name = name
                            .map(normalize_name)
                            .transpose()?
                            .unwrap_or_else(|| expected.record.name.clone());
                        if current.profile != *profile
                            || current.record.name != candidate_name
                            || current.source_url.as_deref() != source_url
                        {
                            return Err(ProfileError::ProfileChanged {
                                id: expected.record.id.clone(),
                            });
                        }
                        let bytes = encode_with_timestamp(
                            &expected.record.id,
                            &expected.record.name,
                            &expected.profile,
                            expected.source_url.as_deref(),
                            expected.record.created_epoch_secs,
                        )?;
                        self.directory.write_replace_atomic(
                            &profile_file_name(&expected.record.id),
                            &bytes,
                        )?;
                    }
                    if let Some(selection) =
                        selection.filter(|value| value.profile_id() == expected.record.id)
                    {
                        self.directory.write_replace_atomic(
                            SELECTION_FILE_NAME,
                            &encode_selection(&selection)?,
                        )?;
                    }
                    self.repository.recover_repository(&self.directory)?;
                    Ok::<_, ProfileError>(())
                })();
                match recovery {
                    Ok(()) => Err(operation),
                    Err(recovery) => Err(ProfileError::SelectedReplaceRecovery {
                        operation: operation.to_string(),
                        recovery: recovery.to_string(),
                    }),
                }
            }
        }
    }
}
