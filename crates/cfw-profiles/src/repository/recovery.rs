//! Recovery of owned temporaries and of an interrupted selected-profile
//! replacement.

use super::*;

impl ProfileRepository {
    pub(super) fn recover_repository(
        &self,
        directory: &RepositoryDirectory,
    ) -> Result<(), ProfileError> {
        directory.recover_owned_temporaries()?;
        self.recover_selected_replace(directory).map(|_| ())
    }

    fn recover_selected_replace(
        &self,
        directory: &RepositoryDirectory,
    ) -> Result<SelectedReplaceRecovery, ProfileError> {
        if !directory.entry_exists(SELECTED_REPLACE_FILE_NAME)? {
            return Ok(SelectedReplaceRecovery::None);
        }
        let intent = selected_replace::decode(directory.open_selected_replace_file()?)?;
        match self.selected_replace_state(directory, &intent)? {
            SelectedReplaceState::Previous => {
                self.finish_selected_replace(directory)?;
                Ok(SelectedReplaceRecovery::Aborted)
            }
            SelectedReplaceState::ReplacementProfileWithPreviousSelection => {
                let selection = ProfileSelection::new(
                    intent.profile_id(),
                    intent.replacement_profile_digest(),
                )?;
                directory
                    .write_replace_atomic(SELECTION_FILE_NAME, &encode_selection(&selection)?)?;
                if self.selected_replace_state(directory, &intent)?
                    != SelectedReplaceState::Replacement
                {
                    return Err(ProfileError::SelectedReplaceConflict(
                        "selection roll-forward did not produce the exact replacement state".into(),
                    ));
                }
                self.finish_selected_replace(directory)?;
                Ok(SelectedReplaceRecovery::Committed)
            }
            SelectedReplaceState::Replacement => {
                self.finish_selected_replace(directory)?;
                Ok(SelectedReplaceRecovery::Committed)
            }
        }
    }

    pub(super) fn recover_after_selected_replace_error(
        &self,
        directory: &RepositoryDirectory,
        operation: &ProfileError,
    ) -> Result<SelectedReplaceRecovery, ProfileError> {
        directory
            .recover_owned_temporaries()
            .and_then(|_| self.recover_selected_replace(directory))
            .map_err(|recovery| ProfileError::SelectedReplaceRecovery {
                operation: operation.to_string(),
                recovery: recovery.to_string(),
            })
    }

    fn selected_replace_state(
        &self,
        directory: &RepositoryDirectory,
        intent: &SelectedProfileReplaceIntent,
    ) -> Result<SelectedReplaceState, ProfileError> {
        let current = self
            .decode_entry(
                intent.profile_id(),
                directory
                    .open_profile_file(intent.profile_id())
                    .map_err(|error| {
                        ProfileError::SelectedReplaceConflict(format!(
                            "replacement profile is unavailable: {error}"
                        ))
                    })?,
            )
            .map_err(|error| {
                ProfileError::SelectedReplaceConflict(format!(
                    "replacement profile is unreadable: {error}"
                ))
            })?;
        let selection = decode_selection(directory.open_selection_file().map_err(|error| {
            ProfileError::SelectedReplaceConflict(format!(
                "selected-profile metadata is unavailable: {error}"
            ))
        })?)
        .map_err(|error| {
            ProfileError::SelectedReplaceConflict(format!(
                "selected-profile metadata is unreadable: {error}"
            ))
        })?;
        if selection.profile_id() != intent.profile_id() {
            return Err(ProfileError::SelectedReplaceConflict(
                "selected profile identity changed while replacement intent was pending".into(),
            ));
        }

        // An interrupted replacement still resolves when this build rejects
        // either document: an invalid entry is matched by its stored digests.
        let (current_envelope_digest, current_profile_digest) = match &current {
            StoredEntry::Valid(stored) => (
                stored_envelope_digest(stored)?,
                stored.record.digest.as_str(),
            ),
            StoredEntry::Invalid(entry) => (entry.envelope_digest.clone(), entry.digest.as_str()),
        };
        let selected_profile_digest = selection.profile_digest();
        if current_envelope_digest == intent.previous_envelope_digest()
            && current_profile_digest == intent.previous_profile_digest()
            && selected_profile_digest == intent.previous_profile_digest()
        {
            Ok(SelectedReplaceState::Previous)
        } else if current_envelope_digest == intent.replacement_envelope_digest()
            && current_profile_digest == intent.replacement_profile_digest()
            && selected_profile_digest == intent.previous_profile_digest()
        {
            Ok(SelectedReplaceState::ReplacementProfileWithPreviousSelection)
        } else if current_envelope_digest == intent.replacement_envelope_digest()
            && current_profile_digest == intent.replacement_profile_digest()
            && selected_profile_digest == intent.replacement_profile_digest()
        {
            Ok(SelectedReplaceState::Replacement)
        } else {
            Err(ProfileError::SelectedReplaceConflict(
                "profile envelope and selection do not match an allowed transaction phase".into(),
            ))
        }
    }

    pub(super) fn finish_selected_replace(
        &self,
        directory: &RepositoryDirectory,
    ) -> Result<(), ProfileError> {
        directory.unlink(SELECTED_REPLACE_FILE_NAME)?;
        directory.sync_committed(SELECTED_REPLACE_FILE_NAME)
    }
}
