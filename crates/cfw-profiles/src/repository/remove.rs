//! Deleting one profile entry and clearing the managed profiles.

use super::*;

impl ProfileRepository {
    /// Deletes one unselected profile, or the selected one when it fails
    /// validation and the caller holds the engine Off. Deleting never selects
    /// another profile.
    pub fn delete(
        &self,
        id: &str,
        invalid_selection: InvalidSelection,
    ) -> Result<bool, ProfileError> {
        let id = validate_profile_id(id)?;
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Ok(false);
        };
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        let snapshot = self.read_all(&directory)?;
        let clears_selection = snapshot
            .selection
            .as_ref()
            .is_some_and(|selection| selection.profile_id() == id);
        if clears_selection {
            match (snapshot.invalid(id), invalid_selection) {
                (None, _) => return Err(ProfileError::SelectedProfileDeletion(id.to_owned())),
                (Some(entry), InvalidSelection::Keep) => {
                    return Err(ProfileError::InvalidSelectionKept(entry.record.label()));
                }
                (Some(_), InvalidSelection::Clear) => {}
            }
        }
        let file = match directory.open_profile_file(id) {
            Ok(file) => file,
            Err(ProfileError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        // An entry that fails validation is deleted like a valid one; corrupt
        // or unsafe entries still fail closed before anything is unlinked.
        self.decode_entry(id, file)?;
        if clears_selection {
            // Selection first: an interrupted deletion leaves the entry listed
            // and unselected, never a selection naming a missing profile.
            directory.unlink(SELECTION_FILE_NAME)?;
            directory.sync_committed(SELECTION_FILE_NAME)?;
        }
        directory.unlink(&profile_file_name(id))?;
        directory.sync_committed(&profile_file_name(id))?;
        Ok(true)
    }

    /// Permanently removes the contents of the application-managed profiles
    /// directory without reading, converting, backing up, or following them.
    ///
    /// This one-way migration API intentionally refuses to traverse real
    /// subdirectories. Symlinks are unlinked as directory entries, so their
    /// external targets are never touched.
    pub fn clear_managed_profiles(&self) -> Result<usize, ProfileError> {
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Ok(0);
        };
        directory.lock_exclusive()?;
        let entries = directory.entry_names()?;
        for name in &entries {
            if directory.entry_is_directory(name)? {
                return Err(ProfileError::UnexpectedManagedSubdirectory(
                    name.to_string_lossy().into_owned(),
                ));
            }
        }
        let mut removed = 0;
        for name in &entries {
            if let Err(error) = directory.unlink_os(name) {
                if removed == 0 {
                    return Err(error);
                }
                return Err(ProfileError::PartialManagedCleanup {
                    removed,
                    operation: error.to_string(),
                });
            }
            removed += 1;
        }
        if removed > 0 {
            directory.sync_committed("managed profile cleanup")?;
        }
        Ok(entries.len())
    }
}
