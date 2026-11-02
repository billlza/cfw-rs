//! Listing snapshots and the credential snapshots and mutations that lock them.

use super::*;

impl ProfileRepository {
    /// Repository entry name of an existing profile.
    ///
    /// This is the only path from a profile id to a filesystem name. It returns
    /// the bare entry name, never a full path, so a caller can reveal or open
    /// the stored envelope without being able to construct a name the repository
    /// would not accept.
    pub fn profile_entry_name(&self, id: &str) -> Result<Option<String>, ProfileError> {
        let id = validate_profile_id(id)?;
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Ok(None);
        };
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        let file_name = profile_file_name(id);
        if directory.entry_exists(&file_name)? {
            Ok(Some(file_name))
        } else {
            Ok(None)
        }
    }

    pub fn snapshot(&self) -> Result<ProfileRepositorySnapshot, ProfileError> {
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Ok(ProfileRepositorySnapshot {
                profiles: Vec::new(),
                invalid_profiles: Vec::new(),
                selected_profile_id: None,
            });
        };
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        self.read_all(&directory)
            .map(|snapshot| ProfileRepositorySnapshot {
                profiles: snapshot.records,
                invalid_profiles: snapshot
                    .invalid
                    .into_iter()
                    .map(|entry| entry.record)
                    .collect(),
                selected_profile_id: snapshot
                    .selection
                    .map(|selection| selection.profile_id().to_owned()),
            })
    }

    /// Returns one lock-consistent, secret-free identity for credential vault
    /// garbage collection. Every managed profile contributes its immutable
    /// references, including selected and newly imported unselected profiles.
    /// It is refused while any entry fails validation, whose references are
    /// unknown, until that entry is deleted.
    pub fn credential_snapshot(&self) -> Result<ProfileCredentialSnapshot, ProfileError> {
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return build_credential_snapshot(&[], None);
        };
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        repository_credential_snapshot(&self.read_all(&directory)?)
    }

    pub fn lock_credential_snapshot(
        &self,
    ) -> Result<LockedProfileCredentialSnapshot, ProfileError> {
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        let snapshot = repository_credential_snapshot(&self.read_all(&directory)?)?;
        Ok(LockedProfileCredentialSnapshot {
            snapshot,
            _directory: directory,
        })
    }

    /// Begins a credential-bearing profile mutation under the same
    /// cross-process lock used by credential garbage-collection commits.
    pub fn begin_credential_profile_mutation(
        &self,
    ) -> Result<LockedCredentialProfileMutation, ProfileError> {
        let directory = RepositoryDirectory::open_or_create(&self.profiles_dir)?;
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;
        Ok(LockedCredentialProfileMutation {
            repository: self.clone(),
            directory,
        })
    }

    /// Begins a credential-bearing replacement only if the profile loaded
    /// before external I/O is still the exact repository value. The exclusive
    /// lock remains held across the subsequent vault prepare and repository
    /// commit, so stale subscription responses cannot create orphan audiences.
    pub fn begin_credential_profile_mutation_if_unchanged(
        &self,
        expected: &StoredProfile,
    ) -> Result<LockedCredentialProfileMutation, ProfileError> {
        validate_stored_profile(expected)?;
        let mutation = self.begin_credential_profile_mutation()?;
        let id = validate_profile_id(&expected.record.id)?;
        let current = mutation
            .repository
            .decode(id, mutation.directory.open_profile_file(id)?)?;
        if &current != expected {
            return Err(ProfileError::ProfileChanged { id: id.to_owned() });
        }
        Ok(mutation)
    }
}
