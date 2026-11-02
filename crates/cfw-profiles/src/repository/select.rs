//! Selecting the active profile.

use super::*;

impl ProfileRepository {
    pub fn select(&self, id: &str) -> Result<ProfileRecord, ProfileError> {
        let id = validate_profile_id(id)?;
        let Some(directory) = RepositoryDirectory::open_if_present(&self.profiles_dir)? else {
            return Err(ProfileError::SelectedProfileMissing(id.to_owned()));
        };
        directory.lock_exclusive()?;
        self.recover_repository(&directory)?;

        self.select_in_directory(&directory, id)
    }

    pub(super) fn select_in_directory(
        &self,
        directory: &RepositoryDirectory,
        id: &str,
    ) -> Result<ProfileRecord, ProfileError> {
        let id = validate_profile_id(id)?;

        // Selecting a known-good profile is also the explicit recovery path
        // for malformed or stale selection metadata. Profile envelopes remain
        // fully validated before the replacement is committed.
        let profiles = self.read_profiles(directory)?;
        let record = match profiles.records.iter().find(|record| record.id == id) {
            Some(record) => record.clone(),
            None => {
                return Err(match find_invalid(&profiles.invalid, id) {
                    Some(entry) => entry.record.load_error(),
                    None => ProfileError::SelectedProfileMissing(id.to_owned()),
                });
            }
        };
        let selection = ProfileSelection::new(&record.id, &record.digest)?;
        let bytes = encode_selection(&selection)?;
        ensure_repository_bytes(profiles.stored_bytes, bytes.len())?;
        directory.write_replace_atomic(SELECTION_FILE_NAME, &bytes)?;
        Ok(record)
    }
}
