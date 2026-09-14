//! Private application settings storage. The data-plane crate owns the typed
//! runtime preferences; this layer only owns bounded canonical storage and CAS.
use crate::{
    SettingsStore, SettingsStoreError,
    settings_storage::{FilePolicy, SecureDirectory},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const FILE_NAME: &str = "cfw-runtime-settings.json";
const AUTOMATION_FILE_NAME: &str = "cfw-automation-settings.json";
const MAX_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeDocument<T> {
    schema_version: u16,
    settings: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeSettingsSnapshot<T> {
    pub settings: T,
    pub revision: Option<String>,
}

impl SettingsStore {
    pub fn runtime_settings<T: Serialize + DeserializeOwned + Default>(
        &self,
    ) -> Result<RuntimeSettingsSnapshot<T>, SettingsStoreError> {
        self.structured_settings(FILE_NAME)
    }

    pub fn automation_settings<T: Serialize + DeserializeOwned + Default>(
        &self,
    ) -> Result<RuntimeSettingsSnapshot<T>, SettingsStoreError> {
        self.structured_settings(AUTOMATION_FILE_NAME)
    }

    fn structured_settings<T: Serialize + DeserializeOwned + Default>(
        &self,
        file_name: &str,
    ) -> Result<RuntimeSettingsSnapshot<T>, SettingsStoreError> {
        let directory = SecureDirectory::open_or_create(&self.paths().app_home)?;
        let Some(stored) = directory.read_optional(file_name, MAX_BYTES, FilePolicy::Private)?
        else {
            return Ok(RuntimeSettingsSnapshot {
                settings: T::default(),
                revision: None,
            });
        };
        let document: RuntimeDocument<T> = serde_json::from_slice(&stored.bytes)?;
        if document.schema_version != 1 {
            return Err(SettingsStoreError::UnsupportedSchema(
                document.schema_version,
            ));
        }
        if serde_json::to_vec(&document)? != stored.bytes {
            return Err(SettingsStoreError::NonCanonicalJson);
        }
        Ok(RuntimeSettingsSnapshot {
            settings: document.settings,
            revision: Some(stored.identity.revision()),
        })
    }

    pub fn compare_and_swap_runtime_settings<T: Serialize>(
        &self,
        expected_revision: Option<&str>,
        settings: &T,
    ) -> Result<(), SettingsStoreError> {
        self.compare_and_swap_structured_settings(FILE_NAME, expected_revision, settings)
    }

    pub fn compare_and_swap_automation_settings<T: Serialize>(
        &self,
        expected_revision: Option<&str>,
        settings: &T,
    ) -> Result<(), SettingsStoreError> {
        self.compare_and_swap_structured_settings(AUTOMATION_FILE_NAME, expected_revision, settings)
    }

    fn compare_and_swap_structured_settings<T: Serialize>(
        &self,
        file_name: &str,
        expected_revision: Option<&str>,
        settings: &T,
    ) -> Result<(), SettingsStoreError> {
        let document = RuntimeDocument {
            schema_version: 1,
            settings,
        };
        let bytes = serde_json::to_vec(&document)?;
        SecureDirectory::open_or_create(&self.paths().app_home)?.compare_and_swap_atomic(
            file_name,
            expected_revision,
            &bytes,
            MAX_BYTES,
        )
    }
}
