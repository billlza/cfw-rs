use core_foundation::data::CFData;
use security_framework::item::{
    ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, ItemUpdateOptions, ItemUpdateValue,
    Location, SearchResult, update_item,
};
use security_framework::passwords::{PasswordOptions, generic_password};
use security_framework_sys::base::{errSecDuplicateItem, errSecItemNotFound};

use super::{
    AuthorityRecord, CompareExchangeOutcome, CreateOutcome, GenerationStoreError, LineageAuthority,
};

const SERVICE: &str = "com.bill.clashformac.engine-lineage";
const ACCOUNT: &str = "canonical";
pub(super) const HOST_KEYCHAIN_ACCESS_GROUP: &str = "YKUPL7Z869.com.bill.clashformac";

pub(super) struct MacOsKeychainAuthority;

impl MacOsKeychainAuthority {
    fn password_options() -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(SERVICE, ACCOUNT);
        options.set_access_group(HOST_KEYCHAIN_ACCESS_GROUP);
        options.set_access_synchronized(Some(false));
        options.use_protected_keychain();
        options
    }

    fn search(revision: Option<&str>, load_data: bool) -> ItemSearchOptions {
        let mut search = ItemSearchOptions::new();
        search
            .ignore_legacy_keychains()
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(ACCOUNT)
            .access_group(HOST_KEYCHAIN_ACCESS_GROUP)
            .cloud_sync(Some(false))
            .load_data(load_data);
        if let Some(revision) = revision {
            search.label(revision);
        }
        search
    }
}

impl LineageAuthority for MacOsKeychainAuthority {
    fn load(&self) -> Result<Option<AuthorityRecord>, GenerationStoreError> {
        let bytes = match generic_password(Self::password_options()) {
            Ok(bytes) => bytes,
            Err(error) if error.code() == errSecItemNotFound => return Ok(None),
            Err(error) => {
                return Err(GenerationStoreError::AuthorityLoad(format!(
                    "Security.framework status {}: {error}",
                    error.code()
                )));
            }
        };
        let revision = super::revision_for(&bytes);
        let results = Self::search(Some(&revision), true)
            .search()
            .map_err(|error| {
                GenerationStoreError::AuthorityInconsistent(format!(
                    "document and revision are not an atomic pair (status {}: {error})",
                    error.code()
                ))
            })?;
        match results.as_slice() {
            [SearchResult::Data(matched)] if matched == &bytes => {
                Ok(Some(AuthorityRecord { bytes, revision }))
            }
            _ => Err(GenerationStoreError::AuthorityInconsistent(
                "expected exactly one Keychain item matching its document revision".into(),
            )),
        }
    }

    fn create(&self, record: &AuthorityRecord) -> Result<CreateOutcome, GenerationStoreError> {
        let mut options = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(&record.bytes),
        });
        options
            .set_location(Location::DataProtectionKeychain)
            .set_service(SERVICE)
            .set_account_name(ACCOUNT)
            .set_access_group(HOST_KEYCHAIN_ACCESS_GROUP)
            .set_label(&record.revision);
        match options.add() {
            Ok(()) => Ok(CreateOutcome::Created),
            Err(error) if error.code() == errSecDuplicateItem => Ok(CreateOutcome::AlreadyExists),
            Err(error) => Err(GenerationStoreError::AuthorityCreate(format!(
                "Security.framework status {}: {error}",
                error.code()
            ))),
        }
    }

    fn compare_exchange(
        &self,
        expected_revision: &str,
        replacement: &AuthorityRecord,
    ) -> Result<CompareExchangeOutcome, GenerationStoreError> {
        let search = Self::search(Some(expected_revision), false);
        let mut update = ItemUpdateOptions::new();
        update
            .set_value(ItemUpdateValue::Data(CFData::from_buffer(
                &replacement.bytes,
            )))
            .set_label(&replacement.revision);
        match update_item(&search, &update) {
            Ok(()) => Ok(CompareExchangeOutcome::Swapped),
            Err(error) if error.code() == errSecItemNotFound => {
                Ok(CompareExchangeOutcome::Conflict)
            }
            Err(error) => Err(GenerationStoreError::AuthoritySave(format!(
                "Security.framework status {}: {error}",
                error.code()
            ))),
        }
    }
}
