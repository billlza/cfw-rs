use super::*;
use serde::Deserialize;

pub(super) const MAX_MANIFEST: usize = 4096;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    schema_version: u32,
    pub(super) product_version: String,
    pub(super) build_number: u64,
    pub(super) msi_product_code: String,
    pub(super) msi_package_code: String,
    architecture: String,
    pub(super) engine_version: String,
    pub(super) runtime_sha256: String,
    pub(super) desktop_sha256: String,
    pub(super) engine_sha256: String,
}
impl Manifest {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        Self::decode_for_version(bytes, env!("CARGO_PKG_VERSION"))
    }
    /// Only the read-only updater observation uses another expected version.
    /// Normal host admission remains bound to this executable's own version.
    pub(super) fn decode_for_version(bytes: &[u8], version: &str) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_MANIFEST {
            return Err(HostError::Manifest);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| HostError::Manifest)?;
        if value.schema_version != 2
            || value.product_version != version
            || !semver::Version::parse(version).is_ok_and(|v| v.to_string() == version)
            || value.build_number == 0
            || !canonical_guid(&value.msi_product_code)
            || !canonical_guid(&value.msi_package_code)
            || value.msi_product_code == value.msi_package_code
            || value.msi_product_code == MSI_UPGRADE_CODE
            || value.msi_package_code == MSI_UPGRADE_CODE
            || value.architecture != "x86_64"
            || value.engine_version.is_empty()
            || value.engine_version.len() > 32
            || !value
                .engine_version
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'.')
        {
            return Err(HostError::Manifest);
        }
        for digest in [
            &value.runtime_sha256,
            &value.desktop_sha256,
            &value.engine_sha256,
        ] {
            Self::digest(digest)?;
        }
        Ok(value)
    }
    pub(super) fn digest(value: &str) -> Result<[u8; 32]> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(HostError::Manifest);
        }
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| HostError::Manifest)?;
        }
        Ok(bytes)
    }
}

fn canonical_guid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|id| !id.is_nil() && id.braced().to_string().to_ascii_uppercase() == value)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> serde_json::Value {
        serde_json::json!({"schema_version":2,"product_version":env!("CARGO_PKG_VERSION"),"build_number":1,
            "msi_product_code":"{E66ACF84-7639-4707-BC01-0A370C9B2E3E}",
            "msi_package_code":"{E58D1FC6-A003-4849-900C-45D6861E75D9}",
            "architecture":"x86_64","engine_version":"1.14.2","runtime_sha256":"a1".repeat(32),"desktop_sha256":"b2".repeat(32),"engine_sha256":"c3".repeat(32)})
    }
    #[test]
    fn update_observation_of_a_new_version_does_not_relax_runtime_host_admission() {
        let mut next = manifest();
        let (newer, later) = ("0.6.0", "0.6.1");
        assert_ne!(env!("CARGO_PKG_VERSION"), newer);
        next["product_version"] = serde_json::json!(newer);
        let bytes = serde_json::to_vec(&next).unwrap();
        assert!(Manifest::decode(&bytes).is_err());
        Manifest::decode_for_version(&bytes, newer).unwrap();
        assert!(Manifest::decode_for_version(&bytes, later).is_err());
        for version in ["", "05.1", "0.5.01", "not-a-version"] {
            next["product_version"] = serde_json::json!(version);
            assert!(
                Manifest::decode_for_version(&serde_json::to_vec(&next).unwrap(), version).is_err()
            );
        }
    }
    #[test]
    fn installation_manifest_is_closed_and_cannot_select_paths_service_or_another_contract() {
        let original = manifest();
        Manifest::decode(&serde_json::to_vec(&original).unwrap()).unwrap();
        for (key, value) in [
            ("path", serde_json::json!("C:\\evil")),
            ("service_name", serde_json::json!("other")),
            ("schema_version", serde_json::json!(1)),
            ("product_version", serde_json::json!("0.4.0")),
            ("architecture", serde_json::json!("arm64")),
            ("engine_sha256", serde_json::json!("AB".repeat(32))),
            ("build_number", serde_json::json!(0)),
            ("build_number", serde_json::json!("1")),
            ("msi_product_code", serde_json::json!("not-a-guid")),
            (
                "msi_package_code",
                serde_json::json!("{00000000-0000-0000-0000-000000000000}"),
            ),
            ("msi_package_code", original["msi_product_code"].clone()),
            ("msi_product_code", serde_json::json!(MSI_UPGRADE_CODE)),
            ("msi_package_code", serde_json::json!(MSI_UPGRADE_CODE)),
            (
                "msi_package_code",
                serde_json::json!("{e58d1fc6-a003-4849-900c-45d6861e75d9}"),
            ),
        ] {
            let mut altered = original.clone();
            altered[key] = value;
            assert!(
                Manifest::decode(&serde_json::to_vec(&altered).unwrap()).is_err(),
                "{key}"
            );
        }
        let mut duplicate = serde_json::to_string(&original).unwrap();
        duplicate.pop();
        duplicate.push_str(",\"schema_version\":2}");
        assert!(Manifest::decode(duplicate.as_bytes()).is_err());
        assert!(Manifest::decode(&vec![b' '; MAX_MANIFEST + 1]).is_err());
        assert!(Manifest::decode(b"{}").is_err());
        for required in ["build_number", "msi_product_code", "msi_package_code"] {
            let mut incomplete = original.clone();
            incomplete.as_object_mut().unwrap().remove(required);
            assert!(Manifest::decode(&serde_json::to_vec(&incomplete).unwrap()).is_err());
        }
    }
}
