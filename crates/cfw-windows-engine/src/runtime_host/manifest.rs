use super::*;
use serde::Deserialize;

pub(super) const MAX_MANIFEST: usize = 4096;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    schema_version: u32,
    product_version: String,
    architecture: String,
    pub(super) engine_version: String,
    pub(super) runtime_sha256: String,
    pub(super) desktop_sha256: String,
    pub(super) engine_sha256: String,
}
impl Manifest {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_MANIFEST {
            return Err(HostError::Manifest);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| HostError::Manifest)?;
        if value.schema_version != 1
            || value.product_version != env!("CARGO_PKG_VERSION")
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
#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> serde_json::Value {
        serde_json::json!({"schema_version":1,"product_version":"0.5.0","architecture":"x86_64","engine_version":"1.14.2","runtime_sha256":"a1".repeat(32),"desktop_sha256":"b2".repeat(32),"engine_sha256":"c3".repeat(32)})
    }
    #[test]
    fn installation_manifest_is_closed_and_cannot_select_paths_service_or_another_contract() {
        let original = manifest();
        Manifest::decode(&serde_json::to_vec(&original).unwrap()).unwrap();
        for (key, value) in [
            ("path", serde_json::json!("C:\\evil")),
            ("service_name", serde_json::json!("other")),
            ("schema_version", serde_json::json!(2)),
            ("product_version", serde_json::json!("0.4.0")),
            ("architecture", serde_json::json!("arm64")),
            ("engine_sha256", serde_json::json!("AB".repeat(32))),
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
        duplicate.push_str(",\"schema_version\":1}");
        assert!(Manifest::decode(duplicate.as_bytes()).is_err());
        assert!(Manifest::decode(&vec![b' '; MAX_MANIFEST + 1]).is_err());
        assert!(Manifest::decode(b"{}").is_err());
    }
}
