use cfw_core::update::ReleaseTarget;
use reqwest::Url;
use serde_json::Value;

pub(super) use cfw_core::update::{UpdateAuthorization, UpdateContractError};

pub(super) fn target() -> Result<ReleaseTarget, UpdateContractError> {
    ReleaseTarget::for_platform(std::env::consts::OS, std::env::consts::ARCH)
}

pub(super) fn validate_update(
    version: &str,
    download_url: &Url,
    signature: &str,
    raw_manifest: &Value,
) -> Result<UpdateAuthorization, UpdateContractError> {
    cfw_core::update::validate_update(target()?, version, download_url, signature, raw_manifest)
}
