use super::*;
use cfw_windows_engine::{
    authority::{
        AuthorityChannel,
        wire::{Command, Request, Response},
    },
    runtime_host::{InstalledRuntime, SERVICE_NAME},
};
use std::sync::Arc;

/// This fixture is installed as the admitted desktop image in disposable CI.
/// It exercises the production service executable and authenticated commands.
pub(super) fn probe() -> Result<()> {
    if std::env::var("CFW_NATIVE_SERVICE_MUTATION_TESTS").as_deref() != Ok("1") {
        return Err("installed host probe requires disposable CI opt-in".into());
    }
    let installed = InstalledRuntime::open().map_err(|e| e.to_string())?;
    installed
        .require_desktop_process()
        .map_err(|e| e.to_string())?;
    let mut channel = AuthorityChannel::connect(
        SERVICE_NAME,
        ServiceClientRole::Desktop,
        Arc::new(installed.runtime().map_err(|e| e.to_string())?),
    )
    .map_err(|e| e.to_string())?;
    let Response::Observed(snapshot) = channel
        .request(
            Request::new(Command::Observe).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        )
        .map_err(|e| e.to_string())?
    else {
        return Err("installed service omitted status".into());
    };
    let Response::Lineage(lineage) = channel
        .request(
            Request::new(Command::LoadLineage).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        )
        .map_err(|e| e.to_string())?
    else {
        return Err("installed service omitted lineage".into());
    };
    if snapshot.state != cfw_engine_api::authority_v1::AuthorityState::Off
        || snapshot.revision.is_none()
        || snapshot
            .root
            .as_ref()
            .is_none_or(|root| root.installation_id != lineage.installation_id)
    {
        return Err("installed service did not admit exact production Off".into());
    }
    println!(
        "{}",
        serde_json::json!({"snapshot":snapshot,"lineage":lineage,"authenticated_product_service":true,"release_accepted":false})
    );
    Ok(())
}
