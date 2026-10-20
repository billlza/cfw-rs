//! Exercise the actual application observer in a real medium-integrity process.
use super::{Result, restricted};

#[path = "../../../../../apps/cfw-tauri-shell/src/process_identity.rs"]
mod process_identity;

pub(super) fn observe() -> Result<serde_json::Value> {
    let native = restricted::require_medium_user_context()?;
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let observed: process_identity::ProcessIdentity =
        process_identity::current_process_identity(&executable)
            .map_err(|error| format!("observe current desktop identity: {error}"))?;
    let wire = serde_json::to_value(&observed).map_err(|e| e.to_string())?;
    let decoded: process_identity::ProcessIdentity =
        serde_json::from_value(wire.clone()).map_err(|e| e.to_string())?;
    let present = process_identity::process_identity_exists(&decoded)
        .map_err(|error| format!("reobserve persisted desktop identity: {error}"))?;
    let processes = process_identity::exact_processes(&executable)
        .map_err(|error| format!("enumerate current desktop logon: {error}"))?;
    if !observed.is_this_process()
        || decoded != observed
        || !present
        || !processes.contains(&observed)
        || wire["logon"]["sid"] != native.identity().user_sid()
        || wire["logon"]["authentication_id"] != native.identity().authentication_id()
        || wire["logon"]["session_id"] != native.identity().session_id()
        || wire["creation_filetime"] != native.identity().process_creation_time()
        || wire.get("uid").is_some()
    {
        return Err(
            "desktop process observer lost native identity or failed current-session enumeration"
                .into(),
        );
    }
    Ok(serde_json::json!({
        "medium_integrity": true, "administrator_member": false,
        "actual_desktop_module": true, "native_logon_and_filetime_preserved": true,
        "serialized_claim_reobserved": true, "current_session_contains_self": true,
        "pid": native.process_id(),
        "creation_filetime": native.identity().process_creation_time(),
        "system_wide_absence_proven": false,
    }))
}
