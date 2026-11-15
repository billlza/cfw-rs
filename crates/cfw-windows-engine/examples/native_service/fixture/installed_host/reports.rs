//! What the installed suites leave for the receipts directory beyond their
//! own reports: a diagnostic of an expired suite, and the combined report.
use super::*;

/// Failure diagnostics only: the expired test remains failed. Query before
/// terminating the exact client, so loss of that owner cannot erase its phase.
pub(in super::super) fn timeout_snapshot(directory: &Path, prefix: &str) -> Result<()> {
    let observed = (|| -> Result<serde_json::Value> {
        let installed = InstalledRuntime::open().map_err(|e| e.to_string())?;
        let mut channel = AuthorityChannel::connect(
            SERVICE_NAME,
            ServiceClientRole::Desktop,
            Arc::new(installed.runtime().map_err(|e| e.to_string())?),
        )
        .map_err(|e| e.to_string())?;
        let response = channel
            .request(
                Request::new(Command::ReadRuntimeScope).map_err(|e| e.to_string())?,
                Instant::now() + Duration::from_secs(5),
            )
            .map_err(|e| e.to_string())?;
        let Response::RuntimeScope(scope) = response else {
            return Err("timeout diagnostic omitted runtime scope".into());
        };
        Ok(serde_json::json!({"snapshot":scope.snapshot(),"operation":scope.operation()}))
    })();
    let observation = match observed {
        Ok(scope) => serde_json::json!({"status":"observed","scope":scope}),
        Err(error) => serde_json::json!({"status":"observation_failed","error":error}),
    };
    let bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "product_source":std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e|e.to_string())?,
        "test_deadline_exceeded":true,"observation":observation,"release_accepted":false,
    }))
    .map_err(|e| e.to_string())?;
    if bytes.len() > 16384 {
        return Err("timeout diagnostic exceeds its bound".into());
    }
    std::fs::write(
        directory.join(format!("{prefix}-timeout-scope.json")),
        bytes,
    )
    .map_err(|e| e.to_string())
}

pub(in super::super) fn combine_reports(directory: &Path) -> Result<()> {
    fn read(path: &Path) -> Result<serde_json::Value> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|e| e.to_string())?
            .take(16385)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 16384 {
            return Err("installed case report exceeds its bound".into());
        }
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    }
    let mut direct = read(&directory.join("installed-host-lifecycle.json"))?;
    let modes = read(&directory.join("installed-host-backend-lifecycle.json"))?;
    let exited = read(&directory.join("installed-host-backend-exit-lifecycle.json"))?;
    for (report, key) in [(&modes, "backend_modes"), (&exited, "backend_exit")] {
        if report["source"] != direct["source"]
            || report["release_accepted"] != false
            || report[key]["shared_engine_backend"] != true
            || report[key]["proxy_restored"] != true
            || report[key]["listeners_released"] != true
        {
            return Err("backend suites do not share verified source and cleanup".into());
        }
    }
    let mut backend = modes["backend_modes"].clone();
    let combined = backend
        .as_object_mut()
        .ok_or("missing normal backend evidence")?;
    if combined
        .insert(
            "failure_case".into(),
            exited["backend_exit"]["failure_case"].clone(),
        )
        .is_some()
        || combined
            .insert(
                "exited_engine_query_rejected".into(),
                exited["backend_exit"]["exited_engine_query_rejected"].clone(),
            )
            .is_some()
    {
        return Err("backend failure evidence was already combined".into());
    }
    combined
        .get_mut("authorizations")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("missing normal authorization evidence")?
        .extend(
            exited["backend_exit"]["authorizations"]
                .as_array()
                .ok_or("missing final authorization evidence")?
                .iter()
                .cloned(),
        );
    if direct
        .as_object_mut()
        .ok_or("installed report is not an object")?
        .insert("backend".into(), backend)
        .is_some()
    {
        return Err("backend evidence was already combined".into());
    }
    for (suite, key, proof) in [
        (
            InstalledSuite::Profile,
            "profile_probes",
            "shared_profile_delay_backend",
        ),
        (
            InstalledSuite::Coordinator,
            "coordinator",
            "shared_mode_coordinator",
        ),
        (
            InstalledSuite::Startup,
            "startup_registration",
            "registration_removed",
        ),
        (InstalledSuite::Tunnel, "backend_tunnel", "tunnel_runtime"),
    ] {
        let report = read(&directory.join(format!("{}-lifecycle.json", suite.prefix())))?;
        if direct["source"] != report["source"]
            || report[key][proof] != true
            || report["release_accepted"] != false
        {
            return Err("installed suites do not share verified source and scope".into());
        }
        if direct
            .as_object_mut()
            .ok_or("installed report is not an object")?
            .insert(key.into(), report[key].clone())
            .is_some()
        {
            return Err("installed suite report was already combined".into());
        }
    }
    let bytes = serde_json::to_vec(&direct).map_err(|e| e.to_string())?;
    if bytes.len() > 16384 {
        return Err("combined installed report exceeds its original bound".into());
    }
    std::fs::write(directory.join("installed-host-lifecycle.json"), bytes)
        .map_err(|e| e.to_string())
}
