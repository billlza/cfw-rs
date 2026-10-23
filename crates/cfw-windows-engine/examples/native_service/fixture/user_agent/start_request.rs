use super::*;

pub(super) fn reject_before_vault_access(
    launch: UserAgentLaunch,
    service: &str,
    service_image: Arc<VerifiedExecutable>,
    engine: &EngineInstallation,
    root: &Path,
) -> Result<()> {
    // This file cannot be a private vault directory. If preparation resolves
    // credentials before native binding, the result is a storage error instead
    // of the required authenticated ticket rejection below.
    let vault_path = root.join("invalid-vault-directory");
    std::fs::write(&vault_path, b"fixture-non-directory").map_err(|e| e.to_string())?;
    let plan = launch
        .into_plan(WindowsCredentialStore::new(&vault_path))
        .map_err(|e| format!("native request validation accessed vault before binding: {e}"))?;
    let child_directory = root.join("must-not-start");
    let assets = UserAgentRuntime::new(
        VerifiedExecutable::open(&engine.path, engine.digest, &engine.version)
            .map_err(|e| e.to_string())?,
        child_directory.clone(),
        None,
    );
    let mut session = UserAgentSession::new(plan, service.into(), service_image, assets)
        .map_err(|e| e.to_string())?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let outcome = session.run(&AtomicBool::new(false), sender);
    match outcome {
        Err(UserAgentError::Control(error))
            if matches!(
                error.as_ref(),
                ControlError::Wire(WireError::Rejected(Rejection::Ticket))
            ) => {}
        Err(error) => {
            return Err(format!(
                "invalid binding did not precede vault access: {error}"
            ));
        }
        Ok(_) => return Err("invalid runtime ticket started an operation".into()),
    }
    if !matches!(receiver.try_recv(), Err(mpsc::TryRecvError::Disconnected))
        || session
            .local_cleanup()
            .is_none_or(|cleanup| cleanup.process_id().is_some())
        || child_directory.try_exists().map_err(|e| e.to_string())?
        || std::fs::read(&vault_path).map_err(|e| e.to_string())? != b"fixture-non-directory"
    {
        return Err("rejected native binding touched the runtime or lost cleanup evidence".into());
    }
    Ok(())
}
