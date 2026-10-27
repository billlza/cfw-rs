use super::*;

impl Service {
    /// This raw fixture trigger calls the trusted supervisor API; it is not a
    /// production wire command and supplies no cleanup evidence or resource ID.
    pub(crate) fn reconcile_local_recovery(&mut self) -> Result<()> {
        if self.mode != Mode::Local
            || !self.recovered
            || self.cleanup_publications != 0
            || self.proxy_observations != 0
        {
            return Err("invalid local recovery fixture sequence".into());
        }
        let authority = self
            .authority
            .as_mut()
            .ok_or("missing local recovery authority")?;
        let before = authority.snapshot();
        let prior = authority
            .recovery_target()
            .cloned()
            .ok_or("missing local recovery record")?;
        if before.state != AuthorityState::Recovering || authority.lease_owner().is_some() {
            return Err("local recovery restored execution before cleanup".into());
        }
        let verified = authority
            .reconcile_local_recovery()
            .map_err(|e| e.to_string())?;
        let metadata = authority
            .recovery_target()
            .cloned()
            .ok_or("local recovery lost its committed record")?;
        if verified.prior() != &prior
            || verified.snapshot().state != AuthorityState::Off
            || verified.snapshot().revision != prior.revision().checked_add(1)
            || metadata.operation().is_some()
            || metadata.transition()
                != cfw_windows_engine::authority_journal::JournalTransition::ReconcileOff
            || authority.lease_owner().is_some()
        {
            return Err("local recovery did not commit exact Off without a lease".into());
        }
        if !matches!(
            authority.reconcile_local_recovery(),
            Err(AuthorityError::Recovering)
        ) || authority.snapshot() != *verified.snapshot()
        {
            return Err("completed local recovery was replayed".into());
        }
        publish(
            &self.root,
            "runtime-restart-local-cleanup.json",
            &serde_json::json!({
                "prior":prior,"before":before,"processes":authority_wire::process_report("local_recovery",verified.processes()),
                "snapshot":verified.snapshot(),"metadata":metadata,"production_cleanup":true,"lease_restored":false,"replay_rejected":true,
            }),
        )?;
        self.cleanup_publications += 1;
        Ok(())
    }
}

pub(super) fn observe(
    name: &str,
    root: &Path,
    image: Arc<VerifiedExecutable>,
    observer: &mut AuthorityChannel,
    context: &cfw_windows_engine::authority::LeaseContext,
    recorded: &cfw_windows_engine::authority::RecordedRuntimeScope,
) -> Result<()> {
    let mut trigger = ServiceChannel::connect(name, ServiceClientRole::Desktop, image)
        .map_err(|e| e.to_string())?;
    if trigger
        .request(b"authority-local-recovery", Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
        .as_bytes()
        != b"local-off"
    {
        return Err("local recovery supervisor reply differs".into());
    }
    let Response::Observed(snapshot) = observer
        .request(
            Request::new(Command::Observe).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        )
        .map_err(|e| e.to_string())?
    else {
        return Err("local recovery did not expose a fresh state".into());
    };
    if snapshot.state != AuthorityState::Off
        || snapshot.root.as_ref() != Some(&context.operation.root)
        || snapshot.revision != recorded.snapshot().revision.and_then(|v| v.checked_add(1))
    {
        return Err("local recovery fresh Off does not match its former runtime".into());
    }
    if !matches!(
        observer.request(
            Request::new(Command::OwnedLease).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT
        ),
        Err(WireError::Rejected(Rejection::Identity))
    ) {
        return Err("local recovery restored a former execution lease".into());
    }
    publish(
        root,
        "runtime-restart-local-observer.json",
        &serde_json::json!({
            "context":context,"snapshot":snapshot,"fresh_off_observed":true,"old_execution_lease_absent":true,
        }),
    )
}
