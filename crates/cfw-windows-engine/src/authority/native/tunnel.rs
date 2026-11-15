//! The SYSTEM side of a lease that owns a tunnel. The bound UserAgent opens
//! SYSTEM's own tunnel network and confirms the packet endpoint SYSTEM placed
//! in its process. SYSTEM routes the adapter when it accepts Ready; a combined
//! run has it routed earlier, before it applies this user's proxy settings.
//! Once the lease leaves Starting/Active the supervisor retires that network,
//! and Off needs the retirement's observed adapter absence together with an
//! empty runtime Job, or with the ended logon of a run whose Job is gone. No
//! wire report from the UserAgent is a cleanup fact.
use super::super::wire::TunnelOpenRequest;
use super::*;
use crate::RunMode;
use crate::tunnel::{EndpointHandoff, EndpointOffer, TunnelHost, TunnelNetworkPlan};

/// One Tunnel run's network host and its pending endpoint handoff.
pub(in crate::authority) struct TunnelRun {
    context: LeaseContext,
    host: TunnelHost,
    /// Present from the offer until its confirmation, or until the lease is
    /// no longer live.
    handoff: Option<EndpointHandoff>,
    /// An endpoint was offered; a lost offer is never offered again.
    offered: bool,
    pump_running: bool,
    routed: bool,
}

/// The answer to one OpenTunnel request.
pub(in crate::authority) enum TunnelProgress {
    Pending,
    Offered(EndpointOffer),
}

/// What a supervision tick established about a Tunnel record's network.
enum TunnelNetwork {
    /// Retirement or stale-adapter recovery has not finished yet.
    Pending,
    /// The host thread exited and the adapter was observed absent.
    Retired,
}

impl WindowsAuthority {
    /// The first request starts SYSTEM's tunnel network on its own thread and
    /// reports it pending, so the Authority guard is never held while Windows
    /// creates an adapter or first installs the pinned driver. Repeating the
    /// same request polls; once the link is configured SYSTEM places the
    /// endpoint in the requesting UserAgent and offers it exactly once. Each
    /// authenticated request also renews the bound runtime's liveness.
    pub(in crate::authority) fn open_tunnel(
        &mut self,
        authorization: &ServicePeerAuthorization,
        request: &TunnelOpenRequest,
    ) -> Result<TunnelProgress> {
        let deadline = Instant::now() + ADMISSION;
        let peer = self.admit(authorization, deadline)?;
        let now = Instant::now();
        self.advance_timers(now)?;
        self.machine
            .require_starting_runtime(&peer, &request.context)?;
        if !request.context.operation.mode.owns_tunnel() || !self.keeper_confirmed {
            return Err(AuthorityError::Identity);
        }
        let plan = TunnelNetworkPlan::new(&request.network_options())?;
        let progress = match self.tunnel.as_mut() {
            None => {
                if self.tunnel_recovery.is_some() {
                    return Err(AuthorityError::Stale);
                }
                let host = TunnelHost::start(request.context.operation.root.installation_id, plan)?;
                // Retained at once: whatever happens next, the supervisor
                // retires this host and proves its adapter gone before Off.
                self.tunnel = Some(TunnelRun {
                    context: request.context.clone(),
                    host,
                    handoff: None,
                    offered: false,
                    pump_running: false,
                    routed: false,
                });
                TunnelProgress::Pending
            }
            Some(run) => {
                if run.context != request.context || run.host.plan()? != &plan || run.offered {
                    return Err(AuthorityError::Stale);
                }
                match run.host.poll_link() {
                    None => TunnelProgress::Pending,
                    Some(link) => {
                        link?;
                        let handoff = EndpointHandoff::create(
                            run.host.adapter(),
                            run.host.plan()?.mtu(),
                            authorization,
                        )?;
                        let offer = handoff.offer();
                        run.handoff = Some(handoff);
                        run.offered = true;
                        TunnelProgress::Offered(offer)
                    }
                }
            }
        };
        self.machine
            .heartbeat(&peer, &request.context, Instant::now())?;
        self.after_publication(authorization, Instant::now() + ADMISSION)?;
        Ok(progress)
    }

    pub(in crate::authority) fn confirm_tunnel_endpoint(
        &mut self,
        authorization: &ServicePeerAuthorization,
        context: &LeaseContext,
        value: u64,
    ) -> Result<AuthoritySnapshot> {
        let deadline = Instant::now() + ADMISSION;
        let peer = self.admit(authorization, deadline)?;
        self.advance_timers(Instant::now())?;
        self.machine.require_starting_runtime(&peer, context)?;
        let run = self.tunnel.as_mut().ok_or(AuthorityError::Stale)?;
        if run.context != *context || run.pump_running {
            return Err(AuthorityError::Stale);
        }
        // Confirmation consumes the handoff: any refusal retires the endpoint.
        let handoff = run.handoff.take().ok_or(AuthorityError::Stale)?;
        let server = handoff.confirm(authorization, value)?;
        let policy = run.host.plan()?.delivery_policy()?;
        run.host.start_pump(server, policy, deadline)?;
        run.pump_running = true;
        self.machine.heartbeat(&peer, context, Instant::now())?;
        self.after_publication(authorization, deadline)?;
        Ok(self.snapshot())
    }

    /// A combined run has its adapter routed before it applies this user's
    /// proxy settings, so that those never point at a run without its tunnel.
    /// The pump must be running; Ready still attests its bounds.
    pub(in crate::authority) fn route_tunnel(
        &mut self,
        authorization: &ServicePeerAuthorization,
        context: &LeaseContext,
    ) -> Result<AuthoritySnapshot> {
        let deadline = Instant::now() + ADMISSION;
        let peer = self.admit(authorization, deadline)?;
        self.advance_timers(Instant::now())?;
        self.machine.require_starting_runtime(&peer, context)?;
        if context.operation.mode != RunMode::TunnelSystemProxy || !self.keeper_confirmed {
            return Err(AuthorityError::Identity);
        }
        let run = self.tunnel.as_mut().ok_or(AuthorityError::Stale)?;
        if run.context != *context || !run.pump_running {
            return Err(AuthorityError::Stale);
        }
        if run.host.pump_ended() {
            return Err(crate::tunnel::Error::from("tunnel packet pump has ended").into());
        }
        if !run.routed {
            run.host.route(deadline)?;
            run.routed = true;
        }
        self.machine.heartbeat(&peer, context, Instant::now())?;
        self.after_publication(authorization, deadline)?;
        Ok(self.snapshot())
    }

    /// Before a Tunnel Ready commits: the report must attest SYSTEM's own
    /// pump bounds, and the adapter is routed only while that pump runs.
    pub(super) fn route_tunnel_for_ready(
        &mut self,
        report: &ReadyReport,
        deadline: Instant,
    ) -> Result<()> {
        let run = self.tunnel.as_mut().ok_or(AuthorityError::Identity)?;
        if run.context != report.context || !run.pump_running {
            return Err(AuthorityError::Identity);
        }
        if report.packet_pump_limits
            != Some(crate::tunnel::packet_pump_limits(run.host.plan()?.mtu()))
        {
            return Err(AuthorityError::Invalid);
        }
        if run.host.pump_ended() {
            return Err(crate::tunnel::Error::from("tunnel packet pump has ended").into());
        }
        if !run.routed {
            run.host.route(deadline)?;
            run.routed = true;
        }
        Ok(())
    }

    /// Every supervision tick. A live run whose pump ended is revoked; a run
    /// whose lease left Starting/Active is retired as soon as no runtime
    /// process can still use its endpoint, or at once when the stop can no
    /// longer complete normally. An endpoint that was offered and not yet
    /// confirmed is retired on the first such tick.
    pub(super) fn drive_tunnel(&mut self) -> Result<()> {
        let phase = self.machine.phase();
        let Some(run) = self.tunnel.as_mut() else {
            return Ok(());
        };
        let live = matches!(phase, AuthorityState::Starting | AuthorityState::Active)
            && self.machine.context() == Some(&run.context);
        if live {
            if run.host.pump_ended() {
                self.revoke_current(false, "tunnel packet pump ended", Instant::now())?;
                return Err(crate::tunnel::Error::from(
                    "tunnel packet pump ended while the lease was live",
                )
                .into());
            }
            return Ok(());
        }
        // Only the bound runtime of a Starting lease can confirm an endpoint,
        // and this lease is no longer that. Dropping the handoff closes
        // SYSTEM's server end and its own client reference, which leaves the
        // copy in the UserAgent dead. Kept, it would stay with SYSTEM until
        // the service restarts, and the run's endpoint could never be proven
        // closed. It goes first: nothing below may keep it.
        run.handoff = None;
        let retire = !run.host.retiring()
            && (matches!(
                phase,
                AuthorityState::Quarantined | AuthorityState::Recovering | AuthorityState::Off
            ) || self.observe_runtime_processes()?.processes_retired());
        let run = self.tunnel.as_mut().ok_or(AuthorityError::Invalid)?;
        run.host.expect_peer_close()?;
        if retire {
            run.host
                .begin_retirement(Instant::now() + Duration::from_millis(STOP_WAIT_MS))?;
        }
        Ok(())
    }

    /// Whether this record's tunnel network is gone. A serving host must have
    /// retired with its adapter observed absent; otherwise, including after a
    /// SYSTEM restart, a recovery host removes the installation's adapter and
    /// proves it absent. Nothing new is created on this path.
    fn tunnel_network(&mut self, installation: uuid::Uuid) -> Result<TunnelNetwork> {
        if let Some(run) = self.tunnel.as_mut() {
            match run.host.retirement()? {
                None => return Ok(TunnelNetwork::Pending),
                Some(retired) if retired.adapter_absent => return Ok(TunnelNetwork::Retired),
                // The adapter outlived its closed handle: remove it below.
                Some(_) => {}
            }
        }
        if self.tunnel_recovery.is_none() {
            if crate::tunnel::adapter_absent(crate::tunnel::adapter_guid(installation))? {
                return Ok(TunnelNetwork::Retired);
            }
            self.tunnel_recovery = Some(TunnelHost::recover(installation)?);
        }
        let serving = self
            .tunnel
            .as_mut()
            .map(|run| run.host.retirement())
            .transpose()?
            .flatten()
            .cloned();
        let host = self
            .tunnel_recovery
            .as_mut()
            .ok_or(AuthorityError::Invalid)?;
        Ok(match host.retirement()? {
            None => TunnelNetwork::Pending,
            Some(retired) if retired.adapter_absent => TunnelNetwork::Retired,
            // Both outcomes are diagnostic observations of this adapter only.
            Some(recovery) => {
                return Err(crate::tunnel::Error::Contract(format!(
                    "tunnel adapter removal is unproven: serving={}, recovery={}",
                    serde_json::to_string(&serving).map_err(|_| AuthorityError::Invalid)?,
                    serde_json::to_string(recovery).map_err(|_| AuthorityError::Invalid)?
                ))
                .into());
            }
        })
    }

    /// Whether SYSTEM's own network of a combined run is gone: its adapter
    /// observed absent and its endpoint handoff retired. The caller has seen
    /// every process of the run retired. Off for such a run is committed by
    /// the proof of its proxy settings, never from here.
    pub(super) fn combined_tunnel_retired(&mut self, installation: uuid::Uuid) -> Result<bool> {
        let network = matches!(self.tunnel_network(installation)?, TunnelNetwork::Retired);
        Ok(network && self.tunnel.as_ref().is_none_or(|run| run.handoff.is_none()))
    }

    /// A supervision tick for a combined record that is stopping or in
    /// recovery: SYSTEM retires its network without waiting for a Desktop,
    /// including an adapter an earlier SYSTEM process left. Returns false
    /// while that is pending.
    pub(super) fn retire_combined_tunnel(&mut self) -> Result<bool> {
        require_service()?;
        let target = match self.machine.phase() {
            AuthorityState::Stopping => self
                .machine
                .stopped_cleanup_target(RunMode::TunnelSystemProxy)?,
            AuthorityState::Recovering => {
                self.machine.recovery_target(RunMode::TunnelSystemProxy)?
            }
            _ => return Err(AuthorityError::CleanupUnproven),
        };
        let processes = self.observe_runtime_processes()?;
        if processes.run_retirement(target.root()).is_none()
            || !self.combined_tunnel_retired(target.root().installation_id)?
        {
            return Ok(false);
        }
        // The hosts have ended. The proxy proof observes the adapter afresh
        // rather than reading what they recorded.
        self.tunnel = None;
        self.tunnel_recovery = None;
        Ok(true)
    }

    /// Reconcile a Tunnel record to Off once every process of its run is
    /// gone and its network retired: after an acknowledged stop, or after the
    /// execution lease was lost. Returns false while retirement is pending.
    pub(super) fn reconcile_tunnel(&mut self) -> Result<bool> {
        require_service()?;
        let target = match self.machine.phase() {
            AuthorityState::Stopping => self.machine.stopped_cleanup_target(RunMode::Tunnel)?,
            AuthorityState::Recovering => {
                if self.machine.context().is_some()
                    || self.keeper_confirmed
                    || self.desktop_reference_issued
                    || self.desktop_reference_confirmed
                    || self.proxy_recovery.is_some()
                {
                    return Err(AuthorityError::CleanupUnproven);
                }
                self.machine.recovery_target(RunMode::Tunnel)?
            }
            _ => return Err(AuthorityError::CleanupUnproven),
        };
        let operation = target
            .operation()
            .ok_or(AuthorityError::CleanupUnproven)?
            .clone();
        let processes = self.observe_runtime_processes()?;
        let retired = processes.run_retirement(target.root()).is_some();
        if !retired {
            return Ok(false);
        }
        let network = match self.tunnel_network(target.root().installation_id)? {
            TunnelNetwork::Pending => return Ok(false),
            TunnelNetwork::Retired => true,
        };
        let handoff_retired = self.tunnel.as_ref().is_none_or(|run| run.handoff.is_none());
        // The Job held the UserAgent, its engine and every descendant, and
        // admission disallows breakaway: an empty Job, or the end of the
        // logon they all ran under, closed their sockets, endpoint client
        // and memory. The host thread's exit closed the session, the
        // endpoint's server end and the adapter handle, and the adapter was
        // then observed absent with every route and resolver it carried. A
        // plain Tunnel run never owns WinINet settings: the UserAgent applies
        // them only for a run whose mode owns them.
        let evidence = CleanupEvidence {
            binding: CleanupBinding::TunnelRuntime(target.clone()),
            revision: target.revision(),
            lease_id: Some(operation.lease_id()),
            proxy_listener_closed: retired,
            system_proxy_restored: operation.mode() == RunMode::Tunnel,
            tunnel_engine_stopped: retired,
            packet_pump_closed: network,
            managed_tunnel_off: network,
            endpoints_closed: retired && network && handoff_retired,
            secret_buffers_cleared: retired,
        };
        evidence.validate_scope(self.machine.metadata())?;
        if !evidence.exact() {
            return Err(AuthorityError::CleanupUnproven);
        }
        self.reconcile_off(evidence)?;
        self.tunnel = None;
        self.tunnel_recovery = None;
        Ok(true)
    }
}

/// How long a retiring pump waits for the engine to close its endpoint.
const STOP_WAIT_MS: u64 = cfw_engine_api::authority_v1::STOP_ATTESTATION_TIMEOUT_MS;
