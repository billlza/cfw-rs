//! Windows control protocol. Payloads are borrowed before typed decoding so
//! ticket material is never copied through serde_json::Value or an untyped map.
use super::{AuthorityError, types::*};
use cfw_engine_api::authority_v1::{AuthorityState, WireValidate};
use serde::{
    Deserialize, Serialize,
    de::{self, SeqAccess, Visitor},
    ser::SerializeTuple,
};
use serde_json::value::RawValue;
use std::fmt;
use uuid::Uuid;
use zeroize::Zeroizing;
mod recovery;
mod runtime_reference;
pub use recovery::{
    ProxyCleanupReceipt, ProxyRecoveryGrant, ProxyRecoveryReceipt, ProxyRecoveryReport,
};
#[cfg(windows)]
pub use runtime_reference::RuntimeReference;
pub use runtime_reference::RuntimeReferenceGrant;

pub const MAX_MESSAGE_BYTES: usize = 8192;
const PROTOCOL: &str = "cfw.windows.authority";
// v6 also transfers a separately verified, zero-access Desktop lifetime
// reference. It remains distinct from the UserAgent's execution binding.
// v7 lets the bound Tunnel UserAgent open SYSTEM's tunnel network, poll it
// until SYSTEM offers a packet endpoint, and confirm that endpoint.
const VERSION: u16 = 7;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("Windows authority message length is invalid")]
    Length,
    #[error("Windows authority message is malformed or has unknown fields")]
    Malformed,
    #[error("Windows authority protocol or version is unsupported")]
    Version,
    #[error("Windows authority response does not match its request")]
    Correlation,
    #[error("Windows authority command was rejected: {0:?}")]
    Rejected(Rejection),
    #[error("Windows authority native owner claim: {0}")]
    Owner(#[from] crate::authority_journal::JournalValidationError),
    #[cfg(windows)]
    #[error("Windows authority channel: {0}")]
    Transport(#[from] crate::ServiceTransportError),
    #[cfg(windows)]
    #[error("Windows authority client identity: {0}")]
    Identity(#[from] crate::PeerIdentityError),
    #[cfg(windows)]
    #[error("Windows authority runtime keeper: {0}")]
    Keeper(#[from] super::RuntimeJobError),
    // Boxed: handoff errors can carry installation errors, which carry these.
    #[cfg(windows)]
    #[error("Windows authority packet endpoint adoption: {0}")]
    Handoff(Box<crate::tunnel::HandoffError>),
}
#[cfg(windows)]
impl From<crate::tunnel::HandoffError> for WireError {
    fn from(error: crate::tunnel::HandoffError) -> Self {
        Self::Handoff(Box::new(error))
    }
}
type Result<T> = std::result::Result<T, WireError>;

/// No Debug, Clone or serde entrypoint on the full message. The initialized
/// fixed-capacity allocation is wiped even when encoding fails midway.
pub struct Message {
    bytes: Zeroizing<Vec<u8>>,
    length: usize,
}
impl Message {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}
fn encode(value: &impl Serialize) -> Result<Message> {
    let mut bytes = Zeroizing::new(vec![0; MAX_MESSAGE_BYTES]);
    let length = {
        let mut remaining = bytes.as_mut_slice();
        serde_json::to_writer(&mut remaining, value).map_err(|_| WireError::Length)?;
        MAX_MESSAGE_BYTES - remaining.len()
    };
    Ok(Message { bytes, length })
}
fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE_BYTES {
        return Err(WireError::Length);
    }
    // Do not expose a serde diagnostic containing untrusted ticket/body bytes.
    serde_json::from_slice(bytes).map_err(|_| WireError::Malformed)
}

/// Fixed-size ticket storage; neither decoding failures nor drop leave its
/// initialized bytes in an ordinary Vec or a derived Debug representation.
pub struct TicketMaterial(Zeroizing<[u8; 32]>);
impl TicketMaterial {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(WireError::Malformed);
        }
        let mut result = Self(Zeroizing::new([0; 32]));
        result.0.copy_from_slice(bytes);
        Ok(result)
    }
    pub fn with_bytes<T>(&self, action: impl FnOnce(&[u8]) -> T) -> T {
        action(self.0.as_ref())
    }
}
impl Serialize for TicketMaterial {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_tuple(32)?;
        for byte in self.0.iter() {
            sequence.serialize_element(byte)?;
        }
        sequence.end()
    }
}
impl<'de> Deserialize<'de> for TicketMaterial {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct TicketVisitor;
        impl<'de> Visitor<'de> for TicketVisitor {
            type Value = TicketMaterial;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("exactly 32 ticket bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut ticket = TicketMaterial(Zeroizing::new([0; 32]));
                for byte in ticket.0.iter_mut() {
                    *byte = sequence
                        .next_element()?
                        .ok_or_else(|| de::Error::custom("short ticket"))?;
                }
                if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("long ticket"));
                }
                Ok(ticket)
            }
        }
        deserializer.deserialize_tuple(32, TicketVisitor)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CommandTag {
    Observe,
    LoadLineage,
    ReadRuntimeScope,
    BeginProxyRecovery,
    ConfirmProxyRecovery,
    BeginProxyCleanup,
    ReconcileProxyCleanup,
    RetainRuntime,
    ConfirmRuntimeReference,
    ReserveGeneration,
    Prepare,
    BindUserAgent,
    ConfirmRuntimeKeeper,
    OpenTunnel,
    ConfirmTunnelEndpoint,
    Ready,
    Heartbeat,
    BeginStop,
    AbortPrepared,
    Stopped,
    OwnedLease,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindRequest {
    pub context: LeaseContext,
    pub ticket: TicketMaterial,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeeperRequest {
    pub context: LeaseContext,
    pub handle: u64,
}
/// The network options of the bound Tunnel run, from its digest-bound start
/// request. SYSTEM derives its adapter plan from these alone; the system proxy
/// port of a combined run stays with the UserAgent and is not sent. The first
/// request starts SYSTEM's tunnel network; repeating the same request reports
/// its progress until SYSTEM offers the endpoint, exactly once.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelOpenRequest {
    pub context: LeaseContext,
    pub ipv6_enabled: bool,
    pub bypass_private_networks: bool,
    pub direct_ipv4_hosts: cfw_singbox_config::DirectIpv4HostRoutes,
    pub mtu: u16,
}
impl TunnelOpenRequest {
    pub fn new(context: LeaseContext, options: &cfw_engine_api::TunnelNetworkOptions) -> Self {
        Self {
            context,
            ipv6_enabled: options.ipv6_enabled,
            bypass_private_networks: options.bypass_private_networks,
            direct_ipv4_hosts: options.direct_ipv4_hosts,
            mtu: options.mtu,
        }
    }
    pub fn network_options(&self) -> cfw_engine_api::TunnelNetworkOptions {
        cfw_engine_api::TunnelNetworkOptions {
            ipv6_enabled: self.ipv6_enabled,
            bypass_private_networks: self.bypass_private_networks,
            direct_ipv4_hosts: self.direct_ipv4_hosts,
            mtu: self.mtu,
            system_proxy_port: None,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopRequest {
    pub context: LeaseContext,
    pub expected_revision: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
pub enum Command {
    Observe,
    LoadLineage,
    ReadRuntimeScope,
    BeginProxyRecovery(super::ProxyRecoveryTarget),
    ConfirmProxyRecovery(ProxyRecoveryReport),
    BeginProxyCleanup(super::ProxyRecoveryTarget),
    ReconcileProxyCleanup(ProxyRecoveryReport),
    RetainRuntime(LeaseContext),
    ConfirmRuntimeReference(KeeperRequest),
    ReserveGeneration(super::AuthorityLineage),
    Prepare(PrepareRequest),
    BindUserAgent(BindRequest),
    ConfirmRuntimeKeeper(KeeperRequest),
    OpenTunnel(TunnelOpenRequest),
    ConfirmTunnelEndpoint(KeeperRequest),
    Ready(ReadyReport),
    Heartbeat(LeaseContext),
    BeginStop(StopRequest),
    AbortPrepared(StopRequest),
    Stopped(StoppedReport),
    OwnedLease,
}
impl Command {
    pub(super) fn tag(&self) -> CommandTag {
        match self {
            Self::Observe => CommandTag::Observe,
            Self::LoadLineage => CommandTag::LoadLineage,
            Self::ReadRuntimeScope => CommandTag::ReadRuntimeScope,
            Self::BeginProxyRecovery(_) => CommandTag::BeginProxyRecovery,
            Self::ConfirmProxyRecovery(_) => CommandTag::ConfirmProxyRecovery,
            Self::BeginProxyCleanup(_) => CommandTag::BeginProxyCleanup,
            Self::ReconcileProxyCleanup(_) => CommandTag::ReconcileProxyCleanup,
            Self::RetainRuntime(_) => CommandTag::RetainRuntime,
            Self::ConfirmRuntimeReference(_) => CommandTag::ConfirmRuntimeReference,
            Self::ReserveGeneration(_) => CommandTag::ReserveGeneration,
            Self::Prepare(_) => CommandTag::Prepare,
            Self::BindUserAgent(_) => CommandTag::BindUserAgent,
            Self::ConfirmRuntimeKeeper(_) => CommandTag::ConfirmRuntimeKeeper,
            Self::OpenTunnel(_) => CommandTag::OpenTunnel,
            Self::ConfirmTunnelEndpoint(_) => CommandTag::ConfirmTunnelEndpoint,
            Self::Ready(_) => CommandTag::Ready,
            Self::Heartbeat(_) => CommandTag::Heartbeat,
            Self::BeginStop(_) => CommandTag::BeginStop,
            Self::AbortPrepared(_) => CommandTag::AbortPrepared,
            Self::Stopped(_) => CommandTag::Stopped,
            Self::OwnedLease => CommandTag::OwnedLease,
        }
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Observe | Self::OwnedLease | Self::LoadLineage | Self::ReadRuntimeScope => Ok(()),
            Self::BeginProxyRecovery(target) | Self::BeginProxyCleanup(target) => {
                target.validate().map_err(|_| WireError::Malformed)
            }
            Self::ConfirmProxyRecovery(report) | Self::ReconcileProxyCleanup(report) => {
                report.validate()?;
                let expected = if matches!(self, Self::ConfirmProxyRecovery(_)) {
                    super::ProxyRecoveryPurpose::Observe
                } else {
                    super::ProxyRecoveryPurpose::ReconcileOff
                };
                if report.context.purpose != expected {
                    return Err(WireError::Malformed);
                }
                Ok(())
            }
            Self::ReserveGeneration(expected) => {
                expected.validate().map_err(|_| WireError::Malformed)
            }
            Self::Prepare(input) => input.validate().map_err(|_| WireError::Malformed),
            Self::BindUserAgent(input) => validate_context(&input.context),
            Self::ConfirmRuntimeKeeper(input) | Self::ConfirmRuntimeReference(input) => {
                validate_context(&input.context)?;
                validate_handle(input.handle)
            }
            Self::OpenTunnel(input) => {
                validate_context(&input.context)?;
                if input.context.operation.mode
                    != cfw_engine_api::authority_v1::AuthorityMode::Tunnel
                    || !crate::tunnel::HANDOFF_MTU.contains(&input.mtu)
                {
                    return Err(WireError::Malformed);
                }
                Ok(())
            }
            Self::ConfirmTunnelEndpoint(input) => {
                validate_context(&input.context)?;
                if input.context.operation.mode
                    != cfw_engine_api::authority_v1::AuthorityMode::Tunnel
                {
                    return Err(WireError::Malformed);
                }
                validate_handle(input.handle)
            }
            Self::Ready(report) => {
                validate_context(&report.context)?;
                report.validate().map_err(|_| WireError::Malformed)
            }
            Self::Heartbeat(context) | Self::RetainRuntime(context) => validate_context(context),
            Self::BeginStop(input) | Self::AbortPrepared(input) => {
                validate_context(&input.context)?;
                if input.expected_revision == 0 {
                    Err(WireError::Malformed)
                } else {
                    Ok(())
                }
            }
            Self::Stopped(report) => {
                validate_context(&report.context)?;
                report.validate().map_err(|_| WireError::Malformed)
            }
        }
    }
}
pub(crate) fn validate_context(context: &LeaseContext) -> Result<()> {
    let op = &context.operation;
    if context.lease_id.is_nil()
        || op.root.installation_id.is_nil()
        || op.operation_id.is_nil()
        || op.prepared_revision < 2
        || op.root.validate().is_err()
        || op.owner.validate().is_err()
    {
        return Err(WireError::Malformed);
    }
    Ok(())
}

#[derive(Serialize)]
struct Envelope<'a, K: Serialize, T: Serialize> {
    protocol: &'static str,
    version: u16,
    request_id: Uuid,
    kind: K,
    payload: &'a T,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header<'a, K> {
    protocol: &'a str,
    version: u16,
    request_id: Uuid,
    kind: K,
    #[serde(borrow)]
    payload: &'a RawValue,
}
fn header<'a, K: Deserialize<'a>>(bytes: &'a [u8]) -> Result<Header<'a, K>> {
    let value: Header<'a, K> = decode(bytes)?;
    if value.protocol != PROTOCOL || value.version != VERSION {
        return Err(WireError::Version);
    }
    if value.request_id.is_nil() {
        return Err(WireError::Correlation);
    }
    Ok(value)
}
fn envelope<K: Serialize, T: Serialize>(id: Uuid, kind: K, payload: &T) -> Result<Message> {
    encode(&Envelope {
        protocol: PROTOCOL,
        version: VERSION,
        request_id: id,
        kind,
        payload,
    })
}
pub struct Request {
    pub(super) id: Uuid,
    pub(super) command: Command,
}
impl Request {
    pub fn new(command: Command) -> Result<Self> {
        command.validate()?;
        Ok(Self {
            id: Uuid::new_v4(),
            command,
        })
    }
    pub fn encode(&self) -> Result<Message> {
        self.command.validate()?;
        let tag = self.command.tag();
        match &self.command {
            Command::Observe
            | Command::OwnedLease
            | Command::LoadLineage
            | Command::ReadRuntimeScope => envelope(self.id, tag, &Empty {}),
            Command::ReserveGeneration(expected) => envelope(self.id, tag, expected),
            Command::BeginProxyRecovery(input) | Command::BeginProxyCleanup(input) => {
                envelope(self.id, tag, input)
            }
            Command::ConfirmProxyRecovery(input) | Command::ReconcileProxyCleanup(input) => {
                envelope(self.id, tag, input)
            }
            Command::Prepare(input) => envelope(self.id, tag, input),
            Command::BindUserAgent(input) => envelope(self.id, tag, input),
            Command::ConfirmRuntimeKeeper(input)
            | Command::ConfirmRuntimeReference(input)
            | Command::ConfirmTunnelEndpoint(input) => envelope(self.id, tag, input),
            Command::OpenTunnel(input) => envelope(self.id, tag, input),
            Command::Ready(input) => envelope(self.id, tag, input),
            Command::Heartbeat(input) | Command::RetainRuntime(input) => {
                envelope(self.id, tag, input)
            }
            Command::BeginStop(input) | Command::AbortPrepared(input) => {
                envelope(self.id, tag, input)
            }
            Command::Stopped(input) => envelope(self.id, tag, input),
        }
    }
    /// Decode a command, not a grant. Server admission is still mandatory.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let wire = header(bytes)?;
        let body = wire.payload.get().as_bytes();
        let command = match wire.kind {
            CommandTag::Observe => {
                let _: Empty = decode(body)?;
                Command::Observe
            }
            CommandTag::LoadLineage => {
                let _: Empty = decode(body)?;
                Command::LoadLineage
            }
            CommandTag::ReadRuntimeScope => {
                let _: Empty = decode(body)?;
                Command::ReadRuntimeScope
            }
            CommandTag::ReserveGeneration => Command::ReserveGeneration(decode(body)?),
            CommandTag::BeginProxyRecovery => Command::BeginProxyRecovery(decode(body)?),
            CommandTag::BeginProxyCleanup => Command::BeginProxyCleanup(decode(body)?),
            CommandTag::ReconcileProxyCleanup => {
                Command::ReconcileProxyCleanup(ProxyRecoveryReport::decode(body)?)
            }
            CommandTag::ConfirmProxyRecovery => {
                Command::ConfirmProxyRecovery(ProxyRecoveryReport::decode(body)?)
            }
            CommandTag::OwnedLease => {
                let _: Empty = decode(body)?;
                Command::OwnedLease
            }
            CommandTag::Prepare => Command::Prepare(decode(body)?),
            CommandTag::BindUserAgent => Command::BindUserAgent(decode(body)?),
            CommandTag::ConfirmRuntimeKeeper => Command::ConfirmRuntimeKeeper(decode(body)?),
            CommandTag::OpenTunnel => Command::OpenTunnel(decode(body)?),
            CommandTag::ConfirmTunnelEndpoint => Command::ConfirmTunnelEndpoint(decode(body)?),
            CommandTag::ConfirmRuntimeReference => Command::ConfirmRuntimeReference(decode(body)?),
            CommandTag::RetainRuntime => Command::RetainRuntime(decode(body)?),
            CommandTag::Ready => Command::Ready(decode(body)?),
            CommandTag::Heartbeat => Command::Heartbeat(decode(body)?),
            CommandTag::BeginStop => Command::BeginStop(decode(body)?),
            CommandTag::AbortPrepared => Command::AbortPrepared(decode(body)?),
            CommandTag::Stopped => Command::Stopped(decode(body)?),
        };
        command.validate()?;
        Ok(Self {
            id: wire.request_id,
            command,
        })
    }
    pub fn command(&self) -> &Command {
        &self.command
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rejection {
    Recovering,
    Quarantined,
    LeaseConflict,
    Stale,
    Identity,
    Invalid,
    Replay,
    GenerationExhausted,
    Ticket,
    Expired,
    CleanupUnproven,
    Publication,
    Observation,
    Entropy,
    Tunnel,
}
impl Rejection {
    pub(super) fn of(error: &AuthorityError) -> Self {
        match error {
            AuthorityError::Recovering => Self::Recovering,
            AuthorityError::Quarantined => Self::Quarantined,
            AuthorityError::LeaseConflict => Self::LeaseConflict,
            AuthorityError::Stale => Self::Stale,
            AuthorityError::Identity => Self::Identity,
            AuthorityError::Invalid => Self::Invalid,
            AuthorityError::Replay => Self::Replay,
            AuthorityError::GenerationExhausted => Self::GenerationExhausted,
            AuthorityError::Ticket => Self::Ticket,
            AuthorityError::Expired => Self::Expired,
            AuthorityError::CleanupUnproven => Self::CleanupUnproven,
            AuthorityError::JournalValidation(_) => Self::Publication,
            #[cfg(windows)]
            AuthorityError::Journal(_) => Self::Publication,
            #[cfg(windows)]
            AuthorityError::Peer(_)
            | AuthorityError::Process(_)
            | AuthorityError::RuntimeJob(_)
            | AuthorityError::RuntimeEndpoints(_) => Self::Observation,
            #[cfg(windows)]
            AuthorityError::Entropy(_) => Self::Entropy,
            #[cfg(windows)]
            AuthorityError::Tunnel(_) | AuthorityError::Handoff(_) => Self::Tunnel,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResponseTag {
    Observed,
    Lineage,
    RuntimeScope,
    ProxyRecoveryGranted,
    ProxyRecoveryObserved,
    ProxyCleanupReconciled,
    RuntimeRetained,
    Prepared,
    Bound,
    TunnelPending,
    TunnelOffered,
    Status,
    Lease,
    Rejected,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedPayload {
    context: LeaseContext,
    ticket: TicketMaterial,
}
#[derive(Serialize)]
struct PreparedPayloadRef<'a> {
    context: &'a LeaseContext,
    ticket: &'a TicketMaterial,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundPayload {
    context: LeaseContext,
    committed_revision: u64,
    keeper_handle: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectedPayload {
    code: Rejection,
}

/// Only the authenticated channel's validated prepare reply creates a client
/// grant. Possession is not permission to start before a successful bind reply.
pub struct PreparedGrant {
    pub(super) context: LeaseContext,
    pub(super) ticket: TicketMaterial,
}
impl PreparedGrant {
    pub fn context(&self) -> &LeaseContext {
        &self.context
    }
    pub fn into_bind(self) -> BindRequest {
        BindRequest {
            context: self.context,
            ticket: self.ticket,
        }
    }
}
/// No public deserializer/constructor: this receipt comes from the authenticated
/// server reply correlated with the exact bind request. Runtime effects remain
/// the user agent's responsibility and must consume the receipt once.
pub struct BoundGrant {
    pub(super) context: LeaseContext,
    pub(super) committed_revision: u64,
    pub(super) keeper_handle: u64,
    #[cfg(windows)]
    pub(super) keeper: Option<super::RuntimeKeeper>,
}
impl BoundGrant {
    pub fn context(&self) -> &LeaseContext {
        &self.context
    }
    pub fn committed_revision(&self) -> u64 {
        self.committed_revision
    }
    #[cfg(windows)]
    pub(super) fn adopt_keeper(
        &mut self,
        owner: &crate::NativePeerProcess,
        verify: impl FnOnce(u64) -> Result<()>,
    ) -> Result<()> {
        if self.keeper.is_some() {
            return Err(WireError::Correlation);
        }
        self.keeper = Some(super::RuntimeKeeper::adopt(
            self.keeper_handle,
            &self.context.operation.root,
            owner,
            verify,
        )?);
        Ok(())
    }
    #[cfg(windows)]
    pub(crate) fn into_keeper(mut self) -> Result<super::RuntimeKeeper> {
        self.keeper.take().ok_or(WireError::Correlation)
    }
}
pub enum Response {
    Observed(AuthoritySnapshot),
    Lineage(super::AuthorityLineage),
    RuntimeScope(RecordedRuntimeScope),
    ProxyRecoveryGranted(ProxyRecoveryGrant),
    ProxyRecoveryObserved(ProxyRecoveryReceipt),
    ProxyCleanupReconciled(ProxyCleanupReceipt),
    RuntimeRetained(RuntimeReferenceGrant),
    Prepared(PreparedGrant),
    Bound(BoundGrant),
    /// SYSTEM is still creating or configuring its tunnel adapter.
    TunnelPending,
    /// Where SYSTEM placed the packet endpoint in the requesting UserAgent.
    /// Adoption still verifies the handle locally and through confirmation.
    TunnelOffered(crate::tunnel::EndpointOffer),
    Status(AuthoritySnapshot),
    Lease(LeaseContext),
}
impl Response {
    pub(super) fn encode(&self, id: Uuid) -> Result<Message> {
        match self {
            Self::Observed(value) => envelope(id, ResponseTag::Observed, value),
            Self::Lineage(value) => envelope(id, ResponseTag::Lineage, value),
            Self::RuntimeScope(value) => envelope(id, ResponseTag::RuntimeScope, value),
            Self::RuntimeRetained(value) => runtime_reference::encode_reference(id, value),
            Self::ProxyCleanupReconciled(value) => {
                envelope(id, ResponseTag::ProxyCleanupReconciled, value)
            }
            Self::ProxyRecoveryGranted(value) => recovery::encode_grant(id, value),
            Self::ProxyRecoveryObserved(value) => {
                envelope(id, ResponseTag::ProxyRecoveryObserved, value)
            }
            Self::Prepared(value) => envelope(
                id,
                ResponseTag::Prepared,
                &PreparedPayloadRef {
                    context: &value.context,
                    ticket: &value.ticket,
                },
            ),
            Self::Bound(value) => {
                #[cfg(windows)]
                if value.keeper.is_some() {
                    return Err(WireError::Correlation);
                }
                envelope(
                    id,
                    ResponseTag::Bound,
                    &BoundPayload {
                        context: value.context.clone(),
                        committed_revision: value.committed_revision,
                        keeper_handle: value.keeper_handle,
                    },
                )
            }
            Self::TunnelPending => envelope(id, ResponseTag::TunnelPending, &Empty {}),
            Self::TunnelOffered(value) => {
                if !value.is_well_formed() {
                    return Err(WireError::Malformed);
                }
                envelope(id, ResponseTag::TunnelOffered, value)
            }
            Self::Status(value) => envelope(id, ResponseTag::Status, value),
            Self::Lease(value) => envelope(id, ResponseTag::Lease, value),
        }
    }
}
pub(super) fn rejection(id: Uuid, error: &AuthorityError) -> Result<Message> {
    envelope(
        id,
        ResponseTag::Rejected,
        &RejectedPayload {
            code: Rejection::of(error),
        },
    )
}
fn snapshot_valid(value: &AuthoritySnapshot) -> Result<()> {
    if value.revision == Some(0)
        || value.revision.is_none()
            && (value.state != AuthorityState::Recovering || value.root.is_some())
    {
        return Err(WireError::Malformed);
    }
    let before_runtime = matches!(
        value.state,
        AuthorityState::Off | AuthorityState::Recovering | AuthorityState::Quarantined
    );
    if value.root.is_none()
        && value.revision.is_some()
        && !(before_runtime && value.revision == Some(1))
    {
        return Err(WireError::Malformed);
    }
    if let Some(root) = &value.root
        && (root.installation_id.is_nil()
            || (root.epoch, root.generation) == (0, 0) && !before_runtime
            || (root.epoch, root.generation) != (0, 0) && root.validate().is_err())
    {
        return Err(WireError::Malformed);
    }
    Ok(())
}
fn runtime_revision(value: &AuthoritySnapshot, prepared: u64) -> bool {
    match value.state {
        AuthorityState::Starting => prepared.checked_add(1) == value.revision,
        AuthorityState::Active => prepared.checked_add(2) == value.revision,
        AuthorityState::Stopping => prepared
            .checked_add(2)
            .is_some_and(|minimum| value.revision.is_some_and(|revision| revision >= minimum)),
        _ => false,
    }
}
pub(super) fn response(
    request: &Request,
    bytes: &[u8],
    owner: &crate::authority_journal::RecordedOwner,
) -> Result<Response> {
    let wire: Header<'_, ResponseTag> = header(bytes)?;
    if wire.request_id != request.id {
        return Err(WireError::Correlation);
    }
    let payload = wire.payload.get().as_bytes();
    if wire.kind == ResponseTag::Rejected {
        let rejected: RejectedPayload = decode(payload)?;
        return Err(WireError::Rejected(rejected.code));
    }
    match (&request.command, wire.kind) {
        (Command::RetainRuntime(context), ResponseTag::RuntimeRetained) => {
            Ok(Response::RuntimeRetained(
                runtime_reference::decode_reference(payload, context, owner)?,
            ))
        }
        (Command::BeginProxyRecovery(target), ResponseTag::ProxyRecoveryGranted) => {
            Ok(Response::ProxyRecoveryGranted(recovery::decode_grant(
                payload,
                target,
                owner,
                super::ProxyRecoveryPurpose::Observe,
            )?))
        }
        (Command::BeginProxyCleanup(target), ResponseTag::ProxyRecoveryGranted) => {
            Ok(Response::ProxyRecoveryGranted(recovery::decode_grant(
                payload,
                target,
                owner,
                super::ProxyRecoveryPurpose::ReconcileOff,
            )?))
        }
        (Command::ReconcileProxyCleanup(report), ResponseTag::ProxyCleanupReconciled) => Ok(
            Response::ProxyCleanupReconciled(recovery::decode_cleanup(payload, report, owner)?),
        ),
        (Command::ConfirmProxyRecovery(report), ResponseTag::ProxyRecoveryObserved) => Ok(
            Response::ProxyRecoveryObserved(recovery::decode_receipt(payload, report, owner)?),
        ),
        (Command::ReadRuntimeScope, ResponseTag::RuntimeScope) => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct ScopePayload<'a> {
                snapshot: AuthoritySnapshot,
                #[serde(borrow)]
                operation: &'a RawValue,
            }
            let value: ScopePayload<'_> = decode(payload)?;
            let operation: Option<crate::authority_journal::JournalOperation> =
                decode(value.operation.get().as_bytes())?;
            snapshot_valid(&value.snapshot)?;
            if value.snapshot.revision.is_none() || value.snapshot.root.is_none() {
                return Err(WireError::Malformed);
            }
            match value.snapshot.state {
                AuthorityState::Off if operation.is_some() => return Err(WireError::Malformed),
                AuthorityState::Preparing
                | AuthorityState::Starting
                | AuthorityState::Active
                | AuthorityState::Stopping
                    if operation.is_none() =>
                {
                    return Err(WireError::Malformed);
                }
                _ => {}
            }
            if let Some(operation) = &operation {
                operation.validate().map_err(|_| WireError::Malformed)?;
                value
                    .snapshot
                    .root
                    .as_ref()
                    .ok_or(WireError::Malformed)?
                    .validate()
                    .map_err(|_| WireError::Malformed)?;
                if operation.owner().sid_bytes() != owner.sid_bytes() {
                    return Err(WireError::Correlation);
                }
            }
            Ok(Response::RuntimeScope(RecordedRuntimeScope {
                snapshot: value.snapshot,
                operation,
            }))
        }
        (Command::LoadLineage | Command::ReserveGeneration(_), ResponseTag::Lineage) => {
            let value: super::AuthorityLineage = decode(payload)?;
            value.validate().map_err(|_| WireError::Malformed)?;
            if let Command::ReserveGeneration(expected) = &request.command
                && (value.installation_id != expected.installation_id
                    || value.config_epoch != expected.config_epoch
                    || expected.generation.checked_add(1) != Some(value.generation))
            {
                return Err(WireError::Correlation);
            }
            Ok(Response::Lineage(value))
        }
        (Command::Observe, ResponseTag::Observed) => {
            let value = decode(payload)?;
            snapshot_valid(&value)?;
            Ok(Response::Observed(value))
        }
        (Command::Prepare(input), ResponseTag::Prepared) => {
            let value: PreparedPayload = decode(payload)?;
            validate_context(&value.context)?;
            let operation = &value.context.operation;
            if operation.root != input.root
                || operation.operation_id != input.operation_id
                || operation.mode != input.mode
                || operation.config_sha256 != input.config_sha256
                || operation.identity_sha256 != input.identity_sha256
                || operation.owner != *owner
                || input.expected_revision.checked_add(1) != Some(operation.prepared_revision)
            {
                return Err(WireError::Correlation);
            }
            Ok(Response::Prepared(PreparedGrant {
                context: value.context,
                ticket: value.ticket,
            }))
        }
        (Command::BindUserAgent(input), ResponseTag::Bound) => {
            let value: BoundPayload = decode(payload)?;
            validate_handle(value.keeper_handle)?;
            if value.context != input.context
                || value.context.operation.owner != *owner
                || input.context.operation.prepared_revision.checked_add(1)
                    != Some(value.committed_revision)
            {
                return Err(WireError::Correlation);
            }
            Ok(Response::Bound(BoundGrant {
                context: value.context,
                committed_revision: value.committed_revision,
                keeper_handle: value.keeper_handle,
                #[cfg(windows)]
                keeper: None,
            }))
        }
        (Command::OpenTunnel(input), ResponseTag::TunnelPending) => {
            let _: Empty = decode(payload)?;
            if input.context.operation.owner != *owner {
                return Err(WireError::Correlation);
            }
            Ok(Response::TunnelPending)
        }
        (Command::OpenTunnel(input), ResponseTag::TunnelOffered) => {
            let value: crate::tunnel::EndpointOffer = decode(payload)?;
            if !value.is_well_formed() {
                return Err(WireError::Malformed);
            }
            if value.mtu != input.mtu || input.context.operation.owner != *owner {
                return Err(WireError::Correlation);
            }
            Ok(Response::TunnelOffered(value))
        }
        (Command::OwnedLease, ResponseTag::Lease) => {
            let value: LeaseContext = decode(payload)?;
            validate_context(&value)?;
            if value.operation.owner != *owner {
                return Err(WireError::Correlation);
            }
            Ok(Response::Lease(value))
        }
        (command, ResponseTag::Status) => {
            let value: AuthoritySnapshot = decode(payload)?;
            snapshot_valid(&value)?;
            let (context, accepted) = match command {
                Command::ConfirmRuntimeReference(input) => (
                    &input.context,
                    value.state == AuthorityState::Active
                        && input.context.operation.prepared_revision.checked_add(2)
                            == value.revision,
                ),
                Command::ConfirmRuntimeKeeper(input) | Command::ConfirmTunnelEndpoint(input) => (
                    &input.context,
                    value.state == AuthorityState::Starting
                        && input.context.operation.prepared_revision.checked_add(1)
                            == value.revision,
                ),
                Command::Ready(report) => (
                    &report.context,
                    value.state == AuthorityState::Active
                        && report.context.operation.prepared_revision.checked_add(2)
                            == value.revision,
                ),
                Command::Heartbeat(context) => (
                    context,
                    runtime_revision(&value, context.operation.prepared_revision),
                ),
                Command::BeginStop(input) => (
                    &input.context,
                    (value.state == AuthorityState::Off
                        && input.expected_revision == input.context.operation.prepared_revision
                        && input.expected_revision.checked_add(2) == value.revision)
                        || value.state == AuthorityState::Stopping
                            && runtime_revision(&value, input.context.operation.prepared_revision)
                            && (value.revision == Some(input.expected_revision)
                                || input.expected_revision.checked_add(1) == value.revision),
                ),
                Command::AbortPrepared(input) => (
                    &input.context,
                    value.state == AuthorityState::Off
                        && input.expected_revision == input.context.operation.prepared_revision
                        && input.expected_revision.checked_add(2) == value.revision,
                ),
                Command::Stopped(report) => (
                    &report.context,
                    value.state == AuthorityState::Stopping
                        && runtime_revision(&value, report.context.operation.prepared_revision),
                ),
                _ => return Err(WireError::Correlation),
            };
            if !accepted
                || value.root.as_ref() != Some(&context.operation.root)
                || context.operation.owner != *owner
            {
                return Err(WireError::Correlation);
            }
            Ok(Response::Status(value))
        }
        _ => Err(WireError::Correlation),
    }
}

fn validate_handle(value: u64) -> Result<()> {
    if value == 0 || value > isize::MAX as u64 || value & 3 != 0 {
        return Err(WireError::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
