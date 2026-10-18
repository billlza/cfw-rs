import CFWAppleNetwork
import CFWCredentialTransport
import CFWCredentialVault
import CFWSharedProtocol
import Foundation
@preconcurrency import Security

enum NativeBridgeExecutionError: Error, Equatable, Sendable {
  case failure(NativeBridgeErrorCode, String)

  var responseFailure: NativeBridgeFailure {
    switch self {
    case .failure(let code, let message):
      NativeBridgeFailure(code: code, message: message)
    }
  }
}

enum NativeObservation<Value: Sendable>: Sendable {
  case value(Value)
  case failure(String)
}

protocol NativeCredentialVaulting: Sendable {
  func provision(
    audience: CredentialAudience,
    requiredReferences: [CredentialReference],
    material: CredentialMaterial
  ) throws -> CredentialVaultReceipt
  func presence(
    audience: CredentialAudience,
    of references: [CredentialReference]
  ) throws -> [CredentialPresence]
  func resolve(
    audience: CredentialAudience,
    slots: [CredentialSlot]
  ) throws -> CredentialMaterial
  func previewGarbageCollection(
    _ request: CredentialGarbageCollectionRequest
  ) throws -> CredentialGarbageCollectionPreview
  func commitGarbageCollection(
    _ request: CredentialGarbageCollectionCommitRequest
  ) throws -> CredentialGarbageCollectionReceipt
}

extension CredentialVault: NativeCredentialVaulting {}

protocol NativeHostOperationLeaseHolding: AnyObject, Sendable {
  func release()
}

protocol NativeHostOperationLeaseAcquiring: Sendable {
  func acquire() throws -> any NativeHostOperationLeaseHolding
}

extension CrossProcessEngineLease: NativeHostOperationLeaseHolding {}

struct KernelNativeHostOperationLeaseAcquirer: NativeHostOperationLeaseAcquiring {
  private let store = CrossProcessHostOperationLeaseStore()

  func acquire() throws -> any NativeHostOperationLeaseHolding {
    try store.acquire()
  }
}

struct NativeAuthorityStopContext: Equatable, Sendable {
  let operation: OperationContext
  let leaseID: AuthorityIdentifier
}

enum NativeStopOwner: Equatable, Sendable {
  case localProxy
  case systemProxy
  case tunnel

  init(mode: AuthorityMode) {
    switch mode {
    case .localProxy: self = .localProxy
    case .systemProxy: self = .systemProxy
    case .tunnel: self = .tunnel
    }
  }

  var engineMode: EngineMode {
    switch self {
    case .localProxy: .localProxy
    case .systemProxy: .systemProxy
    case .tunnel: .tunnel
    }
  }
}

/// Exact, non-secret Host recovery view of a durable Authority lease that is
/// already stopping. A restarted Host has lost its in-process `pendingStop`, but
/// the Authority still retains the complete operation and lease identity needed
/// to finish the same stop transaction without reconstructing it from an
/// ambiguous owner Off snapshot.
struct NativeRecoveredStop: Equatable, Sendable {
  let owner: NativeStopOwner
  let commandContext: EngineCommandContext
  let authorityContext: NativeAuthorityStopContext

  init(operation: OperationContext, leaseID: AuthorityIdentifier) throws {
    owner = NativeStopOwner(mode: operation.mode)
    commandContext = try EngineCommandContext(
      installationID: operation.root.installationID.rawValue,
      configEpoch: operation.root.epoch,
      generation: operation.root.generation)
    authorityContext = NativeAuthorityStopContext(
      operation: operation,
      leaseID: leaseID)
  }
}

/// Where the Global Authority stands in one native stop.
enum NativeStopAuthorityPhase: Equatable, Sendable {
  /// The Authority has not been asked to stop the lease yet.
  case unordered
  /// The Authority stops the lease the context names.
  case ordered(NativeAuthorityStopContext)
  /// The Authority committed Off for that lease.
  case completed(NativeAuthorityStopContext)
  /// The Authority holds no lease to stop: it is Recovering, after a restart or
  /// once the stop's quarantined owner ended, it already reached Off at this
  /// stop's generation, or it passed that generation. The stop ends with the
  /// Host's own Off proof: the reconciliation a restart needs, at this stop's
  /// generation, or, once the Authority passed it, the stop's own owner Off.
  case released
}

/// Host-side durable-within-process stop transaction. The exact descriptor and
/// Authority context are retained across command failures so a retry continues the
/// unfinished barrier instead of requiring an owner that may already be Off.
struct NativeStopTransaction: Sendable {
  let owner: NativeStopOwner
  let commandContext: EngineCommandContext
  let descriptor: ConfigurationDescriptor
  var authority: NativeStopAuthorityPhase
  var ownerStopped: Bool
  var preferenceCompensated: Bool

  init(
    owner: NativeStopOwner,
    commandContext: EngineCommandContext,
    descriptor: ConfigurationDescriptor
  ) {
    self.owner = owner
    self.commandContext = commandContext
    self.descriptor = descriptor
    authority = .unordered
    ownerStopped = false
    preferenceCompensated = false
  }
}

struct NativeStartCleanupReceipt: Equatable, Sendable {
  let owner: NativeStopOwner
  let commandContext: EngineCommandContext
  let descriptor: ConfigurationDescriptor
}

enum NativeTunnelInstallationState: Equatable, Sendable {
  /// A callback wait is currently submitted by the active mutation.
  case waiting
  /// The local wait timed out, was canceled, or reported user approval. The
  /// exact generation may reattach to the same submitted OS request.
  case retryable
  /// The OS returned a terminal failure/restart result. The exact cancel command
  /// must acknowledge this receipt before another request can be submitted.
  case terminalReceipt
}

struct NativePendingTunnelInstallation: Equatable, Sendable {
  let context: EngineCommandContext
  var state: NativeTunnelInstallationState
}

protocol NativeEngineLeaseInspecting: Sendable {
  func isAvailable() async throws -> Bool
  /// Reports the Global Authority's machine-wide ownership observation used to
  /// require exact agreement before declaring an owner Active. A default
  /// implementation derives a coarse observation from `isAvailable()`.
  func authorityOwnership() async throws -> AuthorityOwnershipObservation
  /// Commits a restarted Authority to Off only after the Host has independently
  /// proven both native owners Off and supplied the exact public managed-tunnel
  /// status. Implementations without a production recovery channel fail closed.
  func reconcileOff(
    managedTunnel: RecoveryManagedTunnelStatus
  ) async throws -> AuthorityOwnershipObservation
  /// Recovers the exact persisted stopping lease after a Host restart. A nil
  /// result means the Authority is not currently in the recoverable Stopping
  /// state; it never means that global Off has been proven.
  func recoverStoppingLease() async throws -> NativeRecoveredStop?
  /// Cancels an exact unredeemed preparation. Returns true only when no
  /// preparation is left that the Authority could still authorize: a fresh
  /// snapshot proves global Off, or the Authority is Recovering, which holds no
  /// lease and admits no start until the Host proves Off. Returns false when the
  /// same lease has already advanced to an owner-controlled state and must use
  /// stop.
  func cancelPreparedStart(for descriptor: ConfigurationDescriptor) async throws -> Bool
  /// Durably orders the exact active Global Authority lease to stop before the
  /// Host asks either native owner to tear down its data plane. A Recovering
  /// Authority, which holds no lease, fails with `globalAuthorityRecovering`.
  func beginStop(for descriptor: ConfigurationDescriptor) async throws
    -> NativeAuthorityStopContext
  /// Commits global Off only after the owner has attested its teardown and the
  /// Host has observed the matching OS-facing endpoint at its Off barrier. A
  /// Recovering Authority fails with `globalAuthorityRecovering`.
  func completeStop(_ context: NativeAuthorityStopContext) async throws
  /// What one fresh snapshot says of a stop's generation; this does not
  /// replace the proof that the owner and the OS are Off.
  func stopResolution(_ context: EngineCommandContext) async throws -> NativeStopResolution
}

/// What the Global Authority's state says of one stop's generation.
enum NativeStopResolution: Equatable, Sendable {
  /// Off, with the replay cursor at the stop's generation: the stop's lease
  /// ended with this Off.
  case completed
  /// The replay cursor of the same installation passed the stop's generation.
  /// The cursor advances only through a start prepared from a proven Off, so
  /// the stop's lease ended through a proven Off, and no lease of that
  /// generation can exist again.
  case superseded
  /// Neither: the Authority's state says nothing final of the stop's lease.
  case unresolved
}

protocol Installed40019AuthorityOffProving: Sendable {
  func proveOff() async throws
}

private struct UnavailableInstalled40019AuthorityOffProver:
  Installed40019AuthorityOffProving
{
  func proveOff() async throws {
    throw AuthorityDomainError(code: .globalAuthorityUnavailable)
  }
}

private struct UnavailableInstalled40019ProxySnapshotter:
  Installed40019ProxySnapshotting
{
  func snapshotInstalled40019ForMigration() async throws -> EngineSnapshot {
    throw ProxyAgentHostError.transportUnavailable(
      "installed-40019 compatibility transport is unavailable")
  }
}

extension NativeEngineLeaseInspecting {
  func reconcileOff(
    managedTunnel: RecoveryManagedTunnelStatus
  ) async throws -> AuthorityOwnershipObservation {
    throw AuthorityDomainError(code: .globalAuthorityRecovering)
  }

  func recoverStoppingLease() async throws -> NativeRecoveredStop? { nil }
  func stopResolution(_ context: EngineCommandContext) async throws -> NativeStopResolution {
    .unresolved
  }
  func cancelPreparedStart(for descriptor: ConfigurationDescriptor) async throws -> Bool {
    false
  }
}

/// The end of one bounded Host wait for an owner to report readiness, counted
/// in time the Mac is awake. The owner's own start deadline keeps counting while
/// the Mac sleeps, so after a sleep the owner still reports its start before
/// this wait ends.
struct NativeReadinessDeadline: Sendable {
  let end: SuspendingClock.Instant
  let now: @Sendable () -> SuspendingClock.Instant

  /// Ends `length` after `now()`.
  static func awake(
    after length: Duration,
    now: @escaping @Sendable () -> SuspendingClock.Instant = { SuspendingClock.now }
  ) -> NativeReadinessDeadline {
    NativeReadinessDeadline(end: now().advanced(by: length), now: now)
  }

  func hasPassed() -> Bool { now() >= end }
}

actor NativeBridgeCoordinator {
  let proxy: any ProxyAgentTransporting
  let installed40019Proxy: any Installed40019ProxySnapshotting
  let systemProxyPreparer: any SystemProxyStartPreparing
  let tunnel: any TunnelHostBridging
  let engineLease: any NativeEngineLeaseInspecting
  let installed40019Authority: any Installed40019AuthorityOffProving
  let credentialVault: any NativeCredentialVaulting
  let hostOperationLease: any NativeHostOperationLeaseAcquiring
  let serviceMaintainer: any CurrentAppServiceMaintaining
  let serviceRuntimeObserver: any CurrentAppServiceRuntimeObserving
  let serviceBuildObserver: any CurrentAppServiceBuildObserving
  let systemProxySwitchObserver: any CurrentSystemProxySwitchObserving
  /// Arms the Host's wait of the given length for Packet Tunnel readiness.
  let armTunnelReadinessDeadline: @Sendable (Duration) -> NativeReadinessDeadline
  var serviceBuildPollCheckpoint: ServiceBuildRegistrationCheckpoint?
  var serviceBuildUpgradePending = false
  var activeOperation: UUID?
  var startupPreferenceRecoveryComplete = false
  var pendingTunnelInstallation: NativePendingTunnelInstallation?
  var pendingStop: NativeStopTransaction?
  var pendingStartCleanup: NativeStopTransaction?
  var pendingFailedStartOff: NativeStopTransaction?
  var completedStartCleanup: NativeStartCleanupReceipt?

  init(
    proxy: any ProxyAgentTransporting,
    installed40019Proxy: (any Installed40019ProxySnapshotting)? = nil,
    systemProxyPreparer: any SystemProxyStartPreparing,
    tunnel: any TunnelHostBridging,
    engineLease: any NativeEngineLeaseInspecting,
    installed40019Authority: any Installed40019AuthorityOffProving =
      UnavailableInstalled40019AuthorityOffProver(),
    credentialVault: any NativeCredentialVaulting,
    hostOperationLease: any NativeHostOperationLeaseAcquiring,
    serviceMaintainer: any CurrentAppServiceMaintaining = CurrentAppServiceMaintainer(),
    serviceRuntimeObserver: any CurrentAppServiceRuntimeObserving =
      CurrentAppServiceRuntimeObserver(),
    systemProxySwitchObserver: any CurrentSystemProxySwitchObserving =
      CurrentSystemProxySwitchObserver(),
    serviceBuildObserver: any CurrentAppServiceBuildObserving,
    armTunnelReadinessDeadline: @escaping @Sendable (Duration) -> NativeReadinessDeadline = {
      .awake(after: $0)
    }
  ) {
    self.proxy = proxy
    self.installed40019Proxy =
      installed40019Proxy ?? UnavailableInstalled40019ProxySnapshotter()
    self.systemProxyPreparer = systemProxyPreparer
    self.tunnel = tunnel
    self.engineLease = engineLease
    self.installed40019Authority = installed40019Authority
    self.credentialVault = credentialVault
    self.hostOperationLease = hostOperationLease
    self.serviceMaintainer = serviceMaintainer
    self.serviceRuntimeObserver = serviceRuntimeObserver
    self.serviceBuildObserver = serviceBuildObserver
    self.systemProxySwitchObserver = systemProxySwitchObserver
    self.armTunnelReadinessDeadline = armTunnelReadinessDeadline
  }

  func execute(_ command: NativeBridgeCommand) async throws -> NativeBridgeResult {
    try Task.checkCancellation()
    // Profile probes neither own nor mutate the machine's network state.
    if case .testProfileDelays(let request) = command {
      try await requireCurrentServiceBuilds(allowHandoff: false)
      return .profileDelays(try await testProfileDelays(request))
    }
    // Proxy authorization obtains rights, with which the ProxyAgent restores
    // only settings an ended session left, serialized with its own start and
    // stop; it needs no mutation lease.
    // Registration status only reads SMAppService metadata. It must remain
    // observable when another Host is busy; it cannot attest engine Off or
    // authorize service mutation. All proof, repair and runtime queries below
    // still acquire the existing cross-process operation lease.
    // Tunnel authorization writes a disabled manager, so it keeps the existing
    // cross-process preference-mutation lease through the bounded user wait.
    let operationLease: (any NativeHostOperationLeaseHolding)?
    do {
      if command == .authorizeSystemProxy || command == .authorizeSystemProxyRestoration
        || command == .maintainCurrentServices(.status)
      {
        operationLease = nil
      } else {
        operationLease = try hostOperationLease.acquire()
      }
    } catch CrossProcessEngineLeaseError.alreadyHeld {
      throw NativeBridgeExecutionError.failure(
        .busy,
        "Another Host process is performing a native operation."
      )
    } catch {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "The crash-safe Host operation lease could not be acquired."
      )
    }
    defer { operationLease?.release() }

    if Self.requiresCurrentServices(command) {
      let buildOperation = try beginOperation()
      do {
        try await requireCurrentServiceBuilds(allowHandoff: true)
        endOperation(buildOperation)
      } catch {
        endOperation(buildOperation)
        throw Self.map(error)
      }
    } else if command == .authorizeSystemProxy {
      try await requireCurrentServiceBuilds(allowHandoff: false)
    }

    switch command {
    case .testProfileDelays:
      throw NativeBridgeProtocolError.invalidCommand
    case .queryStatus:
      return .status(try await queryExternalStatus())
    case .authorizeSystemProxy, .authorizeSystemProxyRestoration:
      do {
        try await proxy.authorizeSystemProxy(
          restorationOnly: command == .authorizeSystemProxyRestoration)
        try Task.checkCancellation()
        return .acknowledged
      } catch {
        throw Self.map(error)
      }
    case .maintainCurrentServices(let action):
      return .serviceMaintenance(try await maintainCurrentServices(action))
    case .checkConfiguration(let request):
      try await validateCandidateConfiguration(request)
      return .acknowledged
    case .startSystemProxy(let request):
      return .runtime(try await startSystemProxy(request))
    case .startLocalProxy(let request):
      return .runtime(try await startLocalProxy(request))
    case .stopLocalProxy(let context):
      try await stopLocalProxy(context)
      return .acknowledged
    case .stopSystemProxy(let context):
      try await stopSystemProxy(context)
      return .acknowledged
    case .installTunnel(let context):
      return .tunnelInstall(try await installTunnel(context))
    case .cancelTunnelInstall(let context):
      try await cancelTunnelInstall(context)
      return .acknowledged
    case .authorizeTunnelConfiguration(let request):
      try await authorizeTunnelConfiguration(request)
      return .acknowledged
    case .startTunnel(let request):
      return .runtime(try await startTunnel(request))
    case .stopTunnel(let context):
      try await stopTunnel(context)
      return .acknowledged
    case .provisionCredentials(let request):
      return .credentialReceipt(try await provisionCredentials(request))
    case .rebindProfileCredentials(let request):
      return .credentialReceipt(try rebindProfileCredentials(request))
    case .queryCredentialPresence(let request):
      return .credentialPresence(try await queryCredentialPresence(request))
    case .preflightCutover(let request):
      return .cutoverPreflight(try await preflightCutover(request))
    case .previewCredentialGarbageCollection(let request):
      return .credentialGarbageCollectionPreview(
        try await previewCredentialGarbageCollection(request)
      )
    case .commitCredentialGarbageCollection(let request):
      return .credentialGarbageCollectionReceipt(
        try await commitCredentialGarbageCollection(request)
      )
    }
  }

  private func queryExternalStatus() async throws -> NativeEngineStatus {
    let operationID = try beginOperation()
    defer { endOperation(operationID) }
    return try await queryStatusWithServiceBuildReconciliation()
  }

  func queryStatus(
    enforcePreferenceBarrier: Bool = true
  ) async throws -> NativeEngineStatus {
    if enforcePreferenceBarrier {
      if try await tunnel.pendingPreferenceMutationConfiguration() != nil {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "A durable Tunnel preference mutation must be recovered before status can be projected."
        )
      }
      if !startupPreferenceRecoveryComplete {
        startupPreferenceRecoveryComplete = true
      }
    }
    // Every ProxyAgent observation must follow an explicit SMAppService
    // registration check. A fresh installation is registered here; approval or
    // missing-bundle states remain typed failures instead of false global Off.
    do {
      try await proxy.ensureRegistered()
    } catch {
      throw Self.map(error)
    }

    // Launching the signed Agent is also the only production path that executes
    // its persisted SystemConfiguration ownership recovery. The unconditional
    // registration boundary above therefore covers both ordinary reads and
    // restarted-Authority reconciliation.

    async let proxyObservation = Self.observe { try await self.proxy.snapshot() }
    async let tunnelObservation = Self.observe { try await self.tunnel.snapshot() }
    let (proxyObservationValue, tunnelObservationValue) = await (
      proxyObservation, tunnelObservation
    )

    let proxySnapshot = try Self.requireObservation(
      proxyObservationValue,
      component: "ProxyAgent"
    )
    let tunnelSnapshot = try Self.requireObservation(
      tunnelObservationValue,
      component: "Packet Tunnel"
    )
    let proxyMode: EngineMode = proxySnapshot.mode == .localProxy ? .localProxy : .systemProxy
    let proxyDescriptor = try Self.activeDescriptor(
      proxySnapshot,
      expectedMode: proxyMode
    )
    let tunnelDescriptor = try Self.activeDescriptor(
      tunnelSnapshot,
      expectedMode: .tunnel
    )
    guard proxyDescriptor == nil || tunnelDescriptor == nil else {
      throw NativeBridgeExecutionError.failure(
        .busy,
        "ProxyAgent and Packet Tunnel both reported active ownership."
      )
    }

    var ownership: AuthorityOwnershipObservation
    do {
      ownership = try await engineLease.authorityOwnership()
    } catch let conflict as AuthorityDomainError where conflict.code == .globalLeaseConflict {
      // Another user's lease, which this Host cannot observe: a later read
      // succeeds once it ends.
      throw NativeBridgeExecutionError.failure(
        .busy, "Another user's connection holds the Global Authority.")
    } catch {
      throw Self.map(error)
    }

    if let proxyDescriptor {
      guard tunnelDescriptor == nil, Self.isStableOff(tunnelSnapshot) else {
        throw NativeBridgeExecutionError.failure(
          .identityRejected,
          "ProxyAgent readiness does not match machine-wide engine ownership."
        )
      }
      // Classify Active only on exact agreement between the Global_Lease,
      // Operation_Context, owner-ready attestation, configuration digest, and the
      // effective SystemConfiguration owner state. Any mismatch fails closed.
      try Self.requireActiveAgreement(
        descriptor: proxyDescriptor,
        mode: proxyMode,
        ownership: ownership
      )
      let runtime = try Self.runtime(descriptor: proxyDescriptor, proxy: true)
      return proxyMode == .localProxy ? .localProxy(runtime) : .systemProxy(runtime)
    }
    if let tunnelDescriptor {
      guard Self.isStableOff(proxySnapshot) else {
        throw NativeBridgeExecutionError.failure(
          .identityRejected,
          "Packet Tunnel readiness does not match machine-wide engine ownership."
        )
      }
      // Classify Active only on exact agreement between the Global_Lease,
      // Operation_Context, owner-ready attestation, configuration digest, and the
      // effective Network Extension owner state. Any mismatch fails closed.
      try Self.requireActiveAgreement(
        descriptor: tunnelDescriptor,
        mode: .tunnel,
        ownership: ownership
      )
      return .tunnel(try Self.runtime(descriptor: tunnelDescriptor, proxy: false))
    }
    guard Self.isStableOff(proxySnapshot), Self.isStableOff(tunnelSnapshot) else {
      throw NativeBridgeExecutionError.failure(
        .busy,
        "A native endpoint is not at the stable Off barrier."
      )
    }
    if ownership.state == .recovering {
      let managedTunnel: RecoveryManagedTunnelStatus
      do {
        managedTunnel = try await tunnel.recoveryManagedTunnelStatus()
        ownership = try await engineLease.reconcileOff(
          managedTunnel: managedTunnel)
      } catch {
        throw Self.map(error)
      }
    }
    if ownership.state == .stopping {
      do {
        guard let recovered = try await engineLease.recoverStoppingLease(),
          Self.matches(recovered, ownership: ownership)
        else {
          throw AuthorityDomainError(code: .cleanupUnproven)
        }
        // The two owner snapshots above prove the Host-observed OS-facing Off
        // barrier. Authority.completeStop independently requires the exact lease
        // and its durable ownerStopped attestation; a missing owner proof is
        // rejected rather than inferred from these snapshots.
        try await engineLease.completeStop(recovered.authorityContext)
        ownership = try await engineLease.authorityOwnership()
      } catch {
        throw Self.map(error)
      }
    }
    try Self.requireGlobalOff(ownership)
    return .off
  }

  private static func matches(
    _ recovered: NativeRecoveredStop,
    ownership: AuthorityOwnershipObservation
  ) -> Bool {
    guard ownership.state == .stopping,
      let lease = ownership.lease,
      lease.leaseState == .stopping || lease.leaseState == .revoked
    else { return false }
    let operation = recovered.authorityContext.operation
    return operation.mode == lease.mode
      && recovered.owner == NativeStopOwner(mode: lease.mode)
      && recovered.commandContext.installationID == lease.installationID
      && recovered.commandContext.configEpoch == lease.epoch
      && recovered.commandContext.generation == lease.generation
      && operation.root.installationID.rawValue == lease.installationID
      && operation.root.epoch == lease.epoch
      && operation.root.generation == lease.generation
      && operation.ownerUID == lease.ownerUID
      && operation.configSHA256 == lease.configSHA256
      && operation.identitySHA256 == lease.identitySHA256
  }
}
