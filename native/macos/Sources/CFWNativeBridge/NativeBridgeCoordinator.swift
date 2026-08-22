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
  case systemProxy
  case tunnel
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
    owner = operation.mode == .systemProxy ? .systemProxy : .tunnel
    commandContext = try EngineCommandContext(
      installationID: operation.root.installationID.rawValue,
      configEpoch: operation.root.epoch,
      generation: operation.root.generation)
    authorityContext = NativeAuthorityStopContext(
      operation: operation,
      leaseID: leaseID)
  }
}

/// Host-side durable-within-process stop transaction. The exact descriptor and
/// Authority context are retained across command failures so a retry continues the
/// unfinished barrier instead of requiring an owner that may already be Off.
struct NativeStopTransaction: Sendable {
  let owner: NativeStopOwner
  let commandContext: EngineCommandContext
  let descriptor: ConfigurationDescriptor
  var authorityContext: NativeAuthorityStopContext?
  var ownerStopped: Bool
  var authorityCompleted: Bool
  var preferenceCompensated: Bool

  init(
    owner: NativeStopOwner,
    commandContext: EngineCommandContext,
    descriptor: ConfigurationDescriptor
  ) {
    self.owner = owner
    self.commandContext = commandContext
    self.descriptor = descriptor
    authorityContext = nil
    ownerStopped = false
    authorityCompleted = false
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
  /// Cancels an exact unredeemed preparation. Returns true only when a fresh
  /// Authority snapshot proves global Off; returns false when the same lease
  /// has already advanced to an owner-controlled state and must use stop.
  func cancelPreparedStart(for descriptor: ConfigurationDescriptor) async throws -> Bool
  /// Durably orders the exact active Global Authority lease to stop before the
  /// Host asks either native owner to tear down its data plane.
  func beginStop(for descriptor: ConfigurationDescriptor) async throws
    -> NativeAuthorityStopContext
  /// Commits global Off only after the owner has attested its teardown and the
  /// Host has observed the matching OS-facing endpoint at its Off barrier.
  func completeStop(_ context: NativeAuthorityStopContext) async throws
}

extension NativeEngineLeaseInspecting {
  func reconcileOff(
    managedTunnel: RecoveryManagedTunnelStatus
  ) async throws -> AuthorityOwnershipObservation {
    throw AuthorityDomainError(code: .globalAuthorityRecovering)
  }

  func recoverStoppingLease() async throws -> NativeRecoveredStop? { nil }
  func cancelPreparedStart(for descriptor: ConfigurationDescriptor) async throws -> Bool {
    false
  }
}

actor NativeBridgeCoordinator {
  let proxy: any ProxyAgentTransporting
  let systemProxyPreparer: any SystemProxyStartPreparing
  let tunnel: any TunnelHostBridging
  let engineLease: any NativeEngineLeaseInspecting
  let credentialVault: any NativeCredentialVaulting
  let hostOperationLease: any NativeHostOperationLeaseAcquiring
  var activeOperation: UUID?
  var startupPreferenceRecoveryComplete = false
  var pendingTunnelInstallation: NativePendingTunnelInstallation?
  var pendingStop: NativeStopTransaction?
  var pendingStartCleanup: NativeStopTransaction?
  var pendingFailedStartOff: NativeStopTransaction?
  var completedStartCleanup: NativeStartCleanupReceipt?

  init(
    proxy: any ProxyAgentTransporting,
    systemProxyPreparer: any SystemProxyStartPreparing,
    tunnel: any TunnelHostBridging,
    engineLease: any NativeEngineLeaseInspecting,
    credentialVault: any NativeCredentialVaulting,
    hostOperationLease: any NativeHostOperationLeaseAcquiring
  ) {
    self.proxy = proxy
    self.systemProxyPreparer = systemProxyPreparer
    self.tunnel = tunnel
    self.engineLease = engineLease
    self.credentialVault = credentialVault
    self.hostOperationLease = hostOperationLease
  }

  func execute(_ command: NativeBridgeCommand) async throws -> NativeBridgeResult {
    try Task.checkCancellation()
    let operationLease: any NativeHostOperationLeaseHolding
    do {
      operationLease = try hostOperationLease.acquire()
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
    defer { operationLease.release() }

    switch command {
    case .queryStatus:
      return .status(try await queryExternalStatus())
    case .startSystemProxy(let request):
      return .runtime(try await startSystemProxy(request))
    case .stopSystemProxy(let context):
      try await stopSystemProxy(context)
      return .acknowledged
    case .installTunnel(let context):
      return .tunnelInstall(try await installTunnel(context))
    case .cancelTunnelInstall(let context):
      try await cancelTunnelInstall(context)
      return .acknowledged
    case .startTunnel(let request):
      return .runtime(try await startTunnel(request))
    case .stopTunnel(let context):
      try await stopTunnel(context)
      return .acknowledged
    case .provisionCredentials(let request):
      return .credentialReceipt(try await provisionCredentials(request))
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
    return try await queryStatus(enforcePreferenceBarrier: true)
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
    let proxyDescriptor = try Self.activeDescriptor(
      proxySnapshot,
      expectedMode: .systemProxy
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
        mode: .systemProxy,
        ownership: ownership
      )
      return .systemProxy(try Self.runtime(descriptor: proxyDescriptor, proxy: true))
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
      && recovered.owner == (lease.mode == .systemProxy ? .systemProxy : .tunnel)
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
