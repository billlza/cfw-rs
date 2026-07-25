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
    profileID: String,
    requiredReferences: [CredentialReference],
    material: CredentialMaterial
  ) throws -> CredentialVaultReceipt
  func presence(of references: [CredentialReference]) throws -> [CredentialPresence]
  func resolve(slots: [CredentialSlot]) throws -> CredentialMaterial
  func previewGarbageCollection(
    _ request: CredentialGarbageCollectionRequest
  ) throws -> CredentialGarbageCollectionPreview
  func commitGarbageCollection(
    _ request: CredentialGarbageCollectionCommitRequest
  ) throws -> CredentialGarbageCollectionReceipt
}

extension CredentialVault: NativeCredentialVaulting {}

protocol NativeConfigurationStoring: Sendable {
  func persist(_ configuration: Data, descriptor: ConfigurationDescriptor) throws
}

extension AppGroupConfigurationStore: NativeConfigurationStoring {}

protocol NativeEngineLeaseInspecting: Sendable {
  func isAvailable() async throws -> Bool
  /// Reports the Global Authority's machine-wide ownership observation used to
  /// require exact agreement before declaring an owner Active. A default
  /// implementation derives a coarse observation from `isAvailable()`.
  func authorityOwnership() async throws -> AuthorityOwnershipObservation
}

actor NativeBridgeCoordinator {
  let proxy: any ProxyAgentTransporting
  let tunnel: any TunnelHostBridging
  let configurationStore: any NativeConfigurationStoring
  let engineLease: any NativeEngineLeaseInspecting
  let credentialVault: any NativeCredentialVaulting
  var activeMutation: UUID?
  var pendingInstallationContext: EngineCommandContext?

  init(
    proxy: any ProxyAgentTransporting,
    tunnel: any TunnelHostBridging,
    configurationStore: any NativeConfigurationStoring,
    engineLease: any NativeEngineLeaseInspecting,
    credentialVault: any NativeCredentialVaulting
  ) {
    self.proxy = proxy
    self.tunnel = tunnel
    self.configurationStore = configurationStore
    self.engineLease = engineLease
    self.credentialVault = credentialVault
  }

  func execute(_ command: NativeBridgeCommand) async throws -> NativeBridgeResult {
    switch command {
    case .queryStatus:
      return .status(try await queryStatus())
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
      return .credentialReceipt(try provisionCredentials(request))
    case .queryCredentialPresence(let request):
      return .credentialPresence(try queryCredentialPresence(request))
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

  func queryStatus() async throws -> NativeEngineStatus {
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

    let ownership: AuthorityOwnershipObservation
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
    try Self.requireGlobalOff(ownership)
    return .off
  }
}
