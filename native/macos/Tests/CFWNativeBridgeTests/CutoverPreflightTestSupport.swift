import CFWAppleNetwork
import CFWCredentialTransport
import CryptoKit
import Foundation
import Testing

@testable import CFWCredentialVault
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Shared by the cutover preflight, profile rebind and garbage collection tests:
// a recording ProxyAgent and tunnel host, an available engine lease, an empty
// credential vault, and the coordinator built from them.
actor RecordingProxyAgent: ProxyAgentTransporting {
  func testProfileProxies(
    configuration: Data, proxies: [String], timeoutMS: UInt16, targetURL: String,
    expectedStatus: String
  ) async throws
    -> [ProfileProxyDelay]
  {
    #expect(!configuration.isEmpty)
    #expect(timeoutMS == 5000)
    return try proxies.map { try ProfileProxyDelay(name: $0, delay: 42, errorKind: nil) }
  }

  func authorizeSystemProxy(restorationOnly: Bool) async throws {}
  private let observedSnapshot: EngineSnapshot
  private let rejectsValidation: Bool
  private(set) var startCalls = 0
  private(set) var stopCalls = 0
  private(set) var validationCalls = 0

  init(
    observedSnapshot: EngineSnapshot = .off,
    rejectsValidation: Bool = false
  ) {
    self.observedSnapshot = observedSnapshot
    self.rejectsValidation = rejectsValidation
  }

  func registrationStatus() -> ProxyAgentRegistrationStatus { .notRegistered }
  func ensureRegistered() throws {}

  func start(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    authorization: HostPreparedSystemProxyStart
  ) throws {
    _ = configuration
    _ = descriptor
    authorization.erase()
    throw UnusedSystemProxyStartPreparerError.unexpectedInvocation
  }

  func stop(configuration: ConfigurationDescriptor) throws {
    _ = configuration
    stopCalls += 1
  }

  func restoreSettingsBeforeStop(configuration: ConfigurationDescriptor) throws {
    Issue.record("a cutover preflight stops no System Proxy session")
  }

  func snapshot() -> EngineSnapshot { observedSnapshot }

  func validateConfiguration(
    _ configuration: Data,
    descriptor: ConfigurationDescriptor
  ) throws {
    _ = descriptor
    #expect(!configuration.isEmpty)
    validationCalls += 1
    if rejectsValidation {
      throw ProxyAgentHostError.agentFailure(
        EngineFailure(
          code: "configuration-rejected",
          message: "Source-built libbox rejected the configuration.",
          isRetryable: false
        )
      )
    }
  }

  func mutationCounts() -> (Int, Int) { (startCalls, stopCalls) }
  func validationCount() -> Int { validationCalls }
}

actor RecordingTunnelHost: TunnelHostBridging {
  private var installResults: [SystemExtensionInstallResult]
  private let managedConfiguration: ConfigurationDescriptor?
  private(set) var installCalls = 0
  private(set) var cancelCalls = 0
  private(set) var startCalls = 0
  private(set) var stopCalls = 0

  init(
    installResult: SystemExtensionInstallResult = .completed,
    managedConfiguration: ConfigurationDescriptor? = nil
  ) {
    installResults = [installResult]
    self.managedConfiguration = managedConfiguration
  }

  init(installResults: [SystemExtensionInstallResult]) {
    self.installResults = installResults
    managedConfiguration = nil
  }

  func installTunnel() throws -> SystemExtensionInstallResult {
    installCalls += 1
    guard !installResults.isEmpty else {
      throw AppleNetworkError.unknownSystemExtensionResult(-1)
    }
    return installResults.removeFirst()
  }

  func awaitTunnelInstallationApproval() -> SystemExtensionApprovalWait {
    Issue.record("a cutover preflight never awaits an approval")
    return .noPendingRequest
  }

  func cancelTunnelInstallationWait() { cancelCalls += 1 }

  func authorizeTunnelConfiguration(_ descriptor: ConfigurationDescriptor) throws {
    throw AppleNetworkError.providerDidNotRespond
  }

  func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) {
    _ = configuration
    _ = descriptor
    _ = credentialPayload
    startCalls += 1
  }

  func stopTunnel(expectedConfiguration: ConfigurationDescriptor) {
    _ = expectedConfiguration
    stopCalls += 1
  }

  func snapshot() -> EngineSnapshot { .off }
  func hasManagedTunnelConfiguration() -> Bool { false }
  func managedTunnelConfiguration() -> ConfigurationDescriptor? { managedConfiguration }
  func pendingPreferenceMutationConfiguration() -> ConfigurationDescriptor? { nil }
  func compensatePendingPreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor,
    revokePreparation: @escaping @Sendable () async throws -> Void
  ) async throws -> Bool { false }
  func finishPreferenceCompensation(
    expectedConfiguration: ConfigurationDescriptor
  ) async throws {}
  func completePreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor
  ) {}

  func mutationCounts() -> (install: Int, cancel: Int, start: Int, stop: Int) {
    (installCalls, cancelCalls, startCalls, stopCalls)
  }
}

struct AvailableEngineLease: NativeEngineLeaseInspecting {
  func isAvailable() async throws -> Bool { true }
  func beginStop(
    for descriptor: ConfigurationDescriptor
  ) async throws -> NativeAuthorityStopContext {
    throw NativeBridgeExecutionError.failure(.unavailable, "unused stop boundary")
  }
  func completeStop(_ context: NativeAuthorityStopContext) async throws {
    throw NativeBridgeExecutionError.failure(.unavailable, "unused stop boundary")
  }
}

final class EmptyCredentialVault: NativeCredentialVaulting, @unchecked Sendable {
  func provision(
    audience: CredentialAudience,
    requiredReferences: [CredentialReference],
    material: CredentialMaterial
  ) throws -> CFWCredentialVault.CredentialVaultReceipt {
    _ = requiredReferences
    _ = material
    return CFWCredentialVault.CredentialVaultReceipt(audience: audience)
  }

  func presence(
    audience: CredentialAudience,
    of references: [CredentialReference]
  ) throws -> [CFWCredentialVault.CredentialPresence] {
    references.map {
      CFWCredentialVault.CredentialPresence(reference: $0, present: false)
    }
  }

  func resolve(
    audience: CredentialAudience,
    slots: [CredentialSlot]
  ) throws -> CredentialMaterial {
    guard slots.isEmpty else {
      throw CredentialMaterialError.missingReference(slots[0].reference.id)
    }
    return .empty
  }

  func previewGarbageCollection(
    _ request: CredentialGarbageCollectionRequest
  ) throws -> CredentialGarbageCollectionPreview {
    _ = request
    throw CredentialVaultError.missingVault
  }

  func commitGarbageCollection(
    _ request: CredentialGarbageCollectionCommitRequest
  ) throws -> CredentialGarbageCollectionReceipt {
    _ = request
    throw CredentialVaultError.missingVault
  }
}

func makePreflightCoordinator(
  proxy: any ProxyAgentTransporting,
  tunnel: any TunnelHostBridging,
  credentialVault: any NativeCredentialVaulting
) -> NativeBridgeCoordinator {
  NativeBridgeCoordinator(
    proxy: proxy,
    systemProxyPreparer: UnusedSystemProxyStartPreparer(),
    tunnel: tunnel,
    engineLease: AvailableEngineLease(),
    credentialVault: credentialVault,
    hostOperationLease: AvailableNativeHostOperationLease(),
    serviceBuildObserver: FixedCurrentServiceBuildObserver())
}
