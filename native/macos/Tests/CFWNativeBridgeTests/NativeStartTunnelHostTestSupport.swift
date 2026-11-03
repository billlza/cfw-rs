import CFWCredentialTransport
import CFWCredentialVault
import CryptoKit
import Foundation
@preconcurrency import NetworkExtension
@preconcurrency import SystemExtensions
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// In-memory Packet Tunnel hosts for the start command tests, including one
// whose installation blocks until a retry.
actor StartableTunnelHost: TunnelHostBridging {
  private(set) var authorizationCalls = 0
  nonisolated let authorizationHandshake = NativeFixtureHandshake()
  nonisolated let approvalHandshake = NativeFixtureHandshake()
  private let blocksAuthorization: Bool
  private let blocksApprovalWait: Bool
  private let authorizationError: AppleNetworkError?
  func authorizeTunnelConfiguration(_ descriptor: ConfigurationDescriptor) async throws {
    #expect(descriptor == self.descriptor)
    authorizationCalls += 1
    if blocksAuthorization {
      try await authorizationHandshake.enter()
    }
    if let authorizationError { throw authorizationError }
  }
  private let expectedInjectedConfiguration: Data?
  private let descriptor: ConfigurationDescriptor
  private let recoveryStatus: RecoveryManagedTunnelStatus
  private let startError: AppleNetworkError?
  private let installResult: SystemExtensionInstallResult
  private let installError: AppleNetworkError?
  private let cleanupEvents: NativeCleanupEventLog?
  private let failedStartSnapshot: EngineFailure?
  private let reportsAsynchronousStartFailure: Bool
  private let staysStarting: Bool
  private let startPendingPreferenceDescriptor: ConfigurationDescriptor?
  private var remainingSnapshotFailures: Int
  private var snapshotCalls = 0
  private let snapshotHook: @Sendable (Int) -> Void
  private(set) var installCalls = 0
  private(set) var cancelInstallCalls = 0
  private(set) var approvalWaitCalls = 0
  private var approvalWait: SystemExtensionApprovalWait = .resolved
  private(set) var startCalls = 0
  private(set) var stopCalls = 0
  private var started = false
  private var failedOwnerPresent = false
  private var managerReplaced = false
  private var pendingPreferenceDescriptor: ConfigurationDescriptor?
  private var remainingCompensationFailures: Int
  private(set) var compensationCalls = 0
  private(set) var finishCompensationCalls = 0

  init(
    descriptor: ConfigurationDescriptor,
    recoveryStatus: RecoveryManagedTunnelStatus = .disconnected,
    startError: AppleNetworkError? = nil,
    installResult: SystemExtensionInstallResult = .completed,
    installError: AppleNetworkError? = nil,
    pendingPreferenceDescriptor: ConfigurationDescriptor? = nil,
    startPendingPreferenceDescriptor: ConfigurationDescriptor? = nil,
    cleanupEvents: NativeCleanupEventLog? = nil,
    failedStartSnapshot: EngineFailure? = nil,
    reportsAsynchronousStartFailure: Bool = false,
    staysStarting: Bool = false,
    snapshotFailures: Int = 0,
    compensationFailures: Int = 0,
    expectedInjectedConfiguration: Data? = nil,
    blocksAuthorization: Bool = false,
    blocksApprovalWait: Bool = false,
    authorizationError: AppleNetworkError? = nil,
    snapshotHook: @escaping @Sendable (Int) -> Void = { _ in }
  ) {
    self.blocksAuthorization = blocksAuthorization
    self.blocksApprovalWait = blocksApprovalWait
    self.authorizationError = authorizationError
    self.snapshotHook = snapshotHook
    self.expectedInjectedConfiguration = expectedInjectedConfiguration
    self.descriptor = descriptor
    self.recoveryStatus = recoveryStatus
    self.startError = startError
    self.installResult = installResult
    self.installError = installError
    self.pendingPreferenceDescriptor = pendingPreferenceDescriptor
    self.startPendingPreferenceDescriptor = startPendingPreferenceDescriptor
    self.cleanupEvents = cleanupEvents
    self.failedStartSnapshot = failedStartSnapshot
    self.reportsAsynchronousStartFailure = reportsAsynchronousStartFailure
    self.staysStarting = staysStarting
    remainingSnapshotFailures = snapshotFailures
    remainingCompensationFailures = compensationFailures
  }

  func installTunnel() throws -> SystemExtensionInstallResult {
    installCalls += 1
    if let installError { throw installError }
    return installResult
  }
  func awaitTunnelInstallationApproval() async throws -> SystemExtensionApprovalWait {
    approvalWaitCalls += 1
    if blocksApprovalWait {
      try await approvalHandshake.enter()
    }
    return approvalWait
  }
  func answerApprovalWaits(with wait: SystemExtensionApprovalWait) { approvalWait = wait }
  func cancelTunnelInstallationWait() { cancelInstallCalls += 1 }

  func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) throws {
    let authorityDescriptor = try AuthorityConfigurationDescriptor(
      byteCount: UInt32(descriptor.byteCount), configSHA256: descriptor.sha256,
      identitySHA256: descriptor.identitySHA256,
      credentialAudience: descriptor.credentialAudience,
      credentialSlots: descriptor.credentialSlots, tunnelOptions: descriptor.tunnelOptions)
    let material = try AuthoritySecretPayloadCodec.decode(
      credentialPayload, descriptor: authorityDescriptor)
    defer { material.erase() }
    let entries = try material.slots.map { slot in
      try slot.withUnsafeBytes {
        try CredentialMaterialEntry(reference: slot.reference, secret: Data($0))
      }
    }
    var credentials = try CredentialMaterial(entries: entries)
    defer { credentials.erase() }
    let filled = try CredentialInjector.inject(
      template: configuration, slots: descriptor.credentialSlots, material: credentials)
    if let expectedInjectedConfiguration {
      #expect(
        try JSONSerialization.jsonObject(with: filled) as? NSDictionary
          == JSONSerialization.jsonObject(with: expectedInjectedConfiguration) as? NSDictionary)
    }
    startCalls += 1
    if let startPendingPreferenceDescriptor {
      pendingPreferenceDescriptor = startPendingPreferenceDescriptor
    }
    if let startError {
      failedOwnerPresent = failedStartSnapshot != nil
      throw startError
    }
    started = true
    failedOwnerPresent = reportsAsynchronousStartFailure && failedStartSnapshot != nil
  }

  func stopTunnel(expectedConfiguration: ConfigurationDescriptor) throws {
    stopCalls += 1
    // As HostBridge: no manager of the stop's configuration is left to stop.
    if managerReplaced { throw AppleNetworkError.staleStopRequest }
    started = false
    failedOwnerPresent = false
  }

  /// A later start wrote its own manager over this one, so every stop of this
  /// configuration is stale; the session this manager ran ended unless
  /// `sessionRuns`.
  func replaceManager(sessionRuns: Bool) {
    managerReplaced = true
    if !sessionRuns {
      started = false
      failedOwnerPresent = false
    }
  }

  func snapshot() throws -> EngineSnapshot {
    snapshotCalls += 1
    snapshotHook(snapshotCalls)
    if remainingSnapshotFailures > 0 {
      remainingSnapshotFailures -= 1
      throw AppleNetworkError.providerMessageFailed("injected owner observation failure")
    }
    if failedOwnerPresent, let failedStartSnapshot {
      return .tunnelFailed(failedStartSnapshot, configuration: descriptor, sequence: 1)
    }
    guard started else { return .off }
    return staysStarting
      ? .tunnelStarting(configuration: descriptor, sequence: 1)
      : .tunnelActive(configuration: descriptor, sequence: 1)
  }

  func recoveryManagedTunnelStatus() -> RecoveryManagedTunnelStatus {
    recoveryStatus
  }

  func simulateRuntimeFailure() {
    started = false
    failedOwnerPresent = true
  }

  func hasManagedTunnelConfiguration() -> Bool { false }
  func managedTunnelConfiguration() -> ConfigurationDescriptor? { nil }
  func pendingPreferenceMutationConfiguration() -> ConfigurationDescriptor? {
    pendingPreferenceDescriptor
  }
  func compensatePendingPreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor,
    revokePreparation: @escaping @Sendable () async throws -> Void
  ) async throws -> Bool {
    guard pendingPreferenceDescriptor == expectedConfiguration else { return false }
    try await revokePreparation()
    if remainingCompensationFailures > 0 {
      remainingCompensationFailures -= 1
      throw AppleNetworkError.tunnelStopTimedOut
    }
    compensationCalls += 1
    started = false
    // HostBridge forgets the started configuration when it compensates, so it
    // no longer reports the provider's last disconnect error.
    failedOwnerPresent = false
    cleanupEvents?.append("compensate-preferences")
    return true
  }
  func finishPreferenceCompensation(
    expectedConfiguration: ConfigurationDescriptor
  ) async throws {
    guard pendingPreferenceDescriptor == expectedConfiguration else { return }
    finishCompensationCalls += 1
    pendingPreferenceDescriptor = nil
    cleanupEvents?.append("finish-preferences")
  }
  func completePreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor
  ) {}

  func counters() -> (install: Int, start: Int, stop: Int) {
    (installCalls, startCalls, stopCalls)
  }
  func cancelInstallCount() -> Int { cancelInstallCalls }
  func compensationCounts() -> (compensate: Int, finish: Int) {
    (compensationCalls, finishCompensationCalls)
  }
  func injectPendingPreferenceMutation(_ descriptor: ConfigurationDescriptor) {
    pendingPreferenceDescriptor = descriptor
  }
}

/// Holds the first installation callback open until the test releases it as a
/// typed timeout, then completes the exact-generation retry. This exercises the
/// coordinator mutation lifetime without relying on a real System Extension.
actor BlockingRetryableInstallationTunnelHost: TunnelHostBridging {
  func authorizeTunnelConfiguration(_ descriptor: ConfigurationDescriptor) throws {
    throw AppleNetworkError.providerDidNotRespond
  }
  private let descriptor: ConfigurationDescriptor
  nonisolated let installationHandshake = NativeFixtureHandshake()
  private(set) var installCalls = 0

  init(descriptor: ConfigurationDescriptor) {
    self.descriptor = descriptor
  }

  func installTunnel() async throws -> SystemExtensionInstallResult {
    installCalls += 1
    if installCalls == 1 {
      try await installationHandshake.enter()
      throw AppleNetworkError.systemExtensionInstallationTimedOut
    }
    return .completed
  }

  func awaitTunnelInstallationApproval() -> SystemExtensionApprovalWait {
    Issue.record("this fixture never awaits an approval")
    return .noPendingRequest
  }

  func cancelTunnelInstallationWait() {}
  func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) {}
  func stopTunnel(expectedConfiguration: ConfigurationDescriptor) {}
  func snapshot() -> EngineSnapshot { .off }
  func recoveryManagedTunnelStatus() -> RecoveryManagedTunnelStatus { .disconnected }
  func hasManagedTunnelConfiguration() -> Bool { false }
  func managedTunnelConfiguration() -> ConfigurationDescriptor? { nil }
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
}
