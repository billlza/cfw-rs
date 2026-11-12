import Foundation
import LocalAuthentication
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

private actor RecoveryLease: NativeEngineLeaseInspecting {
  var identity: InstallationRecoveryIdentity?
  let state: AuthorityState
  init(identity: InstallationRecoveryIdentity?, state: AuthorityState = .off) {
    self.identity = identity
    self.state = state
  }
  func replace(_ identity: InstallationRecoveryIdentity) { self.identity = identity }
  func installationRecoveryIdentity() -> InstallationRecoveryState { .init(identity: identity) }
  func isAvailable() -> Bool { state == .off }
  func authorityOwnership() -> AuthorityOwnershipObservation { .init(state: state, lease: nil) }
  func beginStop(for descriptor: ConfigurationDescriptor) throws -> NativeAuthorityStopContext {
    throw NativeBridgeExecutionError.failure(.unavailable, "unused stop")
  }
  func completeStop(_ context: NativeAuthorityStopContext) throws {
    throw NativeBridgeExecutionError.failure(.unavailable, "unused stop")
  }
}

private actor RecoveryAuthenticator: InstallationRecoveryAuthenticating {
  var calls = 0
  let action: @Sendable () async throws -> Void
  init(_ action: @escaping @Sendable () async throws -> Void = {}) { self.action = action }
  func authenticate() async throws {
    calls += 1
    try await action()
  }
}

private func recoveryIdentity(revision: UInt64 = 8, uid: UInt32 = geteuid()) throws
  -> InstallationRecoveryIdentity
{
  try .init(
    installationID: AuthorityIdentifier(fixtureInstallationID), acceptedEpoch: 4,
    revision: revision, consoleUID: uid)
}

private func recoveryCoordinator(
  lease: RecoveryLease, authentication: RecoveryAuthenticator,
  hostLease: any NativeHostOperationLeaseAcquiring = AvailableNativeHostOperationLease(),
  pendingPreference: ConfigurationDescriptor? = nil
) -> NativeBridgeCoordinator {
  NativeBridgeCoordinator(
    proxy: StubProxyAgent(.off), systemProxyPreparer: UnusedSystemProxyStartPreparer(),
    tunnel: StubTunnelHost(.off, pendingPreference: pendingPreference), engineLease: lease,
    credentialVault: StubCredentialVault(), hostOperationLease: hostLease,
    serviceMaintainer: StubServiceMaintainer(),
    serviceRuntimeObserver: StubServiceRuntimeObserver(),
    systemProxySwitchObserver: StubSystemProxySwitchObserver(observed: .disabled),
    serviceBuildObserver: FixedCurrentServiceBuildObserver(), recoveryAuthenticator: authentication)
}

@Test func installationRecoveryAuthenticatesUnderTheHostLeaseAndReturnsTheExactRootIdentity()
  async throws
{
  let expected = try recoveryIdentity()
  let lease = RecoveryLease(identity: expected)
  let sentinel = LeaseSentinel()
  let authentication = RecoveryAuthenticator { #expect(sentinel.isHeld) }
  let subject = recoveryCoordinator(
    lease: lease, authentication: authentication,
    hostLease: SentinelLeaseAcquirer(sentinel: sentinel))
  #expect(
    try await subject.execute(.authorizeInstallationRecovery)
      == .installationRecovery(InstallationRecoveryState(identity: expected)))
  #expect(await authentication.calls == 1)
  #expect(!sentinel.isHeld)
  #expect(NativeBridgeABITiming.waitsForPerson(.authorizeInstallationRecovery))
}

@Test func deniedRecoveryProducesNoIdentityAndReleasesTheHostLease() async throws {
  let sentinel = LeaseSentinel()
  let authentication = RecoveryAuthenticator {
    throw NativeBridgeExecutionError.failure(.permissionDenied, "denied")
  }
  let subject = recoveryCoordinator(
    lease: RecoveryLease(identity: try recoveryIdentity()), authentication: authentication,
    hostLease: SentinelLeaseAcquirer(sentinel: sentinel))
  await #expect(throws: NativeBridgeExecutionError.self) {
    try await subject.execute(.authorizeInstallationRecovery)
  }
  #expect(!sentinel.isHeld)
}

@Test(arguments: [false, true])
func changedAuthorityOrConsoleDuringRecoveryIsRejected(consoleChange: Bool) async throws {
  let lease = RecoveryLease(identity: try recoveryIdentity())
  let authentication = RecoveryAuthenticator {
    await lease.replace(
      try recoveryIdentity(
        revision: consoleChange ? 8 : 9, uid: consoleChange ? geteuid() + 1 : geteuid()))
  }
  let subject = recoveryCoordinator(lease: lease, authentication: authentication)
  await #expect(throws: NativeBridgeExecutionError.self) {
    try await subject.execute(.authorizeInstallationRecovery)
  }
}

@Test func cancellationAfterAuthenticationDoesNotReturnAnIdentity() async throws {
  let authentication = RecoveryAuthenticator { throw CancellationError() }
  let subject = recoveryCoordinator(
    lease: RecoveryLease(identity: try recoveryIdentity()), authentication: authentication)
  await #expect(throws: CancellationError.self) {
    try await subject.execute(.authorizeInstallationRecovery)
  }
}

@Test func recoveryRefusesUnfinishedTunnelPreferencesBeforeAuthentication() async throws {
  let authentication = RecoveryAuthenticator()
  let subject = recoveryCoordinator(
    lease: RecoveryLease(identity: try recoveryIdentity()), authentication: authentication,
    pendingPreference: try descriptor(slot: .tunnel))
  await #expect(throws: NativeBridgeExecutionError.self) {
    try await subject.execute(.authorizeInstallationRecovery)
  }
  #expect(await authentication.calls == 0)
}

@Test func recoveryDistinguishesAnUnenrolledMachineBeforeAuthentication() async throws {
  let authentication = RecoveryAuthenticator()
  let subject = recoveryCoordinator(
    lease: RecoveryLease(identity: nil), authentication: authentication)
  #expect(
    try await subject.execute(.authorizeInstallationRecovery)
      == .installationRecovery(InstallationRecoveryState(identity: nil)))
  #expect(await authentication.calls == 0)
}

@Test func recoveryCommandAcceptsNoRendererChosenIdentityOrAuthorization() throws {
  let command = NativeBridgeCommand.authorizeInstallationRecovery
  let envelope = NativeRequestEnvelope(requestID: UUID(), command: command)
  let encoded = try JSONEncoder().encode(envelope)
  #expect(try NativeBridgeProtocolCodec.decodeRequest(encoded).command == command)
  let forged = String(decoding: encoded, as: UTF8.self).replacingOccurrences(
    of: "\"opcode\":\"authorize_installation_recovery\"",
    with: "\"opcode\":\"authorize_installation_recovery\",\"payload\":{\"authorized\":true}")
  #expect(throws: (any Error).self) {
    try NativeBridgeProtocolCodec.decodeRequest(Data(forged.utf8))
  }
}

@Test func installationRecoveryWireMatchesRustFixtures() throws {
  var root = URL(fileURLWithPath: #filePath)
  for _ in 0..<5 { root.deleteLastPathComponent() }
  func fixture(_ name: String) throws -> Data {
    try Data(contentsOf: root.appendingPathComponent("contracts/native-bridge-v10/\(name).json"))
  }
  let request = try NativeBridgeProtocolCodec.decodeRequest(
    fixture("installation-recovery-request"))
  #expect(request.command == .authorizeInstallationRecovery)
  for (name, enrolled) in [
    ("installation-recovery-response", true), ("installation-unenrolled-response", false),
  ] {
    let response = try JSONDecoder().decode(NativeResponseEnvelope.self, from: fixture(name))
    guard case .installationRecovery(let state) = response.result else {
      Issue.record("expected installation recovery response")
      continue
    }
    #expect((state.identity != nil) == enrolled)
    let roundtrip = try JSONDecoder().decode(
      NativeResponseEnvelope.self, from: NativeBridgeProtocolCodec.encodeResponse(response))
    #expect(roundtrip == response)
  }
}

@Test func recoveryAuthenticationKeepsDenialUnavailabilityAndInternalFailureDistinct() {
  #expect(
    DeviceOwnerRecoveryAuthenticator.failure(LAError(.userCancel)).responseFailure.code
      == .permissionDenied)
  #expect(
    DeviceOwnerRecoveryAuthenticator.failure(LAError(.authenticationFailed)).responseFailure.code
      == .permissionDenied)
  #expect(
    DeviceOwnerRecoveryAuthenticator.failure(LAError(.systemCancel)).responseFailure.code
      == .approvalDenied)
  #expect(
    DeviceOwnerRecoveryAuthenticator.failure(LAError(.notInteractive)).responseFailure.code
      == .unavailable)
  #expect(DeviceOwnerRecoveryAuthenticator.failure(nil).responseFailure.code == .internal)
  #expect(
    DeviceOwnerRecoveryAuthenticator.failure(NSError(domain: "unexpected", code: 1)).responseFailure
      .code == .internal)
}
