import CFWSharedProtocol
import Foundation
import Security
import Testing

@testable import CFWAppleNetwork

private struct FixedProxyAgentServiceController: ProxyAgentServiceControlling {
  let status: ProxyAgentRegistrationStatus

  func registrationStatus() -> ProxyAgentRegistrationStatus { status }

  func ensureRegistered() throws {}
}

private final class FakeProxyAgentService: ProxyAgentServicing, @unchecked Sendable {
  private(set) var registerCalls = 0
  var statuses: [ProxyAgentRegistrationStatus]
  var registerError: (any Error)?

  init(
    _ statuses: [ProxyAgentRegistrationStatus],
    registerError: (any Error)? = nil
  ) {
    self.statuses = statuses
    self.registerError = registerError
  }

  var registrationStatus: ProxyAgentRegistrationStatus {
    statuses.count > 1 ? statuses.removeFirst() : statuses[0]
  }

  func register() throws {
    registerCalls += 1
    if let registerError { throw registerError }
  }

  func unregister() throws {}
}

private enum ProxyAgentRegistrationTestError: Error { case denied }

private final class ProxyAgentTestCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var value = 0

  func increment() { lock.withLock { value += 1 } }
  var count: Int { lock.withLock { value } }
}

private final class ProxyAgentTestLatch: @unchecked Sendable {
  private let lock = NSLock()
  private var signaled = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func signal() {
    let values = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
      guard !signaled else { return [] }
      signaled = true
      let values = waiters
      waiters.removeAll()
      return values
    }
    for value in values { value.resume() }
  }

  func wait() async {
    await withCheckedContinuation { continuation in
      let ready = lock.withLock {
        guard !signaled else { return true }
        waiters.append(continuation)
        return false
      }
      if ready { continuation.resume() }
    }
  }
}

private func transport(
  status: ProxyAgentRegistrationStatus
) throws -> AuthenticatedProxyAgentTransport {
  try AuthenticatedProxyAgentTransport(
    machServiceName: "com.bill.clashformac.proxy-agent",
    teamIdentifier: "YKUPL7Z869",
    proxyAgentBundleIdentifier: "com.bill.clashformac.proxy-agent",
    serviceController: FixedProxyAgentServiceController(status: status))
}

private enum Installed40019TestObservationError: Error { case rejected }

private enum Installed40019TestResponse: Equatable, Sendable {
  case off
  case active
  case failed
  case tunnelActive
  case currentSchema
}

private struct Installed40019TestResponseEnvelope: Encodable {
  let schemaVersion: UInt16
  let requestID: RequestID
  let result: CommandResult
}

private func installed40019SnapshotDescriptor(
  slot: ConfigurationSlot
) throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: slot,
    tunnelOptions: slot == .tunnel ? TunnelNetworkOptions(ipv6Enabled: true) : nil,
    credentialAudience: try appleCredentialAudience(),
    installationID: UUID(),
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "ab", count: 32)),
    identitySHA256: SHA256Digest(hex: String(repeating: "cd", count: 32))
  )
}

private final class Installed40019MigrationHarness: @unchecked Sendable {
  private let lock = NSLock()
  private var observations: [Result<Installed40019ServiceProcessIdentity, Error>]
  private let response: Installed40019TestResponse
  private let peerPID: pid_t
  private let peerUID: uid_t
  private var mutableEvents: [String] = []
  private var mutableRequests: [Data] = []
  private var mutableRequirements: [String] = []

  init(
    observations: [Result<Installed40019ServiceProcessIdentity, Error>],
    response: Installed40019TestResponse = .off,
    peerPID: pid_t,
    peerUID: uid_t
  ) {
    self.observations = observations
    self.response = response
    self.peerPID = peerPID
    self.peerUID = peerUID
  }

  func observe() throws -> Installed40019ServiceProcessIdentity {
    let result = lock.withLock { () -> Result<Installed40019ServiceProcessIdentity, Error> in
      mutableEvents.append("observe")
      guard !observations.isEmpty else {
        return .failure(Installed40019TestObservationError.rejected)
      }
      return observations.count == 1 ? observations[0] : observations.removeFirst()
    }
    return try result.get()
  }

  func makeConnection(_ serviceName: String) -> NSXPCConnection {
    lock.withLock { mutableEvents.append("connect:\(serviceName)") }
    return NSXPCConnection(machServiceName: "com.bill.clashformac.tests.never-activated")
  }

  func prepareConnection(_ connection: NSXPCConnection, requirement: String) {
    _ = connection
    lock.withLock {
      mutableEvents.append("prepare")
      mutableRequirements.append(requirement)
    }
  }

  func activateConnection(_ connection: NSXPCConnection) {
    _ = connection
    lock.withLock { mutableEvents.append("activate") }
  }

  func execute(
    _ connection: NSXPCConnection,
    request: Data,
    reply: @escaping @Sendable (Data?, NSError?) -> Void
  ) {
    _ = connection
    let requestID: UUID? = lock.withLock {
      mutableEvents.append("execute")
      mutableRequests.append(request)
      guard
        let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
        let requestID = object["requestID"] as? [String: Any],
        let rawValue = requestID["rawValue"] as? String
      else { return nil }
      return UUID(uuidString: rawValue)
    }
    guard let requestID else {
      reply(nil, NSError(domain: NSCocoaErrorDomain, code: 1))
      return
    }
    do {
      reply(try responseData(requestID: requestID), nil)
    } catch {
      reply(nil, error as NSError)
    }
  }

  func observedPeerPID(_ connection: NSXPCConnection) -> pid_t {
    _ = connection
    return peerPID
  }

  func observedPeerUID(_ connection: NSXPCConnection) -> uid_t {
    _ = connection
    return peerUID
  }

  var events: [String] { lock.withLock { mutableEvents } }
  var requests: [Data] { lock.withLock { mutableRequests } }
  var requirements: [String] { lock.withLock { mutableRequirements } }

  private func responseData(requestID: UUID) throws -> Data {
    let schemaVersion: UInt16 = response == .currentSchema ? 6 : 5
    let snapshot: EngineSnapshot
    switch response {
    case .off, .currentSchema:
      snapshot = .off(sequence: 9)
    case .active:
      snapshot = .proxyActive(
        configuration: try installed40019SnapshotDescriptor(slot: .systemProxy),
        sequence: 9
      )
    case .failed:
      snapshot = try EngineSnapshot(
        mode: .off,
        state: .failed(
          EngineFailure(code: "test-failure", message: "test failure", isRetryable: false)
        ),
        configuration: nil,
        sequence: 9
      )
    case .tunnelActive:
      snapshot = .tunnelActive(
        configuration: try installed40019SnapshotDescriptor(slot: .tunnel),
        sequence: 9
      )
    }
    return try JSONEncoder().encode(
      Installed40019TestResponseEnvelope(
        schemaVersion: schemaVersion,
        requestID: RequestID(rawValue: requestID),
        result: try CommandResult(kind: .snapshot, snapshot: snapshot)
      )
    )
  }
}

private final class SequencedProxyAgentServiceController:
  ProxyAgentServiceControlling, @unchecked Sendable
{
  private let lock = NSLock()
  private var statuses: [ProxyAgentRegistrationStatus]

  init(_ statuses: [ProxyAgentRegistrationStatus]) { self.statuses = statuses }

  func registrationStatus() -> ProxyAgentRegistrationStatus {
    lock.withLock {
      statuses.count == 1 ? statuses[0] : statuses.removeFirst()
    }
  }

  func ensureRegistered() throws {}
}

private func installed40019Identity(
  pid: pid_t = 4242,
  uid: uid_t = 501,
  startSeconds: UInt64 = 1_700_000_000,
  requirement: String? = nil
) -> Installed40019ServiceProcessIdentity {
  Installed40019ServiceProcessIdentity(
    service: .proxyAgent,
    processIdentifier: pid,
    userIdentifier: uid,
    startSeconds: startSeconds,
    startMicroseconds: 123_456,
    xpcCodeSigningRequirement: requirement
      ?? Installed40019ServiceProcessObserver.codeSigningRequirement(
        for: .proxyAgent, invokingUserIdentifier: uid)
  )
}

private func installed40019Transport(
  harness: Installed40019MigrationHarness,
  statuses: [ProxyAgentRegistrationStatus] = [.enabled]
) throws -> AuthenticatedProxyAgentTransport {
  try AuthenticatedProxyAgentTransport(
    machServiceName: "com.bill.clashformac.proxy-agent",
    teamIdentifier: "YKUPL7Z869",
    proxyAgentBundleIdentifier: "com.bill.clashformac.proxy-agent",
    serviceController: SequencedProxyAgentServiceController(statuses),
    installed40019Dependencies: Installed40019ProxyTransportDependencies(
      observeProcess: { try harness.observe() },
      makeConnection: { harness.makeConnection($0) },
      prepareConnection: { harness.prepareConnection($0, requirement: $1) },
      activateConnection: { harness.activateConnection($0) },
      execute: { harness.execute($0, request: $1, reply: $2) },
      peerProcessIdentifier: { harness.observedPeerPID($0) },
      peerUserIdentifier: { harness.observedPeerUID($0) }
    )
  )
}

@Suite(.serialized)
struct ProxyAgentHostClientTests {
  @Test func registrationRepairsNotFoundServiceRecord() throws {
    let service = FakeProxyAgentService([.notFound, .enabled])
    let controller = SMProxyAgentServiceController(service: service)
    try controller.ensureRegistered()
    #expect(service.registerCalls == 1)
    #expect(controller.registrationStatus() == .enabled)
  }

  @Test func registrationKeepsMissingBundleDistinctWhenNotFoundPersists() {
    let service = FakeProxyAgentService(
      [.notFound],
      registerError: ProxyAgentRegistrationTestError.denied
    )
    #expect(throws: ProxyAgentHostError.registrationUnavailable) {
      try SMProxyAgentServiceController(service: service).ensureRegistered()
    }
    #expect(service.registerCalls == 1)
  }

  @Test func outstandingReplyRegistryAppliesExactBoundAndReleasesCapacity() throws {
    var registry = BoundedProxyAgentRequestRegistry(maximum: 2)
    let first = try registry.reserve()
    let second = try registry.reserve()
    #expect(registry.tokens.count == 2)
    #expect(throws: ProxyAgentHostError.transportCapacityExceeded) {
      _ = try registry.reserve()
    }

    registry.release(first)
    let replacement = try registry.reserve()
    #expect(registry.tokens == [second, replacement])
    registry.release(UUID())
    #expect(registry.tokens.count == 2)
  }

  @Test func timeoutCancellationTransportLossAndProtocolDriftRequireConnectionRotation() {
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.transportTimedOut))
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.transportUnavailable("injected")))
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: CancellationError()))
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.malformedResponse))
    #expect(
      AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.responseMismatch))
    #expect(
      !AuthenticatedProxyAgentTransport.shouldRetireConnection(
        after: ProxyAgentHostError.transportCapacityExceeded))
  }

  @Test func retiringAConnectionFailsEveryConcurrentRequestAndInvalidatesExactlyOnce() {
    let invalidations = ProxyAgentTestCounter()
    let failures = ProxyAgentTestCounter()
    let lifecycle = ProxyAgentConnectionLifecycle {
      invalidations.increment()
    }
    let first = UUID()
    let second = UUID()
    #expect(lifecycle.register(token: first) { failures.increment() })
    #expect(lifecycle.register(token: second) { failures.increment() })
    #expect(lifecycle.pendingCount == 2)

    lifecycle.retire()
    lifecycle.retire()
    #expect(lifecycle.isRetired)
    #expect(lifecycle.pendingCount == 0)
    #expect(failures.count == 2)
    #expect(invalidations.count == 1)

    #expect(!lifecycle.register(token: UUID()) { failures.increment() })
    #expect(failures.count == 3)
  }

  @Test func lateReplyOnRetiredConnectionCannotCompleteReplacementGeneration() async throws {
    let oldLifecycle = ProxyAgentConnectionLifecycle {}
    let oldGate = CallbackContinuationGate<Int>()
    let oldInstalled = ProxyAgentTestLatch()
    let oldToken = UUID()
    let oldTask = Task<Int, Error> {
      try await withCheckedThrowingContinuation { continuation in
        oldGate.install(continuation)
        #expect(
          oldLifecycle.register(token: oldToken) {
            oldGate.finish(
              .failure(ProxyAgentHostError.transportUnavailable("connection-retired"))
            )
          }
        )
        oldInstalled.signal()
      }
    }
    await oldInstalled.wait()
    oldLifecycle.retire()
    await #expect(throws: ProxyAgentHostError.self) {
      _ = try await oldTask.value
    }

    let replacementGate = CallbackContinuationGate<Int>()
    let replacementInstalled = ProxyAgentTestLatch()
    let replacementTask = Task<Int, Error> {
      try await withCheckedThrowingContinuation { continuation in
        replacementGate.install(continuation)
        replacementInstalled.signal()
      }
    }
    await replacementInstalled.wait()
    oldGate.finish(.success(1))
    replacementGate.finish(.success(2))
    #expect(try await replacementTask.value == 2)
  }

  @Test func snapshotRequiresApprovedRegistrationInsteadOfProjectingFalseOff() async throws {
    let awaitingApproval = try transport(status: .requiresApproval)
    await #expect(throws: ProxyAgentHostError.registrationRequiresApproval) {
      _ = try await awaitingApproval.snapshot()
    }

    for status in [ProxyAgentRegistrationStatus.notRegistered, .notFound] {
      let unavailable = try transport(status: status)
      await #expect(throws: ProxyAgentHostError.registrationUnavailable) {
        _ = try await unavailable.snapshot()
      }
    }
  }

  @Test func installed40019CompatibilityUsesOneExactV5ReadOnlySnapshot() async throws {
    let identity = installed40019Identity()
    let harness = Installed40019MigrationHarness(
      observations: [.success(identity), .success(identity), .success(identity)],
      peerPID: identity.processIdentifier,
      peerUID: identity.userIdentifier
    )
    let transport = try installed40019Transport(harness: harness)

    let snapshot = try await transport.snapshotInstalled40019ForMigration()
    #expect(snapshot == .off(sequence: 9))
    #expect(
      harness.events
        == [
          "observe", "observe", "connect:com.bill.clashformac.proxy-agent",
          "prepare", "activate", "execute", "observe",
        ])
    #expect(harness.requests.count == 1)
    #expect(harness.requirements == [identity.xpcCodeSigningRequirement])

    let request = try #require(
      JSONSerialization.jsonObject(with: harness.requests[0]) as? [String: Any])
    #expect(request["schemaVersion"] as? Int == 5)
    let command = try #require(request["command"] as? [String: Any])
    #expect(Set(command.keys) == ["kind"])
    #expect(command["kind"] as? String == "snapshot")
    #expect(throws: ProtocolValidationError.unsupportedSchemaVersion(5)) {
      try ProtocolCodec.decodeRequest(harness.requests[0])
    }
  }

  @Test func installed40019IdentityFailureNeverCreatesAConnection() async throws {
    for observations: [Result<Installed40019ServiceProcessIdentity, Error>] in [
      [.failure(Installed40019TestObservationError.rejected)],
      [.success(installed40019Identity()), .failure(Installed40019TestObservationError.rejected)],
      [.success(installed40019Identity()), .success(installed40019Identity(startSeconds: 2))],
    ] {
      let harness = Installed40019MigrationHarness(
        observations: observations,
        peerPID: 4242,
        peerUID: 501
      )
      let transport = try installed40019Transport(harness: harness)
      await #expect(throws: ProxyAgentHostError.responseMismatch) {
        _ = try await transport.snapshotInstalled40019ForMigration()
      }
      #expect(!harness.events.contains(where: { $0.hasPrefix("connect:") }))
      #expect(harness.requests.isEmpty)
    }
  }

  @Test func installed40019MissingRegistrationNeverObservesOrConnects() async throws {
    let harness = Installed40019MigrationHarness(
      observations: [.success(installed40019Identity())],
      peerPID: 4242,
      peerUID: 501
    )
    let transport = try installed40019Transport(
      harness: harness,
      statuses: [.notRegistered]
    )
    await #expect(throws: ProxyAgentHostError.registrationUnavailable) {
      _ = try await transport.snapshotInstalled40019ForMigration()
    }
    #expect(harness.events.isEmpty)
    #expect(harness.requests.isEmpty)
  }

  @Test func installed40019PeerOrPostObservationDriftRejectsTheSingleReply() async throws {
    let identity = installed40019Identity()
    let wrongPeer = Installed40019MigrationHarness(
      observations: [.success(identity), .success(identity), .success(identity)],
      peerPID: identity.processIdentifier + 1,
      peerUID: identity.userIdentifier
    )
    await #expect(throws: ProxyAgentHostError.responseMismatch) {
      _ = try await installed40019Transport(harness: wrongPeer)
        .snapshotInstalled40019ForMigration()
    }
    #expect(wrongPeer.requests.count == 1)
    #expect(wrongPeer.events.filter { $0 == "observe" }.count == 2)

    let wrongUID = Installed40019MigrationHarness(
      observations: [.success(identity), .success(identity), .success(identity)],
      peerPID: identity.processIdentifier,
      peerUID: identity.userIdentifier + 1
    )
    await #expect(throws: ProxyAgentHostError.responseMismatch) {
      _ = try await installed40019Transport(harness: wrongUID)
        .snapshotInstalled40019ForMigration()
    }
    #expect(wrongUID.requests.count == 1)
    #expect(wrongUID.events.filter { $0 == "observe" }.count == 2)

    let drifted = installed40019Identity(startSeconds: identity.startSeconds + 1)
    let postDrift = Installed40019MigrationHarness(
      observations: [.success(identity), .success(identity), .success(drifted)],
      peerPID: identity.processIdentifier,
      peerUID: identity.userIdentifier
    )
    await #expect(throws: ProxyAgentHostError.responseMismatch) {
      _ = try await installed40019Transport(harness: postDrift)
        .snapshotInstalled40019ForMigration()
    }
    #expect(postDrift.requests.count == 1)
    #expect(postDrift.events.filter { $0 == "observe" }.count == 3)
  }

  @Test func installed40019ReturnsStructurallyValidActiveAndFailedSnapshots() async throws {
    let identity = installed40019Identity()
    for response in [Installed40019TestResponse.active, .failed] {
      let harness = Installed40019MigrationHarness(
        observations: [.success(identity), .success(identity), .success(identity)],
        response: response,
        peerPID: identity.processIdentifier,
        peerUID: identity.userIdentifier
      )
      let snapshot = try await installed40019Transport(harness: harness)
        .snapshotInstalled40019ForMigration()
      switch response {
      case .active:
        #expect(snapshot.mode == .systemProxy)
        #expect(snapshot.state.kind == .proxyActive)
        #expect(snapshot.configuration != nil)
      case .failed:
        #expect(snapshot.mode == .off)
        #expect(snapshot.state.kind == .failed)
        #expect(snapshot.configuration == nil)
      case .off, .tunnelActive, .currentSchema:
        Issue.record("unexpected legacy snapshot test case")
      }
      #expect(harness.requests.count == 1)
    }
  }

  @Test func installed40019RejectsCurrentSchemaTunnelRoleAndRegistrationDrift() async throws {
    let identity = installed40019Identity()
    for response in [Installed40019TestResponse.currentSchema, .tunnelActive] {
      let harness = Installed40019MigrationHarness(
        observations: [.success(identity), .success(identity), .success(identity)],
        response: response,
        peerPID: identity.processIdentifier,
        peerUID: identity.userIdentifier
      )
      let transport = try installed40019Transport(harness: harness)
      await #expect(throws: ProxyAgentHostError.malformedResponse) {
        _ = try await transport.snapshotInstalled40019ForMigration()
      }
      #expect(harness.requests.count == 1)
    }

    let registrationDrift = Installed40019MigrationHarness(
      observations: [.success(identity), .success(identity), .success(identity)],
      peerPID: identity.processIdentifier,
      peerUID: identity.userIdentifier
    )
    let transport = try installed40019Transport(
      harness: registrationDrift,
      statuses: [.enabled, .enabled, .notRegistered]
    )
    await #expect(throws: ProxyAgentHostError.responseMismatch) {
      _ = try await transport.snapshotInstalled40019ForMigration()
    }
    #expect(registrationDrift.requests.count == 1)
  }

  @Test func installed40019ClosedServiceRequirementsPinExactCdHashes() throws {
    let proxy = Installed40019ServiceProcessObserver.codeSigningRequirement(
      for: .proxyAgent, invokingUserIdentifier: 501)
    let authority = Installed40019ServiceProcessObserver.codeSigningRequirement(
      for: .globalAuthority, invokingUserIdentifier: 501)
    #expect(proxy.contains("identifier \"com.bill.clashformac.proxy-agent\""))
    #expect(proxy.contains("cdhash H\"0b5d6a714fc9599f2ddd808e2d7c1ba222f5aeac\""))
    #expect(authority.contains("identifier \"com.bill.clashformac.global-authority\""))
    #expect(authority.contains("cdhash H\"aa1c4ff3a4a36a4a479719071116fad3a24f17e3\""))
    for value in [proxy, authority] {
      var requirement: SecRequirement?
      #expect(
        SecRequirementCreateWithString(value as CFString, [], &requirement) == errSecSuccess)
      #expect(requirement != nil)
    }
  }

  @Test func kernelProcessIdentityReadsTheCurrentUnprivilegedProcess() throws {
    let identity = try Installed40019ServiceProcessObserver.kernelProcessIdentity(getpid())
    #expect(identity.processIdentifier == getpid())
    #expect(identity.effectiveUserIdentifier == geteuid())
    #expect(identity.realUserIdentifier == getuid())
    #expect(identity.startSeconds > 0)
    #expect(identity.startMicroseconds < 1_000_000)
  }

  @Test func kernelProcessIdentityReadsRootLaunchdWithoutPrivilege() throws {
    let identity = try Installed40019ServiceProcessObserver.kernelProcessIdentity(1)
    #expect(identity.processIdentifier == 1)
    #expect(identity.effectiveUserIdentifier == 0)
    #expect(identity.realUserIdentifier == 0)
    #expect(identity.startSeconds > 0)
    #expect(identity.startMicroseconds < 1_000_000)
  }

  @Test func kernelProcessIdentityRejectsPidAndTimestampAmbiguity() {
    #expect(throws: (any Error).self) {
      try Installed40019ServiceProcessObserver.validatedKernelProcessIdentity(
        expectedProcessIdentifier: 12,
        observedProcessIdentifier: 13,
        effectiveUserIdentifier: 0,
        realUserIdentifier: 0,
        startSeconds: 1,
        startMicroseconds: 0
      )
    }
    #expect(throws: (any Error).self) {
      try Installed40019ServiceProcessObserver.validatedKernelProcessIdentity(
        expectedProcessIdentifier: 12,
        observedProcessIdentifier: 12,
        effectiveUserIdentifier: 0,
        realUserIdentifier: 0,
        startSeconds: 1,
        startMicroseconds: 1_000_000
      )
    }
  }
}
