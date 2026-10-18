import CFWCredentialTransport
import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWLibboxRuntime
@testable import CFWPacketTunnel

private enum FixtureError: Error { case forced }

// MARK: - Fakes

private final class BlockingCallGate: @unchecked Sendable {
  private let entered = DispatchSemaphore(value: 0)
  private let released = DispatchSemaphore(value: 0)

  func block() {
    entered.signal()
    _ = released.wait(timeout: .now() + 2)
  }

  func waitUntilEntered() -> Bool {
    entered.wait(timeout: .now() + 2) == .success
  }

  func release() { released.signal() }
}

private final class FakeMonotonicClock: ProviderMonotonicClock, @unchecked Sendable {
  let value: UInt64
  init(value: UInt64) { self.value = value }
  func nowMilliseconds() -> UInt64 { value }
}

private final class FakeOwnerAuthorityClient: EngineOwnerAuthorityClient, @unchecked Sendable {
  private let lock = NSLock()
  private let makeRedeemed: @Sendable () throws -> RedeemedTunnelStart
  private let onRedeem: @Sendable () -> Void
  private let redeemGate: BlockingCallGate?
  private var redeemCountValue = 0
  private var readyValue: [ReadyAttestation] = []
  private var stoppedValue: [StoppedAttestation] = []
  private var readyThrows: Bool
  private let readyGate: BlockingCallGate?
  private var stoppedFailuresRemaining: Int
  private var stoppedAttemptCountValue = 0
  private let stoppedGate: BlockingCallGate?
  private let stoppedSignal = DispatchSemaphore(value: 0)

  init(
    readyThrows: Bool = false,
    readyGate: BlockingCallGate? = nil,
    stoppedFailures: Int = 0,
    stoppedGate: BlockingCallGate? = nil,
    redeemGate: BlockingCallGate? = nil,
    onRedeem: @escaping @Sendable () -> Void = {},
    makeRedeemed: @escaping @Sendable () throws -> RedeemedTunnelStart
  ) {
    self.readyThrows = readyThrows
    self.readyGate = readyGate
    self.stoppedFailuresRemaining = stoppedFailures
    self.stoppedGate = stoppedGate
    self.redeemGate = redeemGate
    self.onRedeem = onRedeem
    self.makeRedeemed = makeRedeemed
  }

  var redeemCount: Int { lock.withLock { redeemCountValue } }
  var readyAttestations: [ReadyAttestation] { lock.withLock { readyValue } }
  var stoppedAttestations: [StoppedAttestation] { lock.withLock { stoppedValue } }
  var stoppedAttemptCount: Int { lock.withLock { stoppedAttemptCountValue } }
  func waitForStoppedAttempt() -> Bool {
    stoppedSignal.wait(timeout: .now() + 2) == .success
  }

  func bind(
    _ capability: OwnerCapability,
    context: ProxyOwnerContext
  ) async throws -> LeaseView {
    _ = context
    capability.erase()
    throw AuthorityDomainError(code: .globalAuthorityUnavailable)
  }

  func redeem(_ ticket: StartTicket) async throws -> RedeemedTunnelStart {
    ticket.erase()
    let count = lock.withLock { () -> Int in
      redeemCountValue += 1
      return redeemCountValue
    }
    guard count == 1 else {
      // A single ticket must never be redeemed twice.
      throw AuthorityDomainError(code: .ticketAlreadyRedeemed)
    }
    onRedeem()
    redeemGate?.block()
    return try makeRedeemed()
  }

  func attestReady(_ attestation: ReadyAttestation) async throws {
    lock.withLock { readyValue.append(attestation) }
    readyGate?.block()
    if readyThrows { throw AuthorityDomainError(code: .globalAuthorityUnavailable) }
  }

  func attestStopped(_ attestation: StoppedAttestation) async throws {
    let shouldFail = lock.withLock { () -> Bool in
      stoppedAttemptCountValue += 1
      if stoppedFailuresRemaining > 0 {
        stoppedFailuresRemaining -= 1
        return true
      }
      stoppedValue.append(attestation)
      return false
    }
    stoppedSignal.signal()
    stoppedGate?.block()
    if shouldFail {
      throw AuthorityDomainError(code: .globalAuthorityUnavailable)
    }
  }
}

private final class FailingRedeemAuthorityClient: EngineOwnerAuthorityClient, @unchecked Sendable {
  private let error: AuthorityDomainError
  private let lock = NSLock()
  private var redeemCountValue = 0

  init(error: AuthorityDomainError) { self.error = error }

  var redeemCount: Int { lock.withLock { redeemCountValue } }

  func bind(
    _ capability: OwnerCapability,
    context: ProxyOwnerContext
  ) async throws -> LeaseView {
    _ = context
    capability.erase()
    throw error
  }

  func redeem(_ ticket: StartTicket) async throws -> RedeemedTunnelStart {
    ticket.erase()
    lock.withLock { redeemCountValue += 1 }
    throw error
  }

  func attestReady(_ attestation: ReadyAttestation) async throws {}
  func attestStopped(_ attestation: StoppedAttestation) async throws {}
}

private final class FakeEngine: PacketEngine, @unchecked Sendable {
  private let lock = NSLock()
  private var ownedDescriptor: Int32 = -1
  private var startCountValue = 0
  private var stopCountValue = 0
  private var stopFailure: LibboxInstanceUnclosable?
  private var startDeadlines: [EngineStartDeadline] = []

  var startCount: Int { lock.withLock { startCountValue } }
  var stopCount: Int { lock.withLock { stopCountValue } }
  var deadlines: [EngineStartDeadline] { lock.withLock { startDeadlines } }

  /// Makes this and every later stop throw `failure`, as an engine whose
  /// libbox instance could not be closed does.
  func failStops(with failure: LibboxInstanceUnclosable) {
    lock.withLock { stopFailure = failure }
  }

  deinit { closeOwned() }

  func start(configuration: Data, packetFileDescriptor: Int32, deadline: EngineStartDeadline)
    throws
  {
    lock.withLock {
      startCountValue += 1
      startDeadlines.append(deadline)
      ownedDescriptor = packetFileDescriptor
    }
  }

  func stop() throws(LibboxInstanceUnclosable) {
    let failure = lock.withLock { () -> LibboxInstanceUnclosable? in
      stopCountValue += 1
      if let stopFailure {
        return stopFailure
      }
      closeOwnedLocked()
      return nil
    }
    if let failure {
      throw failure
    }
  }

  func healthCheck() throws {}

  private func closeOwned() { lock.withLock { closeOwnedLocked() } }
  private func closeOwnedLocked() {
    guard ownedDescriptor >= 0 else { return }
    Darwin.close(ownedDescriptor)
    ownedDescriptor = -1
  }
}

private struct FakeEngineFactory: PacketEngineFactory {
  let engine: FakeEngine
  func makeEngine() throws -> any PacketEngine { engine }
}

/// A runtime whose failed start libbox could not close: the start throws the
/// close failure, and so does every stop.
private final class UnclosablePacketRuntime: LibboxServiceRuntime, @unchecked Sendable {
  private let lock = NSLock()
  private let closeFailure: LibboxInstanceUnclosable
  private var stopCountValue = 0

  init(closeFailure: LibboxInstanceUnclosable) {
    self.closeFailure = closeFailure
  }

  var stopCount: Int { lock.withLock { stopCountValue } }

  func start(configuration: Data, packetFileDescriptor: Int32?, deadline: EngineStartDeadline)
    throws
  {
    // The runtime owns the descriptor on every path, failures included.
    if let packetFileDescriptor {
      Darwin.close(packetFileDescriptor)
    }
    throw closeFailure
  }

  func stop() throws(LibboxInstanceUnclosable) {
    lock.withLock { stopCountValue += 1 }
    throw closeFailure
  }

  func healthCheck() throws {}
  func resetNetwork() {}
}

private struct UnclosablePacketRuntimeFactory: LibboxServiceRuntimeFactory {
  let runtime: UnclosablePacketRuntime

  func makeRuntime(role: LibboxRuntimeRole) throws -> any LibboxServiceRuntime { runtime }
}

/// What happened, in order: completions the test records and ended processes.
private final class EventLog: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [String] = []

  func record(_ event: String) {
    lock.withLock { events.append(event) }
  }

  var values: [String] { lock.withLock { events } }
}

private final class ProcessEndRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let semaphore = DispatchSemaphore(value: 0)
  private var failures: [LibboxInstanceUnclosable] = []

  func record(_ failure: LibboxInstanceUnclosable) {
    lock.withLock { failures.append(failure) }
    semaphore.signal()
  }

  func wait() -> Bool { semaphore.wait(timeout: .now() + 2) == .success }
  var values: [LibboxInstanceUnclosable] { lock.withLock { failures } }
}

private final class FakePump: PacketPumping, @unchecked Sendable {
  private let lock = NSLock()
  private var transferred = false
  private var startCountValue = 0
  private var stopCountValue = 0

  var startCount: Int { lock.withLock { startCountValue } }
  var stopCount: Int { lock.withLock { stopCountValue } }

  func takeEngineFileDescriptor() throws -> Int32 {
    try lock.withLock {
      guard !transferred else {
        throw PacketPumpError.engineFileDescriptorAlreadyTransferred
      }
      transferred = true
      let descriptor = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
      guard descriptor >= 0 else { throw FixtureError.forced }
      return descriptor
    }
  }

  func start() throws { lock.withLock { startCountValue += 1 } }
  func stop() { lock.withLock { stopCountValue += 1 } }
}

private final class CompletionRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let semaphore = DispatchSemaphore(value: 0)
  private var recorded: [PacketTunnelProviderError?] = []

  func record(_ error: Error?) {
    lock.withLock { recorded.append(error as? PacketTunnelProviderError) }
    semaphore.signal()
  }

  func wait() -> Bool { semaphore.wait(timeout: .now() + 2) == .success }
  var values: [PacketTunnelProviderError?] { lock.withLock { recorded } }
}

private final class StopResultRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let semaphore = DispatchSemaphore(value: 0)
  private var results: [Result<Void, PacketTunnelStopError>] = []

  func record(_ result: Result<Void, PacketTunnelStopError>) {
    lock.withLock { results.append(result) }
    semaphore.signal()
  }

  func wait() -> Bool { semaphore.wait(timeout: .now() + 2) == .success }
  var values: [Result<Void, PacketTunnelStopError>] { lock.withLock { results } }
}

private final class StopFailureRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let semaphore = DispatchSemaphore(value: 0)
  private var errorsValue: [PacketTunnelStopError] = []

  func record(_ error: PacketTunnelStopError) {
    lock.withLock { errorsValue.append(error) }
    semaphore.signal()
  }

  func wait() -> Bool { semaphore.wait(timeout: .now() + 2) == .success }
  var errors: [PacketTunnelStopError] { lock.withLock { errorsValue } }
}

private final class CompletionSignal: @unchecked Sendable {
  private let lock = NSLock()
  private let semaphore = DispatchSemaphore(value: 0)
  private var countValue = 0

  func record() {
    lock.withLock { countValue += 1 }
    semaphore.signal()
  }

  func wait() -> Bool { semaphore.wait(timeout: .now() + 2) == .success }
  var count: Int { lock.withLock { countValue } }
}

// MARK: - Builders

private func tunnelDescriptor() throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
    credentialAudience: CredentialAudience(
      profileID: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
      profileDigest: SHA256Digest(hex: String(repeating: "ee", count: 32))),
    installationID: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "ab", count: 32)),
    identitySHA256: SHA256Digest(hex: String(repeating: "cd", count: 32))
  )
}

private func operationContext(
  matching descriptor: ConfigurationDescriptor
) throws -> OperationContext {
  try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: AuthorityIdentifier(descriptor.installationID),
      epoch: descriptor.epoch,
      generation: descriptor.generation),
    mode: .tunnel,
    configSHA256: descriptor.sha256,
    identitySHA256: descriptor.identitySHA256,
    ownerUID: 501,
    authorityRevision: 1)
}

private struct RedeemedFixture {
  let redeemed: RedeemedTunnelStart
  let configuration: SensitiveBytes
  let secrets: AuthoritySecretMaterial
}

private func makeRedeemedFixture(
  descriptor: ConfigurationDescriptor,
  withSecretSlot: Bool
) throws -> RedeemedFixture {
  let operation = try operationContext(matching: descriptor)
  let leaseID = AuthorityIdentifier(UUID())
  let lease = try LeaseView(
    leaseID: leaseID, operation: operation, state: .starting, expiryMonotonic: 10_000)
  let configuration = try SensitiveBytes(
    copying: Data("{}".utf8), maximumCount: AuthorityV1Limits.maximumConfigurationBytes)
  let slots: [AuthoritySecretSlot] =
    withSecretSlot
    ? [
      try AuthoritySecretSlot(
        reference: CredentialReference(id: UUID(), kind: .shadowsocksPassword),
        copying: Data("s3cr3t".utf8))
    ]
    : []
  let secrets = try AuthoritySecretMaterial(slots: slots)
  let redeemed = try RedeemedTunnelStart(
    operation: operation, lease: lease, configuration: configuration, secrets: secrets)
  return RedeemedFixture(redeemed: redeemed, configuration: configuration, secrets: secrets)
}

private struct CoordinatorFixture {
  let coordinator: TunnelTicketStartCoordinator
  let descriptor: ConfigurationDescriptor
  let engine: FakeEngine
  let pump: FakePump
  let revocation: TunnelRevocationChannel
  let revocationFailures: StopFailureRecorder
  let revocationCompletions: CompletionSignal
  let processEnds: ProcessEndRecorder
  let events: EventLog
}

private func makeCoordinator(
  authority: any EngineOwnerAuthorityClient,
  clockValue: UInt64 = 12_345,
  revocation: TunnelRevocationChannel = TunnelRevocationChannel(),
  failPreparation: Bool = false,
  runtimeFactory: (any LibboxServiceRuntimeFactory)? = nil
) throws -> CoordinatorFixture {
  let descriptor = try tunnelDescriptor()
  let engine = FakeEngine()
  let pump = FakePump()
  let revocationFailures = StopFailureRecorder()
  let revocationCompletions = CompletionSignal()
  let processEnds = ProcessEndRecorder()
  let events = EventLog()
  let dependencies = PacketTunnelSessionDependencies(
    prepareConfiguration: { receivedDescriptor, configuration, _ in
      if failPreparation { throw FixtureError.forced }
      return PreparedTunnelConfiguration(
        descriptor: receivedDescriptor,
        configuration: configuration,
        lease: UnleasedEngineOwnership())
    },
    makePump: { _, _ in pump },
    applyNetworkSettings: { _, completion in completion(nil) }
  )
  let engineFactory: any PacketEngineFactory =
    runtimeFactory.map { LibboxPacketEngineFactory(runtimeFactory: $0) }
    ?? FakeEngineFactory(engine: engine)
  let lifecycle = PacketTunnelSessionLifecycle(
    engineFactory: engineFactory,
    dependencies: dependencies,
    cancelTunnel: { _ in },
    endProcess: { failure in
      events.record("end")
      processEnds.record(failure)
    }
  )
  let coordinator = TunnelTicketStartCoordinator(
    authority: authority,
    sessionLifecycle: lifecycle,
    revocation: revocation,
    clock: FakeMonotonicClock(value: clockValue),
    reportRevocationFailure: { revocationFailures.record($0) },
    completeRevocation: { revocationCompletions.record() })
  return CoordinatorFixture(
    coordinator: coordinator, descriptor: descriptor, engine: engine, pump: pump,
    revocation: revocation, revocationFailures: revocationFailures,
    revocationCompletions: revocationCompletions, processEnds: processEnds, events: events)
}

private func makeTicket() throws -> StartTicket {
  try StartTicket(copying: Data(repeating: 0x7a, count: AuthorityV1Limits.ticketBytes))
}

private func stopSucceeded(
  _ result: Result<Void, PacketTunnelStopError>?
) -> Bool {
  guard let result else { return false }
  if case .success = result { return true }
  return false
}

private func unclosableStopFailure(
  _ result: Result<Void, PacketTunnelStopError>?
) -> LibboxInstanceUnclosable? {
  guard let result, case .failure(.localRuntime(.engineUnclosable(let failure))) = result else {
    return nil
  }
  return failure
}

private func isAttestationStopFailure(
  _ result: Result<Void, PacketTunnelStopError>?
) -> Bool {
  guard let result else { return false }
  if case .failure(.authorityAttestation(.globalAuthorityUnavailable)) = result {
    return true
  }
  return false
}

// MARK: - Tests

@Suite(.serialized)
struct TicketOnlyStartupTests {
  @Test func revocationLatchedAfterRedeemPreventsTunnelDataPlaneStart() throws {
    let descriptor = try tunnelDescriptor()
    let redeemedFixture = try makeRedeemedFixture(
      descriptor: descriptor, withSecretSlot: false)
    let revocation = TunnelRevocationChannel()
    let authority = FakeOwnerAuthorityClient(
      onRedeem: { revocation.revoke() },
      makeRedeemed: { redeemedFixture.redeemed })
    let fixture = try makeCoordinator(
      authority: authority, revocation: revocation)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }

    #expect(start.wait())
    #expect(start.values.count == 1)
    #expect(start.values[0] == .globalAuthorityUnavailable)
    #expect(authority.redeemCount == 1)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.pump.startCount == 0)
    #expect(authority.readyAttestations.isEmpty)
    #expect(authority.stoppedAttestations.count == 1)
    #expect(fixture.revocationCompletions.wait())
    #expect(fixture.revocationCompletions.count == 1)
  }

  @Test func explicitStopDuringRedeemCancelsStartAndWaitsForStoppedAttestation() throws {
    let redeemGate = BlockingCallGate()
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient(
      redeemGate: redeemGate
    ) { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(redeemGate.waitUntilEntered())

    let stop = StopResultRecorder()
    fixture.coordinator.stop { stop.record($0) }
    #expect(stop.values.isEmpty)
    redeemGate.release()

    #expect(stop.wait())
    #expect(stopSucceeded(stop.values.first))
    #expect(start.wait())
    #expect(start.values == [.startupCancelled])
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.pump.startCount == 0)
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.first?.operation == fixtureData.redeemed.operation)
    #expect(fixture.revocationCompletions.count == 0)

    // The cancelled attempt converged back to idle. A new ticket reaches Authority
    // (and is rejected as already redeemed by this one-shot fake) rather than being
    // masked by a leaked coordinator lifecycle conflict.
    let next = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { next.record($0) }
    #expect(next.wait())
    #expect(next.values == [.invalidStartTicket])
    #expect(authority.redeemCount == 2)
  }

  @Test func ticketOnlyStartupInjectsRedeemedMaterialAndAttestsReady() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }

    #expect(start.wait())
    #expect(start.values == [nil])
    #expect(authority.redeemCount == 1)
    #expect(fixture.engine.startCount == 1)
    #expect(fixture.pump.startCount == 1)

    let ready = authority.readyAttestations
    #expect(ready.count == 1)
    #expect(ready.first?.ownerRole == .provider)
    #expect(ready.first?.readyFlags == .all)
    #expect(ready.first?.packetPumpLimits?.maximumPacketBytes == 1_500)
    #expect(ready.first?.monotonicTimestamp == 12_345)
    // The redeemed transport configuration buffer is wiped after injection.
    #expect(fixtureData.configuration.isErased)
  }

  @Test func missingTicketOptionIsRejectedBeforeReachingAuthority() throws {
    let authority = FailingRedeemAuthorityClient(
      error: AuthorityDomainError(code: .globalAuthorityUnavailable))
    // No options at all fails closed with invalidStartTicket.
    #expect(throws: PacketTunnelProviderError.invalidStartTicket) {
      _ = try PacketTunnelProvider.startTicket(from: nil)
    }
    // Platform metadata or inline configuration cannot replace the ticket.
    let metadataOnly: [String: NSObject] = [
      "ServerAddress": "Clash for Mac" as NSString,
      "VendorData": ["configuration": "untrusted-inline-configuration"] as NSDictionary,
      "configuration": Data("{}".utf8) as NSData,
    ]
    #expect(throws: PacketTunnelProviderError.invalidStartTicket) {
      _ = try PacketTunnelProvider.startTicket(from: metadataOnly)
    }
    #expect(authority.redeemCount == 0)
  }

  @Test func wrongSizedTicketValueIsRejected() throws {
    let tooShort: [String: NSObject] = [
      NativeProtocolConstants.tunnelStartTicketOptionKey: Data([0x1, 0x2, 0x3]) as NSData
    ]
    #expect(throws: PacketTunnelProviderError.invalidStartTicket) {
      _ = try PacketTunnelProvider.startTicket(from: tooShort)
    }
    let wrongType: [String: NSObject] = [
      NativeProtocolConstants.tunnelStartTicketOptionKey: NSNumber(value: 7)
    ]
    #expect(throws: PacketTunnelProviderError.invalidStartTicket) {
      _ = try PacketTunnelProvider.startTicket(from: wrongType)
    }
  }

  @Test func exactSizedTicketValueIsAccepted() throws {
    let options: [String: NSObject] = [
      NativeProtocolConstants.tunnelStartTicketOptionKey:
        Data(repeating: 0x5, count: AuthorityV1Limits.ticketBytes) as NSData
    ]
    let ticket = try PacketTunnelProvider.startTicket(from: options)
    ticket.erase()
  }

  @Test func platformMetadataDoesNotReplaceTheAuthorityTicket() throws {
    let options: [String: NSObject] = [
      NativeProtocolConstants.tunnelStartTicketOptionKey:
        Data(repeating: 0x5, count: AuthorityV1Limits.ticketBytes) as NSData,
      "ServerAddress": "Clash for Mac" as NSString,
      "VendorData": ["configuration": "untrusted-inline-configuration"] as NSDictionary,
    ]
    let ticket = try PacketTunnelProvider.startTicket(from: options)
    defer { ticket.erase() }
    #expect(try ticket.withUnsafeBytes { Data($0) } == Data(repeating: 0x5, count: 32))

    let authority = FailingRedeemAuthorityClient(
      error: AuthorityDomainError(code: .ticketInvalid))
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()
    fixture.coordinator.start(ticket: ticket, descriptor: fixture.descriptor) { start.record($0) }
    #expect(start.wait())
    #expect(authority.redeemCount == 1)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.pump.startCount == 0)
  }

  @Test func authorityUnavailableFailsClosedWithNoEngineStart() throws {
    let authority = FailingRedeemAuthorityClient(
      error: AuthorityDomainError(code: .globalAuthorityUnavailable))
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }

    #expect(start.wait())
    #expect(start.values == [.globalAuthorityUnavailable])
    #expect(authority.redeemCount == 1)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.pump.startCount == 0)
  }

  @Test func invalidTicketRedemptionFailsClosed() throws {
    let authority = FailingRedeemAuthorityClient(
      error: AuthorityDomainError(code: .ticketInvalid))
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }

    #expect(start.wait())
    #expect(start.values == [.invalidStartTicket])
    #expect(fixture.engine.startCount == 0)
  }

  @Test func expiredTicketKeepsItsTypedCauseAndNeverStartsTheEngine() throws {
    let authority = FailingRedeemAuthorityClient(
      error: AuthorityDomainError(code: .ticketExpired))
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()
    let ticket = try makeTicket()

    fixture.coordinator.start(ticket: ticket, descriptor: fixture.descriptor) { start.record($0) }

    #expect(start.wait())
    let failure = try #require(start.values.first ?? nil).engineFailure
    #expect(failure.code == PacketTunnelFailureCode.startTicketExpired.rawValue)
    #expect(authority.redeemCount == 1)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.pump.startCount == 0)
    #expect(throws: (any Error).self) { try ticket.withUnsafeBytes { _ in () } }
  }

  @Test func providerOnlyEncodesExpiredTicketsAsFreshRetryEvidence() throws {
    let descriptor = try tunnelDescriptor()
    let expired =
      try #require(
        PacketTunnelProvider.platformStartError(
          PacketTunnelProviderError.expiredStartTicket, configuration: descriptor)) as NSError
    #expect(
      TunnelStartupFailure.matchingFailure(expired, configuration: descriptor)
        == TunnelStartupFailure.ticketExpired)
    let replay = TunnelTicketStartCoordinator.mapRedeemError(
      AuthorityDomainError(code: .ticketAlreadyRedeemed))
    #expect(replay == .invalidStartTicket)
    let invalid =
      try #require(
        PacketTunnelProvider.platformStartError(
          replay, configuration: descriptor)) as NSError
    #expect(TunnelStartupFailure.matchingFailure(invalid, configuration: descriptor) == nil)
    #expect(PacketTunnelProvider.platformStartError(nil, configuration: descriptor) == nil)
  }

  @Test func providerReportsAStartTimeoutToTheHostWithItsLineage() throws {
    let descriptor = try tunnelDescriptor()
    #expect(
      PacketTunnelProviderError.engineStartTimedOut.engineFailure
        == TunnelStartupFailure.engineStartTimedOut)
    let timedOut =
      try #require(
        PacketTunnelProvider.platformStartError(
          PacketTunnelProviderError.engineStartTimedOut, configuration: descriptor)) as NSError
    #expect(
      TunnelStartupFailure.matchingFailure(timedOut, configuration: descriptor)
        == TunnelStartupFailure.engineStartTimedOut)
    // Other engine failures keep reaching the Host through its readiness wait.
    let failed =
      try #require(
        PacketTunnelProvider.platformStartError(
          PacketTunnelProviderError.engineStart("libbox failed"), configuration: descriptor))
      as NSError
    #expect(TunnelStartupFailure.matchingFailure(failed, configuration: descriptor) == nil)
  }

  @Test func providerReportsAnUnclosableEngineToTheHostWithItsLineage() throws {
    let descriptor = try tunnelDescriptor()
    let unclosable = PacketTunnelProviderError.engineUnclosable(
      LibboxInstanceUnclosable(closeFailure: "secret close detail"))
    #expect(unclosable.engineFailure == TunnelStartupFailure.engineUnclosable)
    let reported =
      try #require(PacketTunnelProvider.platformStartError(unclosable, configuration: descriptor))
      as NSError
    #expect(
      TunnelStartupFailure.matchingFailure(reported, configuration: descriptor)
        == TunnelStartupFailure.engineUnclosable)
    #expect(!reported.localizedDescription.contains("secret"))
  }

  @Test func libboxDeadlineIsFixedWhenMacOSDeliversTheStartNotAfterRedemption() throws {
    let redeemGate = BlockingCallGate()
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient(redeemGate: redeemGate) { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()
    let receivedBefore = ContinuousClock.now
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    let receivedAfter = ContinuousClock.now
    #expect(redeemGate.waitUntilEntered())
    // A slow redemption must spend the libbox start's time, not extend it.
    Thread.sleep(forTimeInterval: 0.3)
    redeemGate.release()
    #expect(start.wait())
    #expect(start.values == [nil])
    let deadline = try #require(fixture.engine.deadlines.first)
    #expect(fixture.engine.deadlines.count == 1)
    #expect(deadline.instant >= receivedBefore.advanced(by: EngineStartBudget.ownerLibboxStart))
    #expect(deadline.instant <= receivedAfter.advanced(by: EngineStartBudget.ownerLibboxStart))
  }

  @Test func redeemedMismatchWithDescriptorFailsClosed() throws {
    // Build a redeemed operation whose digests do not match the provider descriptor.
    let otherDescriptor = try ConfigurationDescriptor(
      slot: .tunnel,
      tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
      credentialAudience: CredentialAudience(
        profileID: UUID(),
        profileDigest: SHA256Digest(hex: String(repeating: "ee", count: 32))),
      installationID: UUID(),
      epoch: 1,
      generation: 1,
      byteCount: 2,
      sha256: SHA256Digest(hex: String(repeating: "11", count: 32)),
      identitySHA256: SHA256Digest(hex: String(repeating: "22", count: 32)))
    let mismatched = try makeRedeemedFixture(descriptor: otherDescriptor, withSecretSlot: true)
    let authority = FakeOwnerAuthorityClient { mismatched.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }

    #expect(start.wait())
    #expect(start.values == [.invalidConfigurationSlot])
    #expect(fixture.engine.startCount == 0)
    // Transport buffers are wiped even on the rejection path.
    #expect(mismatched.configuration.isErased)
    let mismatchSecretsErased = mismatched.secrets.slots.allSatisfy { $0.isErased }
    #expect(mismatchSecretsErased)
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.count == 1)
    #expect(authority.stoppedAttestations.first?.operation == mismatched.redeemed.operation)
    #expect(authority.stoppedAttestations.first?.leaseID == mismatched.redeemed.lease.leaseID)
  }

  @Test func postRedeemSessionStartFailureStopsAndAttestsBeforeCompleting() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority, failPreparation: true)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }

    #expect(start.wait())
    guard case .configuration = start.values[0] else {
      Issue.record("Expected the injected configuration preparation failure")
      return
    }
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.pump.startCount == 0)
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.count == 1)
    #expect(authority.stoppedAttestations.first?.operation == fixtureData.redeemed.operation)
  }

  @Test func explicitStopDuringReadyAttestationCannotReportAStoppedTunnelReady() throws {
    let readyGate = BlockingCallGate()
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient(
      readyGate: readyGate
    ) { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(readyGate.waitUntilEntered())

    let stop = StopResultRecorder()
    fixture.coordinator.stop { stop.record($0) }
    #expect(stop.wait())
    #expect(stopSucceeded(stop.values.first))
    #expect(start.values.isEmpty)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.pump.stopCount == 1)
    #expect(authority.stoppedAttemptCount == 1)

    readyGate.release()
    #expect(start.wait())
    #expect(start.values == [.startupCancelled])
    #expect(authority.readyAttestations.count == 1)
    #expect(authority.stoppedAttestations.count == 1)
  }

  @Test func readyAttestationFailureTearsDownAndFailsClosed() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: true)
    let authority = FakeOwnerAuthorityClient(readyThrows: true) { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }

    #expect(start.wait())
    #expect(start.values == [.globalAuthorityUnavailable])
    // libbox was started for injection, then torn down when readiness could not be attested.
    #expect(fixture.engine.startCount == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.count == 1)
    #expect(fixtureData.configuration.isErased)
    let readySecretsErased = fixtureData.secrets.slots.allSatisfy { $0.isErased }
    #expect(readySecretsErased)
  }

  @Test func readyFailureWithStoppedAttestationFailureRetainsExactContext() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient(
      readyThrows: true,
      stoppedFailures: 1
    ) { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(start.wait())
    #expect(start.values == [.globalAuthorityUnavailable])
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.isEmpty)

    let blocked = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { blocked.record($0) }
    #expect(blocked.wait())
    #expect(blocked.values == [.lifecycleConflict])
    #expect(authority.redeemCount == 1)

    let retry = StopResultRecorder()
    fixture.coordinator.stop { retry.record($0) }
    #expect(retry.wait())
    #expect(stopSucceeded(retry.values.first))
    #expect(fixture.engine.stopCount == 1)
    #expect(authority.stoppedAttemptCount == 2)
    #expect(authority.stoppedAttestations.first?.operation == fixtureData.redeemed.operation)
  }

  @Test func stopAttestsStoppedExactlyWithBoundContext() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority, clockValue: 999)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(start.wait())
    #expect(start.values == [nil])

    let stop = StopResultRecorder()
    fixture.coordinator.stop { stop.record($0) }
    #expect(stop.wait())
    #expect(stopSucceeded(stop.values.first))

    let stopped = authority.stoppedAttestations
    #expect(stopped.count == 1)
    #expect(stopped.first?.libboxStopped == true)
    #expect(stopped.first?.transportClosed == true)
    #expect(stopped.first?.osRestored == true)
    #expect(stopped.first?.monotonicTimestamp == 999)
    #expect(stopped.first?.operation == fixtureData.redeemed.operation)
    #expect(fixture.engine.stopCount == 1)
  }

  @Test func unclosableEngineNeverAttestsStoppedAndEndsTheProcessOnce() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(start.wait())
    #expect(start.values == [nil])

    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)
    let failedStop = StopResultRecorder()
    fixture.coordinator.stop { result in
      fixture.events.record("stop")
      failedStop.record(result)
    }
    #expect(failedStop.wait())
    #expect(fixture.processEnds.wait())
    #expect(unclosableStopFailure(failedStop.values.first) == closeFailure)
    // The process end is armed before the failure completes anything; it
    // ends the process only once Network Extension received the completions.
    #expect(fixture.events.values == ["end", "stop"])
    #expect(authority.stoppedAttemptCount == 0)
    #expect(authority.stoppedAttestations.isEmpty)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.pump.stopCount == 1)

    let blockedStart = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.lifecycleConflict])
    #expect(authority.redeemCount == 1)

    // A retry reaches neither libbox nor the Authority, and ends nothing again.
    let retry = StopResultRecorder()
    fixture.coordinator.stop { retry.record($0) }
    #expect(retry.wait())
    #expect(unclosableStopFailure(retry.values.first) == closeFailure)
    #expect(authority.stoppedAttemptCount == 0)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.processEnds.values == [closeFailure])
  }

  @Test func unclosableRuntimeArmsTheProcessEndAndFailsTheStartWithoutAttesting() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close failed service")
    let runtime = UnclosablePacketRuntime(closeFailure: closeFailure)
    let fixture = try makeCoordinator(
      authority: authority, runtimeFactory: UnclosablePacketRuntimeFactory(runtime: runtime))
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { error in
      fixture.events.record("start")
      start.record(error)
    }
    #expect(start.wait())
    #expect(fixture.processEnds.wait())

    #expect(start.values == [.engineUnclosable(closeFailure)])
    // The process end is armed before the failure completes anything; it
    // ends the process only once Network Extension received the completions.
    #expect(fixture.events.values == ["end", "start"])
    #expect(fixture.processEnds.values == [closeFailure])
    #expect(authority.readyAttestations.isEmpty)
    #expect(authority.stoppedAttemptCount == 0)
    #expect(runtime.stopCount == 1)
  }

  @Test func stoppedAttestationFailureKeepsContextForAnExactRetry() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient(stoppedFailures: 1) { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(start.wait())

    let failedStop = StopResultRecorder()
    fixture.coordinator.stop { failedStop.record($0) }
    #expect(failedStop.wait())
    #expect(isAttestationStopFailure(failedStop.values.first))
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.isEmpty)
    #expect(fixture.engine.stopCount == 1)

    let blockedStart = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.lifecycleConflict])
    #expect(authority.redeemCount == 1)

    let retry = StopResultRecorder()
    fixture.coordinator.stop { retry.record($0) }
    #expect(retry.wait())
    #expect(stopSucceeded(retry.values.first))
    #expect(authority.stoppedAttemptCount == 2)
    #expect(authority.stoppedAttestations.count == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.pump.stopCount == 1)
  }

  @Test func unclosableEngineDuringRevocationIsReportedAndEndsTheProcessOnce() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(start.wait())
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)

    fixture.revocation.revoke()
    #expect(fixture.revocationFailures.wait())
    #expect(fixture.processEnds.wait())
    #expect(fixture.revocationFailures.errors == [.localRuntime(.engineUnclosable(closeFailure))])
    #expect(authority.stoppedAttemptCount == 0)
    #expect(authority.stoppedAttestations.isEmpty)

    let blockedStart = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.lifecycleConflict])

    let retry = StopResultRecorder()
    fixture.coordinator.stop { retry.record($0) }
    #expect(retry.wait())
    #expect(unclosableStopFailure(retry.values.first) == closeFailure)
    #expect(authority.stoppedAttemptCount == 0)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.processEnds.values == [closeFailure])
  }

  @Test func successfulRevocationStopsAuthorityAndCompletesTheOSSession() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(start.wait())
    fixture.revocation.revoke()

    #expect(fixture.revocationCompletions.wait())
    #expect(fixture.revocationCompletions.count == 1)
    #expect(fixture.revocationFailures.errors.isEmpty)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.pump.stopCount == 1)
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.count == 1)
  }

  @Test func concurrentExplicitStopAndRevocationShareOneStopTransaction() throws {
    let stoppedGate = BlockingCallGate()
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient(
      stoppedGate: stoppedGate
    ) { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(start.wait())

    let stop = StopResultRecorder()
    fixture.coordinator.stop { stop.record($0) }
    #expect(stoppedGate.waitUntilEntered())
    fixture.revocation.revoke()
    stoppedGate.release()

    #expect(stop.wait())
    #expect(stopSucceeded(stop.values.first))
    #expect(fixture.revocationCompletions.wait())
    #expect(fixture.revocationCompletions.count == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.pump.stopCount == 1)
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.count == 1)
  }

  @Test func concurrentSecondStartIsRejectedSoTicketIsRedeemedOnce() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let first = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { first.record($0) }
    #expect(first.wait())
    #expect(first.values == [nil])

    // A second start while active must not redeem another ticket.
    let second = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { second.record($0) }
    #expect(second.wait())
    #expect(second.values == [.lifecycleConflict])
    #expect(authority.redeemCount == 1)
  }
}
