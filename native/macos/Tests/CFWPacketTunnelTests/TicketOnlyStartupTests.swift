import CFWCredentialTransport
import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWPacketTunnel

private enum FixtureError: Error { case forced }

// MARK: - Fakes

private final class FakeMonotonicClock: ProviderMonotonicClock, @unchecked Sendable {
  let value: UInt64
  init(value: UInt64) { self.value = value }
  func nowMilliseconds() -> UInt64 { value }
}

private final class FakeOwnerAuthorityClient: EngineOwnerAuthorityClient, @unchecked Sendable {
  private let lock = NSLock()
  private let makeRedeemed: @Sendable () throws -> RedeemedTunnelStart
  private var redeemCountValue = 0
  private var readyValue: [ReadyAttestation] = []
  private var stoppedValue: [StoppedAttestation] = []
  private var readyThrows: Bool

  init(
    readyThrows: Bool = false,
    makeRedeemed: @escaping @Sendable () throws -> RedeemedTunnelStart
  ) {
    self.readyThrows = readyThrows
    self.makeRedeemed = makeRedeemed
  }

  var redeemCount: Int { lock.withLock { redeemCountValue } }
  var readyAttestations: [ReadyAttestation] { lock.withLock { readyValue } }
  var stoppedAttestations: [StoppedAttestation] { lock.withLock { stoppedValue } }

  func bind(_ capability: OwnerCapability) async throws -> LeaseView {
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
    return try makeRedeemed()
  }

  func attestReady(_ attestation: ReadyAttestation) async throws {
    lock.withLock { readyValue.append(attestation) }
    if readyThrows { throw AuthorityDomainError(code: .globalAuthorityUnavailable) }
  }

  func attestStopped(_ attestation: StoppedAttestation) async throws {
    lock.withLock { stoppedValue.append(attestation) }
  }
}

private final class FailingRedeemAuthorityClient: EngineOwnerAuthorityClient, @unchecked Sendable {
  private let error: AuthorityDomainError
  private let lock = NSLock()
  private var redeemCountValue = 0

  init(error: AuthorityDomainError) { self.error = error }

  var redeemCount: Int { lock.withLock { redeemCountValue } }

  func bind(_ capability: OwnerCapability) async throws -> LeaseView {
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

  var startCount: Int { lock.withLock { startCountValue } }
  var stopCount: Int { lock.withLock { stopCountValue } }

  deinit { closeOwned() }

  func start(configuration: Data, packetFileDescriptor: Int32) throws {
    lock.withLock {
      startCountValue += 1
      ownedDescriptor = packetFileDescriptor
    }
  }

  func stop() throws {
    lock.withLock {
      stopCountValue += 1
      closeOwnedLocked()
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

private final class VoidRecorder: @unchecked Sendable {
  private let semaphore = DispatchSemaphore(value: 0)
  func record() { semaphore.signal() }
  func wait() -> Bool { semaphore.wait(timeout: .now() + 2) == .success }
}

// MARK: - Builders

private func tunnelDescriptor() throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
    installationID: UUID(),
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
    leaseID: leaseID, operation: operation, state: .active, expiryMonotonic: 10_000)
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
}

private func makeCoordinator(
  authority: any EngineOwnerAuthorityClient,
  clockValue: UInt64 = 12_345
) throws -> CoordinatorFixture {
  let descriptor = try tunnelDescriptor()
  let engine = FakeEngine()
  let pump = FakePump()
  let dependencies = PacketTunnelSessionDependencies(
    prepareConfiguration: { receivedDescriptor, configuration, _ in
      PreparedTunnelConfiguration(
        descriptor: receivedDescriptor,
        configuration: configuration,
        lease: UnleasedEngineOwnership())
    },
    makePump: { _, _ in pump },
    applyNetworkSettings: { _, completion in completion(nil) }
  )
  let lifecycle = PacketTunnelSessionLifecycle(
    engineFactory: FakeEngineFactory(engine: engine),
    dependencies: dependencies,
    cancelTunnel: { _ in }
  )
  let coordinator = TunnelTicketStartCoordinator(
    authority: authority,
    sessionLifecycle: lifecycle,
    clock: FakeMonotonicClock(value: clockValue))
  return CoordinatorFixture(
    coordinator: coordinator, descriptor: descriptor, engine: engine, pump: pump)
}

private func makeTicket() throws -> StartTicket {
  try StartTicket(copying: Data(repeating: 0x7a, count: AuthorityV1Limits.ticketBytes))
}

// MARK: - Tests

@Suite(.serialized)
struct TicketOnlyStartupTests {
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
    // Extra keys alongside the ticket fail closed.
    let extra: [String: NSObject] = [
      NativeProtocolConstants.tunnelStartTicketOptionKey:
        Data(repeating: 0x1, count: AuthorityV1Limits.ticketBytes) as NSData,
      "unexpected": NSNumber(value: 1),
    ]
    #expect(throws: PacketTunnelProviderError.invalidStartTicket) {
      _ = try PacketTunnelProvider.startTicket(from: extra)
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

  @Test func redeemedMismatchWithDescriptorFailsClosed() throws {
    // Build a redeemed operation whose digests do not match the provider descriptor.
    let otherDescriptor = try ConfigurationDescriptor(
      slot: .tunnel,
      tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
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
    #expect(fixtureData.configuration.isErased)
    let readySecretsErased = fixtureData.secrets.slots.allSatisfy { $0.isErased }
    #expect(readySecretsErased)
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

    let stop = VoidRecorder()
    fixture.coordinator.stop { stop.record() }
    #expect(stop.wait())

    let stopped = authority.stoppedAttestations
    #expect(stopped.count == 1)
    #expect(stopped.first?.libboxStopped == true)
    #expect(stopped.first?.transportClosed == true)
    #expect(stopped.first?.osRestored == true)
    #expect(stopped.first?.monotonicTimestamp == 999)
    #expect(stopped.first?.operation == fixtureData.redeemed.operation)
    #expect(fixture.engine.stopCount == 1)
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
