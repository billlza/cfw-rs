import CFWCredentialTransport
import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWPacketTunnel

// Integration coverage for task 9.12 (Provider): the ticket-only start coordinator
// returns to a clean idle state after a proven stop and accepts a fresh single-use
// ticket for a subsequent start, and a stop with no active context is a safe no-op
// that attests nothing. All Authority (XPC), libbox, and OS side effects are behind
// injected fakes; no real Network Extension, launchd, or XPC is exercised.

private enum FixtureError: Error { case forced }

private final class FakeMonotonicClock: ProviderMonotonicClock, @unchecked Sendable {
  let value: UInt64
  init(value: UInt64) { self.value = value }
  func nowMilliseconds() -> UInt64 { value }
}

/// Authority owner client that issues a FRESH redeemed start (new sensitive
/// buffers) on every redemption, so the same coordinator can be started, stopped,
/// and started again. Records every redeem/ready/stopped interaction.
private final class RestartableOwnerAuthorityClient: EngineOwnerAuthorityClient,
  @unchecked Sendable
{
  private let lock = NSLock()
  private let descriptor: ConfigurationDescriptor
  private var redeemCountValue = 0
  private var readyValue: [ReadyAttestation] = []
  private var stoppedValue: [StoppedAttestation] = []

  init(descriptor: ConfigurationDescriptor) { self.descriptor = descriptor }

  var redeemCount: Int { lock.withLock { redeemCountValue } }
  var readyAttestations: [ReadyAttestation] { lock.withLock { readyValue } }
  var stoppedAttestations: [StoppedAttestation] { lock.withLock { stoppedValue } }

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
    lock.withLock { redeemCountValue += 1 }
    return try makeRedeemed(descriptor: descriptor)
  }

  func attestReady(_ attestation: ReadyAttestation) async throws {
    lock.withLock { readyValue.append(attestation) }
  }

  func attestStopped(_ attestation: StoppedAttestation) async throws {
    lock.withLock { stoppedValue.append(attestation) }
  }
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

/// Produces a fresh pump per start, exactly as the production `makePump` seam does,
/// so a stop/restart cycle takes a new engine file descriptor rather than tripping
/// the single-transfer guard on a reused pump.
private final class PumpFactory: @unchecked Sendable {
  private let lock = NSLock()
  private var pumpsValue: [FakePump] = []
  func make() -> FakePump {
    let pump = FakePump()
    lock.withLock { pumpsValue.append(pump) }
    return pump
  }
  var pumps: [FakePump] { lock.withLock { pumpsValue } }
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
  private var resultsValue: [Result<Void, PacketTunnelStopError>] = []

  func record(_ result: Result<Void, PacketTunnelStopError>) {
    lock.withLock { resultsValue.append(result) }
    semaphore.signal()
  }

  func wait() -> Bool { semaphore.wait(timeout: .now() + 2) == .success }
  var results: [Result<Void, PacketTunnelStopError>] { lock.withLock { resultsValue } }
}

private func stopSucceeded(
  _ result: Result<Void, PacketTunnelStopError>?
) -> Bool {
  guard let result else { return false }
  if case .success = result { return true }
  return false
}

private func tunnelDescriptor() throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
    credentialAudience: CredentialAudience(
      profileID: UUID(),
      profileDigest: try SHA256Digest(hex: String(repeating: "ee", count: 32))),
    installationID: UUID(),
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "ab", count: 32)),
    identitySHA256: SHA256Digest(hex: String(repeating: "cd", count: 32)))
}

private func makeRedeemed(
  descriptor: ConfigurationDescriptor
) throws -> RedeemedTunnelStart {
  let operation = try OperationContext(
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
  let lease = try LeaseView(
    leaseID: AuthorityIdentifier(UUID()), operation: operation,
    state: .starting, expiryMonotonic: 10_000)
  let configuration = try SensitiveBytes(
    copying: Data("{}".utf8), maximumCount: AuthorityV1Limits.maximumConfigurationBytes)
  let secrets = try AuthoritySecretMaterial(slots: [])
  return try RedeemedTunnelStart(
    operation: operation, lease: lease, configuration: configuration, secrets: secrets)
}

private func makeTicket(byte: UInt8) throws -> StartTicket {
  try StartTicket(copying: Data(repeating: byte, count: AuthorityV1Limits.ticketBytes))
}

private struct CoordinatorFixture {
  let coordinator: TunnelTicketStartCoordinator
  let descriptor: ConfigurationDescriptor
  let authority: RestartableOwnerAuthorityClient
  let engine: FakeEngine
  let pumps: PumpFactory
}

private func makeCoordinator(clockValue: UInt64 = 5_000) throws -> CoordinatorFixture {
  let descriptor = try tunnelDescriptor()
  let engine = FakeEngine()
  let pumps = PumpFactory()
  let authority = RestartableOwnerAuthorityClient(descriptor: descriptor)
  let dependencies = PacketTunnelSessionDependencies(
    prepareConfiguration: { receivedDescriptor, configuration, _ in
      PreparedTunnelConfiguration(
        descriptor: receivedDescriptor,
        configuration: configuration,
        lease: UnleasedEngineOwnership())
    },
    makePump: { _, _ in pumps.make() },
    applyNetworkSettings: { _, completion in completion(nil) })
  let lifecycle = PacketTunnelSessionLifecycle(
    engineFactory: FakeEngineFactory(engine: engine),
    dependencies: dependencies,
    cancelTunnel: { _ in })
  let coordinator = TunnelTicketStartCoordinator(
    authority: authority,
    sessionLifecycle: lifecycle,
    clock: FakeMonotonicClock(value: clockValue))
  return CoordinatorFixture(
    coordinator: coordinator, descriptor: descriptor,
    authority: authority, engine: engine, pumps: pumps)
}

@Suite(.serialized)
struct ProviderTicketRestartIntegrationTests {
  @Test func startStopStartAcceptsAFreshTicketAfterAProvenStop() throws {
    let fixture = try makeCoordinator()

    // First start with a fresh single-use ticket.
    let firstStart = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(byte: 0x11), descriptor: fixture.descriptor
    ) { firstStart.record($0) }
    #expect(firstStart.wait())
    #expect(firstStart.values == [nil])
    #expect(fixture.authority.redeemCount == 1)
    #expect(fixture.engine.startCount == 1)

    // Proven stop returns the coordinator to idle and attests stopped exactly once.
    let stop = StopResultRecorder()
    fixture.coordinator.stop { stop.record($0) }
    #expect(stop.wait())
    #expect(stopSucceeded(stop.results.first))
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)

    // A subsequent start with a DIFFERENT fresh ticket is admitted and redeemed.
    let secondStart = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(byte: 0x22), descriptor: fixture.descriptor
    ) { secondStart.record($0) }
    #expect(secondStart.wait())
    #expect(secondStart.values == [nil])
    #expect(fixture.authority.redeemCount == 2)
    #expect(fixture.engine.startCount == 2)
    #expect(fixture.authority.readyAttestations.count == 2)

    // Clean up the second session.
    let finalStop = StopResultRecorder()
    fixture.coordinator.stop { finalStop.record($0) }
    #expect(finalStop.wait())
    #expect(stopSucceeded(finalStop.results.first))
    #expect(fixture.engine.stopCount == 2)
  }

  @Test func stopWithoutAnActiveContextAttestsNothing() throws {
    let fixture = try makeCoordinator()

    let stop = StopResultRecorder()
    fixture.coordinator.stop { stop.record($0) }
    #expect(stop.wait())
    #expect(stopSucceeded(stop.results.first))

    // No start ever occurred: nothing is redeemed and no stopped attestation is
    // sent to the Authority for a context that was never bound.
    #expect(fixture.authority.redeemCount == 0)
    #expect(fixture.authority.stoppedAttestations.isEmpty)
    #expect(fixture.engine.startCount == 0)
  }
}
