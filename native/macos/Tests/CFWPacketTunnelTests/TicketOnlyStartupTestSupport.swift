import CFWCredentialTransport
import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWLibboxRuntime
@testable import CFWPacketTunnel

// The ticket-only startup fixture: a fixture error, and the builders of
// descriptors, operation contexts, redeemed fixtures, coordinators and tickets.
// The provider ticket restart tests share its stop check.
enum FixtureError: Error { case forced }

// MARK: - Builders

func tunnelDescriptor() throws -> ConfigurationDescriptor {
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

struct RedeemedFixture {
  let redeemed: RedeemedTunnelStart
  let configuration: SensitiveBytes
  let secrets: AuthoritySecretMaterial
}

func makeRedeemedFixture(
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

struct CoordinatorFixture {
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

func makeCoordinator(
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

func makeTicket() throws -> StartTicket {
  try StartTicket(copying: Data(repeating: 0x7a, count: AuthorityV1Limits.ticketBytes))
}

func stopSucceeded(
  _ result: Result<Void, PacketTunnelStopError>?
) -> Bool {
  guard let result else { return false }
  if case .success = result { return true }
  return false
}

func unclosableStopFailure(
  _ result: Result<Void, PacketTunnelStopError>?
) -> LibboxInstanceUnclosable? {
  guard let result, case .failure(.localRuntime(.engineUnclosable(let failure))) = result else {
    return nil
  }
  return failure
}

func isAttestationStopFailure(
  _ result: Result<Void, PacketTunnelStopError>?
) -> Bool {
  guard let result else { return false }
  if case .failure(.authorityAttestation(.globalAuthorityUnavailable)) = result {
    return true
  }
  return false
}
