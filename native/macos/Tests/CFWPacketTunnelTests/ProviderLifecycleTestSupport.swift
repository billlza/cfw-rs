import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWLibboxRuntime
@testable import CFWPacketTunnel

// The provider lifecycle fixture, its tunnel descriptor and its builder.
struct ProviderFixture {
  let lifecycle: PacketTunnelSessionLifecycle
  let descriptor: ConfigurationDescriptor
  let configuration: Data
  let engine: TestEngine
  let lease: TestLease
  let leaseAcquisitionCounter: LeaseAcquisitionCounter
  let pumpHolder: PumpHolder
  let settingsGate: NetworkSettingsGate
  let cancelRecorder: CancelRecorder
  let endRecorder: EndProcessRecorder
  let events: ProviderEventLog
}

func providerTunnelDescriptor() throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
    credentialAudience: CredentialAudience(
      profileID: UUID(),
      profileDigest: SHA256Digest(hex: String(repeating: "ee", count: 32))),
    installationID: UUID(),
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32))
  )
}

/// `processEnd` receives the failure after it was recorded, as the provider's
/// process end would.
func makeProviderFixture(
  failingAt stage: StartupFailureStage?,
  engineStartError: any Error = ForcedFailure.requested,
  processEnd: PacketTunnelProcessEnd? = nil
) throws -> ProviderFixture {
  let descriptor = try providerTunnelDescriptor()
  let configuration = Data("{}".utf8)
  let engine = TestEngine(startFails: stage == .engineStart, startError: engineStartError)
  let lease = TestLease()
  let leaseAcquisitionCounter = LeaseAcquisitionCounter()
  let settingsGate = NetworkSettingsGate()
  let pumpHolder = PumpHolder()
  let cancelRecorder = CancelRecorder()
  let endRecorder = EndProcessRecorder()
  let events = ProviderEventLog()

  let dependencies = PacketTunnelSessionDependencies(
    prepareConfiguration: { receivedDescriptor, receivedConfiguration, _ in
      guard receivedDescriptor == descriptor,
        receivedConfiguration == configuration
      else {
        throw ForcedFailure.requested
      }
      if stage == .configurationLoad {
        throw ForcedFailure.requested
      }
      leaseAcquisitionCounter.record()
      if stage == .leaseAcquisition {
        throw ForcedFailure.requested
      }
      return PreparedTunnelConfiguration(
        descriptor: descriptor,
        configuration: configuration,
        lease: lease
      )
    },
    makePump: { _, failureHandler in
      if stage == .pumpCreation {
        throw ForcedFailure.requested
      }
      let pump = TestPump(
        descriptorTransferFails: stage == .descriptorTransfer,
        startFails: stage == .pumpStart,
        failureHandler: failureHandler
      )
      pumpHolder.install(pump)
      return pump
    },
    applyNetworkSettings: { _, completion in
      if stage == .networkSettings {
        completion(ForcedFailure.requested)
      } else {
        settingsGate.install(completion)
      }
    },
    recordAcceptance: { _ in
      if stage == .configurationAcceptance {
        throw ForcedFailure.requested
      }
    }
  )
  let lifecycle = PacketTunnelSessionLifecycle(
    engineFactory: TestEngineFactory(
      engine: engine,
      creationFails: stage == .engineCreation
    ),
    dependencies: dependencies,
    cancelTunnel: { error in
      events.record("cancel")
      cancelRecorder.record(error)
    },
    endProcess: { failure in
      events.record("end")
      endRecorder.record(failure)
      processEnd?.spent(failure)
    }
  )
  return ProviderFixture(
    lifecycle: lifecycle,
    descriptor: descriptor,
    configuration: configuration,
    engine: engine,
    lease: lease,
    leaseAcquisitionCounter: leaseAcquisitionCounter,
    pumpHolder: pumpHolder,
    settingsGate: settingsGate,
    cancelRecorder: cancelRecorder,
    endRecorder: endRecorder,
    events: events
  )
}
