import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWLibboxRuntime
@testable import CFWPacketTunnel

// Provider starts: stable failure snapshots, every startup failure releasing
// what it acquired, and start timeouts that keep their cause.
@Suite(.serialized)
struct ProviderLifecycleTests {
  /// Each failure the provider reports, with the code and retry flag the Host
  /// decides on: a swapped code or flag changes whether the Host asks again.
  @Test func everyProviderFailureProducesAStableEncodableSnapshot() throws {
    let errors: [(error: PacketTunnelProviderError, code: String, retryable: Bool)] = [
      (.providerUnavailable, "tunnel-provider-unavailable", true),
      (.globalAuthorityUnavailable, "global-authority-unavailable", false),
      (.invalidStartTicket, "tunnel-start-ticket-invalid", false),
      (.expiredStartTicket, "tunnel-start-ticket-expired", true),
      (.malformedProviderConfiguration, "tunnel-provider-configuration-malformed", false),
      (.invalidConfigurationSlot, "tunnel-configuration-slot-invalid", false),
      (.lifecycleConflict, "tunnel-lifecycle-conflict", false),
      (.startupCancelled, "tunnel-startup-cancelled", false),
      (.configuration("secret configuration detail"), "tunnel-configuration-invalid", false),
      (.engineCreation("secret engine detail"), "tunnel-engine-creation-failed", true),
      (.packetPumpSetup("secret pump setup detail"), "tunnel-packet-pump-setup-failed", true),
      (.packetPump(.socketWriteFailed(EMSGSIZE)), "tunnel-packet-pump-failed", true),
      (.engineStart("secret engine start detail"), "tunnel-engine-start-failed", true),
      (.engineStartTimedOut, "tunnel-engine-start-timed-out", false),
      (.controllerEndpointConflict(port: 9090), "controller-endpoint-in-use", false),
      (.mixedEndpointConflict(port: 7890), "mixed-endpoint-in-use", false),
      (
        .engineUnclosable(LibboxInstanceUnclosable(closeFailure: "secret close detail")),
        "tunnel-engine-unclosable", false
      ),
      (.networkSettings("secret network detail"), "tunnel-network-settings-failed", true),
    ]
    let descriptor = try providerTunnelDescriptor()
    var codes = Set<String>()

    for (error, code, retryable) in errors {
      let failure = error.engineFailure
      #expect(failure.code == code, "\(error)")
      #expect(failure.isRetryable == retryable, "\(error)")
      #expect(codes.insert(failure.code).inserted)
      #expect(!failure.message.contains("secret"))
      let snapshot = EngineSnapshot.tunnelFailed(
        failure,
        configuration: descriptor,
        sequence: 1
      )
      let result = try CommandResult(kind: .snapshot, snapshot: snapshot)
      let envelope = ResponseEnvelope(requestID: RequestID(), result: result)
      let encoded = try ProtocolCodec.encode(envelope)
      let decoded = try JSONDecoder().decode(ResponseEnvelope.self, from: encoded)
      #expect(decoded == envelope)
    }
  }

  @Test(arguments: StartupFailureStage.allCases)
  func everyStartupFailureReleasesAllAcquiredResources(
    stage: StartupFailureStage
  ) throws {
    let fixture = try makeProviderFixture(failingAt: stage)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { start.record($0) }

    if stage == .descriptorTransfer || stage == .engineStart || stage == .pumpStart
      || stage == .configurationAcceptance
    {
      #expect(fixture.settingsGate.waitUntilInstalled())
      #expect(fixture.engine.startCount == 0)
      fixture.settingsGate.complete(nil)
    }
    #expect(start.wait())
    #expect(start.values.count == 1)
    #expect(start.values[0] != nil)

    let leaseShouldHaveBeenAcquired =
      stage != .configurationLoad
      && stage != .leaseAcquisition
    #expect(fixture.lease.releaseCount == (leaseShouldHaveBeenAcquired ? 1 : 0))

    if let pump = fixture.pumpHolder.pump {
      #expect(pump.stopCount == 1)
    }
    let engineOwnedDescriptor =
      stage == .engineStart || stage == .pumpStart
      || stage == .configurationAcceptance
    #expect(fixture.engine.stopCount == (engineOwnedDescriptor ? 1 : 0))
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)
  }

  @Test func libboxStartTimeoutBecomesThePacketEnginesTypedTimeout() throws {
    let runtime = TimedOutPacketRuntime()
    let engine = try LibboxPacketEngineFactory(
      runtimeFactory: TimedOutPacketRuntimeFactory(runtime: runtime)
    ).makeEngine()
    let deadline = EngineStartDeadline(receivedAt: .now)
    var descriptors: [Int32] = [-1, -1]
    #expect(Darwin.pipe(&descriptors) == 0)
    Darwin.close(descriptors[1])
    #expect(throws: PacketEngineError.startTimedOut) {
      try engine.start(
        configuration: Data("{}".utf8), packetFileDescriptor: descriptors[0], deadline: deadline)
    }
    #expect(runtime.deadlines == [deadline])
  }

  @Test func engineStartTimeoutKeepsItsCauseAndReleasesEveryResource() throws {
    let fixture = try makeProviderFixture(
      failingAt: .engineStart, engineStartError: PacketEngineError.startTimedOut)
    let deadline = EngineStartDeadline(receivedAt: .now)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: deadline
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())
    fixture.settingsGate.complete(nil)
    #expect(start.wait())
    #expect(start.values == [.engineStartTimedOut])
    #expect(fixture.engine.deadlines == [deadline])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.pumpHolder.pump?.stopCount == 1)
    let snapshot = fixture.lifecycle.testingSnapshot()
    #expect(snapshot.state.kind == .failed)
    #expect(snapshot.state.failure == TunnelStartupFailure.engineStartTimedOut)
  }
}
