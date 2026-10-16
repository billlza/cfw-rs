import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWLibboxRuntime
@testable import CFWPacketTunnel

private enum ForcedFailure: Error {
  case requested
}

enum StartupFailureStage: CaseIterable, Sendable {
  case configurationLoad
  case engineCreation
  case leaseAcquisition
  case configurationAcceptance
  case pumpCreation
  case descriptorTransfer
  case engineStart
  case networkSettings
  case pumpStart
}

private final class TestLease: EngineLeaseHolding, @unchecked Sendable {
  private let lock = NSLock()
  private var releaseCountValue = 0
  private var releaseAttemptCountValue = 0
  private var releaseFailuresRemaining = 0

  var releaseCount: Int {
    lock.withLock { releaseCountValue }
  }

  var releaseAttemptCount: Int {
    lock.withLock { releaseAttemptCountValue }
  }

  func failNextRelease() {
    lock.withLock {
      releaseFailuresRemaining += 1
    }
  }

  func release() throws {
    try lock.withLock {
      releaseAttemptCountValue += 1
      if releaseFailuresRemaining > 0 {
        releaseFailuresRemaining -= 1
        throw ForcedFailure.requested
      }
      releaseCountValue += 1
    }
  }
}

private final class LeaseAcquisitionCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var countValue = 0

  var count: Int {
    lock.withLock { countValue }
  }

  func record() {
    lock.withLock {
      countValue += 1
    }
  }
}

private final class TestPump: PacketPumping, @unchecked Sendable {
  private let lock = NSLock()
  private let failureHandler: PacketPump.FailureHandler
  private let descriptorTransferFails: Bool
  private let startFails: Bool
  private var descriptorTransferred = false
  private var startCountValue = 0
  private var stopCountValue = 0

  init(
    descriptorTransferFails: Bool,
    startFails: Bool,
    failureHandler: @escaping PacketPump.FailureHandler
  ) {
    self.descriptorTransferFails = descriptorTransferFails
    self.startFails = startFails
    self.failureHandler = failureHandler
  }

  var startCount: Int {
    lock.withLock { startCountValue }
  }

  var stopCount: Int {
    lock.withLock { stopCountValue }
  }

  func takeEngineFileDescriptor() throws -> Int32 {
    if descriptorTransferFails {
      throw ForcedFailure.requested
    }
    return try lock.withLock {
      guard !descriptorTransferred else {
        throw PacketPumpError.engineFileDescriptorAlreadyTransferred
      }
      descriptorTransferred = true
      let descriptor = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
      guard descriptor >= 0 else {
        throw ForcedFailure.requested
      }
      return descriptor
    }
  }

  func start() throws {
    try lock.withLock {
      startCountValue += 1
      if startFails {
        throw ForcedFailure.requested
      }
    }
  }

  func stop() {
    lock.withLock {
      stopCountValue += 1
    }
  }

  func fail(_ error: PacketPumpError) {
    failureHandler(error)
  }
}

private final class TestEngine: PacketEngine, @unchecked Sendable {
  private let lock = NSLock()
  private let startFails: Bool
  private let startError: any Error
  private var ownedDescriptor: Int32 = -1
  private var startCountValue = 0
  private var stopCountValue = 0
  private var stopFailure: LibboxInstanceUnclosable?
  private var startDeadlines: [EngineStartDeadline] = []

  init(startFails: Bool, startError: any Error = ForcedFailure.requested) {
    self.startFails = startFails
    self.startError = startError
  }

  deinit {
    closeOwnedDescriptor()
  }

  var startCount: Int {
    lock.withLock { startCountValue }
  }

  var stopCount: Int {
    lock.withLock { stopCountValue }
  }

  var deadlines: [EngineStartDeadline] {
    lock.withLock { startDeadlines }
  }

  /// Makes this and every later stop throw `failure`, as an engine whose
  /// libbox instance could not be closed does.
  func failStops(with failure: LibboxInstanceUnclosable) {
    lock.withLock { stopFailure = failure }
  }

  func start(configuration: Data, packetFileDescriptor: Int32, deadline: EngineStartDeadline)
    throws
  {
    try lock.withLock {
      startCountValue += 1
      startDeadlines.append(deadline)
      if startFails {
        Darwin.close(packetFileDescriptor)
        throw startError
      }
      ownedDescriptor = packetFileDescriptor
    }
  }

  func stop() throws(LibboxInstanceUnclosable) {
    let failure = lock.withLock { () -> LibboxInstanceUnclosable? in
      stopCountValue += 1
      if let stopFailure {
        return stopFailure
      }
      closeOwnedDescriptorLocked()
      return nil
    }
    if let failure {
      throw failure
    }
  }

  func healthCheck() throws {}

  private func closeOwnedDescriptor() {
    lock.withLock {
      closeOwnedDescriptorLocked()
    }
  }

  private func closeOwnedDescriptorLocked() {
    guard ownedDescriptor >= 0 else {
      return
    }
    Darwin.close(ownedDescriptor)
    ownedDescriptor = -1
  }
}

private struct TestEngineFactory: PacketEngineFactory {
  let engine: TestEngine
  let creationFails: Bool

  func makeEngine() throws -> any PacketEngine {
    if creationFails {
      throw ForcedFailure.requested
    }
    return engine
  }
}

private final class NetworkSettingsGate: @unchecked Sendable {
  private let lock = NSLock()
  private let installed = DispatchSemaphore(value: 0)
  private var completion: (@Sendable (Error?) -> Void)?

  func install(_ completion: @escaping @Sendable (Error?) -> Void) {
    lock.withLock {
      self.completion = completion
    }
    installed.signal()
  }

  func waitUntilInstalled() -> Bool {
    installed.wait(timeout: .now() + 1) == .success
  }

  func complete(_ error: Error?) {
    let completion = lock.withLock { self.completion }
    completion?(error)
  }
}

private final class StartCompletionRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let completed = DispatchSemaphore(value: 0)
  private var errors: [PacketTunnelProviderError?] = []

  func record(_ error: Error?) {
    lock.withLock {
      errors.append(error as? PacketTunnelProviderError)
    }
    completed.signal()
  }

  func wait() -> Bool {
    completed.wait(timeout: .now() + 1) == .success
  }

  var values: [PacketTunnelProviderError?] {
    lock.withLock { errors }
  }
}

private final class StopCompletionRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let completed = DispatchSemaphore(value: 0)
  private var results: [PacketTunnelStopResult] = []

  func record(_ result: PacketTunnelStopResult) {
    lock.withLock { results.append(result) }
    completed.signal()
  }

  func wait() -> Bool {
    completed.wait(timeout: .now() + 1) == .success
  }

  var values: [PacketTunnelStopResult] {
    lock.withLock { results }
  }
}

private func successfulStopProof(
  _ result: PacketTunnelStopResult?
) -> PacketTunnelStopProof? {
  guard let result else { return nil }
  switch result {
  case .success(let proof): return proof
  case .failure: return nil
  }
}

private func unclosableFailure(
  _ result: PacketTunnelStopResult?
) -> LibboxInstanceUnclosable? {
  guard let result, case .failure(.localRuntime(.engineUnclosable(let failure))) = result else {
    return nil
  }
  return failure
}

/// What happened, in order: completions the test records, cancelled tunnels
/// and ended processes.
private final class EventLog: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [String] = []

  func record(_ event: String) {
    lock.withLock { events.append(event) }
  }

  var values: [String] {
    lock.withLock { events }
  }
}

private final class EndProcessRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let ended = DispatchSemaphore(value: 0)
  private var failures: [LibboxInstanceUnclosable] = []

  func record(_ failure: LibboxInstanceUnclosable) {
    lock.withLock { failures.append(failure) }
    ended.signal()
  }

  func wait() -> Bool {
    ended.wait(timeout: .now() + 1) == .success
  }

  var values: [LibboxInstanceUnclosable] {
    lock.withLock { failures }
  }
}

private final class CancelRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let completed = DispatchSemaphore(value: 0)
  private var errors: [PacketTunnelProviderError] = []

  func record(_ error: PacketTunnelProviderError) {
    lock.withLock {
      errors.append(error)
    }
    completed.signal()
  }

  func wait() -> Bool {
    completed.wait(timeout: .now() + 1) == .success
  }

  var values: [PacketTunnelProviderError] {
    lock.withLock { errors }
  }
}

private final class PumpHolder: @unchecked Sendable {
  private let lock = NSLock()
  private var value: TestPump?

  func install(_ pump: TestPump) {
    lock.withLock {
      value = pump
    }
  }

  var pump: TestPump? {
    lock.withLock { value }
  }
}

/// A runtime whose start ran past its deadline and was interrupted.
private final class TimedOutPacketRuntime: LibboxServiceRuntime, @unchecked Sendable {
  private let lock = NSLock()
  private var startDeadlines: [EngineStartDeadline] = []

  var deadlines: [EngineStartDeadline] { lock.withLock { startDeadlines } }

  func start(configuration: Data, packetFileDescriptor: Int32?, deadline: EngineStartDeadline)
    throws
  {
    lock.withLock { startDeadlines.append(deadline) }
    // The runtime owns the descriptor on every path, failures included.
    if let packetFileDescriptor {
      Darwin.close(packetFileDescriptor)
    }
    throw LibboxRuntimeError.serviceStartTimedOut
  }

  func stop() throws(LibboxInstanceUnclosable) {}
  func healthCheck() throws {}
  func resetNetwork() {}
}

private struct TimedOutPacketRuntimeFactory: LibboxServiceRuntimeFactory {
  let runtime: TimedOutPacketRuntime

  func makeRuntime(role: LibboxRuntimeRole) throws -> any LibboxServiceRuntime { runtime }
}

private struct ProviderFixture {
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
  let events: EventLog
}

private func tunnelDescriptor() throws -> ConfigurationDescriptor {
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
private func fixture(
  failingAt stage: StartupFailureStage?,
  engineStartError: any Error = ForcedFailure.requested,
  processEnd: PacketTunnelProcessEnd? = nil
) throws -> ProviderFixture {
  let descriptor = try tunnelDescriptor()
  let configuration = Data("{}".utf8)
  let engine = TestEngine(startFails: stage == .engineStart, startError: engineStartError)
  let lease = TestLease()
  let leaseAcquisitionCounter = LeaseAcquisitionCounter()
  let settingsGate = NetworkSettingsGate()
  let pumpHolder = PumpHolder()
  let cancelRecorder = CancelRecorder()
  let endRecorder = EndProcessRecorder()
  let events = EventLog()

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
    let descriptor = try tunnelDescriptor()
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
    let fixture = try fixture(failingAt: stage)
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
    let fixture = try fixture(
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

  @Test func stopDuringNetworkSettingsInvalidatesLateCallbacksAndCleansOnce() throws {
    let fixture = try fixture(failingAt: nil)
    let start = StartCompletionRecorder()
    let stop = StopCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())
    #expect(fixture.engine.startCount == 0)

    fixture.lifecycle.stop { stop.record($0) }
    #expect(stop.wait())
    #expect(successfulStopProof(stop.values.first) != nil)
    #expect(start.wait())
    #expect(start.values == [.startupCancelled])
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.pumpHolder.pump?.stopCount == 1)

    fixture.settingsGate.complete(nil)
    fixture.settingsGate.complete(ForcedFailure.requested)
    _ = fixture.lifecycle.testingSnapshot()

    #expect(start.values.count == 1)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.pumpHolder.pump?.startCount == 0)
    #expect(fixture.pumpHolder.pump?.stopCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test(arguments: [StartupFailureStage.engineCreation, .pumpCreation])
  func failedStartupRetainsLeaseWhenRollbackReleaseNeedsRetry(
    stage: StartupFailureStage
  ) throws {
    let fixture = try fixture(failingAt: stage)
    fixture.lease.failNextRelease()
    let start = StartCompletionRecorder()

    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { start.record($0) }

    #expect(start.wait())
    #expect(start.values.count == 1)
    #expect(start.values[0] != nil)
    #expect(fixture.lease.releaseAttemptCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)

    let blockedStart = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.lifecycleConflict])

    let stop = StopCompletionRecorder()
    fixture.lifecycle.stop { stop.record($0) }
    #expect(stop.wait())
    #expect(successfulStopProof(stop.values.first) != nil)
    #expect(fixture.lease.releaseAttemptCount == 2)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func duplicateNetworkSettingsCallbackCompletesStartExactlyOnce() throws {
    let fixture = try fixture(failingAt: nil)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())

    fixture.settingsGate.complete(nil)
    fixture.settingsGate.complete(ForcedFailure.requested)
    #expect(start.wait())
    _ = fixture.lifecycle.testingSnapshot()

    #expect(start.values.count == 1)
    #expect(start.values[0] == nil)
    #expect(fixture.pumpHolder.pump?.startCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .tunnelActive)

    let stop = StopCompletionRecorder()
    fixture.lifecycle.stop { stop.record($0) }
    #expect(stop.wait())
    #expect(successfulStopProof(stop.values.first) != nil)
  }

  @Test func repeatedStopIsIdempotentForAllOwnedResources() throws {
    let fixture = try fixture(failingAt: nil)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())
    fixture.settingsGate.complete(nil)
    #expect(start.wait())

    let firstStop = StopCompletionRecorder()
    fixture.lifecycle.stop { firstStop.record($0) }
    #expect(firstStop.wait())
    let secondStop = StopCompletionRecorder()
    fixture.lifecycle.stop { secondStop.record($0) }
    #expect(secondStop.wait())

    #expect(successfulStopProof(firstStop.values.first) != nil)
    #expect(successfulStopProof(secondStop.values.first) != nil)

    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.pumpHolder.pump?.stopCount == 1)
    #expect(fixture.cancelRecorder.values.isEmpty)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  /// With the extension's process end armed, the failure's own stop
  /// completion ends nothing: the extension ends once Network Extension's stop
  /// was answered after it, and a start in between is refused.
  @Test func aSpentLifecycleEndsTheExtensionOnlyAfterTheStopWasAnswered() throws {
    let manual = ManualProcessEnd()
    let processEnd = manual.processEnd()
    let fixture = try fixture(failingAt: nil, processEnd: processEnd)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())
    fixture.settingsGate.complete(nil)
    #expect(start.wait())
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)

    let failedStop = StopCompletionRecorder()
    let completion = PacketTunnelProvider.stopCompletion(
      { fixture.events.record("answered") }, processEnd: processEnd)
    fixture.lifecycle.stop { result in
      completion()
      failedStop.record(result)
    }
    #expect(failedStop.wait())
    #expect(unclosableFailure(failedStop.values.first) == closeFailure)
    #expect(fixture.events.values == ["end", "answered"])
    #expect(manual.exits.isEmpty, "the end ran inside the stop's completion")
    #expect(PacketTunnelProvider.startRefusal(processEnd, configuration: fixture.descriptor) != nil)
    try #require(manual.deadlines.count == 2)
    manual.run(1)
    #expect(manual.exits == [EX_SOFTWARE])
  }

  @Test func unclosableEngineIsSpentAndArmsTheProcessEndBeforeTheStopCompletes() throws {
    let fixture = try fixture(failingAt: nil)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())
    fixture.settingsGate.complete(nil)
    #expect(start.wait())
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)

    let failedStop = StopCompletionRecorder()
    fixture.lifecycle.stop { result in
      fixture.events.record("stop")
      failedStop.record(result)
    }
    #expect(failedStop.wait())
    #expect(fixture.endRecorder.wait())
    #expect(unclosableFailure(failedStop.values.first) == closeFailure)
    // The process end is armed before the failure completes anything; it
    // ends the process only once Network Extension received the completions.
    #expect(fixture.events.values == ["end", "stop"])
    #expect(fixture.endRecorder.values == [closeFailure])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.pumpHolder.pump?.stopCount == 1)
    let failed = fixture.lifecycle.testingSnapshot()
    #expect(failed.state.kind == .failed)
    #expect(failed.state.failure?.code == "tunnel-engine-unclosable")

    // The extension is spent: no stop reaches libbox again, no start begins,
    // and the process ends once.
    let secondStop = StopCompletionRecorder()
    fixture.lifecycle.stop { secondStop.record($0) }
    #expect(secondStop.wait())
    #expect(unclosableFailure(secondStop.values.first) == closeFailure)
    let blockedStart = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.engineUnclosable(closeFailure)])
    _ = fixture.lifecycle.testingSnapshot()
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.engine.startCount == 1)
    #expect(fixture.leaseAcquisitionCounter.count == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.endRecorder.values.count == 1)
    #expect(fixture.cancelRecorder.values.isEmpty)
  }

  @Test func unclosableEngineAfterAFailedStartArmsTheProcessEndThenFailsTheStart() throws {
    let fixture = try fixture(failingAt: .engineStart)
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close failed service")
    fixture.engine.failStops(with: closeFailure)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { error in
      fixture.events.record("start")
      start.record(error)
    }
    #expect(fixture.settingsGate.waitUntilInstalled())
    fixture.settingsGate.complete(nil)
    #expect(start.wait())
    #expect(fixture.endRecorder.wait())

    #expect(start.values == [.engineUnclosable(closeFailure)])
    // The process end is armed before the failure completes anything; it
    // ends the process only once Network Extension received the completions.
    #expect(fixture.events.values == ["end", "start"])
    #expect(fixture.endRecorder.values == [closeFailure])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.cancelRecorder.values.isEmpty)
    #expect(
      fixture.lifecycle.testingSnapshot().state.failure?.code == "tunnel-engine-unclosable")
  }

  @Test func unclosableEngineAfterAPumpFailureArmsTheProcessEndThenCancelsTheTunnel() throws {
    let fixture = try fixture(failingAt: nil)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())
    fixture.settingsGate.complete(nil)
    #expect(start.wait())
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)
    let pump = try #require(fixture.pumpHolder.pump)

    pump.fail(.packetFlowWriteFailed)
    pump.fail(.socketReadFailed(EIO))
    #expect(fixture.cancelRecorder.wait())
    #expect(fixture.endRecorder.wait())
    _ = fixture.lifecycle.testingSnapshot()

    #expect(fixture.cancelRecorder.values == [.engineUnclosable(closeFailure)])
    // The process end is armed before the failure completes anything; it
    // ends the process only once Network Extension received the completions.
    #expect(fixture.events.values == ["end", "cancel"])
    #expect(fixture.endRecorder.values == [closeFailure])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(pump.stopCount == 1)
  }

  @Test func repeatedRuntimePumpFailureCancelsAndCleansExactlyOnce() throws {
    let fixture = try fixture(failingAt: nil)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration,
      deadline: EngineStartDeadline(receivedAt: .now)
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())
    fixture.settingsGate.complete(nil)
    #expect(start.wait())
    let pump = try #require(fixture.pumpHolder.pump)

    pump.fail(.packetFlowWriteFailed)
    pump.fail(.socketReadFailed(EIO))
    #expect(fixture.cancelRecorder.wait())
    _ = fixture.lifecycle.testingSnapshot()

    #expect(fixture.cancelRecorder.values == [.packetPump(.packetFlowWriteFailed)])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(pump.stopCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)
  }
}
