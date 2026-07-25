import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

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
  private var failedStopCountValue = 0
  private var releaseAttemptCountValue = 0
  private var releaseFailuresRemaining = 0

  var releaseCount: Int {
    lock.withLock { releaseCountValue }
  }

  var failedStopCount: Int {
    lock.withLock { failedStopCountValue }
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

  func markStopFailed() throws {
    lock.withLock {
      failedStopCountValue += 1
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
  private var ownedDescriptor: Int32 = -1
  private var startCountValue = 0
  private var stopCountValue = 0
  private var stopFailuresRemaining = 0

  init(startFails: Bool) {
    self.startFails = startFails
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

  func failNextStop() {
    lock.withLock {
      stopFailuresRemaining += 1
    }
  }

  func start(configuration: Data, packetFileDescriptor: Int32) throws {
    try lock.withLock {
      startCountValue += 1
      if startFails {
        Darwin.close(packetFileDescriptor)
        throw ForcedFailure.requested
      }
      ownedDescriptor = packetFileDescriptor
    }
  }

  func stop() throws {
    try lock.withLock {
      stopCountValue += 1
      if stopFailuresRemaining > 0 {
        stopFailuresRemaining -= 1
        throw ForcedFailure.requested
      }
      closeOwnedDescriptorLocked()
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
  private let completed = DispatchSemaphore(value: 0)

  func record() {
    completed.signal()
  }

  func wait() -> Bool {
    completed.wait(timeout: .now() + 1) == .success
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
}

private func tunnelDescriptor() throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
    installationID: UUID(),
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32))
  )
}

private func fixture(failingAt stage: StartupFailureStage?) throws -> ProviderFixture {
  let descriptor = try tunnelDescriptor()
  let configuration = Data("{}".utf8)
  let engine = TestEngine(startFails: stage == .engineStart)
  let lease = TestLease()
  let leaseAcquisitionCounter = LeaseAcquisitionCounter()
  let settingsGate = NetworkSettingsGate()
  let pumpHolder = PumpHolder()
  let cancelRecorder = CancelRecorder()

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
    cancelTunnel: { cancelRecorder.record($0) }
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
    cancelRecorder: cancelRecorder
  )
}

@Suite(.serialized)
struct ProviderLifecycleTests {
  @Test func everyProviderFailureProducesAStableEncodableSnapshot() throws {
    let errors: [PacketTunnelProviderError] = [
      .providerUnavailable,
      .invalidStartTicket,
      .malformedProviderConfiguration,
      .invalidConfigurationSlot,
      .lifecycleConflict,
      .startupCancelled,
      .configuration("secret configuration detail"),
      .engineCreation("secret engine detail"),
      .packetPumpSetup("secret pump setup detail"),
      .packetPump(.socketWriteFailed(EMSGSIZE)),
      .engineStart("secret engine start detail"),
      .engineStop("secret engine stop detail"),
      .networkSettings("secret network detail"),
    ]
    let descriptor = try tunnelDescriptor()
    var codes = Set<String>()

    for error in errors {
      let failure = error.engineFailure
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
      configuration: fixture.configuration
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

  @Test func stopDuringNetworkSettingsInvalidatesLateCallbacksAndCleansOnce() throws {
    let fixture = try fixture(failingAt: nil)
    let start = StartCompletionRecorder()
    let stop = StopCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())
    #expect(fixture.engine.startCount == 0)

    fixture.lifecycle.stop { stop.record() }
    #expect(stop.wait())
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
      configuration: fixture.configuration
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
      configuration: fixture.configuration
    ) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.lifecycleConflict])

    let stop = StopCompletionRecorder()
    fixture.lifecycle.stop { stop.record() }
    #expect(stop.wait())
    #expect(fixture.lease.releaseAttemptCount == 2)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func duplicateNetworkSettingsCallbackCompletesStartExactlyOnce() throws {
    let fixture = try fixture(failingAt: nil)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration
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
    fixture.lifecycle.stop { stop.record() }
    #expect(stop.wait())
  }

  @Test func repeatedStopIsIdempotentForAllOwnedResources() throws {
    let fixture = try fixture(failingAt: nil)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())
    fixture.settingsGate.complete(nil)
    #expect(start.wait())

    let firstStop = StopCompletionRecorder()
    fixture.lifecycle.stop { firstStop.record() }
    #expect(firstStop.wait())
    let secondStop = StopCompletionRecorder()
    fixture.lifecycle.stop { secondStop.record() }
    #expect(secondStop.wait())

    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.pumpHolder.pump?.stopCount == 1)
    #expect(fixture.cancelRecorder.values.isEmpty)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func engineStopFailureRetainsLeaseAndBlocksRestartUntilRetry() throws {
    let fixture = try fixture(failingAt: nil)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration
    ) { start.record($0) }
    #expect(fixture.settingsGate.waitUntilInstalled())
    fixture.settingsGate.complete(nil)
    #expect(start.wait())
    fixture.engine.failNextStop()
    fixture.engine.failNextStop()

    let failedStop = StopCompletionRecorder()
    fixture.lifecycle.stop { failedStop.record() }
    #expect(failedStop.wait())

    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.lease.failedStopCount == 1)
    #expect(fixture.pumpHolder.pump?.stopCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)

    let blockedStart = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration
    ) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.lifecycleConflict])
    #expect(fixture.leaseAcquisitionCounter.count == 1)

    let secondFailedStop = StopCompletionRecorder()
    fixture.lifecycle.stop { secondFailedStop.record() }
    #expect(secondFailedStop.wait())

    #expect(fixture.engine.stopCount == 2)
    #expect(fixture.lease.releaseCount == 0)
    #expect(fixture.lease.failedStopCount == 2)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .failed)

    let successfulRetry = StopCompletionRecorder()
    fixture.lifecycle.stop { successfulRetry.record() }
    #expect(successfulRetry.wait())

    #expect(fixture.engine.stopCount == 3)
    #expect(fixture.lease.releaseCount == 1)
    #expect(fixture.pumpHolder.pump?.stopCount == 1)
    #expect(fixture.lifecycle.testingSnapshot().state.kind == .off)
  }

  @Test func repeatedRuntimePumpFailureCancelsAndCleansExactlyOnce() throws {
    let fixture = try fixture(failingAt: nil)
    let start = StartCompletionRecorder()
    fixture.lifecycle.start(
      descriptor: fixture.descriptor,
      configuration: fixture.configuration
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
