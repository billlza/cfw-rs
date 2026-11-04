import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWLibboxRuntime
@testable import CFWPacketTunnel

// The provider lifecycle fakes: leases, pumps, engines, the network settings
// gate, completion and event recorders, and runtimes that time out.
enum ForcedFailure: Error {
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

final class TestLease: EngineLeaseHolding, @unchecked Sendable {
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

final class LeaseAcquisitionCounter: @unchecked Sendable {
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

final class TestPump: PacketPumping, @unchecked Sendable {
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

final class TestEngine: PacketEngine, @unchecked Sendable {
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

struct TestEngineFactory: PacketEngineFactory {
  let engine: TestEngine
  let creationFails: Bool

  func makeEngine() throws -> any PacketEngine {
    if creationFails {
      throw ForcedFailure.requested
    }
    return engine
  }
}

final class NetworkSettingsGate: @unchecked Sendable {
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

final class StartCompletionRecorder: @unchecked Sendable {
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

final class StopCompletionRecorder: @unchecked Sendable {
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

func successfulStopProof(
  _ result: PacketTunnelStopResult?
) -> PacketTunnelStopProof? {
  guard let result else { return nil }
  switch result {
  case .success(let proof): return proof
  case .failure: return nil
  }
}

func unclosableFailure(
  _ result: PacketTunnelStopResult?
) -> LibboxInstanceUnclosable? {
  guard let result, case .failure(.localRuntime(.engineUnclosable(let failure))) = result else {
    return nil
  }
  return failure
}

/// What happened, in order: completions the test records, cancelled tunnels
/// and ended processes.
final class ProviderEventLog: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [String] = []

  func record(_ event: String) {
    lock.withLock { events.append(event) }
  }

  var values: [String] {
    lock.withLock { events }
  }
}

final class EndProcessRecorder: @unchecked Sendable {
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

final class CancelRecorder: @unchecked Sendable {
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

final class PumpHolder: @unchecked Sendable {
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
final class TimedOutPacketRuntime: LibboxServiceRuntime, @unchecked Sendable {
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

struct TimedOutPacketRuntimeFactory: LibboxServiceRuntimeFactory {
  let runtime: TimedOutPacketRuntime

  func makeRuntime(role: LibboxRuntimeRole) throws -> any LibboxServiceRuntime { runtime }
}
