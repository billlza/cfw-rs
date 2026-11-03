import CFWCredentialTransport
import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWLibboxRuntime
@testable import CFWPacketTunnel

// The ticket-only startup fakes: call gates, a clock, the owner authority
// clients, engines, runtimes, pumps and recorders. The provider ticket restart
// tests share its clock and completion recorder.
// MARK: - Fakes

final class BlockingCallGate: @unchecked Sendable {
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

final class FakeMonotonicClock: ProviderMonotonicClock, @unchecked Sendable {
  let value: UInt64
  init(value: UInt64) { self.value = value }
  func nowMilliseconds() -> UInt64 { value }
}

final class FakeOwnerAuthorityClient: EngineOwnerAuthorityClient, @unchecked Sendable {
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

final class FailingRedeemAuthorityClient: EngineOwnerAuthorityClient, @unchecked Sendable {
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

final class FakeEngine: PacketEngine, @unchecked Sendable {
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

struct FakeEngineFactory: PacketEngineFactory {
  let engine: FakeEngine
  func makeEngine() throws -> any PacketEngine { engine }
}

/// A runtime whose failed start libbox could not close: the start throws the
/// close failure, and so does every stop.
final class UnclosablePacketRuntime: LibboxServiceRuntime, @unchecked Sendable {
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

struct UnclosablePacketRuntimeFactory: LibboxServiceRuntimeFactory {
  let runtime: UnclosablePacketRuntime

  func makeRuntime(role: LibboxRuntimeRole) throws -> any LibboxServiceRuntime { runtime }
}

/// What happened, in order: completions the test records and ended processes.
final class EventLog: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [String] = []

  func record(_ event: String) {
    lock.withLock { events.append(event) }
  }

  var values: [String] { lock.withLock { events } }
}

final class ProcessEndRecorder: @unchecked Sendable {
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

final class FakePump: PacketPumping, @unchecked Sendable {
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

final class CompletionRecorder: @unchecked Sendable {
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

final class StopResultRecorder: @unchecked Sendable {
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

final class StopFailureRecorder: @unchecked Sendable {
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

final class CompletionSignal: @unchecked Sendable {
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
