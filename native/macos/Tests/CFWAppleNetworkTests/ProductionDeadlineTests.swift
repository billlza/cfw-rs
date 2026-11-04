import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension
import Testing

@testable import CFWAppleNetwork

// The production deadline: a strict timer late by a tenth of its wait at most,
// one firing, and an action released once it fires or is cancelled.
/// Records when a production deadline fired, measured inside its action.
final class DeadlineFiringLog: @unchecked Sendable {
  private let lock = NSLock()
  private var instants: [ContinuousClock.Instant] = []

  func record() { lock.withLock { instants.append(.now) } }

  var firings: [ContinuousClock.Instant] { lock.withLock { instants } }

  /// The first firing, or nil when none happened within `limit`.
  func firstFiring(within limit: Duration) async throws -> ContinuousClock.Instant? {
    let end = ContinuousClock.now.advanced(by: limit)
    while firings.isEmpty, ContinuousClock.now < end {
      try await Task.sleep(for: .milliseconds(5))
    }
    return firings.first
  }
}

/// Held only by a deadline's action, so a test sees when the action is released.
private final class ActionLifetime: Sendable {}

/// Swift's weak references may be read while another thread releases the
/// object, which is what lets the test poll this one.
private final class WeakActionLifetime: @unchecked Sendable {
  private weak var lifetime: ActionLifetime?

  init(_ lifetime: ActionLifetime) { self.lifetime = lifetime }

  func released(within limit: Duration) async throws -> Bool {
    let end = ContinuousClock.now.advanced(by: limit)
    while lifetime != nil, ContinuousClock.now < end {
      try await Task.sleep(for: .milliseconds(5))
    }
    return lifetime == nil
  }
}

/// Arms `scheduler` with an action that records its firings and is the only
/// holder of a fresh lifetime.
private func armObservedDeadline(
  _ scheduler: CallbackDeadlineScheduler, log: DeadlineFiringLog
) -> (cancel: CallbackDeadlineScheduler.Cancel, lifetime: WeakActionLifetime) {
  let lifetime = ActionLifetime()
  let cancel = scheduler.schedule {
    withExtendedLifetime(lifetime) { log.record() }
  }
  return (cancel, WeakActionLifetime(lifetime))
}

/// The bridge budget's nesting needs every production deadline to fire within
/// its leeway: a strict timer, late by a tenth of its wait at most and never by
/// more than the maximum leeway.
@Test func productionDeadlineArmsAStrictTimerLateByATenthOfItsWaitAtMost() {
  typealias Arming = CallbackDeadlineScheduler.TimerArming
  #expect(
    CallbackDeadlineScheduler.arming(for: .milliseconds(300))
      == Arming(delay: 0.3, leeway: .nanoseconds(30_000_000)))
  #expect(
    CallbackDeadlineScheduler.arming(for: .seconds(1))
      == Arming(delay: 1, leeway: .nanoseconds(100_000_000)))
  #expect(
    CallbackDeadlineScheduler.arming(for: EngineStartBudget.proxyAgentStartReply)
      == Arming(delay: 18, leeway: .nanoseconds(100_000_000)))
  #expect(
    CallbackDeadlineScheduler.arming(for: .seconds(290))
      == Arming(delay: 290, leeway: .nanoseconds(100_000_000)))
  #expect(CallbackDeadlineScheduler.arming(for: .seconds(1)).flags == .strict)
}

/// A production deadline fires once and then releases its action, so a wait
/// that timed out keeps nothing alive.
@Test func productionDeadlineFiresOnceAndThenReleasesItsAction() async throws {
  let log = DeadlineFiringLog()
  let armed = ContinuousClock.now
  let deadline = armObservedDeadline(
    CallbackDeadlineScheduler(timeout: .milliseconds(300)), log: log)
  let firing = try await log.firstFiring(within: .seconds(5))
  let firedAt = try #require(firing, "the deadline never fired")
  #expect(armed.duration(to: firedAt) >= .milliseconds(300))
  #expect(
    try await deadline.lifetime.released(within: .seconds(2)), "a fired deadline kept its action")
  try await Task.sleep(for: .milliseconds(300))
  #expect(log.firings.count == 1)
  deadline.cancel()
}

/// A wait whose result arrived first cancels its deadline: the deadline lets go
/// of its action at once, long before it would have fired, and never fires, so
/// it costs no wakeup.
@Test func cancelledProductionDeadlineReleasesItsActionAtOnceAndNeverFires() async throws {
  let distantLog = DeadlineFiringLog()
  let distant = armObservedDeadline(
    CallbackDeadlineScheduler(timeout: .seconds(60)), log: distantLog)
  distant.cancel()
  #expect(
    try await distant.lifetime.released(within: .seconds(2)),
    "a cancelled deadline kept its action until it would have fired")

  let nearLog = DeadlineFiringLog()
  let near = armObservedDeadline(
    CallbackDeadlineScheduler(timeout: .milliseconds(300)), log: nearLog)
  near.cancel()
  try await Task.sleep(for: .milliseconds(600))
  #expect(nearLog.firings.isEmpty, "a cancelled deadline fired")
  #expect(distantLog.firings.isEmpty)
}
