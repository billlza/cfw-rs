import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Security
import Synchronization
import Testing

@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// Ending the ProxyAgent: open connections' replies, answers it still owes,
// their limits, and launchd's restart throttle.
/// Holds the send barrier a connection runs once its earlier sends went out.
private final class HeldSendBarrier: ProxyAgentSendBarrier, @unchecked Sendable {
  private let lock = NSLock()
  private var barrier: (@Sendable () -> Void)?

  func scheduleSendBarrierBlock(_ block: @escaping @Sendable () -> Void) {
    lock.withLock { barrier = block }
  }

  var isScheduled: Bool { lock.withLock { barrier != nil } }

  func sendPendingMessages() {
    let barrier = lock.withLock { () -> (@Sendable () -> Void)? in
      let block = self.barrier
      self.barrier = nil
      return block
    }
    barrier?()
  }
}

private final class ExitRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let exited = DispatchSemaphore(value: 0)
  private var statuses: [Int32] = []

  func record(_ status: Int32) {
    lock.withLock { statuses.append(status) }
    exited.signal()
  }

  func wait(for timeout: DispatchTimeInterval = .seconds(1)) -> Bool {
    exited.wait(timeout: .now() + timeout) == .success
  }

  var values: [Int32] { lock.withLock { statuses } }
}

/// Records each wait the process end asks for instead of waiting, so each test
/// decides when it ends.
private final class ManualExitClock: @unchecked Sendable {
  private let lock = NSLock()
  private var current: DispatchTime
  private var scheduled: [(deadline: DispatchTime, work: @Sendable () -> Void)] = []

  init(_ start: DispatchTime) { current = start }

  var now: @Sendable () -> DispatchTime { { self.lock.withLock { self.current } } }

  var schedule: ProxyAgentProcessExit.Schedule {
    { deadline, work in self.lock.withLock { self.scheduled.append((deadline, work)) } }
  }

  var deadlines: [DispatchTime] { lock.withLock { scheduled.map(\.deadline) } }

  func move(to instant: DispatchTime) { lock.withLock { current = instant } }

  /// Runs the `index`-th scheduled work, as its timer would.
  func fire(_ index: Int) {
    let work = lock.withLock { scheduled[index].work }
    work()
  }
}

private let launch = DispatchTime(uptimeNanoseconds: 1_000_000_000_000)

/// Holds the work the process end runs once every request is answered, so a
/// test decides when the agent answered them.
private final class HeldAnswers: @unchecked Sendable {
  private let lock = NSLock()
  private var waiting: [@Sendable () -> Void] = []

  var whenAnswered: ProxyAgentProcessExit.WhenAnswered {
    { work in self.lock.withLock { self.waiting.append(work) } }
  }

  var isWaiting: Bool { lock.withLock { !waiting.isEmpty } }

  func answerAll() {
    let ready = lock.withLock { () -> [@Sendable () -> Void] in
      defer { waiting = [] }
      return waiting
    }
    for work in ready { work() }
  }
}

private func processExit(
  _ clock: ManualExitClock, connections: [HeldSendBarrier], exits: ExitRecorder,
  whenAnswered: @escaping ProxyAgentProcessExit.WhenAnswered = { $0() }
) -> ProxyAgentProcessExit {
  ProxyAgentProcessExit(
    openConnections: { connections.map { $0 as any ProxyAgentSendBarrier } },
    whenAnswered: whenAnswered, launchedAt: launch, now: clock.now,
    schedule: clock.schedule, exit: { exits.record($0) })
}

@Test func endingTheAgentExitsOnlyOnceEveryOpenConnectionSentItsReplies() {
  let first = HeldSendBarrier()
  let second = HeldSendBarrier()
  let exits = ExitRecorder()
  let clock = ManualExitClock(launch + .seconds(60))
  processExit(clock, connections: [first, second], exits: exits).end(.engineUnclosable(unclosable))
  // It has run long enough already, so it sends its replies at once.
  #expect(clock.deadlines == [launch + .seconds(60)])
  clock.fire(0)
  #expect(first.isScheduled)
  #expect(second.isScheduled)
  first.sendPendingMessages()
  #expect(!exits.wait(for: .milliseconds(200)), "the agent exited before every reply was sent")
  second.sendPendingMessages()
  #expect(exits.wait())
  #expect(exits.values == [EX_SOFTWARE])
}

@Test func endingTheAgentWithoutAnOpenConnectionExitsAtOnce() {
  let exits = ExitRecorder()
  let clock = ManualExitClock(launch + .seconds(60))
  processExit(clock, connections: [], exits: exits).end(.engineUnclosable(unclosable))
  clock.fire(0)
  #expect(exits.wait())
  #expect(exits.values == [EX_SOFTWARE])
}

/// launchd starts an on-demand agent again no sooner than its restart throttle
/// after it last started it, and holds every request for it until then, past
/// the Host's five-second reply wait. A spent agent that started recently keeps
/// answering until its successor can start at once.
@Test func aRecentlyStartedAgentEndsOnlyWhenLaunchdWouldStartItAgainAtOnce() {
  #expect(ProxyAgentProcessExit.launchdRestartThrottle == .seconds(10))
  #expect(ProxyAgentProcessExit.minimumLifetime == .seconds(11))
  let exits = ExitRecorder()
  let clock = ManualExitClock(launch + .seconds(3))
  processExit(clock, connections: [], exits: exits).end(.engineUnclosable(unclosable))
  #expect(clock.deadlines == [launch + ProxyAgentProcessExit.minimumLifetime])
  #expect(!exits.wait(for: .milliseconds(100)))
  clock.move(to: launch + ProxyAgentProcessExit.minimumLifetime)
  clock.fire(0)
  #expect(exits.wait())
  #expect(exits.values == [EX_SOFTWARE])
}

/// A connection whose earlier sends never go out holds replies its Host has
/// stopped waiting for, so the agent ends once the limit passed, and only once.
@Test func aConnectionThatNeverSendsItsRepliesDelaysTheEndOnlyUntilTheLimit() throws {
  #expect(ProxyAgentProcessExit.sendBarrierLimit == .seconds(5))
  let stuck = HeldSendBarrier()
  let exits = ExitRecorder()
  let ended = launch + .seconds(30)
  let clock = ManualExitClock(ended)
  processExit(clock, connections: [stuck], exits: exits).end(.engineUnclosable(unclosable))
  clock.fire(0)
  #expect(stuck.isScheduled)
  try #require(
    clock.deadlines == [
      ended, ended + ProxyAgentProcessExit.unansweredRequestLimit,
      ended + ProxyAgentProcessExit.sendBarrierLimit,
    ])
  #expect(!exits.wait(for: .milliseconds(100)))
  clock.fire(2)
  #expect(exits.wait())
  stuck.sendPendingMessages()
  #expect(!exits.wait(for: .milliseconds(100)), "the agent ended twice")
  #expect(exits.values == [EX_SOFTWARE])
}

/// An agent that still owes a Host an answer, as to a rights request the user
/// is still answering, keeps answering until it gave it; only then do its
/// connections send their replies and the agent exits.
@Test func anEndingAgentWaitsForTheAnswersItStillOwes() {
  let connection = HeldSendBarrier()
  let answers = HeldAnswers()
  let exits = ExitRecorder()
  let clock = ManualExitClock(launch + .seconds(60))
  processExit(clock, connections: [connection], exits: exits, whenAnswered: answers.whenAnswered)
    .end(.retired(unclosable))
  clock.fire(0)
  #expect(answers.isWaiting)
  #expect(!connection.isScheduled)
  #expect(!exits.wait(for: .milliseconds(100)))
  answers.answerAll()
  #expect(connection.isScheduled)
  connection.sendPendingMessages()
  #expect(exits.wait())
  #expect(exits.values == [EX_SOFTWARE])
}

/// No Host waits for an answer longer than for a rights request's, so one
/// still owed then no longer holds the end, and answering it later sends the
/// replies no second time.
@Test func anAnswerStillOwedAtItsLimitHoldsTheEndNoLonger() throws {
  #expect(ProxyAgentRequestBudget.authorizationReply == .seconds(290))
  #expect(ProxyAgentProcessExit.unansweredRequestLimit == .seconds(290))
  let connection = HeldSendBarrier()
  let answers = HeldAnswers()
  let exits = ExitRecorder()
  let ended = launch + .seconds(60)
  let clock = ManualExitClock(ended)
  processExit(clock, connections: [connection], exits: exits, whenAnswered: answers.whenAnswered)
    .end(.quarantinedStop)
  clock.fire(0)
  try #require(clock.deadlines == [ended, ended + ProxyAgentProcessExit.unansweredRequestLimit])
  #expect(!connection.isScheduled)
  clock.fire(1)
  #expect(connection.isScheduled)
  connection.sendPendingMessages()
  #expect(exits.wait())
  answers.answerAll()
  #expect(clock.deadlines.count == 3, "the replies were sent a second time")
  #expect(!exits.wait(for: .milliseconds(100)), "the agent ended twice")
  #expect(exits.values == [EX_SOFTWARE])
}

/// The agent's launchd job sets no restart throttle of its own, so launchd's
/// default is the one the process end waits out.
@Test func proxyAgentJobKeepsLaunchdsDefaultRestartThrottle() throws {
  let plist = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("Config/com.bill.clashformac.proxy-agent.plist")
  let job = try #require(
    try PropertyListSerialization.propertyList(from: Data(contentsOf: plist), format: nil)
      as? [String: Any])
  #expect(job["Label"] as? String == "com.bill.clashformac.proxy-agent")
  #expect(job["ThrottleInterval"] == nil)
  #expect(job["KeepAlive"] == nil, "launchd would restart the ended agent on its own")
  #expect((job["MachServices"] as? [String: Any])?["com.bill.clashformac.proxy-agent"] != nil)
}
