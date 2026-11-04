import CFWSharedProtocol
import Foundation
import OSLog
import Synchronization

/// Ends the ProxyAgent after libbox could not close a runtime: only the process
/// ending releases the listeners, descriptors and goroutines that close left
/// open. launchd starts the agent again for the Host's next request.
struct ProxyAgentProcessExit: Sendable {
  typealias Schedule = @Sendable (DispatchTime, @escaping @Sendable () -> Void) -> Void
  /// Runs work once the agent answered every request it received.
  typealias WhenAnswered = @Sendable (@escaping @Sendable () -> Void) -> Void

  /// launchd starts an on-demand agent again no sooner than this after it last
  /// started it, its default `ThrottleInterval`, which the agent's job keeps,
  /// and holds every request for the agent until then, past the Host's
  /// five-second reply wait. Measured on macOS 27.0.1 on 2026-10-16: an agent
  /// that ended right after a reply had its next request answered 10.0 seconds
  /// after its start, one that ended 11 seconds after its start within 50 ms.
  static let launchdRestartThrottle: DispatchTimeInterval = .seconds(10)
  /// The agent ends no sooner than this after it started, so launchd starts its
  /// successor at once. The extra second covers the time from launchd starting
  /// the agent to the agent reading the clock.
  static let minimumLifetime: DispatchTimeInterval = .seconds(11)
  /// How long the agent waits for the requests it received to be answered:
  /// the Host waits for no answer longer than for a rights request's.
  static let unansweredRequestLimit = DispatchTimeInterval.seconds(
    Int(ProxyAgentRequestBudget.authorizationReply.components.seconds))
  /// How long the agent waits for its connections to send the replies it gave
  /// them. The Host waits five seconds for a reply, so one still unsent then is
  /// no longer awaited.
  static let sendBarrierLimit: DispatchTimeInterval = .seconds(5)

  private static let logger = Logger(
    subsystem: "com.bill.clashformac",
    category: "proxy-agent-exit"
  )
  private let openConnections: @Sendable () -> [any ProxyAgentSendBarrier]
  private let whenAnswered: WhenAnswered
  private let launchedAt: DispatchTime
  private let now: @Sendable () -> DispatchTime
  private let schedule: Schedule
  private let exit: @Sendable (Int32) -> Void

  /// `launchedAt` is when the agent's process started. Dispatch time stops
  /// while the Mac sleeps, so a wait that spans a sleep ends no earlier than
  /// launchd's. `_exit` skips atexit handlers while libbox's threads still run.
  init(
    connections: ProxyAgentConnections, requests: ProxyAgentUnansweredRequests,
    launchedAt: DispatchTime
  ) {
    self.init(
      openConnections: { connections.open }, whenAnswered: { requests.whenNone($0) },
      launchedAt: launchedAt, now: { .now() },
      schedule: { deadline, work in
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: deadline, execute: work)
      },
      exit: { _exit($0) })
  }

  init(
    openConnections: @escaping @Sendable () -> [any ProxyAgentSendBarrier],
    whenAnswered: @escaping WhenAnswered,
    launchedAt: DispatchTime,
    now: @escaping @Sendable () -> DispatchTime,
    schedule: @escaping Schedule,
    exit: @escaping @Sendable (Int32) -> Void
  ) {
    self.openConnections = openConnections
    self.whenAnswered = whenAnswered
    self.launchedAt = launchedAt
    self.now = now
    self.schedule = schedule
    self.exit = exit
  }

  /// Exits once the agent has run `minimumLifetime`, has answered every request
  /// it received, and a send barrier has run on every open connection then, so
  /// every reply, the failure's own included, has been sent; until then the
  /// agent keeps answering. A request still unanswered
  /// `unansweredRequestLimit` later, or a connection that has not sent its
  /// replies `sendBarrierLimit` after its barrier, no longer holds the exit.
  /// Only `ProxyAgentEndReason`'s reasons end the agent this way; libbox's
  /// text is never logged.
  func end(_ reason: ProxyAgentEndReason) {
    switch reason {
    case .engineUnclosable:
      Self.logger.fault("libbox could not close a System Proxy runtime; ending the ProxyAgent")
    case .quarantinedStop:
      Self.logger.notice(
        "The network Authority quarantined a stop this ProxyAgent finished; ending it so the Authority releases the lease"
      )
    case .retired:
      Self.logger.fault(
        "A configuration check or latency test left libbox holding what it built; ending the retired ProxyAgent"
      )
    }
    schedule(max(now(), launchedAt + Self.minimumLifetime)) { [self] in
      exitOnceAnswered()
    }
  }

  private func exitOnceAnswered() {
    let sending = ProxyAgentFirstPath()
    schedule(now() + Self.unansweredRequestLimit) { [self] in
      if sending.run({ exitOnceRepliesAreSent() }) {
        Self.logger.fault("a request was still unanswered at its limit; ending the ProxyAgent")
      }
    }
    whenAnswered { [self] in
      sending.run { exitOnceRepliesAreSent() }
    }
  }

  private func exitOnceRepliesAreSent() {
    let exiting = ProxyAgentFirstPath()
    let exit = self.exit
    let sent = DispatchGroup()
    for connection in openConnections() {
      sent.enter()
      connection.scheduleSendBarrierBlock { sent.leave() }
    }
    sent.notify(queue: .global(qos: .userInitiated)) {
      exiting.run { exit(EX_SOFTWARE) }
    }
    schedule(now() + Self.sendBarrierLimit) {
      if exiting.run({ exit(EX_SOFTWARE) }) {
        Self.logger.fault("a connection did not send its replies in time; ending the ProxyAgent")
      }
    }
  }
}

/// Runs the work of whichever of several paths comes first, and only its.
private final class ProxyAgentFirstPath: Sendable {
  private let taken = Mutex(false)

  /// Runs `work` unless another path came first; returns whether it ran.
  @discardableResult
  func run(_ work: () -> Void) -> Bool {
    let first = taken.withLock { taken -> Bool in
      defer { taken = true }
      return !taken
    }
    if first { work() }
    return first
  }
}
