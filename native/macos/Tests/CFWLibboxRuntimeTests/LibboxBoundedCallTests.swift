import CFWSharedProtocol
import Dispatch
import Foundation
import Synchronization
import Testing

@testable import CFWLibboxRuntime

// Bounded calls into libbox: replies before and past their deadline, calls
// abandoned at their limit, and a held call that holds back no other.
/// What one bounded call delivered, in order, in a form tests compare.
private enum CallEvent: Equatable {
  case replied(Int)
  case repliedFailure
  case repliedStillRunning
  case returned(Int)
  case returnedFailure
  case abandoned(LibboxInstanceUnclosable)
}

private final class CallRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var recorded: [CallEvent] = []
  private let ended = DispatchSemaphore(value: 0)
  private let replied = DispatchSemaphore(value: 0)

  var events: [CallEvent] { lock.withLock { recorded } }

  func reply(_ reply: LibboxCallReply<Int>) {
    lock.withLock {
      switch reply {
      case .returned(.success(let value)): recorded.append(.replied(value))
      case .returned(.failure): recorded.append(.repliedFailure)
      case .stillRunning: recorded.append(.repliedStillRunning)
      }
    }
    replied.signal()
  }

  func end(_ end: LibboxCallEnd<Int>) {
    lock.withLock {
      switch end {
      case .returned(.success(let value)): recorded.append(.returned(value))
      case .returned(.failure): recorded.append(.returnedFailure)
      case .abandoned(let failure): recorded.append(.abandoned(failure))
      }
    }
    ended.signal()
  }

  func awaitReply() -> Bool { replied.wait(timeout: .now() + .seconds(5)) == .success }
  func awaitEnd() -> Bool { ended.wait(timeout: .now() + .seconds(5)) == .success }
}

private func boundedCall(
  _ timers: ManualStartDeadline, replyDeadline: Duration = .seconds(3),
  _ recorder: CallRecorder, _ call: @escaping @Sendable () throws -> Int
) {
  LibboxBoundedCall(afterAwake: timers.afterAwake, startCall: LibboxBoundedCall.onItsOwnQueue).run(
    replyDeadline: replyDeadline, qos: .userInitiated, call,
    reply: { recorder.reply($0) }, ended: { recorder.end($0) })
}

/// Holds a bounded call's work instead of starting its thread, so a test runs
/// it exactly where the race it pins needs the return.
private final class HeldCallStart: @unchecked Sendable {
  private let lock = NSLock()
  private var work: (@Sendable () -> Void)?

  var start: LibboxBoundedCall.StartCall {
    { _, work in self.lock.withLock { self.work = work } }
  }

  /// Runs the held call on this thread, as its own thread would.
  func runHeld() {
    let work = lock.withLock { () -> (@Sendable () -> Void)? in
      defer { self.work = nil }
      return self.work
    }
    guard let work else {
      Issue.record("no bounded call was held")
      return
    }
    work()
  }
}

/// A call that returns before its deadline answers with its result and ends
/// once; the deadline timer is cancelled and no limit is armed.
@Test func aCallReturningBeforeItsReplyAnswersWithItsResultOnce() {
  let timers = ManualStartDeadline()
  let recorder = CallRecorder()
  boundedCall(timers, replyDeadline: .seconds(3), recorder) { 42 }
  #expect(recorder.awaitEnd())
  #expect(recorder.events == [.replied(42), .returned(42)])
  #expect(timers.timers == [.awake(.seconds(3))])
  #expect(timers.cancelled == [0])

  let failing = CallRecorder()
  boundedCall(ManualStartDeadline(), failing) { throw WatchdogTestError.start }
  #expect(failing.awaitEnd())
  #expect(failing.events == [.repliedFailure, .returnedFailure])
}

/// A call still running at its deadline answers that it still runs, and only
/// then is the limit armed. Its later return ends it once, and the limit,
/// should it still fire, changes nothing.
@Test func aCallPastItsReplyAnswersStillRunningAndEndsWhenItReturns() {
  let timers = ManualStartDeadline()
  let recorder = CallRecorder()
  let call = Gate()
  boundedCall(timers, replyDeadline: .seconds(3), recorder) {
    call.pass()
    return 7
  }
  #expect(call.awaitEntry())
  #expect(timers.timers == [.awake(.seconds(3))])
  timers.fire(0)
  #expect(recorder.events == [.repliedStillRunning])
  #expect(timers.timers == [.awake(.seconds(3)), .awake(ProxyAgentCallBudget.abandonAfterReply)])

  call.open()
  #expect(recorder.awaitEnd())
  #expect(recorder.events == [.repliedStillRunning, .returned(7)])
  #expect(timers.cancelled == [1])
  timers.fire(1)
  #expect(recorder.events == [.repliedStillRunning, .returned(7)])
  #expect(!call.hasStalled)
}

/// A call still inside libbox at the limit is abandoned once, and its late
/// return changes nothing.
@Test func aCallStillInsideLibboxAtTheLimitIsAbandonedOnce() {
  let timers = ManualStartDeadline()
  let recorder = CallRecorder()
  let call = Gate()
  let returned = DispatchSemaphore(value: 0)
  boundedCall(timers, recorder) {
    call.pass()
    returned.signal()
    return 7
  }
  #expect(call.awaitEntry())
  timers.fire(0)
  timers.fire(1)
  #expect(
    recorder.events == [
      .repliedStillRunning, .abandoned(LibboxInstanceUnclosable(.callDidNotReturn)),
    ])
  timers.fire(1)
  call.open()
  #expect(returned.wait(timeout: .now() + .seconds(5)) == .success)
  Thread.sleep(forTimeInterval: 0.05)
  #expect(
    recorder.events == [
      .repliedStillRunning, .abandoned(LibboxInstanceUnclosable(.callDidNotReturn)),
    ])
}

/// However a return races the deadline, the call answers once and ends once,
/// in that order.
@Test func aReturnRacingTheReplyDeadlineAnswersAndEndsOnce() {
  for _ in 0..<200 {
    let timers = ManualStartDeadline()
    let recorder = CallRecorder()
    let call = Gate()
    boundedCall(timers, recorder) {
      call.pass()
      return 1
    }
    #expect(call.awaitEntry())
    DispatchQueue.global(qos: .userInitiated).async { timers.fire(0) }
    call.open()
    #expect(recorder.awaitEnd())
    let events = recorder.events
    #expect(
      events == [.replied(1), .returned(1)] || events == [.repliedStillRunning, .returned(1)],
      "\(events)")
  }
}

/// A call that returns while its `stillRunning` reply is on its way ends
/// with its result right after that reply, and no limit is armed for it.
@Test func aCallReturningDuringItsStillRunningReplyEndsRightAfterIt() {
  let timers = ManualStartDeadline()
  let held = HeldCallStart()
  let recorder = CallRecorder()
  LibboxBoundedCall(afterAwake: timers.afterAwake, startCall: held.start).run(
    replyDeadline: .seconds(3), qos: .userInitiated, { 5 },
    reply: { reply in
      recorder.reply(reply)
      if case .stillRunning = reply { held.runHeld() }
    },
    ended: { recorder.end($0) })
  timers.fire(0)
  #expect(recorder.events == [.repliedStillRunning, .returned(5)])
  #expect(timers.timers == [.awake(.seconds(3))])
}

/// A call that returns after its `stillRunning` reply but before the limit is
/// kept ends with its result, and the limit armed after it is cancelled at
/// once.
@Test func aCallReturningAsItsLimitIsArmedCancelsThatLimit() {
  let held = HeldCallStart()
  let timers = ManualStartDeadline(onArm: { index in
    if index == 1 { held.runHeld() }
  })
  let recorder = CallRecorder()
  LibboxBoundedCall(afterAwake: timers.afterAwake, startCall: held.start).run(
    replyDeadline: .seconds(3), qos: .userInitiated, { 6 },
    reply: { recorder.reply($0) }, ended: { recorder.end($0) })
  timers.fire(0)
  #expect(recorder.events == [.repliedStillRunning, .returned(6)])
  #expect(timers.timers == [.awake(.seconds(3)), .awake(ProxyAgentCallBudget.abandonAfterReply)])
  #expect(timers.cancelled == [0, 1])
  timers.fire(1)
  #expect(recorder.events == [.repliedStillRunning, .returned(6)])
}

/// Each call has its own thread, so one held inside libbox holds back no other.
@Test func aHeldCallHoldsBackNoOtherCall() {
  let held = Gate()
  let heldRecorder = CallRecorder()
  boundedCall(ManualStartDeadline(), heldRecorder) {
    held.pass()
    return 1
  }
  #expect(held.awaitEntry())
  let other = CallRecorder()
  boundedCall(ManualStartDeadline(), other) { 2 }
  #expect(other.awaitEnd())
  #expect(other.events == [.replied(2), .returned(2)])
  #expect(heldRecorder.events.isEmpty)
  held.open()
  #expect(heldRecorder.awaitEnd())
}
