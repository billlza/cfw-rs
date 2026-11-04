import CFWSharedProtocol
import Dispatch
import Foundation
import Synchronization
import Testing

@testable import CFWLibboxRuntime

// What the runtime makes of each start outcome, and the bounded close.
/// What a verdict tells the runtime, in a form tests can compare.
private enum StartMeaning: Equatable {
  case started
  case conflict(Int)
  case timedOut
  case failed(WatchdogTestError)
}

private enum InterruptMeaning: Equatable {
  case notFired
  case closed
  case unclosable(LibboxInstanceUnclosable)
}

private func meaning(_ verdict: LibboxStartVerdict<Int>) -> (StartMeaning, InterruptMeaning)? {
  let start: StartMeaning
  switch verdict.start {
  case .success(nil):
    start = .started
  case .success(let conflict?):
    start = .conflict(conflict)
  case .failure(let error):
    if error as? LibboxRuntimeError == .serviceStartTimedOut {
      start = .timedOut
    } else if let error = error as? WatchdogTestError {
      start = .failed(error)
    } else {
      return nil
    }
  }
  switch verdict.interruption {
  case nil:
    return (start, .notFired)
  case .success:
    return (start, .closed)
  case .failure(let error):
    return (start, .unclosable(error))
  }
}

@Test func everyStartOutcomeHasOneMeaningForTheRuntime() {
  typealias Outcome = LibboxStartWatchdog.Outcome<Int?>
  let table: [(Outcome, StartMeaning, InterruptMeaning)] = [
    (.notStarted, .timedOut, .notFired),
    (.completed(.success(nil)), .started, .notFired),
    (.completed(.success(7)), .conflict(7), .notFired),
    (.completed(.failure(WatchdogTestError.start)), .failed(.start), .notFired),
    // libbox reports an interrupted start as success: that start timed out.
    (.interrupted(start: .success(nil), interruption: .success(())), .timedOut, .closed),
    (.interrupted(start: .success(7), interruption: .success(())), .conflict(7), .closed),
    (
      .interrupted(start: .failure(WatchdogTestError.start), interruption: .success(())),
      .failed(.start), .closed
    ),
    (
      .interrupted(start: .success(nil), interruption: .failure(interruptFailure)),
      .timedOut, .unclosable(interruptFailure)
    ),
    // A thread may still be inside libbox, so the runtime cannot be closed.
    (.abandoned, .timedOut, .unclosable(LibboxInstanceUnclosable(.interruptDidNotReturn))),
  ]
  for (outcome, start, interruption) in table {
    let verdict: LibboxStartVerdict<Int> = outcome.verdict()
    guard let observed = meaning(verdict) else {
      Issue.record("\(outcome) produced an unexpected error")
      continue
    }
    #expect(observed.0 == start, "\(outcome)")
    #expect(observed.1 == interruption, "\(outcome)")
  }
}

@Test func boundedCloseReportsWhatTheCloseReturned() {
  #expect(LibboxBoundedClose().bound == EngineStopBudget.libboxClose)
  let bounded = LibboxBoundedClose(bound: .seconds(10))
  #expect(bounded.run {} == .closed)
  #expect(
    bounded.run { throw CloseTestFailure() } == .failed(LibboxDiagnostic(CloseTestFailure.text)))
}

@Test func boundedCloseStopsWaitingAtItsBound() {
  let close = Gate()
  let bound = Duration.milliseconds(200)
  let began = ContinuousClock.now
  let outcome = LibboxBoundedClose(bound: bound).run { close.pass() }
  let waited = began.duration(to: .now)
  close.open()
  #expect(outcome == .didNotReturn)
  #expect(waited >= bound, "gave up after \(waited)")
  #expect(waited < bound + .seconds(1), "gave up after \(waited)")
}
