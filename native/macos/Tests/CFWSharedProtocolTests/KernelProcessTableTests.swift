import Darwin
import Foundation
import Testing

@testable import CFWSharedProtocol

@Test func processTableReadsTheCurrentUnprivilegedProcess() throws {
  let identity = try #require(try KernelProcessTable.lookup(getpid()))
  #expect(identity.processIdentifier == getpid())
  #expect(identity.effectiveUserIdentifier == geteuid())
  #expect(identity.realUserIdentifier == getuid())
  #expect(identity.startSeconds > 0)
  #expect(identity.startMicroseconds < 1_000_000)
  #expect(try KernelProcessTable.lookup(getpid()) == identity)
}

@Test func processTableReadsRootLaunchdWithoutPrivilege() throws {
  let identity = try #require(try KernelProcessTable.lookup(1))
  #expect(identity.processIdentifier == 1)
  #expect(identity.effectiveUserIdentifier == 0)
  #expect(identity.realUserIdentifier == 0)
  #expect(identity.startSeconds > 0)
}

/// Once a process ended and was reaped, its pid names no process, or a later
/// one that started at another time.
@Test func processTableTellsAnEndedProcessApart() throws {
  let child = Process()
  child.executableURL = URL(fileURLWithPath: "/bin/sleep")
  child.arguments = ["30"]
  try child.run()
  let pid = child.processIdentifier
  let running = try #require(try KernelProcessTable.lookup(pid))
  #expect(running.processIdentifier == pid)
  #expect(running.effectiveUserIdentifier == geteuid())
  child.terminate()
  child.waitUntilExit()
  #expect(child.terminationReason == .uncaughtSignal)
  let ended = try KernelProcessTable.lookup(pid)
  #expect(ended != running, "pid \(pid) still names the reaped process")
}

@Test func processTableRejectsAnAmbiguousEntry() throws {
  #expect(throws: KernelProcessTableError.malformedEntry) {
    try KernelProcessTable.validated(
      expectedProcessIdentifier: 12, observedProcessIdentifier: 13,
      effectiveUserIdentifier: 0, realUserIdentifier: 0,
      startSeconds: 1, startMicroseconds: 0)
  }
  #expect(throws: KernelProcessTableError.malformedEntry) {
    try KernelProcessTable.validated(
      expectedProcessIdentifier: 12, observedProcessIdentifier: 12,
      effectiveUserIdentifier: 0, realUserIdentifier: 0,
      startSeconds: 1, startMicroseconds: 1_000_000)
  }
  #expect(throws: KernelProcessTableError.malformedEntry) {
    try KernelProcessTable.validated(
      expectedProcessIdentifier: 12, observedProcessIdentifier: 12,
      effectiveUserIdentifier: 0, realUserIdentifier: 0,
      startSeconds: 0, startMicroseconds: 0)
  }
  #expect(
    try KernelProcessTable.validated(
      expectedProcessIdentifier: 12, observedProcessIdentifier: 12,
      effectiveUserIdentifier: 501, realUserIdentifier: 502,
      startSeconds: 7, startMicroseconds: 999_999)
      == KernelProcessIdentity(
        processIdentifier: 12, effectiveUserIdentifier: 501, realUserIdentifier: 502,
        startSeconds: 7, startMicroseconds: 999_999))
}
