import CFWSharedProtocol
import Dispatch
import Foundation
import Synchronization
import Testing

@testable import CFWLibboxRuntime
@testable import CFWPacketTunnel

/// Records each wait the process end asks for instead of waiting, and each exit.
final class ManualProcessEnd: @unchecked Sendable {
  private let lock = NSLock()
  private var scheduled: [(deadline: DispatchTime, work: @Sendable () -> Void)] = []
  private var statuses: [Int32] = []
  let start = DispatchTime(uptimeNanoseconds: 5_000_000_000_000)

  var schedule: PacketTunnelProcessEnd.Schedule {
    { deadline, work in self.lock.withLock { self.scheduled.append((deadline, work)) } }
  }

  var deadlines: [DispatchTime] { lock.withLock { scheduled.map(\.deadline) } }
  var exits: [Int32] { lock.withLock { statuses } }

  func exit(_ status: Int32) { lock.withLock { statuses.append(status) } }

  /// Runs the `index`-th scheduled work, as its queue would.
  func run(_ index: Int) {
    let work = lock.withLock { scheduled[index].work }
    work()
  }

  func processEnd() -> PacketTunnelProcessEnd {
    PacketTunnelProcessEnd(
      now: { self.start }, schedule: schedule, exit: { self.exit($0) })
  }
}

private let failure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")

/// Network Extension asks the provider to stop only once it received what the
/// provider reported, so the spent extension ends when it answered that stop.
@Test func aSpentExtensionEndsOnceNetworkExtensionStoppedIt() throws {
  let manual = ManualProcessEnd()
  let processEnd = manual.processEnd()
  processEnd.spent(failure)
  #expect(manual.exits.isEmpty)
  try #require(manual.deadlines == [manual.start + PacketTunnelProcessEnd.stopWait])

  processEnd.networkExtensionStopAnswered()
  try #require(manual.deadlines.count == 2)
  #expect(manual.deadlines[1] == manual.start, "the end waits after the stop was answered")
  #expect(manual.exits.isEmpty, "the end ran inside the stop answer")
  manual.run(1)
  #expect(manual.exits == [EX_SOFTWARE])
  // The stop wait passing later, or another stop, ends nothing more.
  manual.run(0)
  processEnd.networkExtensionStopAnswered()
  #expect(manual.exits == [EX_SOFTWARE])
}

/// The provider answers Network Extension's stop before the spent extension's
/// end is even scheduled, so the answer never races the end.
@Test func theStopAnswerPrecedesTheEndItAllows() throws {
  let manual = ManualProcessEnd()
  let processEnd = manual.processEnd()
  processEnd.spent(failure)
  let scheduledWhenAnswered = Mutex<[DispatchTime]?>(nil)
  let completion = PacketTunnelProvider.stopCompletion(
    { scheduledWhenAnswered.withLock { $0 = manual.deadlines } }, processEnd: processEnd)

  completion()
  #expect(
    scheduledWhenAnswered.withLock { $0 } == [manual.start + PacketTunnelProcessEnd.stopWait],
    "the end was scheduled before the stop was answered")
  try #require(manual.deadlines.count == 2)
  #expect(manual.exits.isEmpty)
  manual.run(1)
  #expect(manual.exits == [EX_SOFTWARE])
}

/// Answering a stop ends nothing while libbox could close every runtime.
@Test func aStopAnswerEndsNothingBeforeAFailure() {
  let manual = ManualProcessEnd()
  let answered = Mutex(0)
  PacketTunnelProvider.stopCompletion(
    { answered.withLock { $0 += 1 } }, processEnd: manual.processEnd())()
  #expect(answered.withLock { $0 } == 1)
  #expect(manual.deadlines.isEmpty)
  #expect(manual.exits.isEmpty)
}

/// Network Extension may never ask a provider whose start failed to stop. The
/// spent extension then ends once the stop wait passed.
@Test func aSpentExtensionNetworkExtensionNeverStopsEndsAfterTheStopWait() throws {
  #expect(PacketTunnelProcessEnd.stopWait == .seconds(2))
  let manual = ManualProcessEnd()
  let processEnd = manual.processEnd()
  processEnd.spent(failure)
  try #require(manual.deadlines == [manual.start + PacketTunnelProcessEnd.stopWait])
  manual.run(0)
  #expect(manual.exits == [EX_SOFTWARE])
  processEnd.networkExtensionStopAnswered()
  #expect(manual.deadlines.count == 1)
  #expect(manual.exits == [EX_SOFTWARE])
}

/// A stop answered before libbox failed to close belongs to an earlier
/// session, so it does not end the extension.
@Test func aStopAnsweredBeforeTheFailureEndsNothing() {
  let manual = ManualProcessEnd()
  let processEnd = manual.processEnd()
  processEnd.networkExtensionStopAnswered()
  #expect(manual.deadlines.isEmpty)
  processEnd.spent(failure)
  #expect(manual.deadlines == [manual.start + PacketTunnelProcessEnd.stopWait])
  #expect(manual.exits.isEmpty)
}

/// Whatever libbox left open stays until the process ends, so no start in this
/// process may run libbox again, in this provider or a later one.
@Test func aSpentExtensionRefusesEveryLaterStart() throws {
  let manual = ManualProcessEnd()
  let processEnd = manual.processEnd()
  let configuration = try ConfigurationDescriptor(
    slot: .tunnel, tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true),
    credentialAudience: CredentialAudience(
      profileID: UUID(), profileDigest: SHA256Digest(hex: String(repeating: "ab", count: 32))),
    installationID: UUID(), epoch: 1, generation: 1, byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "11", count: 32)),
    identitySHA256: SHA256Digest(hex: String(repeating: "22", count: 32)))
  #expect(processEnd.spentFailure == nil)
  #expect(PacketTunnelProvider.startRefusal(processEnd, configuration: configuration) == nil)

  processEnd.spent(failure)
  processEnd.spent(LibboxInstanceUnclosable(.closeDidNotReturn))
  #expect(processEnd.spentFailure == failure, "a later failure replaced the first")
  #expect(manual.deadlines.count == 1, "a second failure armed another wait")
  let refusal = try #require(
    PacketTunnelProvider.startRefusal(processEnd, configuration: configuration) as? NSError)
  #expect(
    TunnelStartupFailure.matchingFailure(refusal, configuration: configuration)
      == TunnelStartupFailure.engineUnclosable)
}
