/// Start deadlines shared by the engine owners (ProxyAgent and Packet Tunnel
/// provider) and the Host.
///
/// The Host must not stop waiting for an owner whose serial queue is still
/// inside libbox. Otherwise the Host rolls back, the rollback's stop waits
/// behind that start, and the Authority quarantines the generation. Uncached
/// remote rule sets download inside the libbox start and have no upper bound of
/// their own, so the owner interrupts the start at a deadline it fixes when the
/// start request arrives. Tests pin the nesting for a start that times out: an
/// owner's report (its deadline, the timer tolerance, the interrupt allowance
/// and one Authority attestation) inside the Host's waits, with the rest left
/// for delivering the request, launching the owner and the reply; and a silent
/// ProxyAgent's rollback inside the native bridge operation budget, assuming
/// the Host's own Authority calls answer promptly. A libbox start that returns
/// just before the deadline still has to become ready and attest it; those
/// steps are normally quick and are bounded separately, not by these budgets.
public enum EngineStartBudget {
  /// From the moment an owner receives a start request until its libbox start
  /// must have returned. The runtime interrupts a start still running then.
  public static let ownerLibboxStart: Duration = .seconds(11)
  /// How late the owner's deadline timer may fire. The watchdog sleeps with this
  /// tolerance instead of the system's default, which grows with the wait.
  public static let deadlineTolerance: Duration = .milliseconds(100)
  /// How long interrupting a start and closing what it built may take once the
  /// deadline fired. For a stalled rule-set download the linked runtime test
  /// holds the timer's lateness and the interrupt together within
  /// `deadlineTolerance` plus this allowance; waits libbox does not cancel, such
  /// as its first wait for a network path and the cache file's lock retries,
  /// can take longer.
  public static let interruptAllowance: Duration = .milliseconds(500)
  /// The Host's wait for a ProxyAgent start reply. It covers the owner's libbox
  /// deadline plus one bounded Authority attestation, and leaves the bridge
  /// operation budget room to roll back an owner that never replies.
  public static let proxyAgentStartReply: Duration = .seconds(18)
  /// The Host's wait for Packet Tunnel readiness after macOS accepted the start.
  /// It also lets a cold extension launch report an expired ticket.
  public static let tunnelReadiness: Duration = .seconds(20)
}

/// The instant by which one owner's libbox start must have returned, fixed
/// when the owner received the start request.
public struct EngineStartDeadline: Equatable, Sendable {
  public let instant: ContinuousClock.Instant

  public init(receivedAt: ContinuousClock.Instant) {
    instant = receivedAt.advanced(by: EngineStartBudget.ownerLibboxStart)
  }
}
