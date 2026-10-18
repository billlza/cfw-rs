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
/// for delivering the request, launching the owner and the reply; the same for
/// a start abandoned at the interrupt limit, whose spent owner reports without
/// the attestation; and a silent
/// ProxyAgent's rollback inside the native bridge operation budget, assuming
/// the Host's own Authority calls answer promptly. An interrupt that returns
/// only near `interruptLimit`, as one held by libbox's first wait for a network
/// path does, leaves the attestation little room: should the Authority then
/// answer slowly, the Host's wait ends first and it rolls the start back with
/// its own timeout, while the owner's queue is no longer inside libbox. A
/// libbox start that returns just before the deadline still has to become
/// ready and attest it; those steps are normally quick and are bounded
/// separately, not by these budgets.
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
  /// How long after its deadline fired an owner still waits for an interrupted
  /// start to return. The limit covers the longest wait libbox cannot
  /// interrupt that the platform imposes, the first wait for a network path,
  /// and then closing what the start built. Like that wait and the Host's
  /// waits, it counts only time the Mac is awake. A start still inside libbox
  /// then is abandoned: the owner's runtime is spent and the owner ends its
  /// process, which reports the start without another Authority call.
  public static let interruptLimit: Duration = .milliseconds(5_500)
  /// The Host's wait for a ProxyAgent start reply. It covers the owner's libbox
  /// deadline plus one bounded Authority attestation, and leaves the bridge
  /// operation budget room to roll back an owner that never replies.
  public static let proxyAgentStartReply: Duration = .seconds(18)
  /// The Host's wait for Packet Tunnel readiness after macOS accepted the start.
  /// It also lets a cold extension launch report an expired ticket.
  public static let tunnelReadiness: Duration = .seconds(20)
}

/// Stop bounds shared by the engine owners and the Host.
public enum EngineStopBudget {
  /// How long an owner waits for libbox to close its service at a stop or after
  /// a start that failed on its own. A close still running then is abandoned:
  /// the owner's runtime is spent and the owner reports that, within the
  /// Host's stop waits, instead of holding every later reply behind libbox.
  public static let libboxClose: Duration = .seconds(2)
}

/// Bounds on the ProxyAgent's libbox calls that neither start nor stop an
/// engine: configuration checks and profile probes. Each counts the time the
/// Mac is awake from when the ProxyAgent received the request, as the Host's
/// waits do.
///
/// libbox cannot observe a caller deadline, so such a call runs on its own
/// thread and the ProxyAgent replies at the bound with a timeout that may be
/// retried, while the call keeps running. Tests pin the nesting: the reply,
/// the timer tolerance and a second for delivering the request and the reply
/// stay inside the Host's waits.
public enum ProxyAgentCallBudget {
  /// The ProxyAgent's reply to a configuration check, inside the Host's
  /// 5-second reply wait. On the development Mac (2026-10-17) the largest
  /// projected profile, 1,024 nodes of every protocol with 128 selectors and
  /// 45,000 rules in 3.8 MB, checked in about 1.0 second, and 4 MB of one
  /// domain rule in 0.4 seconds.
  public static let configurationCheckReply: Duration = .milliseconds(3_500)
  /// How long a profile probe may run beyond its own timeout before the
  /// ProxyAgent replies, inside the Host's wait of that timeout plus 5 seconds.
  /// On the development Mac (2026-10-17) a probe of 32 of the largest
  /// profile's 1,024 nodes, none answering, at the smallest timeout of 100 ms,
  /// returned in about 0.11 seconds, building, starting and closing every
  /// outbound and resolver included.
  public static let profileProbeReplyAllowance: Duration = .milliseconds(3_500)
  /// How long after its reply a check or probe still inside libbox is waited
  /// for. One still there then counts as hung: the ProxyAgent retires, refuses
  /// every later check, probe and start, and ends once it is idle.
  public static let abandonAfterReply: Duration = .seconds(30)
}

/// The Host's longest wait for a ProxyAgent reply.
public enum ProxyAgentRequestBudget {
  /// The Host's wait for the answer to a rights request, which waits for the
  /// user at the system's prompt. No other reply is awaited this long, so a
  /// ProxyAgent that ends waits at most this long for the answers it owes.
  public static let authorizationReply: Duration = .seconds(290)
}

/// The instant by which one owner's libbox start must have returned, fixed
/// when the owner received the start request.
public struct EngineStartDeadline: Equatable, Sendable {
  public let instant: ContinuousClock.Instant

  public init(receivedAt: ContinuousClock.Instant) {
    instant = receivedAt.advanced(by: EngineStartBudget.ownerLibboxStart)
  }
}
