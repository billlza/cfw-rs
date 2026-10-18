import Darwin

/// One process as the kernel's process table reports it. A pid alone can name a
/// later process once the first one ended; the start time tells the two apart.
public struct KernelProcessIdentity: Equatable, Sendable {
  public let processIdentifier: pid_t
  public let effectiveUserIdentifier: uid_t
  public let realUserIdentifier: uid_t
  public let startSeconds: UInt64
  public let startMicroseconds: UInt64

  public init(
    processIdentifier: pid_t, effectiveUserIdentifier: uid_t, realUserIdentifier: uid_t,
    startSeconds: UInt64, startMicroseconds: UInt64
  ) {
    self.processIdentifier = processIdentifier
    self.effectiveUserIdentifier = effectiveUserIdentifier
    self.realUserIdentifier = realUserIdentifier
    self.startSeconds = startSeconds
    self.startMicroseconds = startMicroseconds
  }
}

public enum KernelProcessTableError: Error, Equatable, Sendable {
  /// `sysctl` failed with this `errno`.
  case unreadable(Int32)
  /// The kernel's entry is not one well-formed process with the pid asked for.
  case malformedEntry
}

/// Reads the kernel's process table through `sysctl` (`KERN_PROC_PID`), which
/// needs no privilege for any process.
public enum KernelProcessTable {
  /// The process the kernel holds at `processIdentifier`, or nil when it holds
  /// none. A process that exited keeps its entry until it is reaped.
  public static func lookup(
    _ processIdentifier: pid_t
  ) throws(KernelProcessTableError) -> KernelProcessIdentity? {
    var information = kinfo_proc()
    var informationSize = MemoryLayout<kinfo_proc>.size
    var managementInformationBase: [Int32] = [
      CTL_KERN, KERN_PROC, KERN_PROC_PID, processIdentifier,
    ]
    let status = managementInformationBase.withUnsafeMutableBufferPointer { mib in
      withUnsafeMutablePointer(to: &information) { information in
        sysctl(mib.baseAddress, u_int(mib.count), information, &informationSize, nil, 0)
      }
    }
    guard status == 0 else { throw .unreadable(errno) }
    // The kernel reports no entry by returning none.
    if informationSize == 0 { return nil }
    guard informationSize == MemoryLayout<kinfo_proc>.size else { throw .malformedEntry }
    return try validated(
      expectedProcessIdentifier: processIdentifier,
      observedProcessIdentifier: information.kp_proc.p_pid,
      effectiveUserIdentifier: information.kp_eproc.e_ucred.cr_uid,
      realUserIdentifier: information.kp_eproc.e_pcred.p_ruid,
      startSeconds: information.kp_proc.p_starttime.tv_sec,
      startMicroseconds: information.kp_proc.p_starttime.tv_usec)
  }

  static func validated(
    expectedProcessIdentifier: pid_t,
    observedProcessIdentifier: pid_t,
    effectiveUserIdentifier: uid_t,
    realUserIdentifier: uid_t,
    startSeconds: Int,
    startMicroseconds: Int32
  ) throws(KernelProcessTableError) -> KernelProcessIdentity {
    guard observedProcessIdentifier == expectedProcessIdentifier,
      startSeconds > 0,
      startMicroseconds >= 0,
      startMicroseconds < 1_000_000
    else { throw .malformedEntry }
    return KernelProcessIdentity(
      processIdentifier: observedProcessIdentifier,
      effectiveUserIdentifier: effectiveUserIdentifier,
      realUserIdentifier: realUserIdentifier,
      startSeconds: UInt64(startSeconds),
      startMicroseconds: UInt64(startMicroseconds))
  }
}
