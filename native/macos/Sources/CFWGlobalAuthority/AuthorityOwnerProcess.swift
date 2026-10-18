import CFWSharedProtocol
import Darwin

/// Reads the kernel's process table for the Authority. Injected so tests decide
/// which processes exist.
public protocol AuthorityProcessTable: Sendable {
  /// The process the kernel holds at `processIdentifier`, or nil when it holds
  /// none.
  func lookup(_ processIdentifier: pid_t) throws -> KernelProcessIdentity?
}

public struct KernelAuthorityProcessTable: AuthorityProcessTable {
  public init() {}

  public func lookup(_ processIdentifier: pid_t) throws -> KernelProcessIdentity? {
    try KernelProcessTable.lookup(processIdentifier)
  }
}

/// The process that bound a lease, recorded while it waited for the bind reply,
/// so the Authority can later prove that it ended.
struct AuthorityOwnerProcess: Equatable, Sendable {
  /// The lease this process bound. Its end proves nothing about another.
  let leaseID: AuthorityIdentifier
  let processIdentifier: pid_t
  let startSeconds: UInt64
  let startMicroseconds: UInt64

  init(_ identity: KernelProcessIdentity, leaseID: AuthorityIdentifier) {
    self.leaseID = leaseID
    processIdentifier = identity.processIdentifier
    startSeconds = identity.startSeconds
    startMicroseconds = identity.startMicroseconds
  }

  /// Whether `entry`, the kernel's entry now at this pid, shows that this
  /// process ended: there is none, or it is a process that started at another
  /// time. A process that exited keeps its entry until it is reaped, so it has
  /// not ended yet.
  func hasEnded(given entry: KernelProcessIdentity?) -> Bool {
    guard let entry else { return true }
    return entry.startSeconds != startSeconds || entry.startMicroseconds != startMicroseconds
  }
}

/// A quarantine that waits only for its owner: the stop deadline passed before
/// the bound owner attested Stopped. `commit` is the quarantine's own journal
/// record, from which a restart would rebuild the Authority, and `lease` is the
/// lease that record names.
struct AuthorityOwnerQuarantine: Sendable {
  let owner: AuthorityOwnerProcess
  let commit: AuthorityJournalCommit
  let lease: AuthorityRecoveredLease
  /// Whether a failed read of the process table was reported already.
  var reportedUnreadableProcessTable = false

  /// Nil unless the record names the lease `owner` bound, as the record of a
  /// stop's quarantine does.
  init?(owner: AuthorityOwnerProcess, commit: AuthorityJournalCommit) {
    guard commit.state.leaseID == owner.leaseID,
      let lease = AuthorityRecoveredLease(record: commit.state)
    else { return nil }
    self.owner = owner
    self.commit = commit
    self.lease = lease
  }
}

/// The lease the Authority recovered in memory once its owner ended.
struct AuthorityRecoveredLease: Equatable, Sendable {
  let mode: AuthorityMode
  let ownerUID: UInt32

  /// The lease `record` names, or nil for a record without one.
  init?(record: AuthorityCommittedState) {
    guard let mode = record.mode, let ownerUID = record.ownerUID else { return nil }
    self.mode = mode
    self.ownerUID = ownerUID
  }
}

/// One durable journal record and the head the journal returned for it.
struct AuthorityJournalCommit: Equatable, Sendable {
  let state: AuthorityCommittedState
  let head: AuthorityJournalHead
}
