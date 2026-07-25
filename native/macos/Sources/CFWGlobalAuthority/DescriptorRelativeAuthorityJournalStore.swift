import Darwin
import Foundation

public enum AuthorityJournalFaultPoint: Equatable, Sendable {
  case recordSynchronized
  case temporaryHeadSynchronized
  case headRenamed
}

public enum AuthorityJournalStorageError: Error, Equatable, Sendable {
  case invalidStorePath
  case appGroupStoreForbidden
  case systemCall(operation: String, code: Int32)
  case insecureDirectory
  case insecureFile(String)
  case storeLocked
  case recoveryRequired(AuthorityJournalValidationError)
  case nonMonotonicCommit
}

/// Root-context storage for the Authority replay journal. Every journal, head,
/// temporary-head, and lock operation is relative to a verified directory file
/// descriptor and uses O_NOFOLLOW. The lifetime flock provides one-process CAS
/// serialization in addition to the in-process mutex.
public final class DescriptorRelativeAuthorityJournalStore: @unchecked Sendable {
  public static let productionRootPath =
    "/Library/Application Support/com.bill.clashformac/GlobalAuthority"

  private static let journalName = "authority.journal"
  private static let headName = "authority.head"
  private static let temporaryHeadName = ".authority.head.tmp"
  private static let lockName = ".authority.lock"

  private let directoryFD: Int32
  private let processLockFD: Int32
  private let expectedOwnerUID: uid_t
  private let mutex = NSLock()
  private let faultInjector: ((AuthorityJournalFaultPoint) throws -> Void)?

  public convenience init() throws {
    try self.init(
      rootPath: Self.productionRootPath,
      expectedOwnerUID: 0,
      faultInjector: nil
    )
  }

  convenience init(
    testingRootPath rootPath: String,
    expectedOwnerUID: uid_t,
    faultInjector: ((AuthorityJournalFaultPoint) throws -> Void)? = nil
  ) throws {
    try self.init(
      rootPath: rootPath,
      expectedOwnerUID: expectedOwnerUID,
      faultInjector: faultInjector
    )
  }

  private init(
    rootPath: String,
    expectedOwnerUID: uid_t,
    faultInjector: ((AuthorityJournalFaultPoint) throws -> Void)?
  ) throws {
    let directoryFD = try Self.openVerifiedDirectory(
      rootPath, expectedOwnerUID: expectedOwnerUID)
    do {
      let lockFD = try Self.openRegularFile(
        relativeTo: directoryFD,
        name: Self.lockName,
        flags: O_RDWR | O_CREAT,
        mode: 0o600,
        expectedOwnerUID: expectedOwnerUID
      )
      guard flock(lockFD, LOCK_EX | LOCK_NB) == 0 else {
        let code = errno
        close(lockFD)
        if code == EWOULDBLOCK { throw AuthorityJournalStorageError.storeLocked }
        throw AuthorityJournalStorageError.systemCall(operation: "flock", code: code)
      }
      self.directoryFD = directoryFD
      processLockFD = lockFD
      self.expectedOwnerUID = expectedOwnerUID
      self.faultInjector = faultInjector
    } catch {
      close(directoryFD)
      throw error
    }
  }

  deinit {
    _ = flock(processLockFD, LOCK_UN)
    close(processLockFD)
    close(directoryFD)
  }

  public func recover(
    minimumHead: AuthorityJournalHead? = nil
  ) -> AuthorityJournalRecovery {
    mutex.lock()
    defer { mutex.unlock() }
    do {
      return AuthorityJournalRecoveryReducer.recover(
        try loadImage(), minimumHead: minimumHead)
    } catch let error as AuthorityJournalValidationError {
      return AuthorityJournalRecovery(
        committedState: nil, head: nil,
        posture: .quarantined(error))
    } catch {
      return AuthorityJournalRecovery(
        committedState: nil, head: nil,
        posture: .quarantined(.malformedFrame))
    }
  }

  @discardableResult
  public func appendCommitted(_ state: AuthorityCommittedState) throws
    -> AuthorityJournalHead
  {
    mutex.lock()
    defer { mutex.unlock() }

    let recovery = AuthorityJournalRecoveryReducer.recover(try loadImage())
    guard case .recovering = recovery.posture else {
      if case .quarantined(let reason) = recovery.posture {
        throw AuthorityJournalStorageError.recoveryRequired(reason)
      }
      throw AuthorityJournalStorageError.recoveryRequired(.invalidState)
    }
    try validateCommit(state, after: recovery.committedState)

    let sequence = (recovery.head?.sequence ?? 0) + 1
    let previous = recovery.head?.recordSHA256 ?? AuthorityJournalCodec.zeroDigest
    let encoded = try AuthorityJournalCodec.encodeRecord(
      state: state, sequence: sequence, previousSHA256: previous)
    let oldLength = recovery.head?.committedLength ?? 0
    guard oldLength <= UInt64(AuthorityJournalLimits.maximumJournalBytes),
      UInt64(encoded.frame.count) <= UInt64(AuthorityJournalLimits.maximumJournalBytes) - oldLength
    else { throw AuthorityJournalStorageError.recoveryRequired(.journalTooLarge) }

    let journalFD = try Self.openRegularFile(
      relativeTo: directoryFD,
      name: Self.journalName,
      flags: O_WRONLY | O_APPEND | O_CREAT,
      mode: 0o600,
      expectedOwnerUID: expectedOwnerUID
    )
    defer { close(journalFD) }
    var status = stat()
    guard fstat(journalFD, &status) == 0 else {
      throw Self.systemError("fstat journal")
    }
    guard UInt64(status.st_size) == oldLength else {
      throw AuthorityJournalStorageError.recoveryRequired(.trailingData)
    }
    try Self.writeAll(encoded.frame, to: journalFD)
    guard fsync(journalFD) == 0 else { throw Self.systemError("fsync journal") }
    try faultInjector?(.recordSynchronized)

    let head = try AuthorityJournalHead(
      sequence: sequence,
      committedLength: oldLength + UInt64(encoded.frame.count),
      recordSHA256: encoded.digest
    )
    try replaceHead(with: AuthorityJournalCodec.encodeHead(head))
    return head
  }

  private func validateCommit(
    _ next: AuthorityCommittedState,
    after prior: AuthorityCommittedState?
  ) throws {
    guard let prior else {
      guard next.revision > 0 else {
        throw AuthorityJournalStorageError.nonMonotonicCommit
      }
      return
    }
    guard next.installationID == prior.installationID,
      next.revision == prior.revision + 1,
      (next.epoch, next.generation) >= (prior.epoch, prior.generation)
    else { throw AuthorityJournalStorageError.nonMonotonicCommit }
  }

  private func replaceHead(with data: Data) throws {
    let temporaryFD = try Self.openRegularFile(
      relativeTo: directoryFD,
      name: Self.temporaryHeadName,
      flags: O_WRONLY | O_CREAT | O_EXCL,
      mode: 0o600,
      expectedOwnerUID: expectedOwnerUID
    )
    var renamed = false
    defer {
      close(temporaryFD)
      if !renamed {
        _ = unlinkat(directoryFD, Self.temporaryHeadName, 0)
      }
    }
    try Self.writeAll(data, to: temporaryFD)
    guard fsync(temporaryFD) == 0 else { throw Self.systemError("fsync temporary head") }
    try faultInjector?(.temporaryHeadSynchronized)
    guard
      renameat(
        directoryFD, Self.temporaryHeadName,
        directoryFD, Self.headName
      ) == 0
    else { throw Self.systemError("rename head") }
    renamed = true
    try faultInjector?(.headRenamed)
    guard fsync(directoryFD) == 0 else { throw Self.systemError("fsync directory") }
  }

  private func loadImage() throws -> AuthorityJournalImage {
    let journal = try readOptional(
      Self.journalName, maximumBytes: AuthorityJournalLimits.maximumJournalBytes)
    let head = try readOptional(
      Self.headName, maximumBytes: AuthorityJournalLimits.maximumHeadBytes)
    return AuthorityJournalImage(
      journal: journal,
      head: head,
      hasTemporaryHead: try entryExists(Self.temporaryHeadName)
    )
  }

  private func readOptional(_ name: String, maximumBytes: Int) throws -> Data? {
    let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    if fd < 0 {
      if errno == ENOENT { return nil }
      throw Self.systemError("open \(name)")
    }
    defer { close(fd) }
    try Self.verifyRegularFile(fd, name: name, expectedOwnerUID: expectedOwnerUID)
    var status = stat()
    guard fstat(fd, &status) == 0 else { throw Self.systemError("fstat \(name)") }
    guard status.st_size >= 0, status.st_size <= maximumBytes else {
      throw AuthorityJournalValidationError.journalTooLarge
    }
    let expectedCount = Int(status.st_size)
    var result = Data(count: expectedCount)
    var total = 0
    while total < expectedCount {
      let remaining = expectedCount - total
      let count = result.withUnsafeMutableBytes { buffer -> Int in
        guard let base = buffer.baseAddress else { return 0 }
        return Darwin.pread(fd, base.advanced(by: total), remaining, off_t(total))
      }
      if count < 0 {
        if errno == EINTR { continue }
        throw Self.systemError("read \(name)")
      }
      if count == 0 { throw AuthorityJournalValidationError.truncated }
      total += count
    }
    return result
  }

  private func entryExists(_ name: String) throws -> Bool {
    var status = stat()
    if fstatat(directoryFD, name, &status, AT_SYMLINK_NOFOLLOW) == 0 { return true }
    if errno == ENOENT { return false }
    throw Self.systemError("fstatat \(name)")
  }

  private static func openVerifiedDirectory(
    _ path: String, expectedOwnerUID: uid_t
  ) throws -> Int32 {
    guard path.hasPrefix("/"), path != "/" else {
      throw AuthorityJournalStorageError.invalidStorePath
    }
    let components = path.split(separator: "/").map(String.init)
    guard !components.contains("Group Containers"),
      !components.contains(where: { $0.hasPrefix("group.") })
    else { throw AuthorityJournalStorageError.appGroupStoreForbidden }

    var current = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard current >= 0 else { throw systemError("open root") }
    do {
      for component in components {
        guard component != ".", component != "..", !component.isEmpty else {
          throw AuthorityJournalStorageError.invalidStorePath
        }
        let next = openat(
          current, component,
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard next >= 0 else { throw systemError("open directory component") }
        close(current)
        current = next
      }
      var status = stat()
      guard fstat(current, &status) == 0 else { throw systemError("fstat directory") }
      guard (status.st_mode & S_IFMT) == S_IFDIR,
        status.st_uid == expectedOwnerUID,
        (status.st_mode & 0o777) == 0o700
      else { throw AuthorityJournalStorageError.insecureDirectory }
      return current
    } catch {
      close(current)
      throw error
    }
  }

  private static func openRegularFile(
    relativeTo directoryFD: Int32,
    name: String,
    flags: Int32,
    mode: mode_t,
    expectedOwnerUID: uid_t
  ) throws -> Int32 {
    let fd = openat(
      directoryFD, name,
      flags | O_NOFOLLOW | O_CLOEXEC,
      mode
    )
    guard fd >= 0 else { throw systemError("openat \(name)") }
    do {
      try verifyRegularFile(fd, name: name, expectedOwnerUID: expectedOwnerUID)
      return fd
    } catch {
      close(fd)
      throw error
    }
  }

  private static func verifyRegularFile(
    _ fd: Int32, name: String, expectedOwnerUID: uid_t
  ) throws {
    var status = stat()
    guard fstat(fd, &status) == 0 else { throw systemError("fstat \(name)") }
    guard (status.st_mode & S_IFMT) == S_IFREG,
      status.st_uid == expectedOwnerUID,
      (status.st_mode & 0o777) == 0o600,
      status.st_nlink == 1
    else { throw AuthorityJournalStorageError.insecureFile(name) }
  }

  private static func writeAll(_ data: Data, to fd: Int32) throws {
    var total = 0
    while total < data.count {
      let count = data.withUnsafeBytes { buffer -> Int in
        guard let base = buffer.baseAddress else { return 0 }
        return Darwin.write(fd, base.advanced(by: total), data.count - total)
      }
      if count < 0 {
        if errno == EINTR { continue }
        throw systemError("write")
      }
      guard count > 0 else { throw systemError("short write") }
      total += count
    }
  }

  private static func systemError(_ operation: String) -> AuthorityJournalStorageError {
    .systemCall(operation: operation, code: errno)
  }
}
