import CFWSharedProtocol
import Darwin
import Foundation

public enum AuthorityJournalFaultPoint: Equatable, Sendable {
  case beforeStoreLeafCreation
  case anchorPendingSynchronized
  case recordSynchronized
  case temporaryHeadSynchronized
  case headRenamed
  case anchorCommittedSynchronized
  case generationCleanupStarted
  case generationEntryUnlinked
  case generationCleanupDirectorySynchronized
}

public enum AuthorityJournalStorageError: Error, Equatable, Sendable {
  case invalidStorePath
  case appGroupStoreForbidden
  case systemCall(operation: String, code: Int32)
  case insecureDirectory
  case insecureFile(String)
  case storeLocked
  case capacityExhausted
  case anchorUnavailable
  case generationCleanupFailed(operation: String, code: Int32)
  case recoveryRequired(AuthorityJournalValidationError)
  case nonMonotonicCommit
}

/// Root-context storage for the Authority replay journal. Every journal, head,
/// temporary-head, and lock operation is relative to a verified directory file
/// descriptor and uses O_NOFOLLOW. The lifetime flock provides one-process CAS
/// serialization in addition to the in-process mutex.
public final class DescriptorRelativeAuthorityJournalStore: @unchecked Sendable {
  /// A dedicated system-owned leaf directly below the root-owned Application
  /// Support directory. It deliberately does not reuse the per-user product
  /// directory, and the daemon never imports state from that retired path.
  public static let productionRootPath =
    "/Library/Application Support/com.bill.clashformac.global-authority"

  private static let legacyJournalName = "authority.journal"
  private static let legacyHeadName = "authority.head"
  private static let legacyTemporaryHeadName = ".authority.head.tmp"
  private static let storeMarkerName = ".authority.v2-store"
  private static let lockName = ".authority.lock"

  private struct GenerationEntry: Equatable {
    let name: String
    let generation: UInt64
  }

  private let directoryFD: Int32
  private let processLockFD: Int32
  private let expectedOwnerUID: uid_t
  private let anchorStore: any AuthorityJournalAnchorStoring
  private let recordCapacity: UInt64
  private let mutex = NSLock()
  private let faultInjector: ((AuthorityJournalFaultPoint) throws -> Void)?

  public convenience init() throws {
    try self.init(
      rootPath: Self.productionRootPath,
      expectedOwnerUID: 0,
      allowedAncestorOwnerUIDs: [0],
      anchorStore: SystemKeychainAuthorityJournalAnchorStore(),
      recordCapacity: UInt64(AuthorityJournalLimits.maximumRecords),
      faultInjector: nil
    )
  }

  convenience init(
    testingRootPath rootPath: String,
    expectedOwnerUID: uid_t,
    allowedAncestorOwnerUIDs: Set<uid_t>? = nil,
    anchorStore: (any AuthorityJournalAnchorStoring)? = nil,
    recordCapacity: UInt64 = UInt64(AuthorityJournalLimits.maximumRecords),
    faultInjector: ((AuthorityJournalFaultPoint) throws -> Void)? = nil
  ) throws {
    try self.init(
      rootPath: rootPath,
      expectedOwnerUID: expectedOwnerUID,
      allowedAncestorOwnerUIDs: allowedAncestorOwnerUIDs ?? [0, expectedOwnerUID],
      anchorStore: anchorStore ?? InMemoryAuthorityJournalAnchorStore(),
      recordCapacity: recordCapacity,
      faultInjector: faultInjector
    )
  }

  private init(
    rootPath: String,
    expectedOwnerUID: uid_t,
    allowedAncestorOwnerUIDs: Set<uid_t>,
    anchorStore: any AuthorityJournalAnchorStoring,
    recordCapacity: UInt64,
    faultInjector: ((AuthorityJournalFaultPoint) throws -> Void)?
  ) throws {
    guard
      recordCapacity
        > UInt64(AuthorityJournalLimits.minimumLifecycleFinishRecords + 1),
      recordCapacity <= UInt64(AuthorityJournalLimits.maximumRecords)
    else { throw AuthorityJournalStorageError.capacityExhausted }
    let directoryFD = try Self.openVerifiedDirectory(
      rootPath,
      expectedOwnerUID: expectedOwnerUID,
      allowedAncestorOwnerUIDs: allowedAncestorOwnerUIDs,
      faultInjector: faultInjector)
    do {
      let lockFD = try Self.openOrCreateRegularFile(
        relativeTo: directoryFD,
        name: Self.lockName,
        flags: O_RDWR,
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
      self.anchorStore = anchorStore
      self.recordCapacity = recordCapacity
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

  public func recover() -> AuthorityJournalRecovery {
    mutex.lock()
    defer { mutex.unlock() }
    do {
      return try recoverLocked()
    } catch AuthorityJournalAnchorError.unavailable {
      return AuthorityJournalRecovery(
        committedState: nil, head: nil,
        posture: .recovering(.restoreAnchorAccess))
    } catch let error as AuthorityJournalValidationError {
      return Self.quarantine(error)
    } catch AuthorityJournalAnchorError.invalidData,
      AuthorityJournalAnchorError.compareAndSwapFailed
    {
      return Self.quarantine(.anchorMismatch)
    } catch AuthorityJournalStorageError.generationCleanupFailed(_, _) {
      return Self.quarantine(.generationCleanupFailed)
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

    var recovery: AuthorityJournalRecovery
    do {
      recovery = try recoverLocked()
    } catch AuthorityJournalAnchorError.unavailable {
      throw AuthorityJournalStorageError.anchorUnavailable
    }
    guard case .recovering = recovery.posture else {
      if case .quarantined(let reason) = recovery.posture {
        throw AuthorityJournalStorageError.recoveryRequired(reason)
      }
      throw AuthorityJournalStorageError.recoveryRequired(.invalidState)
    }
    try validateCommit(state, after: recovery.committedState)

    var anchor = try ensureAnchorForAppend(recovery: recovery)
    try ensureStoreMarker(anchor.storeID)
    if let committedState = recovery.committedState,
      try shouldCompact(beforeAppending: state, recovery: recovery)
    {
      anchor = try compact(
        committedState: committedState, anchor: anchor)
      recovery = try recoveryForCommittedAnchor(anchor)
    }
    return try append(
      state, recovery: recovery, anchor: anchor,
      generation: anchor.committed?.generation ?? 1)
  }

  private func validateCommit(
    _ next: AuthorityCommittedState,
    after prior: AuthorityCommittedState?
  ) throws {
    guard let prior else {
      guard next.transition == .enrollOff, next.revision > 0 else {
        throw AuthorityJournalStorageError.nonMonotonicCommit
      }
      return
    }
    guard next.installationID == prior.installationID,
      next.revision == prior.revision + 1,
      (next.epoch, next.generation) >= (prior.epoch, prior.generation)
    else { throw AuthorityJournalStorageError.nonMonotonicCommit }
  }

  private func replaceHead(with data: Data, generation: UInt64) throws {
    let temporaryHeadName = Self.temporaryHeadName(generation)
    let headName = Self.headName(generation)
    let temporaryFD = try Self.openRegularFile(
      relativeTo: directoryFD,
      name: temporaryHeadName,
      flags: O_WRONLY | O_CREAT | O_EXCL,
      mode: 0o600,
      expectedOwnerUID: expectedOwnerUID
    )
    var renamed = false
    defer {
      close(temporaryFD)
      if !renamed {
        _ = unlinkat(directoryFD, temporaryHeadName, 0)
      }
    }
    try Self.writeAll(data, to: temporaryFD)
    guard fsync(temporaryFD) == 0 else { throw Self.systemError("fsync temporary head") }
    try faultInjector?(.temporaryHeadSynchronized)
    guard
      renameat(
        directoryFD, temporaryHeadName,
        directoryFD, headName
      ) == 0
    else { throw Self.systemError("rename head") }
    renamed = true
    try faultInjector?(.headRenamed)
    guard fsync(directoryFD) == 0 else { throw Self.systemError("fsync directory") }
  }

  private func loadImage(generation: UInt64) throws -> AuthorityJournalImage {
    let journal = try readOptional(
      Self.journalName(generation),
      maximumBytes: AuthorityJournalLimits.maximumJournalBytes)
    let head = try readOptional(
      Self.headName(generation), maximumBytes: AuthorityJournalLimits.maximumHeadBytes)
    return AuthorityJournalImage(
      journal: journal,
      head: head,
      hasTemporaryHead: try entryExists(Self.temporaryHeadName(generation))
    )
  }

  private static func journalName(_ generation: UInt64) -> String {
    String(format: "authority.v2.%020llu.journal", generation)
  }

  private static func headName(_ generation: UInt64) -> String {
    String(format: "authority.v2.%020llu.head", generation)
  }

  private static func temporaryHeadName(_ generation: UInt64) -> String {
    ".\(headName(generation)).tmp"
  }

  private func scanGenerationEntries() throws -> [GenerationEntry] {
    // dup(2) would share the directory stream offset with directoryFD. Open a
    // new description relative to the already authenticated directory so every
    // validation pass deterministically starts at the beginning.
    let streamFD = openat(
      directoryFD, ".",
      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    )
    guard streamFD >= 0 else {
      throw Self.systemError("open authority store directory stream")
    }
    guard let directory = fdopendir(streamFD) else {
      let code = errno
      close(streamFD)
      throw AuthorityJournalStorageError.systemCall(
        operation: "open authority store directory stream", code: code)
    }
    defer { _ = closedir(directory) }

    var result: [GenerationEntry] = []
    while true {
      errno = 0
      guard let rawEntry = readdir(directory) else {
        let code = errno
        guard code == 0 else {
          throw AuthorityJournalStorageError.systemCall(
            operation: "read authority store directory", code: code)
        }
        return result
      }
      let name = withUnsafePointer(to: &rawEntry.pointee.d_name) { pointer in
        pointer.withMemoryRebound(
          to: CChar.self,
          capacity: MemoryLayout.size(ofValue: rawEntry.pointee.d_name)
        ) { String(cString: $0) }
      }
      if let entry = try Self.generationEntry(named: name) {
        result.append(entry)
      }
    }
  }

  private static func generationEntry(named name: String) throws -> GenerationEntry? {
    let prefix: String
    let suffix: String
    let canonicalName: (UInt64) -> String

    if name.hasPrefix("authority.v2.") {
      prefix = "authority.v2."
      if name.hasSuffix(".journal") {
        suffix = ".journal"
        canonicalName = journalName
      } else if name.hasSuffix(".head") {
        suffix = ".head"
        canonicalName = headName
      } else {
        throw AuthorityJournalValidationError.invalidGenerationEntry
      }
    } else if name.hasPrefix(".authority.v2.") {
      prefix = ".authority.v2."
      guard name.hasSuffix(".head.tmp") else {
        throw AuthorityJournalValidationError.invalidGenerationEntry
      }
      suffix = ".head.tmp"
      canonicalName = temporaryHeadName
    } else {
      return nil
    }

    let digits = name.dropFirst(prefix.count).dropLast(suffix.count)
    guard digits.utf8.count == 20,
      digits.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
      let generation = UInt64(digits), generation > 0,
      canonicalName(generation) == name
    else { throw AuthorityJournalValidationError.invalidGenerationEntry }
    return GenerationEntry(name: name, generation: generation)
  }

  private func enforceGenerationRetention(activeGeneration: UInt64) throws {
    let entries: [GenerationEntry]
    do {
      entries = try scanGenerationEntries()
    } catch let error as AuthorityJournalValidationError {
      throw error
    } catch AuthorityJournalStorageError.systemCall(let operation, let code) {
      throw AuthorityJournalStorageError.generationCleanupFailed(
        operation: operation, code: code)
    }

    if entries.contains(where: { $0.generation > activeGeneration }) {
      throw AuthorityJournalValidationError.rollback
    }

    let obsoleteEntries: [GenerationEntry]
    if activeGeneration > 1 {
      let previousGeneration = activeGeneration - 1
      obsoleteEntries =
        entries
        .filter { $0.generation < previousGeneration }
        .sorted { $0.name < $1.name }
    } else {
      obsoleteEntries = []
    }

    for entry in obsoleteEntries {
      try verifyGenerationEntryForRemoval(entry)
    }

    if !obsoleteEntries.isEmpty {
      try faultInjector?(.generationCleanupStarted)
      for entry in obsoleteEntries {
        guard unlinkat(directoryFD, entry.name, 0) == 0 else {
          throw AuthorityJournalStorageError.generationCleanupFailed(
            operation: "unlink obsolete generation \(entry.name)", code: errno)
        }
        try faultInjector?(.generationEntryUnlinked)
      }
    }

    guard fsync(directoryFD) == 0 else {
      throw AuthorityJournalStorageError.generationCleanupFailed(
        operation: "synchronize generation cleanup directory", code: errno)
    }
    if !obsoleteEntries.isEmpty {
      try faultInjector?(.generationCleanupDirectorySynchronized)
    }
  }

  private func verifyGenerationEntryForRemoval(_ entry: GenerationEntry) throws {
    var directoryStatus = stat()
    guard
      fstatat(
        directoryFD, entry.name, &directoryStatus,
        AT_SYMLINK_NOFOLLOW) == 0
    else {
      throw AuthorityJournalStorageError.generationCleanupFailed(
        operation: "inspect obsolete generation entry \(entry.name)", code: errno)
    }
    guard (directoryStatus.st_mode & S_IFMT) == S_IFREG,
      directoryStatus.st_uid == expectedOwnerUID,
      (directoryStatus.st_mode & 0o7777) == 0o600,
      directoryStatus.st_nlink == 1
    else { throw AuthorityJournalValidationError.invalidGenerationEntry }

    let fd = openat(
      directoryFD, entry.name,
      O_RDONLY | O_NOFOLLOW | O_CLOEXEC
    )
    guard fd >= 0 else {
      throw AuthorityJournalStorageError.generationCleanupFailed(
        operation: "open obsolete generation \(entry.name)", code: errno)
    }
    defer { close(fd) }

    var status = stat()
    guard fstat(fd, &status) == 0 else {
      throw AuthorityJournalStorageError.generationCleanupFailed(
        operation: "inspect obsolete generation \(entry.name)", code: errno)
    }
    guard (status.st_mode & S_IFMT) == S_IFREG,
      status.st_uid == expectedOwnerUID,
      (status.st_mode & 0o7777) == 0o600,
      status.st_nlink == 1,
      status.st_dev == directoryStatus.st_dev,
      status.st_ino == directoryStatus.st_ino
    else { throw AuthorityJournalValidationError.invalidGenerationEntry }
  }

  private static func quarantine(
    _ reason: AuthorityJournalValidationError
  ) -> AuthorityJournalRecovery {
    AuthorityJournalRecovery(
      committedState: nil, head: nil, posture: .quarantined(reason))
  }

  private func recoverLocked() throws -> AuthorityJournalRecovery {
    if try entryExists(Self.legacyJournalName)
      || entryExists(Self.legacyHeadName)
      || entryExists(Self.legacyTemporaryHeadName)
    {
      throw AuthorityJournalValidationError.legacyStateRequiresMigration
    }

    let generationEntries = try scanGenerationEntries()
    let markerExists = try entryExists(Self.storeMarkerName)
    guard var anchor = try anchorStore.load() else {
      if markerExists { throw AuthorityJournalValidationError.anchorMissing }
      if !generationEntries.isEmpty {
        throw AuthorityJournalValidationError.orphanedGenerationState
      }
      return AuthorityJournalRecovery(
        committedState: nil, head: nil, posture: .recovering(.verifyOff))
    }

    if anchor.pending != nil {
      anchor = try reconcilePending(anchor)
    }
    guard anchor.committed != nil else {
      if markerExists { try verifyStoreMarker(anchor.storeID) }
      if !(try scanGenerationEntries()).isEmpty {
        throw AuthorityJournalValidationError.orphanedGenerationState
      }
      return AuthorityJournalRecovery(
        committedState: nil, head: nil, posture: .recovering(.verifyOff))
    }
    guard markerExists else {
      throw AuthorityJournalValidationError.anchorMissing
    }
    try verifyStoreMarker(anchor.storeID)
    let recovery = try recoveryForCommittedAnchor(anchor)
    guard let generation = anchor.committed?.generation else {
      throw AuthorityJournalValidationError.anchorMismatch
    }
    try enforceGenerationRetention(activeGeneration: generation)
    return recovery
  }

  private func recoveryForCommittedAnchor(
    _ anchor: AuthorityJournalAnchor
  ) throws -> AuthorityJournalRecovery {
    guard let committed = anchor.committed else {
      throw AuthorityJournalValidationError.anchorMismatch
    }
    let image = try loadImage(generation: committed.generation)
    let recovery = AuthorityJournalRecoveryReducer.recover(image)
    guard case .recovering = recovery.posture,
      let head = recovery.head,
      let state = recovery.committedState,
      Self.matches(head, committed),
      state.revision == committed.stateRevision
    else {
      if case .quarantined(let reason) = recovery.posture { throw reason }
      throw AuthorityJournalValidationError.anchorMismatch
    }
    return recovery
  }

  private func reconcilePending(
    _ anchor: AuthorityJournalAnchor
  ) throws -> AuthorityJournalAnchor {
    guard let pending = anchor.pending else { return anchor }
    var image = try loadImage(generation: pending.generation)

    if image.hasTemporaryHead {
      let temporaryData = try readOptional(
        Self.temporaryHeadName(pending.generation),
        maximumBytes: AuthorityJournalLimits.maximumHeadBytes)
      guard let temporaryData,
        let journal = image.journal,
        Self.matches(try AuthorityJournalCodec.decodeHead(temporaryData), pending)
      else { throw AuthorityJournalValidationError.interruptedHeadReplacement }
      _ = try validatePendingJournal(journal, cursor: pending)
      guard
        renameat(
          directoryFD, Self.temporaryHeadName(pending.generation),
          directoryFD, Self.headName(pending.generation)) == 0
      else { throw Self.systemError("finish pending head rename") }
      guard fsync(directoryFD) == 0 else {
        throw Self.systemError("fsync recovered pending head")
      }
      image = try loadImage(generation: pending.generation)
    }

    if image.journal == nil, image.head == nil {
      return try clearPending(anchor)
    }
    if let journal = image.journal, journal.isEmpty, image.head == nil {
      try removeEmptyPendingJournal(generation: pending.generation)
      return try clearPending(anchor)
    }

    guard let journal = image.journal else {
      throw AuthorityJournalValidationError.anchorMismatch
    }
    if let headData = image.head {
      let diskHead = try AuthorityJournalCodec.decodeHead(headData)
      if Self.matches(diskHead, pending) {
        _ = try validatePendingJournal(journal, cursor: pending)
        return try promotePending(anchor)
      }
      if let committed = anchor.committed,
        committed.generation == pending.generation,
        Self.matches(diskHead, committed)
      {
        if UInt64(journal.count) == committed.committedLength {
          return try clearPending(anchor)
        }
        guard UInt64(journal.count) == pending.committedLength else {
          throw AuthorityJournalValidationError.anchorMismatch
        }
        _ = try validatePendingJournal(journal, cursor: pending)
        try replaceHead(
          with: AuthorityJournalCodec.encodeHead(try head(from: pending)),
          generation: pending.generation)
        return try promotePending(anchor)
      }
      throw AuthorityJournalValidationError.anchorMismatch
    }

    guard UInt64(journal.count) == pending.committedLength else {
      throw AuthorityJournalValidationError.anchorMismatch
    }
    _ = try validatePendingJournal(journal, cursor: pending)
    try replaceHead(
      with: AuthorityJournalCodec.encodeHead(try head(from: pending)),
      generation: pending.generation)
    return try promotePending(anchor)
  }

  private func validatePendingJournal(
    _ journal: Data, cursor: AuthorityJournalAnchorCursor
  ) throws -> AuthorityJournalRecovery {
    let expectedHead = try head(from: cursor)
    let recovery = AuthorityJournalRecoveryReducer.recover(
      AuthorityJournalImage(
        journal: journal,
        head: try AuthorityJournalCodec.encodeHead(expectedHead)))
    guard case .recovering = recovery.posture,
      recovery.committedState?.revision == cursor.stateRevision,
      recovery.head == expectedHead
    else {
      if case .quarantined(let reason) = recovery.posture { throw reason }
      throw AuthorityJournalValidationError.anchorMismatch
    }
    return recovery
  }

  private func clearPending(
    _ anchor: AuthorityJournalAnchor
  ) throws -> AuthorityJournalAnchor {
    let replacement = try AuthorityJournalAnchor(
      storeID: anchor.storeID, committed: anchor.committed, pending: nil)
    try anchorStore.compareAndSwap(expected: anchor, replacement: replacement)
    return replacement
  }

  private func promotePending(
    _ anchor: AuthorityJournalAnchor
  ) throws -> AuthorityJournalAnchor {
    guard let pending = anchor.pending else {
      throw AuthorityJournalValidationError.anchorMismatch
    }
    let replacement = try AuthorityJournalAnchor(
      storeID: anchor.storeID, committed: pending, pending: nil)
    try anchorStore.compareAndSwap(expected: anchor, replacement: replacement)
    return replacement
  }

  private func ensureAnchorForAppend(
    recovery: AuthorityJournalRecovery
  ) throws -> AuthorityJournalAnchor {
    if let anchor = try anchorStore.load() {
      guard anchor.pending == nil else {
        throw AuthorityJournalValidationError.anchorMismatch
      }
      if recovery.committedState == nil {
        guard anchor.committed == nil else {
          throw AuthorityJournalValidationError.anchorMismatch
        }
      } else {
        guard anchor.committed != nil else {
          throw AuthorityJournalValidationError.anchorMismatch
        }
      }
      return anchor
    }
    guard recovery.committedState == nil,
      !(try entryExists(Self.storeMarkerName))
    else { throw AuthorityJournalValidationError.anchorMissing }
    let created = try AuthorityJournalAnchor(
      storeID: AuthorityIdentifier(UUID()), committed: nil, pending: nil)
    try anchorStore.compareAndSwap(expected: nil, replacement: created)
    return created
  }

  private func shouldCompact(
    beforeAppending state: AuthorityCommittedState,
    recovery: AuthorityJournalRecovery
  ) throws -> Bool {
    guard let head = recovery.head else { return false }
    if head.sequence >= recordCapacity { return true }
    let isPrepare = state.transition == .prepare
    let reserve = UInt64(AuthorityJournalLimits.minimumLifecycleFinishRecords)
    if isPrepare, head.sequence >= recordCapacity - reserve { return true }

    let encoded = try AuthorityJournalCodec.encodeRecord(
      state: state, sequence: head.sequence + 1,
      previousSHA256: head.recordSHA256)
    let nextLength = head.committedLength + UInt64(encoded.frame.count)
    if nextLength > UInt64(AuthorityJournalLimits.maximumJournalBytes) { return true }
    let maximumFrameBytes = UInt64(
      AuthorityJournalCodec.headerBytes
        + AuthorityJournalLimits.maximumRecordPayloadBytes)
    if isPrepare {
      let reservedBytes = reserve * maximumFrameBytes
      return UInt64(AuthorityJournalLimits.maximumJournalBytes) - nextLength
        < reservedBytes
    }
    return false
  }

  private func compact(
    committedState: AuthorityCommittedState,
    anchor: AuthorityJournalAnchor
  ) throws -> AuthorityJournalAnchor {
    guard let committed = anchor.committed, committed.generation < UInt64.max,
      committedState.transition != .enrollOff
    else { throw AuthorityJournalStorageError.capacityExhausted }
    let checkpoint = try AuthorityCommittedState(
      installationID: committedState.installationID,
      epoch: committedState.epoch,
      generation: committedState.generation,
      revision: committedState.revision,
      transition: .checkpoint,
      state: committedState.state,
      operationID: committedState.operationID,
      mode: committedState.mode,
      configSHA256: committedState.configSHA256,
      leaseID: committedState.leaseID,
      ownerUID: committedState.ownerUID)
    _ = try append(
      checkpoint,
      recovery: AuthorityJournalRecovery(
        committedState: nil, head: nil, posture: .recovering(.verifyOff)),
      anchor: anchor,
      generation: committed.generation + 1)
    guard let replacement = try anchorStore.load(), replacement.pending == nil,
      replacement.committed?.generation == committed.generation + 1
    else { throw AuthorityJournalValidationError.anchorMismatch }
    try enforceGenerationRetention(activeGeneration: committed.generation + 1)
    return replacement
  }

  private func append(
    _ state: AuthorityCommittedState,
    recovery: AuthorityJournalRecovery,
    anchor: AuthorityJournalAnchor,
    generation: UInt64
  ) throws -> AuthorityJournalHead {
    let priorSequence = recovery.head?.sequence ?? 0
    guard priorSequence < recordCapacity else {
      throw AuthorityJournalStorageError.capacityExhausted
    }
    let sequence = priorSequence + 1
    let previous = recovery.head?.recordSHA256 ?? AuthorityJournalCodec.zeroDigest
    let encoded = try AuthorityJournalCodec.encodeRecord(
      state: state, sequence: sequence, previousSHA256: previous)
    let oldLength = recovery.head?.committedLength ?? 0
    guard oldLength <= UInt64(AuthorityJournalLimits.maximumJournalBytes),
      UInt64(encoded.frame.count)
        <= UInt64(AuthorityJournalLimits.maximumJournalBytes) - oldLength
    else { throw AuthorityJournalStorageError.capacityExhausted }

    let newHead = try AuthorityJournalHead(
      sequence: sequence,
      committedLength: oldLength + UInt64(encoded.frame.count),
      recordSHA256: encoded.digest)
    let pendingCursor = try AuthorityJournalAnchorCursor(
      generation: generation,
      sequence: newHead.sequence,
      committedLength: newHead.committedLength,
      recordSHA256: newHead.recordSHA256,
      stateRevision: state.revision)
    let pendingAnchor = try AuthorityJournalAnchor(
      storeID: anchor.storeID,
      committed: anchor.committed,
      pending: pendingCursor)
    try anchorStore.compareAndSwap(expected: anchor, replacement: pendingAnchor)
    try faultInjector?(.anchorPendingSynchronized)

    let flags: Int32 =
      oldLength == 0
      ? O_WRONLY | O_APPEND | O_CREAT | O_EXCL
      : O_WRONLY | O_APPEND
    let journalFD = try Self.openRegularFile(
      relativeTo: directoryFD,
      name: Self.journalName(generation),
      flags: flags,
      mode: 0o600,
      expectedOwnerUID: expectedOwnerUID)
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
    try replaceHead(
      with: AuthorityJournalCodec.encodeHead(newHead), generation: generation)

    let committedAnchor = try AuthorityJournalAnchor(
      storeID: pendingAnchor.storeID,
      committed: pendingCursor,
      pending: nil)
    try anchorStore.compareAndSwap(
      expected: pendingAnchor, replacement: committedAnchor)
    try faultInjector?(.anchorCommittedSynchronized)
    return newHead
  }

  private func ensureStoreMarker(_ storeID: AuthorityIdentifier) throws {
    if try entryExists(Self.storeMarkerName) {
      try verifyStoreMarker(storeID)
      return
    }
    let fd = try Self.openRegularFile(
      relativeTo: directoryFD,
      name: Self.storeMarkerName,
      flags: O_WRONLY | O_CREAT | O_EXCL,
      mode: 0o600,
      expectedOwnerUID: expectedOwnerUID)
    defer { close(fd) }
    try Self.writeAll(Self.markerData(storeID), to: fd)
    guard fsync(fd) == 0 else { throw Self.systemError("fsync store marker") }
    guard fsync(directoryFD) == 0 else {
      throw Self.systemError("fsync store marker directory")
    }
  }

  private func verifyStoreMarker(_ storeID: AuthorityIdentifier) throws {
    guard
      try readOptional(Self.storeMarkerName, maximumBytes: 64)
        == Self.markerData(storeID)
    else { throw AuthorityJournalValidationError.anchorMismatch }
  }

  private static func markerData(_ storeID: AuthorityIdentifier) -> Data {
    Data(storeID.rawValue.uuidString.lowercased().utf8)
  }

  private func removeEmptyPendingJournal(generation: UInt64) throws {
    let name = Self.journalName(generation)
    guard unlinkat(directoryFD, name, 0) == 0 else {
      throw Self.systemError("remove empty pending journal")
    }
    guard fsync(directoryFD) == 0 else {
      throw Self.systemError("fsync pending journal removal")
    }
  }

  private func head(
    from cursor: AuthorityJournalAnchorCursor
  ) throws -> AuthorityJournalHead {
    try AuthorityJournalHead(
      sequence: cursor.sequence,
      committedLength: cursor.committedLength,
      recordSHA256: cursor.recordSHA256)
  }

  private static func matches(
    _ head: AuthorityJournalHead,
    _ cursor: AuthorityJournalAnchorCursor
  ) -> Bool {
    head.sequence == cursor.sequence
      && head.committedLength == cursor.committedLength
      && head.recordSHA256 == cursor.recordSHA256
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
    _ path: String,
    expectedOwnerUID: uid_t,
    allowedAncestorOwnerUIDs: Set<uid_t>,
    faultInjector: ((AuthorityJournalFaultPoint) throws -> Void)?
  ) throws -> Int32 {
    guard path.hasPrefix("/"), path != "/" else {
      throw AuthorityJournalStorageError.invalidStorePath
    }
    let components = path.split(separator: "/").map(String.init)
    guard !components.contains("Group Containers"),
      !components.contains(where: { $0.hasPrefix("group.") })
    else { throw AuthorityJournalStorageError.appGroupStoreForbidden }

    // Walk from the filesystem root without resolving a path twice. Every
    // existing ancestor is authenticated before the next component is opened;
    // only the final leaf may be created, and an EEXIST race is re-opened and
    // verified rather than repaired in place.
    var current = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard current >= 0 else { throw systemError("open root") }
    do {
      try verifyAncestorDirectory(
        current,
        component: "/",
        allowedOwnerUIDs: allowedAncestorOwnerUIDs)
      for (index, component) in components.enumerated() {
        guard component != ".", component != "..", !component.isEmpty else {
          throw AuthorityJournalStorageError.invalidStorePath
        }
        let isLeaf = index == components.index(before: components.endIndex)
        var next = openat(
          current, component,
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        if next < 0, isLeaf, errno == ENOENT {
          try faultInjector?(.beforeStoreLeafCreation)
          let mkdirResult = mkdirat(current, component, 0o700)
          let mkdirCode = errno
          let created = mkdirResult == 0
          guard created || mkdirCode == EEXIST else {
            throw AuthorityJournalStorageError.systemCall(
              operation: "mkdirat authority store", code: mkdirCode)
          }

          next = openat(
            current, component,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
          )
          guard next >= 0 else {
            throw systemError("open created authority store")
          }
          do {
            if created {
              try verifyCreatedDirectoryIdentity(
                next,
                expectedOwnerUID: expectedOwnerUID)
              guard fchmod(next, 0o700) == 0 else {
                throw systemError("fchmod created authority store")
              }
            }
            try verifyLeafDirectory(next, expectedOwnerUID: expectedOwnerUID)
            guard fsync(next) == 0 else {
              throw systemError("fsync authority store")
            }
            guard fsync(current) == 0 else {
              throw systemError("fsync authority store parent")
            }
          } catch {
            close(next)
            throw error
          }
        } else {
          guard next >= 0 else {
            throw systemError("open directory component \(component)")
          }
          do {
            if isLeaf {
              try verifyLeafDirectory(next, expectedOwnerUID: expectedOwnerUID)
            } else {
              try verifyAncestorDirectory(
                next,
                component: component,
                allowedOwnerUIDs: allowedAncestorOwnerUIDs)
            }
          } catch {
            close(next)
            throw error
          }
        }
        close(current)
        current = next
      }
      return current
    } catch {
      close(current)
      throw error
    }
  }

  private static func verifyAncestorDirectory(
    _ fd: Int32,
    component: String,
    allowedOwnerUIDs: Set<uid_t>
  ) throws {
    var status = stat()
    guard fstat(fd, &status) == 0 else {
      throw systemError("fstat ancestor directory \(component)")
    }
    guard (status.st_mode & S_IFMT) == S_IFDIR,
      allowedOwnerUIDs.contains(status.st_uid),
      (status.st_mode & 0o022) == 0
    else { throw AuthorityJournalStorageError.insecureDirectory }
  }

  private static func verifyCreatedDirectoryIdentity(
    _ fd: Int32,
    expectedOwnerUID: uid_t
  ) throws {
    var status = stat()
    guard fstat(fd, &status) == 0 else {
      throw systemError("fstat created authority store")
    }
    guard (status.st_mode & S_IFMT) == S_IFDIR,
      status.st_uid == expectedOwnerUID
    else { throw AuthorityJournalStorageError.insecureDirectory }
  }

  private static func verifyLeafDirectory(
    _ fd: Int32,
    expectedOwnerUID: uid_t
  ) throws {
    var status = stat()
    guard fstat(fd, &status) == 0 else {
      throw systemError("fstat authority store")
    }
    guard (status.st_mode & S_IFMT) == S_IFDIR,
      status.st_uid == expectedOwnerUID,
      (status.st_mode & 0o7777) == 0o700
    else { throw AuthorityJournalStorageError.insecureDirectory }
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

  private static func openOrCreateRegularFile(
    relativeTo directoryFD: Int32,
    name: String,
    flags: Int32,
    mode: mode_t,
    expectedOwnerUID: uid_t
  ) throws -> Int32 {
    // Elect the creator explicitly instead of racing two non-exclusive
    // O_CREAT calls. O_EXCL gives the losing opener the stable EEXIST branch
    // required to reopen and authenticate the single canonical lock-file
    // inode.
    let fd = openat(
      directoryFD, name,
      flags | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
      mode
    )
    if fd >= 0 {
      do {
        try verifyRegularFile(fd, name: name, expectedOwnerUID: expectedOwnerUID)
        return fd
      } catch {
        close(fd)
        throw error
      }
    }

    let createCode = errno
    guard createCode == EEXIST else {
      throw AuthorityJournalStorageError.systemCall(
        operation: "openat exclusive create \(name)", code: createCode)
    }
    return try openRegularFile(
      relativeTo: directoryFD,
      name: name,
      flags: flags,
      mode: mode,
      expectedOwnerUID: expectedOwnerUID
    )
  }

  private static func verifyRegularFile(
    _ fd: Int32, name: String, expectedOwnerUID: uid_t
  ) throws {
    var status = stat()
    guard fstat(fd, &status) == 0 else { throw systemError("fstat \(name)") }
    guard (status.st_mode & S_IFMT) == S_IFREG,
      status.st_uid == expectedOwnerUID,
      (status.st_mode & 0o7777) == 0o600,
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
