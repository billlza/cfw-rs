import CFWSharedProtocol
import Darwin
import Foundation

extension DescriptorRelativeAuthorityJournalStore {
  static func openVerifiedDirectory(
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

  static func verifyAncestorDirectory(
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

  static func verifyCreatedDirectoryIdentity(
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

  static func verifyLeafDirectory(
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

  static func openRegularFile(
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

  static func openOrCreateRegularFile(
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

  static func verifyRegularFile(
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

  static func writeAll(_ data: Data, to fd: Int32) throws {
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

  static func systemError(_ operation: String) -> AuthorityJournalStorageError {
    .systemCall(operation: operation, code: errno)
  }
}
