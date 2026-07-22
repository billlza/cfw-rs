import Darwin
import Foundation

public enum AppGroupFileSecurityError: Error, Equatable, Sendable {
  case invalidRelativeName(String)
  case invalidDirectoryType
  case invalidDirectoryOwner(expected: uid_t, actual: uid_t)
  case invalidDirectoryPermissions(actual: mode_t)
  case invalidFileType
  case invalidFileOwner(expected: uid_t, actual: uid_t)
  case invalidFilePermissions(actual: mode_t)
  case hardLinkedFile
  case io(operation: String, code: Int32)
}

extension AppGroupFileSecurityError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .invalidRelativeName(let name):
      return "App Group file name is not a fixed relative identifier: \(name)"
    case .invalidDirectoryType:
      return "App Group state directory is not a directory."
    case .invalidDirectoryOwner(let expected, let actual):
      return "App Group state directory owner is \(actual); expected \(expected)."
    case .invalidDirectoryPermissions(let actual):
      return "App Group state directory mode is \(actual); expected 0700."
    case .invalidFileType:
      return "App Group state file is not a regular file."
    case .invalidFileOwner(let expected, let actual):
      return "App Group state file owner is \(actual); expected \(expected)."
    case .invalidFilePermissions(let actual):
      return "App Group state file mode is \(actual); expected 0600."
    case .hardLinkedFile:
      return "App Group state file has multiple hard links."
    case .io(let operation, let code):
      return "App Group state operation \(operation) failed with errno \(code)."
    }
  }
}

public enum SecureAppGroupFileSystem {
  private static let permissionMask = mode_t(0o7777)
  private static let directoryMode = mode_t(0o700)
  private static let fileMode = mode_t(0o600)

  public static func createAndOpenPrivateDirectory(
    at url: URL,
    expectedOwner: uid_t = geteuid()
  ) throws -> Int32 {
    if mkdir(url.path, directoryMode) != 0, errno != EEXIST {
      throw AppGroupFileSecurityError.io(operation: "create-directory", code: errno)
    }
    return try openPrivateDirectory(at: url, expectedOwner: expectedOwner)
  }

  public static func openPrivateDirectory(
    at url: URL,
    expectedOwner: uid_t = geteuid()
  ) throws -> Int32 {
    let directoryFD = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard directoryFD >= 0 else {
      throw AppGroupFileSecurityError.io(operation: "open-directory", code: errno)
    }
    do {
      try validateAndSecureDirectory(directoryFD, expectedOwner: expectedOwner)
      return directoryFD
    } catch {
      Darwin.close(directoryFD)
      throw error
    }
  }

  public static func createAndOpenPrivateSubdirectory(
    in parentDirectoryFD: Int32,
    named name: String,
    expectedOwner: uid_t = geteuid()
  ) throws -> Int32 {
    try validateRelativeName(name)
    if mkdirat(parentDirectoryFD, name, directoryMode) != 0, errno != EEXIST {
      throw AppGroupFileSecurityError.io(operation: "create-subdirectory", code: errno)
    }
    let directoryFD = openat(
      parentDirectoryFD,
      name,
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    )
    guard directoryFD >= 0 else {
      throw AppGroupFileSecurityError.io(operation: "open-subdirectory", code: errno)
    }
    do {
      try validateAndSecureDirectory(directoryFD, expectedOwner: expectedOwner)
      return directoryFD
    } catch {
      Darwin.close(directoryFD)
      throw error
    }
  }

  public static func openPrivateRegularFile(
    in directoryFD: Int32,
    named name: String,
    flags: Int32,
    expectedOwner: uid_t = geteuid()
  ) throws -> Int32 {
    try validateRelativeName(name)
    let fileFD = openat(directoryFD, name, flags | O_CLOEXEC | O_NOFOLLOW)
    guard fileFD >= 0 else {
      throw AppGroupFileSecurityError.io(operation: "open-file", code: errno)
    }
    do {
      try validatePrivateRegularFile(fileFD, expectedOwner: expectedOwner)
      return fileFD
    } catch {
      Darwin.close(fileFD)
      throw error
    }
  }

  public static func createPrivateRegularFile(
    in directoryFD: Int32,
    named name: String,
    flags: Int32,
    expectedOwner: uid_t = geteuid()
  ) throws -> Int32 {
    try validateRelativeName(name)
    let fileFD = openat(
      directoryFD,
      name,
      flags | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
      fileMode
    )
    guard fileFD >= 0 else {
      throw AppGroupFileSecurityError.io(operation: "create-file", code: errno)
    }
    do {
      guard fchmod(fileFD, fileMode) == 0 else {
        throw AppGroupFileSecurityError.io(operation: "secure-created-file", code: errno)
      }
      try validatePrivateRegularFile(fileFD, expectedOwner: expectedOwner)
      return fileFD
    } catch {
      Darwin.close(fileFD)
      throw error
    }
  }

  public static func openOrCreatePrivateRegularFile(
    in directoryFD: Int32,
    named name: String,
    flags: Int32,
    expectedOwner: uid_t = geteuid()
  ) throws -> Int32 {
    do {
      return try createPrivateRegularFile(
        in: directoryFD,
        named: name,
        flags: flags,
        expectedOwner: expectedOwner
      )
    } catch let error as AppGroupFileSecurityError {
      guard case .io(let operation, let code) = error,
        operation == "create-file",
        code == EEXIST
      else {
        throw error
      }
      return try openPrivateRegularFile(
        in: directoryFD,
        named: name,
        flags: flags,
        expectedOwner: expectedOwner
      )
    }
  }

  public static func validateAndSecureDirectory(
    _ directoryFD: Int32,
    expectedOwner: uid_t = geteuid()
  ) throws {
    var metadata = stat()
    guard fstat(directoryFD, &metadata) == 0 else {
      throw AppGroupFileSecurityError.io(operation: "stat-directory", code: errno)
    }
    guard metadata.st_mode & S_IFMT == S_IFDIR else {
      throw AppGroupFileSecurityError.invalidDirectoryType
    }
    guard metadata.st_uid == expectedOwner else {
      throw AppGroupFileSecurityError.invalidDirectoryOwner(
        expected: expectedOwner,
        actual: metadata.st_uid
      )
    }
    if metadata.st_mode & permissionMask != directoryMode {
      guard fchmod(directoryFD, directoryMode) == 0 else {
        throw AppGroupFileSecurityError.io(operation: "secure-directory", code: errno)
      }
      guard fstat(directoryFD, &metadata) == 0 else {
        throw AppGroupFileSecurityError.io(operation: "restat-directory", code: errno)
      }
    }
    guard metadata.st_mode & S_IFMT == S_IFDIR else {
      throw AppGroupFileSecurityError.invalidDirectoryType
    }
    guard metadata.st_uid == expectedOwner else {
      throw AppGroupFileSecurityError.invalidDirectoryOwner(
        expected: expectedOwner,
        actual: metadata.st_uid
      )
    }
    let actualMode = metadata.st_mode & permissionMask
    guard actualMode == directoryMode else {
      throw AppGroupFileSecurityError.invalidDirectoryPermissions(actual: actualMode)
    }
  }

  public static func validatePrivateRegularFile(
    _ fileFD: Int32,
    expectedOwner: uid_t = geteuid()
  ) throws {
    var metadata = stat()
    guard fstat(fileFD, &metadata) == 0 else {
      throw AppGroupFileSecurityError.io(operation: "stat-file", code: errno)
    }
    guard metadata.st_mode & S_IFMT == S_IFREG else {
      throw AppGroupFileSecurityError.invalidFileType
    }
    guard metadata.st_uid == expectedOwner else {
      throw AppGroupFileSecurityError.invalidFileOwner(
        expected: expectedOwner,
        actual: metadata.st_uid
      )
    }
    let actualMode = metadata.st_mode & permissionMask
    guard actualMode == fileMode else {
      throw AppGroupFileSecurityError.invalidFilePermissions(actual: actualMode)
    }
    guard metadata.st_nlink == 1 else {
      throw AppGroupFileSecurityError.hardLinkedFile
    }
  }

  private static func validateRelativeName(_ name: String) throws {
    guard !name.isEmpty, name != ".", name != "..", !name.contains("/") else {
      throw AppGroupFileSecurityError.invalidRelativeName(name)
    }
  }
}
