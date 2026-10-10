import CryptoKit
import Darwin
import Foundation
@preconcurrency import Security

package enum Installed40019Service: Equatable, Sendable {
  case proxyAgent
  case globalAuthority
}

package struct Installed40019ServiceProcessIdentity: Equatable, Sendable {
  package let service: Installed40019Service
  package let processIdentifier: pid_t
  package let userIdentifier: uid_t
  package let startSeconds: UInt64
  package let startMicroseconds: UInt64
  package let xpcCodeSigningRequirement: String
}

struct Installed40019KernelProcessIdentity: Equatable, Sendable {
  let processIdentifier: pid_t
  let effectiveUserIdentifier: uid_t
  let realUserIdentifier: uid_t
  let startSeconds: UInt64
  let startMicroseconds: UInt64
}

private enum Installed40019ServiceIdentityError: Error, Equatable, Sendable {
  case rejected
}

private struct Installed40019ServiceIdentityContract: Sendable {
  let service: Installed40019Service
  let processName: String
  let executablePath: String
  let staticCodePath: String
  let infoPlistPath: String
  let metadataBundleIdentifier: String
  let signingIdentifier: String
  let binarySHA256: String
  let cdHash: String
  let processUserIdentifier: uid_t
  let fileOwnerIdentifier: uid_t

  static func fixed(
    _ service: Installed40019Service,
    invokingUserIdentifier: uid_t
  ) -> Installed40019ServiceIdentityContract {
    switch service {
    case .proxyAgent:
      let appPath =
        "/Applications/Clash for Mac.app/Contents/Library/LoginItems/CFWProxyAgent.app"
      return Installed40019ServiceIdentityContract(
        service: service,
        processName: "CFWProxyAgent",
        executablePath: appPath + "/Contents/MacOS/CFWProxyAgent",
        staticCodePath: appPath,
        infoPlistPath: appPath + "/Contents/Info.plist",
        metadataBundleIdentifier: "com.bill.clashformac.proxy-agent",
        signingIdentifier: "com.bill.clashformac.proxy-agent",
        binarySHA256:
          "7bedf926913bab036f0a0566bc6a0ffd60fda0b89e71ff1bd8ff3a735415e046",
        cdHash: "0b5d6a714fc9599f2ddd808e2d7c1ba222f5aeac",
        processUserIdentifier: invokingUserIdentifier,
        fileOwnerIdentifier: invokingUserIdentifier
      )
    case .globalAuthority:
      let appPath = "/Applications/Clash for Mac.app"
      return Installed40019ServiceIdentityContract(
        service: service,
        processName: "CFWGlobalAuthority",
        executablePath: appPath + "/Contents/Library/HelperTools/CFWGlobalAuthority",
        staticCodePath: appPath + "/Contents/Library/HelperTools/CFWGlobalAuthority",
        infoPlistPath: appPath + "/Contents/Info.plist",
        metadataBundleIdentifier: "com.bill.clashformac",
        signingIdentifier: "com.bill.clashformac.global-authority",
        binarySHA256:
          "6e193862eef69dc8afb33cb60bec2cecfa97e519d827dcb0eb34d824a9ff3421",
        cdHash: "aa1c4ff3a4a36a4a479719071116fad3a24f17e3",
        processUserIdentifier: 0,
        fileOwnerIdentifier: invokingUserIdentifier
      )
    }
  }

  var designatedRequirement: String {
    "anchor apple generic and identifier \"\(signingIdentifier)\" "
      + "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
      + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
      + "and certificate leaf[subject.OU] = \"YKUPL7Z869\" "
      + "and cdhash H\"\(cdHash)\""
  }
}

/// Installed-only identity proof for the two sealed 40019 services.
///
/// The observer never registers, launches, signals, or sends to the service.
/// A complete process inventory must contain exactly one matching process, and
/// the PID/start tuple, UID, fixed path, bundle metadata, running signature,
/// on-disk signature, executable SHA-256, and CDHash must all agree.
package struct Installed40019ServiceProcessObserver: Sendable {
  private static let maximumProcessInventoryBytes = 1 << 20
  private static let inventorySlackBytes = 4096
  private static let maximumInfoPlistBytes = 1 << 20
  private static let maximumExecutableBytes: off_t = 512 * 1_024 * 1_024
  private static let hashBufferBytes = 64 * 1_024

  package init() {}

  static func codeSigningRequirement(
    for service: Installed40019Service,
    invokingUserIdentifier: uid_t = geteuid()
  ) -> String {
    Installed40019ServiceIdentityContract.fixed(
      service, invokingUserIdentifier: invokingUserIdentifier
    ).designatedRequirement
  }

  package func observe(
    _ service: Installed40019Service
  ) throws -> Installed40019ServiceProcessIdentity {
    let contract = Installed40019ServiceIdentityContract.fixed(
      service, invokingUserIdentifier: geteuid())
    try requireNoSymlinkComponents(contract.staticCodePath)
    try requireNoSymlinkComponents(contract.executablePath)
    try requireNoSymlinkComponents(contract.infoPlistPath)

    let processIdentifier = try uniqueProcessIdentifier(contract)
    let before = try processIdentity(processIdentifier, contract: contract)
    try validateBundleMetadata(contract)
    try validateExecutableHash(contract)
    let requirement = try signingRequirement(contract)
    try validateStaticCode(contract, requirement: requirement)
    try validateRunningCode(processIdentifier, contract: contract, requirement: requirement)
    let after = try processIdentity(processIdentifier, contract: contract)
    guard before == after else { throw Installed40019ServiceIdentityError.rejected }
    return after
  }

  private func uniqueProcessIdentifier(
    _ contract: Installed40019ServiceIdentityContract
  ) throws -> pid_t {
    let requestedBytes = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
    guard requestedBytes > 0 else { throw Installed40019ServiceIdentityError.rejected }
    let capacityBytes = Int(requestedBytes) + Self.inventorySlackBytes
    guard capacityBytes <= Self.maximumProcessInventoryBytes else {
      throw Installed40019ServiceIdentityError.rejected
    }
    let capacity = capacityBytes / MemoryLayout<pid_t>.stride
    var processIdentifiers = [pid_t](repeating: 0, count: capacity)
    let allocatedBytes = processIdentifiers.count * MemoryLayout<pid_t>.stride
    let returnedBytes = processIdentifiers.withUnsafeMutableBytes { buffer in
      proc_listpids(
        UInt32(PROC_ALL_PIDS), 0, buffer.baseAddress, Int32(allocatedBytes))
    }
    guard returnedBytes > 0, Int(returnedBytes) < allocatedBytes,
      Int(returnedBytes) % MemoryLayout<pid_t>.stride == 0
    else { throw Installed40019ServiceIdentityError.rejected }

    var matches: [pid_t] = []
    for processIdentifier in processIdentifiers.prefix(
      Int(returnedBytes) / MemoryLayout<pid_t>.stride)
    where processIdentifier > 0 {
      if let path = processPath(processIdentifier) {
        if path == contract.executablePath {
          matches.append(processIdentifier)
        } else if URL(fileURLWithPath: path).lastPathComponent
          == contract.processName
        {
          throw Installed40019ServiceIdentityError.rejected
        }
      } else if processName(processIdentifier) == contract.processName,
        isLive(processIdentifier)
      {
        // An inaccessible same-named process prevents a complete inventory.
        throw Installed40019ServiceIdentityError.rejected
      }
    }
    guard matches.count == 1, let processIdentifier = matches.first else {
      throw Installed40019ServiceIdentityError.rejected
    }
    return processIdentifier
  }

  private func processIdentity(
    _ processIdentifier: pid_t,
    contract: Installed40019ServiceIdentityContract
  ) throws -> Installed40019ServiceProcessIdentity {
    let information = try Self.kernelProcessIdentity(processIdentifier)
    guard information.effectiveUserIdentifier == contract.processUserIdentifier,
      information.realUserIdentifier == contract.processUserIdentifier,
      processPath(processIdentifier) == contract.executablePath,
      isLive(processIdentifier)
    else { throw Installed40019ServiceIdentityError.rejected }
    return Installed40019ServiceProcessIdentity(
      service: contract.service,
      processIdentifier: processIdentifier,
      userIdentifier: contract.processUserIdentifier,
      startSeconds: information.startSeconds,
      startMicroseconds: information.startMicroseconds,
      xpcCodeSigningRequirement: contract.designatedRequirement
    )
  }

  static func kernelProcessIdentity(
    _ processIdentifier: pid_t
  ) throws -> Installed40019KernelProcessIdentity {
    var processInformation = kinfo_proc()
    var processInformationSize = MemoryLayout<kinfo_proc>.size
    var managementInformationBase: [Int32] = [
      CTL_KERN, KERN_PROC, KERN_PROC_PID, processIdentifier,
    ]
    let status = managementInformationBase.withUnsafeMutableBufferPointer { mib in
      withUnsafeMutablePointer(to: &processInformation) { information in
        sysctl(
          mib.baseAddress,
          u_int(mib.count),
          information,
          &processInformationSize,
          nil,
          0
        )
      }
    }
    guard status == 0, processInformationSize == MemoryLayout<kinfo_proc>.size else {
      throw Installed40019ServiceIdentityError.rejected
    }
    return try validatedKernelProcessIdentity(
      expectedProcessIdentifier: processIdentifier,
      observedProcessIdentifier: processInformation.kp_proc.p_pid,
      effectiveUserIdentifier: processInformation.kp_eproc.e_ucred.cr_uid,
      realUserIdentifier: processInformation.kp_eproc.e_pcred.p_ruid,
      startSeconds: processInformation.kp_proc.p_starttime.tv_sec,
      startMicroseconds: processInformation.kp_proc.p_starttime.tv_usec
    )
  }

  static func validatedKernelProcessIdentity(
    expectedProcessIdentifier: pid_t,
    observedProcessIdentifier: pid_t,
    effectiveUserIdentifier: uid_t,
    realUserIdentifier: uid_t,
    startSeconds: Int,
    startMicroseconds: Int32
  ) throws -> Installed40019KernelProcessIdentity {
    guard observedProcessIdentifier == expectedProcessIdentifier,
      startSeconds > 0,
      startMicroseconds >= 0,
      startMicroseconds < 1_000_000
    else { throw Installed40019ServiceIdentityError.rejected }
    return Installed40019KernelProcessIdentity(
      processIdentifier: observedProcessIdentifier,
      effectiveUserIdentifier: effectiveUserIdentifier,
      realUserIdentifier: realUserIdentifier,
      startSeconds: UInt64(startSeconds),
      startMicroseconds: UInt64(startMicroseconds)
    )
  }

  private func validateBundleMetadata(
    _ contract: Installed40019ServiceIdentityContract
  ) throws {
    let data = try readRegularFile(
      contract.infoPlistPath,
      maximumBytes: off_t(Self.maximumInfoPlistBytes),
      expectedUID: contract.fileOwnerIdentifier
    )
    guard
      let values = try PropertyListSerialization.propertyList(
        from: data, options: [], format: nil) as? [String: Any],
      values["CFBundleIdentifier"] as? String
        == contract.metadataBundleIdentifier,
      values["CFBundleVersion"] as? String == "40019"
    else { throw Installed40019ServiceIdentityError.rejected }
  }

  private func validateExecutableHash(
    _ contract: Installed40019ServiceIdentityContract
  ) throws {
    let path = contract.executablePath
    let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else { throw Installed40019ServiceIdentityError.rejected }
    defer { close(descriptor) }
    let before = try regularFileMetadata(
      descriptor: descriptor,
      path: path,
      maximumBytes: Self.maximumExecutableBytes,
      expectedUID: contract.fileOwnerIdentifier
    )
    var hasher = SHA256()
    var buffer = [UInt8](repeating: 0, count: Self.hashBufferBytes)
    while true {
      let count = buffer.withUnsafeMutableBytes { bytes in
        read(descriptor, bytes.baseAddress, bytes.count)
      }
      if count == 0 { break }
      if count < 0 {
        if errno == EINTR { continue }
        throw Installed40019ServiceIdentityError.rejected
      }
      hasher.update(data: Data(buffer.prefix(count)))
    }
    let after = try regularFileMetadata(
      descriptor: descriptor,
      path: path,
      maximumBytes: Self.maximumExecutableBytes,
      expectedUID: contract.fileOwnerIdentifier
    )
    guard before.st_dev == after.st_dev, before.st_ino == after.st_ino,
      before.st_size == after.st_size,
      hasher.finalize().map({ String(format: "%02x", $0) }).joined()
        == contract.binarySHA256
    else { throw Installed40019ServiceIdentityError.rejected }
  }

  private func validateStaticCode(
    _ contract: Installed40019ServiceIdentityContract,
    requirement: SecRequirement
  ) throws {
    var code: SecStaticCode?
    guard
      SecStaticCodeCreateWithPath(
        URL(fileURLWithPath: contract.staticCodePath) as CFURL,
        [],
        &code
      ) == errSecSuccess,
      let code,
      SecStaticCodeCheckValidity(
        code,
        SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures),
        requirement
      ) == errSecSuccess
    else { throw Installed40019ServiceIdentityError.rejected }
    try validateSigningInformation(code, contract: contract)
  }

  private func validateRunningCode(
    _ processIdentifier: pid_t,
    contract: Installed40019ServiceIdentityContract,
    requirement: SecRequirement
  ) throws {
    let attributes = [kSecGuestAttributePid: NSNumber(value: processIdentifier)] as CFDictionary
    var code: SecCode?
    guard
      SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
      let code,
      SecCodeCheckValidity(
        code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess
    else { throw Installed40019ServiceIdentityError.rejected }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
      throw Installed40019ServiceIdentityError.rejected
    }
    try validateSigningInformation(staticCode, contract: contract)
  }

  private func validateSigningInformation(
    _ code: SecStaticCode,
    contract: Installed40019ServiceIdentityContract
  ) throws {
    var information: CFDictionary?
    guard
      SecCodeCopySigningInformation(
        code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
      let values = information as? [CFString: Any],
      values[kSecCodeInfoTeamIdentifier] as? String
        == "YKUPL7Z869",
      values[kSecCodeInfoIdentifier] as? String
        == contract.signingIdentifier,
      let unique = values[kSecCodeInfoUnique] as? Data,
      unique.map({ String(format: "%02x", $0) }).joined() == contract.cdHash
    else { throw Installed40019ServiceIdentityError.rejected }
  }

  private func signingRequirement(
    _ contract: Installed40019ServiceIdentityContract
  ) throws -> SecRequirement {
    var requirement: SecRequirement?
    guard
      SecRequirementCreateWithString(
        contract.designatedRequirement as CFString,
        [],
        &requirement
      ) == errSecSuccess,
      let requirement
    else { throw Installed40019ServiceIdentityError.rejected }
    return requirement
  }

  private func readRegularFile(
    _ path: String,
    maximumBytes: off_t,
    expectedUID: uid_t
  ) throws -> Data {
    let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else { throw Installed40019ServiceIdentityError.rejected }
    defer { close(descriptor) }
    let metadata = try regularFileMetadata(
      descriptor: descriptor,
      path: path,
      maximumBytes: maximumBytes,
      expectedUID: expectedUID
    )
    var data = Data()
    data.reserveCapacity(Int(metadata.st_size))
    var buffer = [UInt8](repeating: 0, count: min(Self.hashBufferBytes, Int(metadata.st_size)))
    while true {
      let count = buffer.withUnsafeMutableBytes { bytes in
        read(descriptor, bytes.baseAddress, bytes.count)
      }
      if count == 0 { break }
      if count < 0 {
        if errno == EINTR { continue }
        throw Installed40019ServiceIdentityError.rejected
      }
      data.append(contentsOf: buffer.prefix(count))
      guard data.count <= maximumBytes else {
        throw Installed40019ServiceIdentityError.rejected
      }
    }
    let after = try regularFileMetadata(
      descriptor: descriptor,
      path: path,
      maximumBytes: maximumBytes,
      expectedUID: expectedUID
    )
    guard metadata.st_dev == after.st_dev, metadata.st_ino == after.st_ino,
      metadata.st_size == after.st_size, data.count == Int(metadata.st_size)
    else { throw Installed40019ServiceIdentityError.rejected }
    return data
  }

  private func regularFileMetadata(
    descriptor: Int32,
    path: String,
    maximumBytes: off_t,
    expectedUID: uid_t
  ) throws -> stat {
    var opened = stat()
    var visible = stat()
    guard fstat(descriptor, &opened) == 0, lstat(path, &visible) == 0,
      (opened.st_mode & S_IFMT) == S_IFREG,
      (visible.st_mode & S_IFMT) == S_IFREG,
      opened.st_uid == expectedUID,
      opened.st_nlink == 1,
      opened.st_size > 0,
      opened.st_size <= maximumBytes,
      opened.st_dev == visible.st_dev,
      opened.st_ino == visible.st_ino
    else { throw Installed40019ServiceIdentityError.rejected }
    return opened
  }

  private func requireNoSymlinkComponents(_ path: String) throws {
    guard path.hasPrefix("/") else { throw Installed40019ServiceIdentityError.rejected }
    var current = ""
    for component in path.split(separator: "/") {
      current += "/" + component
      var metadata = stat()
      guard lstat(current, &metadata) == 0, (metadata.st_mode & S_IFMT) != S_IFLNK else {
        throw Installed40019ServiceIdentityError.rejected
      }
    }
  }

  private func processPath(_ processIdentifier: pid_t) -> String? {
    var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    let length = buffer.withUnsafeMutableBytes { bytes in
      proc_pidpath(processIdentifier, bytes.baseAddress, UInt32(bytes.count))
    }
    guard length > 0, Int(length) < buffer.count else { return nil }
    return String(bytes: buffer.prefix(Int(length)).map(UInt8.init(bitPattern:)), encoding: .utf8)
  }

  private func processName(_ processIdentifier: pid_t) -> String? {
    var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    let length = buffer.withUnsafeMutableBytes { bytes in
      proc_name(processIdentifier, bytes.baseAddress, UInt32(bytes.count))
    }
    guard length > 0, Int(length) < buffer.count else { return nil }
    return String(bytes: buffer.prefix(Int(length)).map(UInt8.init(bitPattern:)), encoding: .utf8)
  }

  private func isLive(_ processIdentifier: pid_t) -> Bool {
    errno = 0
    return kill(processIdentifier, 0) == 0 || errno == EPERM
  }
}
