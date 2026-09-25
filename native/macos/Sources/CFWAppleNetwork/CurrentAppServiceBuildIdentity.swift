import CFWSharedProtocol
import Darwin
import Foundation
@preconcurrency import Security

public struct CurrentAppServiceCodeIdentity: Equatable, Sendable {
  public let build: Int64
  public let cdHash: Data

  public init(build: Int64, cdHash: Data) throws {
    guard build > 0 else {
      throw CurrentAppServiceBuildError.identityUnavailable
    }
    self.build = build
    self.cdHash = try ServiceCodeHash(cdHash).bytes
  }
}

public struct CurrentAppServiceBuildObservation: Equatable, Sendable {
  public let registration: CurrentAppServiceStatus
  /// Nil is permitted only after a complete, stable process inventory proves absence.
  public let runningCode: CurrentAppServiceCodeIdentity?
  public let expectedCode: CurrentAppServiceCodeIdentity

  public init(
    registration: CurrentAppServiceStatus,
    runningCode: CurrentAppServiceCodeIdentity?,
    expectedCode: CurrentAppServiceCodeIdentity
  ) {
    self.registration = registration
    self.runningCode = runningCode
    self.expectedCode = expectedCode
  }

  public var isCurrent: Bool {
    registration == .enabled && runningCode == expectedCode
  }

  public func requireNonConflictingVersion() throws {
    guard let runningCode, runningCode != expectedCode else { return }
    guard runningCode.build < expectedCode.build else {
      // Equal-build re-signs and downgrades are not an automatic service upgrade.
      throw CurrentAppServiceBuildError.conflictingVersion
    }
  }
}

public struct CurrentAppServiceBuildInspection: Equatable, Sendable {
  public let proxy: CurrentAppServiceBuildObservation
  public let authority: CurrentAppServiceBuildObservation

  public init(
    proxy: CurrentAppServiceBuildObservation, authority: CurrentAppServiceBuildObservation
  ) {
    self.proxy = proxy
    self.authority = authority
  }

  public var isCurrent: Bool { proxy.isCurrent && authority.isCurrent }
}

public enum CurrentAppServiceBuildError: Error, Equatable, Sendable {
  case identityUnavailable
  case conflictingVersion
}

public protocol CurrentAppServiceBuildObserving: Sendable {
  func inspect() throws -> CurrentAppServiceBuildInspection
}

/// Build observations never authorize an XPC message. Normal service operations
/// separately bind the expected code requirement to the connection's audit token.
/// The immutable target is verified once against the running Host and its sealed
/// embedded components. Each inspection makes fresh kernel/signature observations.
public struct CurrentAppServiceBuildObserver: CurrentAppServiceBuildObserving {
  private let expectedProxy: CurrentAppServiceCodeIdentity
  private let expectedAuthority: CurrentAppServiceCodeIdentity
  private let services: any CurrentAppServiceMaintaining

  public init(services: any CurrentAppServiceMaintaining = CurrentAppServiceMaintainer()) throws {
    let hostRequirement = try Self.requirement(identifier: "com.bill.clashformac")
    var host: SecCode?
    guard SecCodeCopySelf([], &host) == errSecSuccess, let host,
      SecCodeCheckValidity(host, Self.validationFlags, hostRequirement) == errSecSuccess
    else { throw CurrentAppServiceBuildError.identityUnavailable }
    let hostIdentity = try Self.runningIdentity(host)
    let bundle = Bundle.main.bundleURL.standardizedFileURL
    guard bundle.isFileURL, bundle == bundle.resolvingSymlinksInPath() else {
      throw CurrentAppServiceBuildError.identityUnavailable
    }
    expectedProxy = try Self.staticIdentity(
      bundle.appendingPathComponent("Contents/Library/LoginItems/CFWProxyAgent.app"),
      identifier: "com.bill.clashformac.proxy-agent")
    expectedAuthority = try Self.staticIdentity(
      bundle.appendingPathComponent("Contents/Library/HelperTools/CFWGlobalAuthority"),
      identifier: "com.bill.clashformac.global-authority")
    guard expectedProxy.build == hostIdentity.build, expectedAuthority.build == hostIdentity.build
    else {
      throw CurrentAppServiceBuildError.conflictingVersion
    }
    self.services = services
  }

  public func currentCodeHash(for service: CurrentAppService) throws -> ServiceCodeHash {
    try ServiceCodeHash((service == .proxyAgent ? expectedProxy : expectedAuthority).cdHash)
  }

  public func inspect() throws -> CurrentAppServiceBuildInspection {
    let before = (services.status(of: .proxyAgent), services.status(of: .globalAuthority))
    let first = try Self.processInventory()
    let proxy = try Self.observe(.proxyAgent, candidates: first)
    let authority = try Self.observe(.globalAuthority, candidates: first)
    guard first == (try Self.processInventory()),
      before.0 == services.status(of: .proxyAgent),
      before.1 == services.status(of: .globalAuthority)
    else { throw CurrentAppServiceBuildError.identityUnavailable }
    return CurrentAppServiceBuildInspection(
      proxy: .init(registration: before.0, runningCode: proxy, expectedCode: expectedProxy),
      authority: .init(
        registration: before.1, runningCode: authority, expectedCode: expectedAuthority))
  }

  private struct Process: Equatable {
    let pid: pid_t
    let path: String
    let kernel: Installed40019KernelProcessIdentity
  }

  private static func processInventory() throws -> [Process] {
    let requested = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
    let capacity = Int(requested) + 4096
    guard requested > 0, capacity <= 1 << 20 else {
      throw CurrentAppServiceBuildError.identityUnavailable
    }
    var pids = [pid_t](repeating: 0, count: capacity / MemoryLayout<pid_t>.stride)
    let returned = pids.withUnsafeMutableBytes {
      proc_listpids(UInt32(PROC_ALL_PIDS), 0, $0.baseAddress, Int32($0.count))
    }
    guard
      CurrentAppServiceRuntimeObserver.isCompleteProcessInventory(
        returnedBytes: returned, capacityBytes: pids.count * MemoryLayout<pid_t>.stride)
    else { throw CurrentAppServiceBuildError.identityUnavailable }
    var results: [Process] = []
    for pid in pids.prefix(Int(returned) / MemoryLayout<pid_t>.stride) where pid > 0 {
      var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
      let count = buffer.withUnsafeMutableBytes {
        proc_pidpath(pid, $0.baseAddress, UInt32($0.count))
      }
      guard count > 0, count < buffer.count else {
        let named = buffer.withUnsafeMutableBytes {
          proc_name(pid, $0.baseAddress, UInt32($0.count))
        }
        if named > 0, named < buffer.count,
          let name = String(
            bytes: buffer.prefix(Int(named)).map(UInt8.init(bitPattern:)), encoding: .utf8),
          ["CFWProxyAgent", "CFWGlobalAuthority"].contains(name)
        {
          let kernel = try Installed40019ServiceProcessObserver.kernelProcessIdentity(pid)
          if try belongsToServiceScope(name: name, kernel: kernel, invokingUID: geteuid()) {
            throw CurrentAppServiceBuildError.identityUnavailable
          }
        }
        continue
      }
      guard
        let path = String(
          bytes: buffer.prefix(Int(count)).map(UInt8.init(bitPattern:)), encoding: .utf8)
      else {
        throw CurrentAppServiceBuildError.identityUnavailable
      }
      guard
        ["CFWProxyAgent", "CFWGlobalAuthority"].contains(
          URL(fileURLWithPath: path).lastPathComponent)
      else { continue }
      // Reuse the existing read-only kernel PID/start/UID reader, not its legacy authorization policy.
      let kernel = try Installed40019ServiceProcessObserver.kernelProcessIdentity(pid)
      if try belongsToServiceScope(
        name: URL(fileURLWithPath: path).lastPathComponent, kernel: kernel, invokingUID: geteuid())
      {
        results.append(Process(pid: pid, path: path, kernel: kernel))
      }
    }
    return results.sorted { $0.pid < $1.pid }
  }

  /// Each logged-in user may have a ProxyAgent. Kernel UID filtering only
  /// selects the processes to observe; it never substitutes for XPC identity.
  static func belongsToServiceScope(
    name: String, kernel: Installed40019KernelProcessIdentity, invokingUID: uid_t
  ) throws -> Bool {
    let expectedUID: uid_t = name == "CFWProxyAgent" ? invokingUID : 0
    guard kernel.realUserIdentifier == expectedUID || kernel.effectiveUserIdentifier == expectedUID
    else { return false }
    guard kernel.realUserIdentifier == expectedUID, kernel.effectiveUserIdentifier == expectedUID
    else { throw CurrentAppServiceBuildError.identityUnavailable }
    return true
  }

  private static func observe(_ service: CurrentAppService, candidates: [Process]) throws
    -> CurrentAppServiceCodeIdentity?
  {
    let name = service == .proxyAgent ? "CFWProxyAgent" : "CFWGlobalAuthority"
    let matches = candidates.filter { URL(fileURLWithPath: $0.path).lastPathComponent == name }
    guard matches.count <= 1 else { throw CurrentAppServiceBuildError.identityUnavailable }
    guard let process = matches.first else { return nil }
    let uid = service == .proxyAgent ? geteuid() : 0
    guard process.kernel.realUserIdentifier == uid, process.kernel.effectiveUserIdentifier == uid
    else {
      throw CurrentAppServiceBuildError.identityUnavailable
    }
    let attributes = [kSecGuestAttributePid: NSNumber(value: process.pid)] as CFDictionary
    var code: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code,
      SecCodeCheckValidity(code, validationFlags, try requirement(identifier: identifier(service)))
        == errSecSuccess
    else { throw CurrentAppServiceBuildError.identityUnavailable }
    return try runningIdentity(code)
  }

  private static let validationFlags: SecCSFlags = [
    .noNetworkAccess, SecCSFlags(rawValue: kSecCSStrictValidate),
  ]

  private static func identifier(_ service: CurrentAppService) -> String {
    service == .proxyAgent
      ? "com.bill.clashformac.proxy-agent" : "com.bill.clashformac.global-authority"
  }

  private static func requirement(identifier: String) throws -> SecRequirement {
    let text = try CodeIdentityRequirement(
      expectedTeamIdentifier: GlobalAuthorityConnectionContract.teamIdentifier,
      expectedBundleIdentifier: identifier
    ).requirementText
    var value: SecRequirement?
    guard SecRequirementCreateWithString(text as CFString, [], &value) == errSecSuccess, let value
    else {
      throw CurrentAppServiceBuildError.identityUnavailable
    }
    return value
  }

  private static func runningIdentity(_ code: SecCode) throws -> CurrentAppServiceCodeIdentity {
    var value: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &value) == errSecSuccess, let value else {
      throw CurrentAppServiceBuildError.identityUnavailable
    }
    return try signingIdentity(value)
  }

  private static func staticIdentity(_ url: URL, identifier: String) throws
    -> CurrentAppServiceCodeIdentity
  {
    var value: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &value) == errSecSuccess, let value,
      SecStaticCodeCheckValidity(value, validationFlags, try requirement(identifier: identifier))
        == errSecSuccess
    else { throw CurrentAppServiceBuildError.identityUnavailable }
    return try signingIdentity(value)
  }

  private static func signingIdentity(_ code: SecStaticCode) throws -> CurrentAppServiceCodeIdentity
  {
    var information: CFDictionary?
    guard
      SecCodeCopySigningInformation(
        code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
      let values = information as? [CFString: Any],
      let plist = values[kSecCodeInfoPList] as? [String: Any],
      let text = plist["CFBundleVersion"] as? String,
      !text.isEmpty, text.utf8.count <= 19, text.utf8.first != 48,
      text.utf8.allSatisfy({ (48...57).contains($0) }), let build = Int64(text),
      let hash = values[kSecCodeInfoUnique] as? Data
    else { throw CurrentAppServiceBuildError.identityUnavailable }
    return try .init(build: build, cdHash: hash)
  }
}
