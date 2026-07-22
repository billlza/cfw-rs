import Darwin
import Foundation

public enum CrossProcessEngineLeaseError: Error, Equatable, Sendable {
  case alreadyHeld
  case invalidPort
  case socket(family: Int32, code: Int32)
  case configure(family: Int32, code: Int32)
  case bind(family: Int32, code: Int32)
  case inspectPort(code: Int32)
}

extension CrossProcessEngineLeaseError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .alreadyHeld:
      return "Another native engine process already holds the machine lease."
    case .invalidPort:
      return "The native engine lease port is invalid."
    case .socket(let family, let code):
      return
        "Creating the native engine lease socket for family \(family) failed with errno \(code)."
    case .configure(let family, let code):
      return
        "Configuring the native engine lease socket for family \(family) failed with errno \(code)."
    case .bind(let family, let code):
      return
        "Binding the native engine lease socket for family \(family) failed with errno \(code)."
    case .inspectPort(let code):
      return "Inspecting the native engine lease port failed with errno \(code)."
    }
  }
}

/// A crash-safe machine-wide exclusion lease shared by the user ProxyAgent and
/// the root-owned Packet Tunnel system extension.
///
/// App Group paths are not a valid cross-context lock on macOS: a system
/// extension can resolve the identifier into a different root-owned container.
/// Instead, both engine processes bind the same IPv4 and IPv6 loopback UDP
/// port without address reuse. The kernel closes both descriptors on process
/// death, so there is no stale ownership record to recover. A local process can
/// deliberately occupy the port and deny service, but cannot impersonate an
/// active engine, read configuration, or gain privilege through this lease.
public final class CrossProcessEngineLease: @unchecked Sendable {
  public let port: UInt16

  private let lock = NSLock()
  private var fileDescriptors: [Int32]

  fileprivate init(port: UInt16, fileDescriptors: [Int32]) {
    self.port = port
    self.fileDescriptors = fileDescriptors
  }

  deinit {
    release()
  }

  public func release() {
    let descriptors = lock.withLock { () -> [Int32] in
      let descriptors = fileDescriptors
      fileDescriptors.removeAll(keepingCapacity: false)
      return descriptors
    }
    for descriptor in descriptors {
      Darwin.close(descriptor)
    }
  }
}

public struct CrossProcessEngineLeaseStore: Sendable {
  /// Product-owned rendezvous port. It is never used for application traffic.
  public static let productionPort: UInt16 = 49_373

  private let requestedPort: UInt16

  public init() {
    requestedPort = Self.productionPort
  }

  /// Port zero asks the kernel for an ephemeral port and is intended only for
  /// isolated tests. The chosen port is exposed by the returned lease so a
  /// second store can test contention against the exact same endpoint.
  init(testingPort: UInt16) {
    requestedPort = testingPort
  }

  public func acquire() throws -> CrossProcessEngineLease {
    var descriptors: [Int32] = []
    do {
      let ipv6 = try bindIPv6(port: requestedPort)
      descriptors.append(ipv6.descriptor)
      let port = ipv6.port
      guard port != 0 else {
        throw CrossProcessEngineLeaseError.invalidPort
      }
      descriptors.append(try bindIPv4(port: port))
      return CrossProcessEngineLease(port: port, fileDescriptors: descriptors)
    } catch {
      for descriptor in descriptors {
        Darwin.close(descriptor)
      }
      throw error
    }
  }

  /// Returns false when any process owns either production endpoint. Other
  /// socket failures remain explicit because treating them as availability
  /// would permit two data planes after a platform or sandbox regression.
  public func isAvailable() throws -> Bool {
    do {
      let lease = try acquire()
      lease.release()
      return true
    } catch CrossProcessEngineLeaseError.alreadyHeld {
      return false
    }
  }

  private func bindIPv6(port: UInt16) throws -> (descriptor: Int32, port: UInt16) {
    let descriptor = Darwin.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    guard descriptor >= 0 else {
      throw CrossProcessEngineLeaseError.socket(family: AF_INET6, code: errno)
    }
    do {
      try configure(descriptor, family: AF_INET6)
      var v6Only: Int32 = 1
      guard
        setsockopt(
          descriptor,
          IPPROTO_IPV6,
          IPV6_V6ONLY,
          &v6Only,
          socklen_t(MemoryLayout.size(ofValue: v6Only))
        ) == 0
      else {
        throw CrossProcessEngineLeaseError.configure(family: AF_INET6, code: errno)
      }
      var address = sockaddr_in6()
      address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
      address.sin6_family = sa_family_t(AF_INET6)
      address.sin6_port = port.bigEndian
      address.sin6_addr = in6addr_loopback
      try bind(descriptor, address: &address, family: AF_INET6)
      return (descriptor, try boundPort(descriptor))
    } catch {
      Darwin.close(descriptor)
      throw error
    }
  }

  private func bindIPv4(port: UInt16) throws -> Int32 {
    let descriptor = Darwin.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    guard descriptor >= 0 else {
      throw CrossProcessEngineLeaseError.socket(family: AF_INET, code: errno)
    }
    do {
      try configure(descriptor, family: AF_INET)
      var address = sockaddr_in()
      address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
      address.sin_family = sa_family_t(AF_INET)
      address.sin_port = port.bigEndian
      address.sin_addr = in_addr(s_addr: INADDR_LOOPBACK.bigEndian)
      try bind(descriptor, address: &address, family: AF_INET)
      return descriptor
    } catch {
      Darwin.close(descriptor)
      throw error
    }
  }

  private func configure(_ descriptor: Int32, family: Int32) throws {
    guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
      throw CrossProcessEngineLeaseError.configure(family: family, code: errno)
    }
  }

  private func bind<Address>(
    _ descriptor: Int32,
    address: inout Address,
    family: Int32
  ) throws {
    let result = withUnsafePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
        Darwin.bind(descriptor, socketAddress, socklen_t(MemoryLayout<Address>.size))
      }
    }
    guard result == 0 else {
      let code = errno
      if code == EADDRINUSE {
        throw CrossProcessEngineLeaseError.alreadyHeld
      }
      throw CrossProcessEngineLeaseError.bind(family: family, code: code)
    }
  }

  private func boundPort(_ descriptor: Int32) throws -> UInt16 {
    var address = sockaddr_in6()
    var length = socklen_t(MemoryLayout<sockaddr_in6>.size)
    let result = withUnsafeMutablePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
        getsockname(descriptor, socketAddress, &length)
      }
    }
    guard result == 0, length == socklen_t(MemoryLayout<sockaddr_in6>.size) else {
      throw CrossProcessEngineLeaseError.inspectPort(code: result == 0 ? EINVAL : errno)
    }
    return UInt16(bigEndian: address.sin6_port)
  }
}
