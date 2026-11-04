import CFWSharedProtocol
import Dispatch
import Foundation
import Synchronization
import Testing

@testable import CFWLibboxRuntime

// Helpers of the linked libbox runtime test, built only where Libbox links:
// loopback ports and a loopback server, the linked endpoints and rule sets, a
// close fault and stall, and a bounded start.
#if canImport(Libbox)
  /// Binds `descriptor` to a loopback TCP port (0 picks a free one) and returns
  /// the port.
  func bindLoopback(_ descriptor: Int32, port: UInt16) throws -> UInt16 {
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    address.sin_port = port.bigEndian
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    let bound = withUnsafeMutablePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
        Darwin.bind(descriptor, socketAddress, length) == 0
          && getsockname(descriptor, socketAddress, &length) == 0
      }
    }
    guard bound else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    return UInt16(bigEndian: address.sin_port)
  }

  /// Binds a fresh loopback socket to `port`, closes it, and returns the port.
  /// Binding fails with `EADDRINUSE` while a socket of this user is still bound
  /// to 127.0.0.1 at that port, which is where the linked configuration has
  /// libbox listen; `SO_REUSEADDR` keeps connections that were closed but linger
  /// in TIME_WAIT from failing it too.
  func probeLoopbackPort(_ port: UInt16) throws -> UInt16 {
    let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { Darwin.close(descriptor) }
    var reuse: Int32 = 1
    guard
      setsockopt(
        descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size)) == 0
    else {
      throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    return try bindLoopback(descriptor, port: port)
  }

  /// A loopback TCP server for linked starts, on plain sockets so that tearing
  /// down its connections logs nothing. It counts the connections it accepts
  /// and either holds them unanswered, so a download from it stalls until the
  /// client gives up, or answers each request once with `response`.
  final class LoopbackServer: @unchecked Sendable {
    let port: UInt16
    private let listener: Int32
    private let response: Data?
    private let queue = DispatchQueue(label: "com.bill.clashformac.tests.loopback-server")
    private let lock = NSLock()
    private var connections: [Int32] = []
    private let acceptSource: any DispatchSourceRead

    /// `response` is the whole HTTP response written once a request's headers
    /// arrived; nil leaves every request unanswered.
    init(response: Data?) throws {
      self.response = response
      let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
      guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
      do {
        port = try bindLoopback(descriptor, port: 0)
        guard Darwin.listen(descriptor, 16) == 0,
          fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL) | O_NONBLOCK) == 0
        else {
          throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
      } catch {
        Darwin.close(descriptor)
        throw error
      }
      listener = descriptor
      acceptSource = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
      acceptSource.setEventHandler { [weak self] in self?.acceptPending() }
      acceptSource.setCancelHandler { Darwin.close(descriptor) }
      acceptSource.resume()
    }

    var acceptedConnections: Int { lock.withLock { connections.count } }

    func cancel() {
      acceptSource.cancel()
      queue.sync {
        lock.withLock {
          for connection in connections { Darwin.close(connection) }
          connections.removeAll()
        }
      }
    }

    private func acceptPending() {
      while true {
        let connection = Darwin.accept(listener, nil, nil)
        guard connection >= 0 else { return }
        lock.withLock { connections.append(connection) }
        if let response {
          Self.answer(connection, with: response)
        }
      }
    }

    /// Reads one request's headers, then writes the response and ends the
    /// stream. A connection that fails either step is reset, which fails the
    /// client's download visibly; a client that closed first fails the write
    /// instead of raising SIGPIPE in the test process.
    private static func answer(_ connection: Int32, with response: Data) {
      var timeout = timeval(tv_sec: 5, tv_usec: 0)
      var noSignal: Int32 = 1
      guard fcntl(connection, F_SETFL, fcntl(connection, F_GETFL) & ~O_NONBLOCK) == 0,
        setsockopt(
          connection, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
          == 0,
        setsockopt(
          connection, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
          == 0
      else {
        _ = Darwin.shutdown(connection, SHUT_RDWR)
        return
      }
      var request = Data()
      var buffer = [UInt8](repeating: 0, count: 4_096)
      while request.range(of: Data("\r\n\r\n".utf8)) == nil {
        let count = Darwin.read(connection, &buffer, buffer.count)
        guard count > 0 else {
          _ = Darwin.shutdown(connection, SHUT_RDWR)
          return
        }
        request.append(contentsOf: buffer[0..<count])
      }
      let written = response.withUnsafeBytes { bytes -> Bool in
        guard let base = bytes.baseAddress else { return false }
        var sent = 0
        while sent < bytes.count {
          let count = Darwin.write(connection, base + sent, bytes.count - sent)
          guard count > 0 else { return false }
          sent += count
        }
        return true
      }
      _ = Darwin.shutdown(connection, written ? SHUT_WR : SHUT_RDWR)
    }
  }

  /// One remote rule set of a linked configuration, downloaded through the
  /// outbound `detour` names.
  struct LinkedRuleSet {
    let tag: String
    let url: String
    let format: String
    var detour = "direct"
  }

  /// The loopback ports of one linked System Proxy runtime.
  struct LinkedEndpoints {
    let mixedPort: UInt16
    let controllerPort: UInt16

    init() throws {
      let mixed = try probeLoopbackPort(0)
      var controller = try probeLoopbackPort(0)
      while controller == mixed {
        controller = try probeLoopbackPort(0)
      }
      mixedPort = mixed
      controllerPort = controller
    }

    /// A configuration the runtime admits whose remote rule sets download from
    /// their URLs, with libbox's cache file at `cacheFile`. With `proxyPort`
    /// it also has a SOCKS outbound tagged `proxy` to that loopback port.
    func configuration(
      ruleSets: [LinkedRuleSet], cacheFile: URL, proxyPort: UInt16? = nil
    ) throws -> Data {
      var outbounds: [[String: Any]] = [["type": "direct", "tag": "direct"]]
      if let proxyPort {
        outbounds.append([
          "type": "socks", "tag": "proxy", "server": "127.0.0.1",
          "server_port": Int(proxyPort),
        ])
      }
      return try JSONSerialization.data(withJSONObject: [
        "log": ["level": "error"],
        "inbounds": [
          [
            "type": "mixed", "tag": "cfw-system-proxy", "listen": "127.0.0.1",
            "listen_port": Int(mixedPort),
          ]
        ],
        "outbounds": outbounds,
        "route": [
          "rule_set": ruleSets.map { ruleSet in
            [
              "type": "remote", "tag": ruleSet.tag, "format": ruleSet.format,
              "url": ruleSet.url, "download_detour": ruleSet.detour,
            ]
          },
          "rules": [
            ["rule_set": ruleSets.map(\.tag), "action": "route", "outbound": "direct"]
          ],
          "final": "direct",
        ],
        "experimental": [
          "cache_file": ["enabled": true, "path": cacheFile.path],
          "clash_api": [
            "external_controller": "127.0.0.1:\(controllerPort)", "secret": "linked-test",
          ],
        ],
      ])
    }
  }

  final class StartResult: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Result<Void, any Error>?
    func record(_ result: Result<Void, any Error>) { lock.withLock { value = result } }
    var result: Result<Void, any Error>? { lock.withLock { value } }
  }

  /// A step expected to fail that started anyway leaves libbox running; stop
  /// it so the later steps and the cleanup still find an idle runtime.
  func stopIfStarted(
    _ runtime: SourceBuiltLibboxServiceRuntime, _ result: Result<Void, any Error>
  ) {
    guard case .success = result else { return }
    do {
      try runtime.stop()
    } catch {
      Issue.record(error, "a start that should have failed did not stop")
    }
  }

  /// Every close of libbox's network monitor in a runtime that throws this
  /// fault fails with it, so libbox fails to close that runtime's instance.
  struct LinkedMonitorCloseFault: LocalizedError {
    static let text = "linked test: the network monitor did not close"
    var errorDescription: String? { Self.text }
  }

  /// Holds every close of libbox's network monitor in a runtime that waits on
  /// it until the test releases it, so libbox's close of that runtime's
  /// instance does not return. A close held for a minute gives up, so a test
  /// that ends early does not leave the thread inside libbox for good.
  final class LinkedMonitorCloseStall: Sendable {
    private let released = DispatchSemaphore(value: 0)

    func hold() {
      _ = released.wait(timeout: .now() + .seconds(60))
    }

    func release() {
      released.signal()
    }
  }

  /// What stopping `runtime` threw, or nil when it stopped.
  func closeFailure(
    of runtime: SourceBuiltLibboxServiceRuntime
  ) -> LibboxInstanceUnclosable? {
    do {
      try runtime.stop()
      return nil
    } catch {
      return error
    }
  }

  /// Starts on another queue so an interrupt that never ends the start fails
  /// the test instead of hanging the lane. Nil means the start never returned.
  func boundedStart(
    _ runtime: SourceBuiltLibboxServiceRuntime, _ configuration: Data,
    deadline: EngineStartDeadline
  ) -> Result<Void, any Error>? {
    let returned = DispatchSemaphore(value: 0)
    let outcome = StartResult()
    DispatchQueue.global(qos: .userInitiated).async {
      outcome.record(
        Result {
          try runtime.start(
            configuration: configuration, packetFileDescriptor: nil, deadline: deadline)
        })
      returned.signal()
    }
    guard returned.wait(timeout: .now() + .seconds(20)) == .success else { return nil }
    return outcome.result
  }
#endif
