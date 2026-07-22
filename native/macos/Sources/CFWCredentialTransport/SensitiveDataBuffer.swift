import Foundation

public enum SensitiveDataBufferError: Error, Equatable, Sendable {
  case unavailable
}

/// Owns one independent copy of secret-bearing bytes and guarantees an
/// explicit overwrite when the synchronous consumer returns or the owner is
/// discarded. Consumers must not retain the Data argument beyond the closure.
public final class SensitiveDataBuffer: @unchecked Sendable {
  private enum State {
    case available(Data)
    case inUse
    case erased
  }

  private let lock = NSLock()
  private var state: State

  public init(copying data: Data) {
    let copy = data.withUnsafeBytes { bytes -> Data in
      guard let baseAddress = bytes.baseAddress else {
        return Data()
      }
      return Data(bytes: baseAddress, count: bytes.count)
    }
    state = .available(copy)
  }

  deinit {
    erase()
  }

  public func withErasingData<Result>(
    _ operation: (Data) throws -> Result
  ) throws -> Result {
    var data: Data = try lock.withLock {
      guard case .available(let data) = state else {
        throw SensitiveDataBufferError.unavailable
      }
      state = .inUse
      return data
    }
    defer {
      data.resetBytes(in: data.startIndex..<data.endIndex)
      data.removeAll(keepingCapacity: false)
      lock.withLock { state = .erased }
    }
    return try operation(data)
  }

  public func erase() {
    let data: Data? = lock.withLock {
      guard case .available(let data) = state else {
        return nil
      }
      state = .erased
      return data
    }
    guard var data else {
      return
    }
    data.resetBytes(in: data.startIndex..<data.endIndex)
    data.removeAll(keepingCapacity: false)
  }

  var isErasedForTesting: Bool {
    lock.withLock {
      if case .erased = state { return true }
      return false
    }
  }
}
