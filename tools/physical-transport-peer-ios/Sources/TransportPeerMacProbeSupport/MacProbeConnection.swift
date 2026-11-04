import Foundation
@preconcurrency import Network

private final class BlockingResult<Value>: @unchecked Sendable {
  private let lock = NSLock()
  private let semaphore = DispatchSemaphore(value: 0)
  private var result: Result<Value, Error>?

  func resolve(_ value: Result<Value, Error>) {
    lock.lock()
    guard result == nil else {
      lock.unlock()
      return
    }
    result = value
    lock.unlock()
    semaphore.signal()
  }

  func wait(label: String) throws -> Value {
    let timeout = DispatchTime.now() + MacProbeContract.connectionDeadlineSeconds
    guard semaphore.wait(timeout: timeout) == .success else {
      throw MacProbeError.deadline(label)
    }
    lock.lock()
    defer { lock.unlock() }
    guard let result else {
      throw MacProbeError.connectionFailed(label)
    }
    return try result.get()
  }
}

private struct ReceiveChunk: Sendable {
  let content: Data
  let complete: Bool
}

enum MacExactReceiveDecision: Equatable, Sendable {
  case readMore
  case complete
  case emptyPartial
  case overflow
  case truncated
}

struct MacExactReceiveTracker: Equatable, Sendable {
  let expectedBytes: Int
  let requiresStreamCompletion: Bool
  private(set) var receivedBytes = 0

  mutating func observe(bytes: Int, streamComplete: Bool) -> MacExactReceiveDecision {
    guard bytes >= 0, expectedBytes > 0 else { return .overflow }
    if bytes == 0, !streamComplete { return .emptyPartial }
    receivedBytes += bytes
    guard receivedBytes <= expectedBytes else { return .overflow }
    if streamComplete, receivedBytes != expectedBytes { return .truncated }
    if receivedBytes == expectedBytes,
      !requiresStreamCompletion || streamComplete
    {
      return .complete
    }
    return .readMore
  }
}

struct MacSendDisposition: Equatable, Sendable {
  let usesFinalContext: Bool
  let completesContext: Bool
}

enum MacSendPlan {
  static let streamMessage = MacSendDisposition(
    usesFinalContext: false,
    completesContext: true
  )
  static let streamFinal = MacSendDisposition(
    usesFinalContext: true,
    completesContext: true
  )
}

enum MacConnectionEndDecision: Equatable, Sendable {
  case clean
  case failed
  case unexpectedBytes
  case remainedOpen
}

extension MacTransportProbe {
  static func connection(
    inputs: MacProbeInputs,
    port rawPort: UInt16,
    parameters: NWParameters
  ) -> NWConnection {
    let port = NWEndpoint.Port(rawValue: rawPort)!
    return NWConnection(
      host: NWEndpoint.Host(inputs.plan.peerIPv4),
      port: port,
      using: parameters
    )
  }

  static func waitUntilReady(_ connection: NWConnection, label: String) throws {
    let result = BlockingResult<Void>()
    connection.stateUpdateHandler = { state in
      switch state {
      case .ready:
        result.resolve(.success(()))
      case .failed, .cancelled:
        result.resolve(.failure(MacProbeError.connectionFailed(label)))
      default:
        break
      }
    }
    connection.start(queue: queue)
    do {
      try result.wait(label: "\(label) ready")
    } catch {
      connection.forceCancel()
      throw error
    }
    guard connection.currentPath?.usesInterfaceType(.wifi) == true else {
      connection.cancel()
      throw MacProbeError.protocolMismatch("\(label) path is not Wi-Fi")
    }
  }

  static func send(
    _ data: Data,
    on connection: NWConnection,
    label: String,
    disposition: MacSendDisposition = MacSendPlan.streamFinal
  ) throws {
    let result = BlockingResult<Void>()
    connection.send(
      content: data,
      contentContext: disposition.usesFinalContext ? .finalMessage : .defaultMessage,
      isComplete: disposition.completesContext,
      completion: .contentProcessed { error in
        if error == nil {
          result.resolve(.success(()))
        } else {
          result.resolve(.failure(MacProbeError.connectionFailed("\(label) send")))
        }
      }
    )
    try result.wait(label: "\(label) send")
  }

  static func receiveExact(
    _ expectedBytes: Int,
    on connection: NWConnection,
    label: String,
    requiresStreamCompletion: Bool = false
  ) throws -> Data {
    var collected = Data()
    var tracker = MacExactReceiveTracker(
      expectedBytes: expectedBytes,
      requiresStreamCompletion: requiresStreamCompletion
    )
    while true {
      let remaining = max(0, expectedBytes - tracker.receivedBytes)
      let result = BlockingResult<ReceiveChunk>()
      connection.receive(minimumIncompleteLength: 1, maximumLength: max(1, remaining + 1)) {
        content, _, isComplete, error in
        if error != nil {
          result.resolve(.failure(MacProbeError.connectionFailed("\(label) receive")))
        } else {
          result.resolve(
            .success(ReceiveChunk(content: content ?? Data(), complete: isComplete))
          )
        }
      }
      let chunk = try result.wait(label: "\(label) receive")
      collected.append(chunk.content)
      switch tracker.observe(
        bytes: chunk.content.count,
        streamComplete: chunk.complete
      ) {
      case .readMore:
        continue
      case .complete:
        return collected
      case .emptyPartial:
        throw MacProbeError.protocolMismatch("\(label) empty partial response")
      case .overflow:
        throw MacProbeError.protocolMismatch("\(label) response overflow")
      case .truncated:
        throw MacProbeError.protocolMismatch("\(label) truncated response")
      }
    }
  }

  static func waitForConnectionEnd(_ connection: NWConnection, label: String) throws {
    let result = BlockingResult<Void>()
    connection.receive(minimumIncompleteLength: 1, maximumLength: 1) {
      content, _, complete, error in
      switch classifyConnectionEnd(
        bytesReceived: content?.count ?? 0,
        complete: complete,
        failed: error != nil
      ) {
      case .clean:
        result.resolve(.success(()))
      case .failed:
        result.resolve(.failure(MacProbeError.connectionFailed("\(label) connection end")))
      case .unexpectedBytes:
        result.resolve(.failure(MacProbeError.protocolMismatch("\(label) unexpected response")))
      case .remainedOpen:
        result.resolve(.failure(MacProbeError.protocolMismatch("\(label) remained open")))
      }
    }
    try result.wait(label: "\(label) connection end")
  }

  static func classifyConnectionEnd(
    bytesReceived: Int,
    complete: Bool,
    failed: Bool
  ) -> MacConnectionEndDecision {
    guard bytesReceived >= 0 else { return .failed }
    if failed { return .failed }
    if bytesReceived != 0 { return .unexpectedBytes }
    return complete ? .clean : .remainedOpen
  }
}
