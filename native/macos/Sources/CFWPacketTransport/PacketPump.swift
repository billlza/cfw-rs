import CFWSharedProtocol
import Darwin
import Dispatch
import Foundation
import NetworkExtension

public protocol PacketFlowClient: AnyObject {
  func readPackets(_ completion: @escaping @Sendable ([Data], [NSNumber]) -> Void)
  func writePackets(_ packets: [Data], protocols: [NSNumber]) -> Bool
}

public final class NetworkExtensionPacketFlowClient: PacketFlowClient, @unchecked Sendable {
  private let packetFlow: NEPacketTunnelFlow

  public init(packetFlow: NEPacketTunnelFlow) {
    self.packetFlow = packetFlow
  }

  public func readPackets(_ completion: @escaping @Sendable ([Data], [NSNumber]) -> Void) {
    packetFlow.readPackets(completionHandler: completion)
  }

  public func writePackets(_ packets: [Data], protocols: [NSNumber]) -> Bool {
    packetFlow.writePackets(packets, withProtocols: protocols)
  }
}

public enum PacketPumpError: Error, Equatable, Sendable {
  case socketPairCreationFailed(Int32)
  case socketConfigurationFailed(Int32)
  case invalidMaximumPacketBytes(Int)
  case engineFileDescriptorAlreadyTransferred
  case engineFileDescriptorNotTransferred
  case alreadyStarted
  case protocolCountMismatch(packets: Int, protocols: Int)
  case protocolValueMismatch(expected: Int32, actual: Int32)
  case packetTooLarge(actual: Int, maximum: Int)
  case inboundPacketTruncated(maximum: Int)
  case invalidPacket(IPPacketError)
  case outboundCapacityExceeded(PacketQueueError)
  case socketWriteFailed(Int32)
  case socketReadFailed(Int32)
  case packetFlowWriteFailed
  case engineSocketClosed
}

private final class FlowSocketOwner: @unchecked Sendable {
  private let lock = NSLock()
  private var descriptorValue: Int32
  private var registeredSources = 0
  private var closeRequested = false

  init(descriptor: Int32) {
    descriptorValue = descriptor
  }

  deinit {
    requestClose()
  }

  var descriptor: Int32 {
    lock.withLock { descriptorValue }
  }

  func registerSource() -> Bool {
    lock.withLock {
      guard descriptorValue >= 0, !closeRequested else {
        return false
      }
      registeredSources += 1
      return true
    }
  }

  func sourceDidCancel() {
    let descriptorToClose: Int32 = lock.withLock {
      precondition(registeredSources > 0, "Unbalanced socket source cancellation")
      registeredSources -= 1
      return takeDescriptorIfReadyToClose()
    }
    if descriptorToClose >= 0 {
      Darwin.close(descriptorToClose)
    }
  }

  func requestClose() {
    let descriptorToClose: Int32 = lock.withLock {
      closeRequested = true
      return takeDescriptorIfReadyToClose()
    }
    if descriptorToClose >= 0 {
      Darwin.close(descriptorToClose)
    }
  }

  private func takeDescriptorIfReadyToClose() -> Int32 {
    guard closeRequested, registeredSources == 0 else {
      return -1
    }
    let descriptor = descriptorValue
    descriptorValue = -1
    return descriptor
  }
}

/// Bridges the public NEPacketTunnelFlow API to a bounded SOCK_DGRAM socketpair.
///
/// The datagram boundary preserves one IP packet per read/write. The flow-facing
/// descriptor is nonblocking and all mutable state is confined to stateQueue.
/// If the bounded queue cannot accept an entire callback batch, the pump fails
/// closed rather than dropping packets or growing without bound.
public final class PacketPump: @unchecked Sendable {
  public typealias FailureHandler = @Sendable (PacketPumpError) -> Void
  public static let minimumTunnelMTU = Int(TunnelNetworkOptions.minimumMTU)
  public static let maximumTunnelMTU = Int(TunnelNetworkOptions.maximumMTU)

  private let packetFlow: PacketFlowClient
  private let stateQueue: DispatchQueue
  private let stateQueueKey: DispatchSpecificKey<UInt8>
  private let failureQueue: DispatchQueue
  private let failureHandler: FailureHandler
  private let maximumPacketBytes: Int
  private var outboundQueue: BoundedPacketQueue
  private let flowSocketOwner: FlowSocketOwner
  private var engineFileDescriptor: Int32
  private var engineDescriptorTransferred = false
  private var started = false
  private var stopped = false
  private var readInFlight = false
  private var readSource: DispatchSourceRead?
  private var writeSource: DispatchSourceWrite?

  public init(
    packetFlow: PacketFlowClient,
    limits: PacketQueueLimits = .production,
    maximumPacketBytes: Int = 1_500,
    failureHandler: @escaping FailureHandler
  ) throws {
    guard
      Self.minimumTunnelMTU...Self.maximumTunnelMTU ~= maximumPacketBytes
    else {
      throw PacketPumpError.invalidMaximumPacketBytes(maximumPacketBytes)
    }
    self.packetFlow = packetFlow
    outboundQueue = BoundedPacketQueue(limits: limits)
    self.failureHandler = failureHandler
    self.maximumPacketBytes = maximumPacketBytes
    stateQueue = DispatchQueue(
      label: "com.bill.clashformac.packet-pump",
      qos: .userInitiated,
      autoreleaseFrequency: .workItem
    )
    failureQueue = DispatchQueue(
      label: "com.bill.clashformac.packet-pump-failure",
      qos: .userInitiated,
      autoreleaseFrequency: .workItem
    )
    stateQueueKey = DispatchSpecificKey<UInt8>()
    stateQueue.setSpecific(key: stateQueueKey, value: 1)

    var descriptors = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &descriptors) == 0 else {
      throw PacketPumpError.socketPairCreationFailed(errno)
    }
    let flowFileDescriptor = descriptors[0]
    engineFileDescriptor = descriptors[1]

    do {
      try Self.makeNonblocking(flowFileDescriptor)
      try Self.makeNonblocking(engineFileDescriptor)
      try Self.configureSocketBuffer(
        flowFileDescriptor,
        requestedBytes: min(limits.maximumBytes, Int(Int32.max))
      )
      try Self.configureSocketBuffer(
        engineFileDescriptor,
        requestedBytes: min(limits.maximumBytes, Int(Int32.max))
      )
    } catch {
      Darwin.close(flowFileDescriptor)
      Darwin.close(engineFileDescriptor)
      throw error
    }
    flowSocketOwner = FlowSocketOwner(descriptor: flowFileDescriptor)
  }

  deinit {
    stop()
  }

  /// Transfers ownership of the engine-facing descriptor exactly once.
  /// The engine must close it after stopping.
  public func takeEngineFileDescriptor() throws -> Int32 {
    try withStateQueue {
      guard !engineDescriptorTransferred else {
        throw PacketPumpError.engineFileDescriptorAlreadyTransferred
      }
      guard !stopped, engineFileDescriptor >= 0 else {
        throw PacketPumpError.engineSocketClosed
      }
      engineDescriptorTransferred = true
      let descriptor = engineFileDescriptor
      engineFileDescriptor = -1
      return descriptor
    }
  }

  public func start() throws {
    try withStateQueue {
      guard !started else {
        throw PacketPumpError.alreadyStarted
      }
      guard engineDescriptorTransferred else {
        throw PacketPumpError.engineFileDescriptorNotTransferred
      }
      guard !stopped else {
        throw PacketPumpError.engineSocketClosed
      }

      started = true
      guard flowSocketOwner.registerSource() else {
        started = false
        throw PacketPumpError.engineSocketClosed
      }
      let source = DispatchSource.makeReadSource(
        fileDescriptor: flowSocketOwner.descriptor,
        queue: stateQueue
      )
      source.setEventHandler { [weak self] in
        self?.drainEnginePackets()
      }
      source.setCancelHandler { [flowSocketOwner] in
        flowSocketOwner.sourceDidCancel()
      }
      readSource = source
      source.resume()
      requestPacketsFromFlow()
    }
  }

  public func stop() {
    withoutThrowingOnStateQueue {
      guard !stopped else {
        return
      }
      stopped = true
      started = false
      readSource?.cancel()
      readSource = nil
      writeSource?.cancel()
      writeSource = nil
      outboundQueue.removeAll()
      flowSocketOwner.requestClose()
      if engineFileDescriptor >= 0 {
        Darwin.close(engineFileDescriptor)
        engineFileDescriptor = -1
      }
    }
  }

  private func requestPacketsFromFlow() {
    guard started, !stopped, !readInFlight, outboundQueue.isEmpty else {
      return
    }
    readInFlight = true
    packetFlow.readPackets { [weak self] packets, protocols in
      let protocolValues = protocols.map(\.int32Value)
      self?.stateQueue.async { [weak self] in
        self?.receiveFlowPackets(packets, protocols: protocolValues)
      }
    }
  }

  private func receiveFlowPackets(_ packets: [Data], protocols: [Int32]) {
    guard started, !stopped else {
      return
    }
    readInFlight = false
    guard packets.count == protocols.count else {
      fail(.protocolCountMismatch(packets: packets.count, protocols: protocols.count))
      return
    }

    do {
      for (packet, suppliedProtocol) in zip(packets, protocols) {
        guard packet.count <= maximumPacketBytes else {
          fail(
            .packetTooLarge(
              actual: packet.count,
              maximum: maximumPacketBytes
            )
          )
          return
        }
        let inferred = try IPPacketFamily.infer(from: packet).rawValue
        guard inferred == suppliedProtocol else {
          fail(.protocolValueMismatch(expected: inferred, actual: suppliedProtocol))
          return
        }
      }
      try outboundQueue.enqueue(packets)
    } catch let error as IPPacketError {
      fail(.invalidPacket(error))
      return
    } catch let error as PacketQueueError {
      fail(.outboundCapacityExceeded(error))
      return
    } catch {
      fail(.socketWriteFailed(EINVAL))
      return
    }

    flushOutboundPackets()
  }

  private func flushOutboundPackets() {
    guard started, !stopped else {
      return
    }
    while let packet = outboundQueue.peek() {
      let written = packet.withUnsafeBytes { buffer in
        Darwin.send(flowSocketOwner.descriptor, buffer.baseAddress, buffer.count, 0)
      }
      if written < 0, errno == EINTR {
        continue
      }
      if written < 0, errno == EAGAIN || errno == EWOULDBLOCK {
        ensureWriteSource()
        return
      }
      guard written == packet.count else {
        fail(.socketWriteFailed(written < 0 ? errno : EMSGSIZE))
        return
      }
      _ = outboundQueue.dequeue()
    }

    writeSource?.cancel()
    writeSource = nil
    requestPacketsFromFlow()
  }

  private func ensureWriteSource() {
    guard writeSource == nil else {
      return
    }
    guard flowSocketOwner.registerSource() else {
      fail(.engineSocketClosed)
      return
    }
    let source = DispatchSource.makeWriteSource(
      fileDescriptor: flowSocketOwner.descriptor,
      queue: stateQueue
    )
    source.setEventHandler { [weak self] in
      self?.flushOutboundPackets()
    }
    source.setCancelHandler { [flowSocketOwner] in
      flowSocketOwner.sourceDidCancel()
    }
    writeSource = source
    source.resume()
  }

  private func drainEnginePackets() {
    guard started, !stopped else {
      return
    }

    var packets: [Data] = []
    var protocols: [NSNumber] = []
    packets.reserveCapacity(64)
    protocols.reserveCapacity(64)
    var storage = [UInt8](repeating: 0, count: maximumPacketBytes)

    for _ in 0..<64 {
      var messageFlags: Int32 = 0
      let count = storage.withUnsafeMutableBytes { buffer in
        var vector = iovec(iov_base: buffer.baseAddress, iov_len: buffer.count)
        return withUnsafeMutablePointer(to: &vector) { vectorPointer in
          var message = msghdr(
            msg_name: nil,
            msg_namelen: 0,
            msg_iov: vectorPointer,
            msg_iovlen: 1,
            msg_control: nil,
            msg_controllen: 0,
            msg_flags: 0
          )
          let received = Darwin.recvmsg(flowSocketOwner.descriptor, &message, 0)
          messageFlags = message.msg_flags
          return received
        }
      }
      if count < 0, errno == EINTR {
        continue
      }
      if count < 0, errno == EAGAIN || errno == EWOULDBLOCK {
        break
      }
      if count == 0 {
        fail(.engineSocketClosed)
        return
      }
      guard count > 0 else {
        fail(.socketReadFailed(errno))
        return
      }
      guard messageFlags & MSG_TRUNC == 0 else {
        fail(.inboundPacketTruncated(maximum: maximumPacketBytes))
        return
      }

      let packet = Data(storage.prefix(count))
      do {
        protocols.append(try IPPacketFamily.infer(from: packet).addressFamily)
        packets.append(packet)
      } catch let error as IPPacketError {
        fail(.invalidPacket(error))
        return
      } catch {
        fail(.socketReadFailed(EINVAL))
        return
      }
    }

    guard packets.isEmpty || packetFlow.writePackets(packets, protocols: protocols) else {
      fail(.packetFlowWriteFailed)
      return
    }
  }

  private func fail(_ error: PacketPumpError) {
    guard !stopped else {
      return
    }
    stop()
    // A failure is detected on stateQueue. Deliver it on a separate serial
    // queue so a lifecycle owner may synchronously stop/release the pump
    // without forming a stateQueue -> owner queue -> stateQueue lock cycle.
    // The stopped guard above also guarantees one terminal callback.
    let failureHandler = failureHandler
    failureQueue.async {
      failureHandler(error)
    }
  }

  private func withStateQueue<T>(_ operation: () throws -> T) rethrows -> T {
    if DispatchQueue.getSpecific(key: stateQueueKey) != nil {
      return try operation()
    }
    return try stateQueue.sync(execute: operation)
  }

  private func withoutThrowingOnStateQueue(_ operation: () -> Void) {
    if DispatchQueue.getSpecific(key: stateQueueKey) != nil {
      operation()
    } else {
      stateQueue.sync(execute: operation)
    }
  }

  private static func makeNonblocking(_ fileDescriptor: Int32) throws {
    let flags = fcntl(fileDescriptor, F_GETFL)
    guard flags >= 0, fcntl(fileDescriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
      throw PacketPumpError.socketConfigurationFailed(errno)
    }
  }

  private static func configureSocketBuffer(_ fileDescriptor: Int32, requestedBytes: Int) throws {
    var size = Int32(requestedBytes)
    guard
      setsockopt(
        fileDescriptor,
        SOL_SOCKET,
        SO_SNDBUF,
        &size,
        socklen_t(MemoryLayout<Int32>.size)
      ) == 0
    else {
      throw PacketPumpError.socketConfigurationFailed(errno)
    }
    guard
      setsockopt(
        fileDescriptor,
        SOL_SOCKET,
        SO_RCVBUF,
        &size,
        socklen_t(MemoryLayout<Int32>.size)
      ) == 0
    else {
      throw PacketPumpError.socketConfigurationFailed(errno)
    }
  }
}
