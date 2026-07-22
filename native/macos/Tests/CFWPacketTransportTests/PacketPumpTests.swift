import Darwin
import Dispatch
import Foundation
import Testing

@testable import CFWPacketTransport

private final class TestPacketFlow: PacketFlowClient, @unchecked Sendable {
  private let lock = NSLock()
  private let readRegistered = DispatchSemaphore(value: 0)
  private let packetWritten = DispatchSemaphore(value: 0)
  private var readHandler: (@Sendable ([Data], [NSNumber]) -> Void)?
  private var writtenPackets: [Data] = []
  private var writtenProtocols: [NSNumber] = []

  func readPackets(_ completion: @escaping @Sendable ([Data], [NSNumber]) -> Void) {
    lock.withLock {
      readHandler = completion
    }
    readRegistered.signal()
  }

  func writePackets(_ packets: [Data], protocols: [NSNumber]) -> Bool {
    lock.withLock {
      writtenPackets.append(contentsOf: packets)
      writtenProtocols.append(contentsOf: protocols)
    }
    packetWritten.signal()
    return true
  }

  func deliver(_ packets: [Data], protocols: [NSNumber]) -> Bool {
    guard readRegistered.wait(timeout: .now() + 1) == .success else {
      return false
    }
    let handler = lock.withLock {
      let handler = readHandler
      readHandler = nil
      return handler
    }
    guard let handler else {
      return false
    }
    handler(packets, protocols)
    return true
  }

  func waitForWrittenPacket() -> (packets: [Data], protocols: [NSNumber])? {
    guard packetWritten.wait(timeout: .now() + 1) == .success else {
      return nil
    }
    return lock.withLock {
      (writtenPackets, writtenProtocols)
    }
  }
}

private final class PumpFailureRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private let recorded = DispatchSemaphore(value: 0)
  private var failures: [PacketPumpError] = []

  func record(_ failure: PacketPumpError) {
    lock.withLock {
      failures.append(failure)
    }
    recorded.signal()
  }

  var values: [PacketPumpError] {
    lock.withLock { failures }
  }

  func wait() -> Bool {
    recorded.wait(timeout: .now() + 1) == .success
  }
}

private final class PumpStopOwner: @unchecked Sendable {
  private let lock = NSLock()
  private var pump: PacketPump?

  func install(_ pump: PacketPump) {
    lock.withLock {
      self.pump = pump
    }
  }

  func stop() {
    let pump = lock.withLock { self.pump }
    pump?.stop()
  }
}

@Test func stoppedPumpNeverTransfersAnInvalidEngineDescriptor() throws {
  let flow = TestPacketFlow()
  let failures = PumpFailureRecorder()
  let pump = try PacketPump(packetFlow: flow) { failures.record($0) }

  pump.stop()

  #expect(throws: PacketPumpError.engineSocketClosed) {
    try pump.takeEngineFileDescriptor()
  }
  #expect(throws: PacketPumpError.engineSocketClosed) {
    try pump.takeEngineFileDescriptor()
  }
  #expect(failures.values.isEmpty)
}

@Test func packetPumpRejectsDuplicateDescriptorTransferAndStart() throws {
  let flow = TestPacketFlow()
  let failures = PumpFailureRecorder()
  let pump = try PacketPump(packetFlow: flow) { failures.record($0) }
  let engineFileDescriptor = try pump.takeEngineFileDescriptor()
  defer {
    pump.stop()
    Darwin.close(engineFileDescriptor)
  }

  #expect(throws: PacketPumpError.engineFileDescriptorAlreadyTransferred) {
    try pump.takeEngineFileDescriptor()
  }
  try pump.start()
  #expect(throws: PacketPumpError.alreadyStarted) {
    try pump.start()
  }
  #expect(failures.values.isEmpty)
}

@Test func packetPumpIgnoresLateFlowCallbackAfterStop() async throws {
  let flow = TestPacketFlow()
  let failures = PumpFailureRecorder()
  let pump = try PacketPump(packetFlow: flow) { failures.record($0) }
  let engineFileDescriptor = try pump.takeEngineFileDescriptor()
  defer { Darwin.close(engineFileDescriptor) }
  try pump.start()
  pump.stop()

  #expect(
    flow.deliver(
      [Data([0x45, 0, 0, 4])],
      protocols: [NSNumber(value: AF_INET)]
    )
  )
  try await Task.sleep(for: .milliseconds(20))
  #expect(failures.values.isEmpty)
}

@Test func packetPumpFailsExactlyOnceForMismatchedProtocolBatch() throws {
  let flow = TestPacketFlow()
  let failures = PumpFailureRecorder()
  let pump = try PacketPump(packetFlow: flow) { failures.record($0) }
  let engineFileDescriptor = try pump.takeEngineFileDescriptor()
  defer {
    pump.stop()
    Darwin.close(engineFileDescriptor)
  }
  try pump.start()

  #expect(flow.deliver([Data([0x45, 0, 0, 4])], protocols: []))
  #expect(failures.wait())
  #expect(
    failures.values == [
      .protocolCountMismatch(packets: 1, protocols: 0)
    ]
  )
}

@Test func failureHandlerMaySynchronouslyStopPumpWithoutDeadlock() throws {
  let flow = TestPacketFlow()
  let owner = PumpStopOwner()
  let failureDelivered = DispatchSemaphore(value: 0)
  let pump = try PacketPump(packetFlow: flow) { _ in
    owner.stop()
    failureDelivered.signal()
  }
  owner.install(pump)
  let engineFileDescriptor = try pump.takeEngineFileDescriptor()
  defer {
    pump.stop()
    Darwin.close(engineFileDescriptor)
  }
  try pump.start()

  #expect(flow.deliver([Data([0x45, 0, 0, 4])], protocols: []))
  #expect(failureDelivered.wait(timeout: .now() + 1) == .success)
}

@Test func packetPumpRejectsFamilyMetadataThatDisagreesWithPacket() throws {
  let flow = TestPacketFlow()
  let failures = PumpFailureRecorder()
  let pump = try PacketPump(packetFlow: flow) { failures.record($0) }
  let engineFileDescriptor = try pump.takeEngineFileDescriptor()
  defer {
    pump.stop()
    Darwin.close(engineFileDescriptor)
  }
  try pump.start()

  #expect(
    flow.deliver(
      [Data([0x45, 0, 0, 4])],
      protocols: [NSNumber(value: AF_INET6)]
    )
  )
  #expect(failures.wait())
  #expect(
    failures.values == [
      .protocolValueMismatch(expected: AF_INET, actual: AF_INET6)
    ]
  )
}

@Test func packetPumpRejectsUnknownIPVersion() throws {
  let flow = TestPacketFlow()
  let failures = PumpFailureRecorder()
  let pump = try PacketPump(packetFlow: flow) { failures.record($0) }
  let engineFileDescriptor = try pump.takeEngineFileDescriptor()
  defer {
    pump.stop()
    Darwin.close(engineFileDescriptor)
  }
  try pump.start()

  #expect(flow.deliver([Data([0x50, 0, 0, 4])], protocols: [NSNumber(value: AF_INET)]))
  #expect(failures.wait())
  #expect(failures.values == [.invalidPacket(.unsupportedVersion(5))])
}

@Test func packetPumpRejectsOversizedPacketBeforeSocketWrite() throws {
  let flow = TestPacketFlow()
  let failures = PumpFailureRecorder()
  let pump = try PacketPump(packetFlow: flow) { failures.record($0) }
  let engineFileDescriptor = try pump.takeEngineFileDescriptor()
  defer {
    pump.stop()
    Darwin.close(engineFileDescriptor)
  }
  try pump.start()

  var packet = Data(repeating: 0, count: 1_501)
  packet[0] = 0x60
  #expect(flow.deliver([packet], protocols: [NSNumber(value: AF_INET6)]))
  #expect(failures.wait())
  #expect(
    failures.values == [
      .packetTooLarge(actual: 1_501, maximum: 1_500)
    ]
  )
}

@Test func packetPumpUsesTheValidatedTunnelMTUAsItsDatagramBound() throws {
  let flow = TestPacketFlow()
  let failures = PumpFailureRecorder()
  let pump = try PacketPump(packetFlow: flow, maximumPacketBytes: 1_280) {
    failures.record($0)
  }
  let engineFileDescriptor = try pump.takeEngineFileDescriptor()
  defer {
    pump.stop()
    Darwin.close(engineFileDescriptor)
  }
  try pump.start()

  var packet = Data(repeating: 0, count: 1_281)
  packet[0] = 0x60
  #expect(flow.deliver([packet], protocols: [NSNumber(value: AF_INET6)]))
  #expect(failures.wait())
  #expect(failures.values == [.packetTooLarge(actual: 1_281, maximum: 1_280)])
}

@Test func packetPumpTransfersExactMaximumMTUThroughTheProductionSocketType() throws {
  let flow = TestPacketFlow()
  let failures = PumpFailureRecorder()
  let maximum = PacketPump.maximumTunnelMTU
  let pump = try PacketPump(packetFlow: flow, maximumPacketBytes: maximum) {
    failures.record($0)
  }
  let engineFileDescriptor = try pump.takeEngineFileDescriptor()
  defer {
    pump.stop()
    Darwin.close(engineFileDescriptor)
  }
  try pump.start()

  var packet = Data(repeating: 0, count: maximum)
  packet[0] = 0x45
  #expect(flow.deliver([packet], protocols: [NSNumber(value: AF_INET)]))

  var pollDescriptor = pollfd(
    fd: engineFileDescriptor,
    events: Int16(POLLIN),
    revents: 0
  )
  #expect(Darwin.poll(&pollDescriptor, 1, 1_000) == 1)
  var received = [UInt8](repeating: 0, count: maximum)
  let receivedCount = Darwin.recv(engineFileDescriptor, &received, received.count, 0)
  #expect(receivedCount == maximum)
  #expect(Data(received.prefix(receivedCount)) == packet)
  #expect(failures.values.isEmpty)

  #expect(throws: PacketPumpError.invalidMaximumPacketBytes(maximum + 1)) {
    try PacketPump(packetFlow: flow, maximumPacketBytes: maximum + 1) { _ in }
  }
}

@Test func packetPumpRejectsBatchThatExceedsConfiguredCapacity() throws {
  let flow = TestPacketFlow()
  let failures = PumpFailureRecorder()
  let limits = try PacketQueueLimits(maximumPackets: 1, maximumBytes: 128)
  let pump = try PacketPump(packetFlow: flow, limits: limits) { failures.record($0) }
  let engineFileDescriptor = try pump.takeEngineFileDescriptor()
  defer {
    pump.stop()
    Darwin.close(engineFileDescriptor)
  }
  try pump.start()

  let packet = Data([0x45, 0, 0, 4])
  #expect(
    flow.deliver(
      [packet, packet],
      protocols: [NSNumber(value: AF_INET), NSNumber(value: AF_INET)]
    )
  )
  #expect(failures.wait())
  #expect(failures.values.count == 1)
  guard case .outboundCapacityExceeded = failures.values[0] else {
    Issue.record("Expected a bounded queue capacity failure")
    return
  }
}

@Test func packetPumpMovesPacketsAcrossBothPublicFlowDirections() throws {
  let flow = TestPacketFlow()
  let failures = PumpFailureRecorder()
  let pump = try PacketPump(packetFlow: flow) { error in
    failures.record(error)
  }
  let engineFileDescriptor = try pump.takeEngineFileDescriptor()
  defer {
    pump.stop()
    Darwin.close(engineFileDescriptor)
  }
  try pump.start()

  let outbound = Data([0x45, 0, 0, 4])
  #expect(flow.deliver([outbound], protocols: [NSNumber(value: AF_INET)]))

  var pollDescriptor = pollfd(
    fd: engineFileDescriptor,
    events: Int16(POLLIN),
    revents: 0
  )
  #expect(Darwin.poll(&pollDescriptor, 1, 1_000) == 1)
  var received = [UInt8](repeating: 0, count: 64)
  let receivedCount = Darwin.recv(engineFileDescriptor, &received, received.count, 0)
  #expect(receivedCount == outbound.count)
  #expect(Data(received.prefix(receivedCount)) == outbound)

  let inbound = Data([0x60, 0, 0, 0])
  let sentCount = inbound.withUnsafeBytes { buffer in
    Darwin.send(engineFileDescriptor, buffer.baseAddress, buffer.count, 0)
  }
  #expect(sentCount == inbound.count)
  let written = try #require(flow.waitForWrittenPacket())
  #expect(written.packets == [inbound])
  #expect(written.protocols.map(\.int32Value) == [AF_INET6])
  #expect(failures.values.isEmpty)
}
