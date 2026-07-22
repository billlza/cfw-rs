import Foundation
import Testing

@testable import CFWPacketTransport

@Test func queuePreservesPacketBoundariesAndFIFOOrder() throws {
  let limits = try PacketQueueLimits(maximumPackets: 3, maximumBytes: 12)
  var queue = BoundedPacketQueue(limits: limits)
  let packets = [Data([1, 2]), Data([3, 4, 5]), Data([6])]

  try queue.enqueue(packets)

  #expect(queue.count == 3)
  #expect(queue.byteCount == 6)
  #expect(queue.dequeue() == packets[0])
  #expect(queue.dequeue() == packets[1])
  #expect(queue.dequeue() == packets[2])
  #expect(queue.isEmpty)
}

@Test func queueRejectsWholeBatchWithoutPartialMutation() throws {
  let limits = try PacketQueueLimits(maximumPackets: 2, maximumBytes: 4)
  var queue = BoundedPacketQueue(limits: limits)
  try queue.enqueue([Data([1])])

  #expect(throws: PacketQueueError.self) {
    try queue.enqueue([Data([2, 3]), Data([4, 5])])
  }
  #expect(queue.count == 1)
  #expect(queue.byteCount == 1)
  #expect(queue.dequeue() == Data([1]))
}

@Test func packetFamilyUsesPublicIPVersionNibble() throws {
  #expect(try IPPacketFamily.infer(from: Data([0x45])) == .ipv4)
  #expect(try IPPacketFamily.infer(from: Data([0x60])) == .ipv6)
  #expect(throws: IPPacketError.emptyPacket) {
    try IPPacketFamily.infer(from: Data())
  }
  #expect(throws: IPPacketError.unsupportedVersion(5)) {
    try IPPacketFamily.infer(from: Data([0x50]))
  }
}
