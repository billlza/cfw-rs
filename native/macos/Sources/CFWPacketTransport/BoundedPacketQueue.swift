import Foundation

public struct PacketQueueLimits: Equatable, Sendable {
  public let maximumPackets: Int
  public let maximumBytes: Int

  public init(maximumPackets: Int = 1_024, maximumBytes: Int = 4 * 1_048_576) throws {
    guard maximumPackets > 0, maximumBytes > 0 else {
      throw PacketQueueError.invalidLimits
    }
    self.maximumPackets = maximumPackets
    self.maximumBytes = maximumBytes
  }

  public static let production = PacketQueueLimits(
    validatedMaximumPackets: 1_024,
    maximumBytes: 4 * 1_048_576
  )

  private init(validatedMaximumPackets: Int, maximumBytes: Int) {
    self.maximumPackets = validatedMaximumPackets
    self.maximumBytes = maximumBytes
  }
}

public enum PacketQueueError: Error, Equatable, Sendable {
  case invalidLimits
  case packetTooLarge(actual: Int, maximum: Int)
  case capacityExceeded(
    packetCount: Int,
    byteCount: Int,
    maximumPackets: Int,
    maximumBytes: Int
  )
}

public struct BoundedPacketQueue: Sendable {
  private var storage: [Data?]
  private var head = 0
  private var tail = 0
  public private(set) var count = 0
  public private(set) var byteCount = 0
  public let limits: PacketQueueLimits

  public init(limits: PacketQueueLimits = .production) {
    self.limits = limits
    storage = Array(repeating: nil, count: limits.maximumPackets)
  }

  public var isEmpty: Bool {
    count == 0
  }

  public mutating func enqueue(_ packets: [Data]) throws {
    let incomingBytes = try packets.reduce(into: 0) { total, packet in
      guard packet.count <= limits.maximumBytes else {
        throw PacketQueueError.packetTooLarge(
          actual: packet.count,
          maximum: limits.maximumBytes
        )
      }
      let (next, overflowed) = total.addingReportingOverflow(packet.count)
      guard !overflowed else {
        throw PacketQueueError.capacityExceeded(
          packetCount: count + packets.count,
          byteCount: .max,
          maximumPackets: limits.maximumPackets,
          maximumBytes: limits.maximumBytes
        )
      }
      total = next
    }

    let requestedPackets = count + packets.count
    let (requestedBytes, bytesOverflowed) = byteCount.addingReportingOverflow(incomingBytes)
    guard !bytesOverflowed,
      requestedPackets <= limits.maximumPackets,
      requestedBytes <= limits.maximumBytes
    else {
      throw PacketQueueError.capacityExceeded(
        packetCount: requestedPackets,
        byteCount: bytesOverflowed ? .max : requestedBytes,
        maximumPackets: limits.maximumPackets,
        maximumBytes: limits.maximumBytes
      )
    }

    for packet in packets {
      storage[tail] = packet
      tail = (tail + 1) % storage.count
      count += 1
      byteCount += packet.count
    }
  }

  public mutating func dequeue() -> Data? {
    guard count > 0, let packet = storage[head] else {
      return nil
    }
    storage[head] = nil
    head = (head + 1) % storage.count
    count -= 1
    byteCount -= packet.count
    return packet
  }

  public func peek() -> Data? {
    guard count > 0 else {
      return nil
    }
    return storage[head]
  }

  public mutating func removeAll() {
    storage = Array(repeating: nil, count: limits.maximumPackets)
    head = 0
    tail = 0
    count = 0
    byteCount = 0
  }
}
