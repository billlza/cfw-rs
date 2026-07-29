import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWGlobalAuthority

private final class ReentrantAuthorityEventSink: NSObject,
  CFWGlobalAuthorityEventSinkProtocol, @unchecked Sendable
{
  private let lock = NSLock()
  private let delivered = DispatchSemaphore(value: 0)
  private var deliveryCount = 0
  private var firstDelivery: (@Sendable () -> Void)?

  func setFirstDelivery(_ action: @escaping @Sendable () -> Void) {
    lock.withLock { firstDelivery = action }
  }

  func deliverEvent(
    _ event: Data,
    reply: @escaping (NSError?) -> Void
  ) {
    _ = event
    let action = lock.withLock { () -> (@Sendable () -> Void)? in
      deliveryCount += 1
      guard deliveryCount == 1 else { return nil }
      defer { firstDelivery = nil }
      return firstDelivery
    }
    action?()
    reply(nil)
    delivered.signal()
  }

  func waitForDeliveries(_ count: Int) -> Bool {
    for _ in 0..<count {
      guard delivered.wait(timeout: .now() + 2) == .success else {
        return false
      }
    }
    return true
  }

  var count: Int { lock.withLock { deliveryCount } }
}

private final class EventInvalidationCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var value = 0

  func increment() { lock.withLock { value += 1 } }
  var count: Int { lock.withLock { value } }
}

private func eventChannelSnapshot(revision: UInt64) throws -> AuthorityEvent {
  .snapshot(
    try AuthoritySnapshot(
      protocolVersion: AuthorityProtocolVersion(),
      state: .off,
      revision: revision,
      replayCursor: nil,
      leaseView: nil,
      lastFailure: nil,
      consoleUID: nil))
}

@Test func eventEnqueuedDuringDrainIsRearmedWithoutLostWakeup() throws {
  let sink = ReentrantAuthorityEventSink()
  let invalidations = EventInvalidationCounter()
  let channel = AuthorityPeerEventChannel(
    sink: sink,
    invalidate: { invalidations.increment() })
  let second = try eventChannelSnapshot(revision: 2)
  sink.setFirstDelivery { [weak channel] in
    channel?.enqueue(second)
  }

  channel.enqueue(try eventChannelSnapshot(revision: 1))

  #expect(sink.waitForDeliveries(2))
  #expect(sink.count == 2)
  #expect(invalidations.count == 0)
}
