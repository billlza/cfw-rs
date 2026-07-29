import Foundation

@testable import CFWNativeBridge

final class TestNativeHostOperationLease: NativeHostOperationLeaseHolding,
  @unchecked Sendable
{
  private let lock = NSLock()
  private(set) var released = false

  func release() {
    lock.withLock { released = true }
  }
}

struct AvailableNativeHostOperationLease: NativeHostOperationLeaseAcquiring {
  func acquire() throws -> any NativeHostOperationLeaseHolding {
    TestNativeHostOperationLease()
  }
}
