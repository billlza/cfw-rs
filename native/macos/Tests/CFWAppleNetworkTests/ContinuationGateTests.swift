import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWAppleNetwork

func appleCredentialAudience() throws -> CredentialAudience {
  CredentialAudience(
    profileID: UUID(uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")!,
    profileDigest: try SHA256Digest(hex: String(repeating: "ab", count: 32))
  )
}

private enum GateTestError: Error {
  case busy
}

private final class TestRequest: @unchecked Sendable {}

private func tunnelDescriptor() throws -> ConfigurationDescriptor {
  let tunnelOptions = try TunnelNetworkOptions(
    ipv6Enabled: true,
    bypassPrivateNetworks: true,
    mtu: 1_500
  )
  return try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: tunnelOptions,
    credentialAudience: try appleCredentialAudience(),
    installationID: UUID(),
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32))
  )
}

private func waitUntilAwaited<Value: Sendable>(
  _ gate: IdentityBoundContinuation<TestRequest, Value>,
  request: TestRequest
) async -> Bool {
  for _ in 0..<1_000 {
    if gate.isAwaited(request: request) {
      return true
    }
    await Task.yield()
  }
  return false
}

@Test func providerResponseGatePreservesFirstTerminalResultBeforeInstall() async throws {
  let gate = ProviderResponseGate()
  let expected = Data("first".utf8)
  gate.finish(.success(expected))
  gate.finish(.success(Data("late".utf8)))

  let received = try await withCheckedThrowingContinuation { continuation in
    gate.install(continuation)
  }

  #expect(received == expected)
}

@Test func identityBoundGateIgnoresOldCancellationAndLateCallback() async throws {
  let gate = IdentityBoundContinuation<TestRequest, Int>()
  let firstRequest = TestRequest()
  let secondRequest = TestRequest()

  let firstTask = Task<Int, Error> {
    try await withCheckedThrowingContinuation { continuation in
      #expect(gate.install(request: firstRequest, continuation: continuation))
    }
  }
  #expect(await waitUntilAwaited(gate, request: firstRequest))
  gate.cancelActiveWait()
  gate.cancelActiveWait()
  do {
    _ = try await firstTask.value
    Issue.record("Canceled continuation unexpectedly succeeded")
  } catch is CancellationError {
    // Expected: cancellation resumes the waiter but retains the in-flight
    // request identity until the operating system reports its terminal result.
  }

  gate.finish(request: firstRequest, result: .success(1))
  let secondTask = Task<Int, Error> {
    try await withCheckedThrowingContinuation { continuation in
      #expect(gate.install(request: secondRequest, continuation: continuation))
    }
  }
  #expect(await waitUntilAwaited(gate, request: secondRequest))

  gate.cancelWait(request: firstRequest)
  gate.finish(request: firstRequest, result: .success(2))
  gate.finish(request: secondRequest, result: .success(3))

  #expect(try await secondTask.value == 3)
}

@Test func identityBoundGateRejectsConcurrentOperationUntilCallbackArrives() async throws {
  let gate = IdentityBoundContinuation<TestRequest, Int>()
  let firstRequest = TestRequest()
  let secondRequest = TestRequest()

  let firstTask = Task<Int, Error> {
    try await withCheckedThrowingContinuation { continuation in
      #expect(gate.install(request: firstRequest, continuation: continuation))
    }
  }
  #expect(await waitUntilAwaited(gate, request: firstRequest))

  do {
    let _: Int = try await withCheckedThrowingContinuation { continuation in
      if !gate.install(request: secondRequest, continuation: continuation) {
        continuation.resume(throwing: GateTestError.busy)
      }
    }
    Issue.record("Concurrent continuation was unexpectedly installed")
  } catch GateTestError.busy {
    // Expected.
  }

  gate.finish(request: firstRequest, result: .success(1))
  #expect(try await firstTask.value == 1)
}
