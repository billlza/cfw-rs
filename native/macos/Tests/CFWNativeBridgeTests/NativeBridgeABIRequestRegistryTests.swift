import Foundation
import Testing

@testable import CFWNativeBridge

private final class ABIResponseRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var responses: [Data] = []

  func record(_ response: Data) {
    lock.withLock { responses.append(response) }
  }

  var values: [Data] { lock.withLock { responses } }
}

private func waitForResponses(
  _ recorder: ABIResponseRecorder,
  count: Int
) async -> Bool {
  for _ in 0..<10_000 {
    if recorder.values.count == count { return true }
    await Task.yield()
  }
  return false
}

private func exportedCancelStatus(_ requestID: String) -> Int32 {
  Data(requestID.utf8).withUnsafeBytes { bytes in
    cfwNativeBridgeCancelV1(
      bytes.bindMemory(to: UInt8.self).baseAddress,
      bytes.count
    )
  }
}

@Suite(.serialized)
struct NativeBridgeABIRequestRegistryTests {
  @Test
  func swiftWatchdogBudgetMatchesReviewedCABIHeader() throws {
    let nativeRoot = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let header = try String(
      contentsOf: nativeRoot.appendingPathComponent("Headers/CFWNativeBridge.h"),
      encoding: .utf8)
    #expect(NativeBridgeABITiming.operationBudgetMilliseconds == 30_000)
    #expect(
      header.contains("#define CFW_NATIVE_BRIDGE_OPERATION_BUDGET_MILLISECONDS 30000u"))
  }

  @Test
  func exportedCancellationRejectsNoncanonicalAndUnknownRequestIdentities() {
    let registry = NativeBridgeABIRequestRegistry.shared
    #expect(registry.activeRequestCount == 0)

    let unknown = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    #expect(exportedCancelStatus(unknown) == 3)
    #expect(exportedCancelStatus(unknown.uppercased()) == 2)
    #expect(exportedCancelStatus("not-a-canonical-request-id") == 2)
    #expect(cfwNativeBridgeCancelV1(nil, 36) == 2)

    #expect(registry.activeRequestCount == 0)
  }

  @Test
  func exactCancellationDoesNotCancelAnotherAcceptedRequest() async {
    let registry = NativeBridgeABIRequestRegistry(operationBudget: .seconds(60))
    let firstID = UUID()
    let secondID = UUID()
    let cancelled = Data("cancelled".utf8)
    let lateSuccess = Data("late-success".utf8)
    let first = ABIResponseRecorder()
    let second = ABIResponseRecorder()

    let firstAccepted = registry.submit(
      requestID: firstID,
      cancellationResponse: cancelled,
      completion: first.record,
      operation: {
        do { try await Task<Never, Never>.sleep(for: .seconds(60)) } catch {}
        return lateSuccess
      })
    let secondAccepted = registry.submit(
      requestID: secondID,
      cancellationResponse: cancelled,
      completion: second.record,
      operation: {
        do { try await Task<Never, Never>.sleep(for: .seconds(60)) } catch {}
        return lateSuccess
      })
    #expect(firstAccepted)
    #expect(secondAccepted)

    #expect(registry.cancel(requestID: firstID))
    #expect(await waitForResponses(first, count: 1))
    #expect(first.values == [cancelled])
    #expect(second.values.isEmpty)
    #expect(registry.activeRequestCount == 1)

    #expect(registry.cancel(requestID: secondID))
    #expect(await waitForResponses(second, count: 1))
    #expect(second.values == [cancelled])
    #expect(registry.activeRequestCount == 0)
  }

  @Test
  func admissionWatchdogCancelsAndSuppressesLateSuccess() async {
    let registry = NativeBridgeABIRequestRegistry(operationBudget: .milliseconds(1))
    let recorder = ABIResponseRecorder()
    let cancelled = Data("bounded-timeout".utf8)

    let accepted = registry.submit(
      requestID: UUID(),
      cancellationResponse: cancelled,
      completion: recorder.record,
      operation: {
        do { try await Task<Never, Never>.sleep(for: .seconds(60)) } catch {}
        return Data("success-after-cancel".utf8)
      })
    #expect(accepted)

    #expect(await waitForResponses(recorder, count: 1))
    #expect(recorder.values == [cancelled])
    #expect(registry.activeRequestCount == 0)
  }

  @Test
  func completionAndCancellationRaceHasOneTerminalCallback() async {
    let registry = NativeBridgeABIRequestRegistry(operationBudget: .seconds(60))

    for iteration in 0..<100 {
      let requestID = UUID()
      let recorder = ABIResponseRecorder()
      let success = Data("success-\(iteration)".utf8)
      let cancelled = Data("cancelled-\(iteration)".utf8)
      let accepted = registry.submit(
        requestID: requestID,
        cancellationResponse: cancelled,
        completion: recorder.record,
        operation: {
          await Task.yield()
          return success
        })
      #expect(accepted)

      async let cancellation: Bool = registry.cancel(requestID: requestID)
      _ = await cancellation
      #expect(await waitForResponses(recorder, count: 1))
      #expect(recorder.values == [success] || recorder.values == [cancelled])
    }

    #expect(registry.activeRequestCount == 0)
  }

  @Test
  func duplicateLiveRequestIdentityIsRejectedWithoutStealingCallback() async {
    let registry = NativeBridgeABIRequestRegistry(operationBudget: .seconds(60))
    let requestID = UUID()
    let accepted = ABIResponseRecorder()
    let rejected = ABIResponseRecorder()
    let cancelled = Data("cancelled".utf8)

    let firstAccepted = registry.submit(
      requestID: requestID,
      cancellationResponse: cancelled,
      completion: accepted.record,
      operation: {
        do { try await Task<Never, Never>.sleep(for: .seconds(60)) } catch {}
        return Data("late-success".utf8)
      })
    let duplicateAccepted = registry.submit(
      requestID: requestID,
      cancellationResponse: cancelled,
      completion: rejected.record,
      operation: { Data("must-not-run".utf8) })
    #expect(firstAccepted)
    #expect(!duplicateAccepted)
    #expect(rejected.values.isEmpty)

    #expect(registry.cancel(requestID: requestID))
    #expect(await waitForResponses(accepted, count: 1))
    #expect(accepted.values == [cancelled])
    #expect(registry.activeRequestCount == 0)
  }
}
