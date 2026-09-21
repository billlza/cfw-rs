import AppKit
import Foundation
import Testing

@testable import CFMNativeDashboard

private func fixture() throws -> Data {
  let url = try #require(
    Bundle.module.url(forResource: "off", withExtension: "json", subdirectory: "Fixtures"))
  return try Data(contentsOf: url)
}

private func payload(_ fields: [String: Any]) throws -> Data {
  var value = try #require(JSONSerialization.jsonObject(with: fixture()) as? [String: Any])
  fields.forEach { value[$0.key] = $0.value }
  return try JSONSerialization.data(withJSONObject: value)
}

@Test func rustWireFixtureDecodesExactly() throws {
  let frame = try OverviewFrame.decode(fixture())
  #expect(frame.phase == .off)
  #expect(frame.core == .inactive)
  #expect(frame.systemProxy == .inactive)
  #expect(frame.tunnel == .inactive)
  #expect(frame.failure == nil)
}

@Test func malformedOrFutureFramesNeverBecomeStopped() throws {
  for fields: [String: Any] in [
    ["version": 2], ["phase": "future"], ["core": "connected"], ["locale": "xx"],
    ["sequence": -1], ["failure": "hidden failure"], ["phase": "failed"],
    ["phase": "failed", "failure": ""], ["core": "active"],
  ] {
    let data = try payload(fields)
    #expect(throws: (any Error).self) { try OverviewFrame.decode(data) }
  }
  #expect(throws: (any Error).self) { try OverviewFrame.decode(Data()) }
  #expect(throws: (any Error).self) { try OverviewFrame.decode(Data(repeating: 32, count: 32_769)) }
}

@Test @MainActor func nativeWindowClosesOnlyItsObservationSubscription() throws {
  NSApplication.shared.setActivationPolicy(.prohibited)
  let releases = UnsafeMutablePointer<Int>.allocate(capacity: 1)
  releases.initialize(to: 0)
  defer {
    releases.deinitialize(count: 1)
    releases.deallocate()
  }
  let closed: DashboardClosed = { context in
    // Test owns this allocation until the native window is closed below.
    guard let value = UnsafeMutablePointer<Int>(bitPattern: context) else { return }
    value.pointee += 1
  }
  let data = try payload(["sequence": 100, "session": 100])
  let status = data.withUnsafeBytes { bytes in
    dashboardPresent(
      bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, closed, UInt(bitPattern: releases))
  }
  #expect(status == 1)
  let window = try #require(NSApp.windows.first { $0.title == "Clash for Mac · 0.5" })
  defer { window.close() }
  RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
  #expect(window.toolbar != nil, "the actual native window must host the SwiftUI toolbar")
  let priorLateFrame = try payload(["sequence": 150, "session": 100])
  #expect(
    priorLateFrame.withUnsafeBytes { bytes in
      dashboardPublish(bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
    } == 1)
  let replacement = try payload(["sequence": 101, "session": 101])
  #expect(
    replacement.withUnsafeBytes { bytes in
      dashboardPresent(
        bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, closed,
        UInt(bitPattern: releases))
    } == 1)
  #expect(releases.pointee == 1)
  let superseded = try payload(["sequence": 101, "session": 99])
  #expect(
    superseded.withUnsafeBytes { bytes in
      dashboardPublish(bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
    } == 2)
  #expect(dashboardInvalidate(99) == 2)
  let next = try payload(["sequence": 151, "session": 101])
  #expect(
    next.withUnsafeBytes { bytes in
      dashboardPublish(bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
    } == 1)
  window.close()
  #expect(releases.pointee == 2)
  window.close()
  #expect(releases.pointee == 2)
}

@Test @MainActor func orderingAndFailureArePreserved() throws {
  let model = OverviewModel()
  #expect(model.frame == nil)
  let failed = try OverviewFrame.decode(
    payload([
      "sequence": 2, "phase": "failed", "core": "unknown", "systemProxy": "unknown",
      "tunnel": "unknown", "failure": "Unavailable",
    ]))
  try model.accept(failed)
  #expect(throws: FrameError.self) { try model.accept(OverviewFrame.decode(fixture())) }
  #expect(model.frame == failed)
  model.rejectDelivery()
  #expect(model.deliveryFailure)
  #expect(model.frame?.failure == "Unavailable")
  try model.accept(OverviewFrame.decode(payload(["sequence": 3])))
  #expect(!model.deliveryFailure)
  #expect(model.frame?.phase == .off)
}

@Test func everyNativeMessageHasAllFourTranslations() {
  let keys = [
    "overview", "closeOverview", "core", "proxy", "tunnel", "off", "connected", "changing",
    "approval", "failed", "loading", "connectionDetail", "active", "inactive", "pending", "unknown",
    "needsAttention", "deliveryFailed", "observationOnly",
  ]
  for locale in ["en", "zh-Hans", "zh-Hant", "ja"] {
    for key in keys { #expect(DashboardStrings.text(key, locale: locale) != key) }
  }
}

@Test func abiRejectsBackgroundCalls() async {
  let status = await Task.detached { dashboardPublish(nil, 0) }.value
  #expect(status == 3)
}

@Test @MainActor func abiRejectsInvalidPointersBeforeOpeningAWindow() {
  #expect(dashboardPresent(nil, 0, nil, 0) == 0)
  #expect(dashboardPublish(nil, 100) == 0)
}
