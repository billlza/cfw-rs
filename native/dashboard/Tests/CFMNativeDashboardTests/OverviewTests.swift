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
  for (key, field) in fields { value[key] = field }
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
    ["version": 3], ["phase": "future"], ["core": "connected"], ["locale": "xx"],
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
      bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, closed, { _, _, _, _, _, _ in 0 },
      UInt(bitPattern: releases))
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
        { _, _, _, _, _, _ in 0 },
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
    "needsAttention", "deliveryFailed", "controlsHelp", "startCore", "stopCore", "applyingChange",
    "changeFailed", "requestRejected", "anotherChangePending", "continueApproval", "retryChange",
    "developmentPreview", "approvalHelp",
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
  #expect(dashboardPresent(nil, 0, nil, nil, 0) == 0)
  #expect(dashboardPublish(nil, 100) == 0)
}

private func availableControls(coreEnabled: Bool = false) -> [String: Any] {
  [
    "core": ["enabled": coreEnabled, "available": true, "reason": NSNull(), "retry": false],
    "systemProxy": ["enabled": false, "available": true, "reason": NSNull(), "retry": false],
    "tunnel": ["enabled": false, "available": true, "reason": NSNull(), "retry": false],
  ]
}

@Test @MainActor func commandsWaitForMatchingResultsWithoutOptimisticConnection() throws {
  let model = OverviewModel()
  try model.beginSession(OverviewFrame.decode(payload(["controls": availableControls()])))
  var requests: [(UInt64, UInt64, UInt64, NativeControl, Bool)] = []
  model.bindControl { session, revision, request, control, enabled in
    requests.append((session, revision, request, control, enabled))
    return 1
  }
  model.request(.core, enabled: true)
  #expect(model.pendingRequest == 1)
  #expect(model.frame?.core == .inactive)
  #expect(model.frame?.controls.core.enabled == false)
  model.request(.tunnel, enabled: true)
  #expect(requests.count == 1)
  #expect(requests[0].0 == 1 && requests[0].1 == 1 && requests[0].2 == 1)
  #expect(requests[0].3 == .core && requests[0].4)
  try model.accept(
    OverviewFrame.decode(
      payload([
        "sequence": 2, "controls": availableControls(),
        "command": ["requestId": 99, "pending": false, "error": NSNull()],
      ])))
  #expect(model.pendingRequest == 1, "an unrelated completion cannot clear pending work")
  try model.accept(
    OverviewFrame.decode(
      payload([
        "sequence": 3, "controls": availableControls(),
        "command": ["requestId": 1, "pending": false, "error": "Approval denied"],
      ])))
  #expect(model.pendingRequest == nil)
  #expect(model.actionError == "Approval denied")
  #expect(model.frame?.core == .inactive)
  model.request(.core, enabled: true)
  #expect(model.pendingRequest == 2)
  try model.accept(
    OverviewFrame.decode(
      payload([
        "sequence": 4, "phase": "active", "core": "active",
        "controls": availableControls(coreEnabled: true),
        "command": ["requestId": 2, "pending": false, "error": NSNull()],
      ])))
  #expect(model.pendingRequest == nil)
  #expect(model.actionError == nil)
  #expect(model.frame?.core == .active)
  model.request(.systemProxy, enabled: true)
  #expect(requests.last?.3 == .systemProxy && requests.last?.1 == 4)
}

@Test @MainActor func unavailableStaleAndClosedViewsCannotSubmit() throws {
  let model = OverviewModel()
  var calls = 0
  try model.beginSession(OverviewFrame.decode(fixture()))
  model.bindControl { _, _, _, _, _ in
    calls += 1
    return 1
  }
  model.request(.core, enabled: true)
  #expect(calls == 0)
  try model.accept(OverviewFrame.decode(payload(["sequence": 2, "controls": availableControls()])))
  model.rejectDelivery()
  model.request(.core, enabled: true)
  #expect(calls == 0)
  try model.accept(OverviewFrame.decode(payload(["sequence": 3, "controls": availableControls()])))
  model.disconnect()
  model.request(.core, enabled: true)
  #expect(calls == 0)
  model.bindControl { _, _, _, _, _ in
    calls += 1
    return 4
  }
  model.request(.core, enabled: true)
  #expect(calls == 1 && model.pendingRequest == nil)
  #expect(model.actionError == "Another change is in progress.")
}

@Test func malformedControlContractsAreRejected() throws {
  for command: [String: Any] in [
    ["requestId": 0, "pending": true, "error": NSNull()],
    ["requestId": 1, "pending": true, "error": "hidden failure"],
    ["requestId": 1, "pending": false, "error": ""],
  ] {
    let data = try payload(["command": command])
    #expect(throws: (any Error).self) { try OverviewFrame.decode(data) }
  }
  var invalid = availableControls()
  invalid["core"] = ["enabled": false, "available": false, "reason": NSNull(), "retry": false]
  let data = try payload(["controls": invalid])
  #expect(throws: (any Error).self) { try OverviewFrame.decode(data) }
}

@Test @MainActor func approvedOrFailedModeCanRetryWithoutTurningItsSwitchOff() throws {
  for phase in ["approval", "failed"] {
    let model = OverviewModel()
    let controls: [String: Any] = [
      "core": ["enabled": true, "available": true, "reason": NSNull(), "retry": true],
      "systemProxy": ["enabled": false, "available": true, "reason": NSNull(), "retry": false],
      "tunnel": ["enabled": true, "available": true, "reason": NSNull(), "retry": true],
    ]
    try model.beginSession(
      OverviewFrame.decode(
        payload([
          "phase": phase, "core": phase == "approval" ? "pending" : "unknown",
          "systemProxy": phase == "approval" ? "pending" : "unknown",
          "tunnel": phase == "approval" ? "pending" : "unknown",
          "failure": phase == "failed" ? "Authorization failed" : NSNull(),
          "controls": controls,
        ])))
    var calls = 0
    model.bindControl { _, _, _, control, enabled in
      #expect(control == .tunnel && enabled)
      calls += 1
      return 1
    }
    #expect(model.request(.tunnel, enabled: true) == 1)
    #expect(calls == 1)
    #expect(model.pendingRequest == 1)
    #expect(model.frame?.controls.tunnel.enabled == true)
  }
}

@Test @MainActor func runningModeCannotRestartWithoutAnAdmittedRetry() throws {
  let model = OverviewModel()
  try model.beginSession(
    OverviewFrame.decode(
      payload([
        "phase": "active", "core": "active", "controls": availableControls(coreEnabled: true),
      ])))
  var calls = 0
  model.bindControl { _, _, _, _, _ in
    calls += 1
    return 1
  }
  #expect(model.request(.core, enabled: true) == 0)
  #expect(calls == 0)
  var invalid = availableControls()
  invalid["core"] = ["enabled": false, "available": true, "reason": NSNull(), "retry": true]
  #expect(throws: (any Error).self) { try OverviewFrame.decode(payload(["controls": invalid])) }
}
