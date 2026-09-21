import AppKit
import SwiftUI
import Testing

@testable import CFMNativeDashboard

@Test @MainActor func rendersFourLanguagesInLightAndDarkAtMinimumSize() throws {
  for locale in ["en", "zh-Hans", "zh-Hant", "ja"] {
    for dark in [false, true] {
      let model = OverviewModel()
      let data = Data(
        """
        {"version":1,"sequence":1,"session":1,"locale":"\(locale)","phase":"failed",
         "core":"unknown","systemProxy":"unknown","tunnel":"unknown",
         "failure":"native operation query_status failed: Unavailable"}
        """.utf8)
      try model.accept(OverviewFrame.decode(data))
      let view = NSHostingView(
        rootView: OverviewView(model: model, onClose: {})
          .preferredColorScheme(dark ? .dark : .light))
      let window = NSWindow(
        contentRect: NSRect(x: -20000, y: -20000, width: 850, height: 603),
        styleMask: [.titled, .resizable], backing: .buffered, defer: false)
      window.isReleasedWhenClosed = false
      window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
      window.contentView = view
      defer { window.close() }
      window.orderFront(nil)
      RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
      view.layoutSubtreeIfNeeded()
      let bitmap = try #require(view.bitmapImageRepForCachingDisplay(in: view.bounds))
      window.effectiveAppearance.performAsCurrentDrawingAppearance {
        view.cacheDisplay(in: view.bounds, to: bitmap)
      }
      #expect(bitmap.pixelsWide >= 850)
      #expect(bitmap.pixelsHigh >= 603)
      if let output = ProcessInfo.processInfo.environment["CFM_NATIVE_RENDER_DIR"] {
        let png = try #require(bitmap.representation(using: .png, properties: [:]))
        let file = URL(fileURLWithPath: output).appendingPathComponent(
          "overview-\(locale)-\(dark ? "dark" : "light").png")
        try png.write(to: file)
      }
    }
  }
}

/// Component baseline only: this does not measure launch, RSS, energy or VPN
/// performance and is never compared against the complete 40073 application.
@Test @MainActor func boundedFrameDecodeAndPresentationBaseline() throws {
  let model = OverviewModel()
  let count = 10_000
  let clock = ContinuousClock()
  var samples = [Double]()
  samples.reserveCapacity(count)
  for index in 1...count {
    let data = Data(
      """
      {"version":1,"sequence":\(index),"session":1,"locale":"en","phase":"off",
       "core":"inactive","systemProxy":"inactive","tunnel":"inactive","failure":null}
      """.utf8)
    let start = clock.now
    try model.accept(OverviewFrame.decode(data))
    let elapsed = start.duration(to: clock.now).components
    samples.append(
      Double(elapsed.seconds) * 1_000_000 + Double(elapsed.attoseconds) / 1_000_000_000_000)
  }
  #expect(model.frame?.sequence == UInt64(count))
  if let output = ProcessInfo.processInfo.environment["CFM_NATIVE_RENDER_DIR"] {
    let sorted = samples.sorted()
    let report: [String: Any] = [
      "scope": "Swift decode and model acceptance only", "build": "debug", "samples": samples,
      "unit": "microseconds", "p50": sorted[count / 2], "p95": sorted[count * 95 / 100],
      "p99": sorted[count * 99 / 100],
      "product_performance_improvement_proven": false,
    ]
    try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
      .write(to: URL(fileURLWithPath: output).appendingPathComponent("frame-baseline.json"))
  }
}
