import AppKit
import Foundation
import WebKit

// Isolated WebKit fault-injection fixture. It never loads a profile, starts a
// core, reaches the network, or uses the installed application's identity.
@MainActor
final class DashboardProbe: NSObject, WKNavigationDelegate {
  let webView: WKWebView
  let expected: String
  var completed = false
  var success = false
  var polling = false
  var observation = ""

  init(expected: String) {
    self.expected = expected
    let configuration = WKWebViewConfiguration()
    configuration.websiteDataStore = .nonPersistent()
    configuration.userContentController.addUserScript(
      WKUserScript(
        source: "window.__TAURI_INTERNALS__={invoke:function(command,args){if(command==='report_dashboard_startup'||command==='reveal_logs_directory')return Promise.resolve();return Promise.reject(new Error('Unexpected fixture IPC'));}};",
        injectionTime: .atDocumentStart,
        forMainFrameOnly: true
      ))
    webView = WKWebView(frame: CGRect(x: 0, y: 0, width: 850, height: 660), configuration: configuration)
    super.init()
    webView.navigationDelegate = self
  }

  func poll() {
    guard !polling, !completed else { return }
    polling = true
    webView.evaluateJavaScript(
      "JSON.stringify({recovery:!!document.getElementById('startup-recovery'),text:document.body.innerText,buttons:Array.from(document.querySelectorAll('#startup-recovery button')).map(b=>b.textContent)})"
    ) { [weak self] value, error in
      guard let self else { return }
      polling = false
      if let error {
        observation = "WebKit evaluation failed: \(error.localizedDescription)"
        return
      }
      guard let value = value as? String,
        let bytes = value.data(using: .utf8),
        let result = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any]
      else {
        observation = "WebKit returned no diagnostic observation"
        return
      }
      observation = value
      if result["recovery"] as? Bool == true,
        let text = result["text"] as? String,
        text.contains(expected),
        result["buttons"] as? [String] == ["Reload dashboard", "Open diagnostic logs"]
      {
        success = true
        completed = true
      }
    }
  }
}

@main
struct ProbeMain {
  @MainActor
  static func main() {
    guard CommandLine.arguments.count == 4,
      let seconds = Double(CommandLine.arguments[3]), seconds > 0, seconds <= 25
    else {
      fputs("usage: dashboard-startup-probe <index.html> <failure-code> <timeout-seconds>\n", stderr)
      exit(64)
    }
    let app = NSApplication.shared
    app.setActivationPolicy(.prohibited)
    let file = URL(fileURLWithPath: CommandLine.arguments[1])
    let probe = DashboardProbe(expected: CommandLine.arguments[2])
    probe.webView.loadFileURL(file, allowingReadAccessTo: file.deletingLastPathComponent())
    let deadline = Date().addingTimeInterval(seconds)
    var nextPoll = Date()
    while !probe.completed && Date() < deadline {
      RunLoop.current.run(until: Date().addingTimeInterval(0.02))
      if Date() >= nextPoll {
        probe.poll()
        nextPoll = Date().addingTimeInterval(0.1)
      }
    }
    print("os=\(ProcessInfo.processInfo.operatingSystemVersionString)")
    print("expected=\(probe.expected) success=\(probe.success)")
    print(probe.observation)
    exit(probe.success ? 0 : 1)
  }
}
