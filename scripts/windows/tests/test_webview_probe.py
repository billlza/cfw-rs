"""Exercise the CI readiness probe over real loopback HTTP, without a GUI mock."""
import http.server
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest


MODULE = Path(__file__).resolve().parents[1] / "webview_probe.psm1"
POWERSHELL = r"""
param([string]$ProbeModule, [string]$Endpoint, [int]$Budget)
$ErrorActionPreference = 'Stop'
Import-Module $ProbeModule -Force
$attempts = [Collections.Generic.List[object]]::new()
$result = $null
$failure = $null
try {
    $result = Wait-CfwWebView2 -Controller ([Diagnostics.Process]::GetCurrentProcess()) `
        -Endpoint $Endpoint -ProbeAttempts $attempts -TimeoutSeconds $Budget
} catch { $failure = $_.Exception.ToString() }
[ordered]@{ result=$result; failure=$failure; attempts=$attempts.ToArray() } | ConvertTo-Json -Depth 8 -Compress
"""


class ProbeTests(unittest.TestCase):
    def probe(self, endpoint, budget=10):
        executable = shutil.which("pwsh")
        self.assertIsNotNone(executable, "PowerShell is required; this boundary test cannot be skipped")
        with tempfile.TemporaryDirectory(prefix="cfw-webview-probe-") as directory:
            script = Path(directory) / "probe.ps1"
            script.write_text(POWERSHELL, encoding="utf-8")
            result = subprocess.run(
                [executable, "-NoProfile", "-File", str(script), "-ProbeModule", str(MODULE),
                 "-Endpoint", endpoint, "-Budget", str(budget)],
                capture_output=True, text=True, timeout=budget + 10, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "", result.stderr)
        return json.loads(result.stdout)

    def serve(self, mode):
        class Handler(http.server.BaseHTTPRequestHandler):
            calls = 0

            def log_message(self, _format, *_arguments):
                pass  # The test examines responses and request counts directly.

            def do_GET(self):
                Handler.calls += 1
                if mode == "delayed" and Handler.calls == 1:
                    # Exceed one HttpClient observation, then close that expired
                    # request without writing to its already-cancelled socket.
                    time.sleep(2.6)
                    self.close_connection = True
                    return
                body = b"invalid json" if mode == "malformed" else json.dumps({
                    "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/browser/readiness-fixture"
                }).encode()
                self.send_response(401 if mode == "unauthorized" else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}", Handler

    def test_startup_timeout_can_be_followed_by_real_metadata(self):
        endpoint, handler = self.serve("delayed")
        value = self.probe(endpoint)
        self.assertIsNone(value["failure"], value["failure"])
        self.assertTrue(value["result"]["webSocketDebuggerUrl"].startswith("ws://127.0.0.1/"))
        self.assertEqual(handler.calls, 2)
        self.assertEqual(len(value["attempts"]), 1)
        self.assertTrue(value["attempts"][0]["request_timed_out"])

    def test_http_authentication_failure_is_not_retried(self):
        endpoint, handler = self.serve("unauthorized")
        value = self.probe(endpoint)
        self.assertIsNone(value["result"])
        self.assertIn("401", value["failure"])
        self.assertEqual(handler.calls, 1)
        self.assertEqual(len(value["attempts"]), 1)
        self.assertFalse(value["attempts"][0]["request_timed_out"])

    def test_malformed_metadata_is_not_retried(self):
        endpoint, handler = self.serve("malformed")
        value = self.probe(endpoint)
        self.assertIsNone(value["result"])
        self.assertIsNotNone(value["failure"])
        self.assertEqual(handler.calls, 1)
        self.assertEqual(len(value["attempts"]), 1)

    def test_unavailable_endpoint_stops_at_the_startup_bound(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            endpoint = f"http://127.0.0.1:{reservation.getsockname()[1]}"
        # The closed endpoint can refuse the connection or reach HttpClient's
        # observation deadline (both were observed on native hosts). Neither
        # outcome may become ready or extend the overall startup budget.
        started = time.monotonic()
        value = self.probe(endpoint, budget=1)
        self.assertIsNone(value["result"])
        self.assertIn("WebView2 startup deadline", value["failure"])
        self.assertTrue(all(
            attempt["connection_refused"] or attempt["request_timed_out"]
            for attempt in value["attempts"]
        ), value["attempts"])
        self.assertGreaterEqual(len(value["attempts"]), 1)
        self.assertLess(time.monotonic() - started, 6)


if __name__ == "__main__":
    unittest.main()
