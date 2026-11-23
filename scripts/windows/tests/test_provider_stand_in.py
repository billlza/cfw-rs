"""Exercise the providers session's health-check stand-in over sockets, as the engine's HTTP outbound speaks to it."""
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "provider_stand_in.mjs"
URL = "http://192.0.2.1/generate_204"
# What the engine's HTTP outbound sends first, and what its URL test then
# sends through the tunnel, as Go's net/http writes them.
CONNECT = (b"CONNECT 192.0.2.1:80 HTTP/1.1\r\nHost: 192.0.2.1:80\r\nUser-Agent: Go-http-client/1.1\r\n"
           b"Proxy-Connection: Keep-Alive\r\n\r\n")
CHECK = b"HEAD /generate_204 HTTP/1.1\r\nHost: 192.0.2.1\r\nUser-Agent: Go-http-client/1.1\r\n\r\n"
ESTABLISHED = b"HTTP/1.1 200 Connection established\r\n\r\n"
ANSWERED = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"


def refusal(status):
    return f"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode()


class StandIn:
    """One stand-in process with its own receipt, stopped by closing its standard input."""

    def __init__(self, test, deadline=30):
        self.test = test
        node = shutil.which("node")
        test.assertIsNotNone(node, "Node is required; this boundary test cannot be skipped")
        self.directory = tempfile.TemporaryDirectory(prefix="cfw-provider-stand-in-")
        test.addCleanup(self.directory.cleanup)
        self.receipt = Path(self.directory.name) / "stand-in.jsonl"
        self.process = subprocess.Popen([node, str(SCRIPT), "127.0.0.1", URL, str(self.receipt), str(deadline)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        test.addCleanup(self.reap)
        self.port = self.wait_for("listening")["port"]

    def reap(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()

    def events(self):
        text = self.receipt.read_text(encoding="utf-8") if self.receipt.exists() else ""
        # A line still being written has no newline yet.
        return [json.loads(line) for line in text.splitlines(keepends=True) if line.endswith("\n")]

    def wait_for(self, event, timeout=10):
        waited = time.monotonic()
        while time.monotonic() - waited < timeout:
            found = [entry for entry in self.events() if entry["event"] == event]
            if found:
                return found[0]
            self.test.assertIsNone(self.process.poll(), f"the stand-in exited before {event}")
            time.sleep(0.02)
        self.test.fail(f"the stand-in recorded no {event} within {timeout} s")

    def exchange(self, *steps, timeout=5):
        """Send each step after the previous answer; return everything received until the stand-in closes."""
        received = b""
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as connection:
            for index, (data, answer) in enumerate(steps):
                connection.sendall(data)
                if index + 1 < len(steps):
                    while len(received) < len(answer):
                        chunk = connection.recv(4096)
                        self.test.assertNotEqual(chunk, b"", "the stand-in closed the connection early")
                        received += chunk
            while chunk := connection.recv(4096):
                received += chunk
        return received

    def close(self):
        self.process.stdin.close()
        self.test.assertEqual(self.process.wait(timeout=10), 0, self.process.stderr.read().decode())
        return self.events()


class ProviderStandInTests(unittest.TestCase):
    def test_a_check_through_the_tunnel_is_answered_and_recorded(self):
        stand_in = StandIn(self)
        self.assertEqual(stand_in.exchange((CONNECT, ESTABLISHED), (CHECK, ANSWERED)), ESTABLISHED + ANSWERED)
        get = CHECK.replace(b"HEAD ", b"GET ", 1).replace(b"Host: 192.0.2.1\r\n", b"host: 192.0.2.1:80\r\n")
        self.assertEqual(stand_in.exchange((CONNECT, ESTABLISHED), (get, ANSWERED)), ESTABLISHED + ANSWERED)
        # A check sent together with the proxy request is answered the same way.
        self.assertEqual(stand_in.exchange((CONNECT + CHECK, ANSWERED)), ESTABLISHED + ANSWERED)
        events = stand_in.close()
        self.assertEqual(events[0], {"event": "listening", "address": "127.0.0.1", "port": stand_in.port})
        self.assertEqual(events[1:], [
            {"event": "answered", "method": "HEAD", "path": "/generate_204", "host": "192.0.2.1"},
            {"event": "answered", "method": "GET", "path": "/generate_204", "host": "192.0.2.1:80"},
            {"event": "answered", "method": "HEAD", "path": "/generate_204", "host": "192.0.2.1"},
            {"event": "closed", "answered": 3, "refused": 0},
        ])

    def test_every_other_request_is_refused_and_none_is_answered(self):
        stand_in = StandIn(self)
        other = b"HEAD /generate_204 HTTP/1.1\r\nHost: %s\r\n\r\n"
        cases = [
            ([(b"CONNECT 192.0.2.2:80 HTTP/1.1\r\nHost: 192.0.2.2:80\r\n\r\n", b"")], "405 Method Not Allowed",
             "unexpected proxy request: CONNECT 192.0.2.2:80 HTTP/1.1"),
            ([(b"GET http://192.0.2.1/generate_204 HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n", b"")], "405 Method Not Allowed",
             "unexpected proxy request: GET http://192.0.2.1/generate_204 HTTP/1.1"),
            ([(CONNECT, ESTABLISHED), (CHECK.replace(b"/generate_204", b"/other"), b"")], "404 Not Found",
             "unexpected checked request: HEAD /other HTTP/1.1"),
            ([(CONNECT, ESTABLISHED), (other % b"example.com", b"")], "404 Not Found",
             "unexpected checked request: HEAD /generate_204 HTTP/1.1"),
            ([(CONNECT, ESTABLISHED), (CHECK.replace(b"HTTP/1.1", b"HTTP/1.0"), b"")], "404 Not Found",
             "unexpected checked request: HEAD /generate_204 HTTP/1.0"),
            ([(CONNECT, ESTABLISHED), (CHECK.replace(b"\r\n\r\n", b"\r\nHost: 192.0.2.1\r\n\r\n"), b"")], "404 Not Found",
             "unexpected checked request: HEAD /generate_204 HTTP/1.1"),
            ([(CONNECT, ESTABLISHED), (b"POST /generate_204 HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n", b"")], "404 Not Found",
             "unexpected checked request: POST /generate_204 HTTP/1.1"),
            ([(b"CONNECT 192.0.2.1:80 HTTP/1.1\r\nX: " + b"a" * 8200, b"")], "431 Request Header Fields Too Large",
             "request head too large"),
        ]
        for steps, status, _ in cases:
            prefix = ESTABLISHED if len(steps) == 2 else b""
            self.assertEqual(stand_in.exchange(*steps), prefix + refusal(status), status)
        events = stand_in.close()
        self.assertEqual([entry for entry in events if entry["event"] == "refused"],
                         [{"event": "refused", "reason": reason} for _, _, reason in cases])
        self.assertEqual(events[-1], {"event": "closed", "answered": 0, "refused": len(cases)})

    def test_an_incomplete_request_is_closed_after_its_idle_time(self):
        stand_in = StandIn(self)
        started = time.monotonic()
        self.assertEqual(stand_in.exchange((CONNECT[:20], b""), timeout=15), b"")
        self.assertGreaterEqual(time.monotonic() - started, 9.5)
        self.assertEqual(stand_in.close()[1:], [{"event": "refused", "reason": "incomplete request"},
                                                {"event": "closed", "answered": 0, "refused": 1}])

    def test_connections_beyond_the_total_bound_are_closed(self):
        stand_in = StandIn(self)
        for _ in range(256):
            self.assertEqual(stand_in.exchange((CONNECT + CHECK, ANSWERED)), ESTABLISHED + ANSWERED)
        # The connection over the bound is closed before it is read.
        self.assertEqual(stand_in.exchange((b"", b"")), b"")
        events = stand_in.close()
        self.assertEqual(events[-2:], [{"event": "refused", "reason": "connection bound"},
                                       {"event": "closed", "answered": 256, "refused": 1}])

    def test_the_deadline_ends_the_stand_in(self):
        stand_in = StandIn(self, deadline=1)
        self.assertEqual(stand_in.process.wait(timeout=10), 3)
        self.assertEqual([entry["event"] for entry in stand_in.events()], ["listening", "deadline"])

    def test_invalid_arguments_exit_before_listening(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is required; this boundary test cannot be skipped")
        with tempfile.TemporaryDirectory(prefix="cfw-provider-stand-in-") as directory:
            receipt = Path(directory) / "receipt.jsonl"
            existing = Path(directory) / "existing.jsonl"
            existing.write_text("kept\n", encoding="utf-8")
            valid = ["127.0.0.1", URL, str(receipt), "30"]
            cases = [
                ["localhost", *valid[1:]], ["::1", *valid[1:]],
                [valid[0], "https://192.0.2.1/generate_204", *valid[2:]],
                [valid[0], "http://user:secret@192.0.2.1/generate_204", *valid[2:]],
                [valid[0], "http://192.0.2.1/generate_204?probe=1", *valid[2:]],
                [valid[0], "http://192.0.2.1/generate_204#probe", *valid[2:]],
                [valid[0], "http://192.0.2.1:80/generate_204", *valid[2:]],
                [*valid[:2], "receipt.jsonl", valid[3]],
                [*valid[:2], str(existing), valid[3]],
                [*valid[:3], "0"], [*valid[:3], "3601"], [*valid[:3], "1.5"], [*valid, "extra"], valid[:3],
            ]
            for arguments in cases:
                # Run in the test's directory, so a relative receipt would land beside the others.
                result = subprocess.run([node, str(SCRIPT), *arguments], stdin=subprocess.DEVNULL, cwd=directory,
                                        capture_output=True, text=True, timeout=30, check=False)
                self.assertEqual(result.returncode, 2, arguments)
                self.assertTrue(result.stderr.startswith("provider stand-in: "), result.stderr)
                self.assertFalse(receipt.exists(), arguments)
            self.assertEqual(existing.read_text(encoding="utf-8"), "kept\n")


if __name__ == "__main__":
    unittest.main()
