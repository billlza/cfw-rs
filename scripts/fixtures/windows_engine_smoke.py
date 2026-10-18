"""Native Windows engine component checks using only isolated loopback traffic."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import http.server
import json
from pathlib import Path
import platform
import queue
import socket
import struct
import subprocess
import threading
import time
import uuid


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def receive_exact(stream: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        block = stream.recv(length - len(result))
        require(bool(block), "peer closed a protocol message early")
        result.extend(block)
    return bytes(result)


def socks_request(port: int, command: int, destination: tuple[str, int]) -> tuple[socket.socket, tuple[str, int]]:
    stream = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        stream.sendall(b"\x05\x01\x00")
        require(receive_exact(stream, 2) == b"\x05\x00", "SOCKS authentication negotiation failed")
        address, destination_port = destination
        stream.sendall(bytes((5, command, 0, 1)) + socket.inet_aton(address) + struct.pack("!H", destination_port))
        require(receive_exact(stream, 4) == b"\x05\x00\x00\x01", "SOCKS request or IPv4 relay failed")
        peer = socket.inet_ntoa(receive_exact(stream, 4)), struct.unpack("!H", receive_exact(stream, 2))[0]
        return stream, peer
    except BaseException:
        stream.close()
        raise


def assert_closed(port: int) -> None:
    try:
        connection = socket.create_connection(("127.0.0.1", port), timeout=2)
    except ConnectionRefusedError:
        return
    connection.close()
    raise RuntimeError(f"test listener on port {port} is still open")


def reserve_port() -> tuple[socket.socket, int]:
    held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    held.bind(("127.0.0.1", 0))
    return held, held.getsockname()[1]


def smoke(artifacts: Path) -> dict[str, object]:
    require(platform.system() == "Windows", "this evidence requires native Windows")
    manifest = json.loads((artifacts / "build-receipt.json").read_text(encoding="utf-8"))
    executable = artifacts / "cfw-engine.exe"
    require(manifest["artifact"]["filename"] == executable.name, "unexpected engine artifact name")
    require(digest(executable) == manifest["artifact"]["sha256"], "engine artifact hash mismatch")
    nonce = uuid.uuid4().hex
    payload = f"cfw-loopback-{nonce}".encode()
    observed: queue.Queue[str] = queue.Queue()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            observed.put(self.path)
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            # A silent controlled fixture; all assertions use captured receipts.
            return

    http_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()
    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server.bind(("127.0.0.1", 0))
    udp_server.settimeout(0.25)
    udp_address = udp_server.getsockname()
    udp_stop = threading.Event()
    udp_failures: queue.Queue[BaseException] = queue.Queue()

    def echo_udp() -> None:
        while not udp_stop.is_set():
            try:
                data, peer = udp_server.recvfrom(4096)
                require(data == payload, "unexpected UDP fixture payload")
                udp_server.sendto(data, peer)
            except socket.timeout:
                continue
            except BaseException as error:
                udp_failures.put(error)
                return

    udp_thread = threading.Thread(target=echo_udp, daemon=True)
    udp_thread.start()
    mixed_reservation, mixed_port = reserve_port()
    api_reservation, api_port = reserve_port()
    token = f"fixture-token-{nonce}"
    configuration = {
        "log": {"disabled": True},
        "inbounds": [{"type": "mixed", "tag": "fixture-in", "listen": "127.0.0.1", "listen_port": mixed_port}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
        "experimental": {"clash_api": {"external_controller": f"127.0.0.1:{api_port}", "secret": token}},
    }
    encoded = json.dumps(configuration, separators=(",", ":")).encode()
    process = None
    log_path = artifacts / "loopback-engine.log"
    try:
        check = subprocess.run([str(executable), "check", "-c", "stdin"], input=encoded,
                               capture_output=True, timeout=15, cwd=artifacts)
        (artifacts / "check.stdout.txt").write_bytes(check.stdout)
        (artifacts / "check.stderr.txt").write_bytes(check.stderr)
        require(check.returncode == 0, "the pinned engine rejected the valid loopback configuration")
        negative = subprocess.run([str(executable), "check", "-c", "stdin"],
                                  input=b'{"inbounds":[{"type":"cfw-invalid-inbound"}]}',
                                  capture_output=True, timeout=15, cwd=artifacts)
        require(negative.returncode != 0, "invalid engine configuration was reported as valid")
        mixed_reservation.close()
        api_reservation.close()
        assert_closed(mixed_port)
        assert_closed(api_port)
        with log_path.open("xb") as log:
            process = subprocess.Popen([str(executable), "run", "-c", "stdin"], stdin=subprocess.PIPE,
                                       stdout=log, stderr=log, cwd=artifacts)
            require(process.stdin is not None, "engine input pipe was not created")
            process.stdin.write(encoded)
            process.stdin.close()
            deadline = time.monotonic() + 15
            while True:
                require(process.poll() is None, "engine exited before controller readiness")
                connection = http.client.HTTPConnection("127.0.0.1", api_port, timeout=2)
                try:
                    connection.request("GET", "/version", headers={"Authorization": f"Bearer {token}"})
                    response = connection.getresponse()
                    body = response.read(4097)
                    require(response.status == 200 and len(body) <= 4096, "engine controller identity response failed")
                    version = json.loads(body)
                    require(manifest["engine_version"][1:] in version["version"], "unexpected controller engine version")
                    break
                except ConnectionRefusedError:
                    require(time.monotonic() < deadline, "controller readiness timed out")
                    time.sleep(0.1)
                finally:
                    connection.close()
            connection = http.client.HTTPConnection("127.0.0.1", api_port, timeout=3)
            try:
                connection.request("GET", "/version")
                response = connection.getresponse()
                require(response.status == 401, "controller accepted an unauthenticated request")
                response.read(4096)
            finally:
                connection.close()
            destination_port = http_server.server_port
            connection = http.client.HTTPConnection("127.0.0.1", mixed_port, timeout=5)
            try:
                connection.request("GET", f"http://127.0.0.1:{destination_port}/http-{nonce}")
                response = connection.getresponse()
                require(response.status == 200 and response.read(len(payload) + 1) == payload,
                        "HTTP proxy did not deliver the exact fixture bytes")
                require(observed.get(timeout=2) == f"/http-{nonce}", "HTTP destination did not observe the proxy request")
            finally:
                connection.close()
            stream, _ = socks_request(mixed_port, 1, ("127.0.0.1", destination_port))
            with stream:
                stream.sendall(f"GET /socks-{nonce} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
                response = http.client.HTTPResponse(stream)
                response.begin()
                require(response.status == 200 and response.read(len(payload) + 1) == payload,
                        "SOCKS TCP did not deliver the exact fixture bytes")
                require(observed.get(timeout=2) == f"/socks-{nonce}", "SOCKS destination did not observe the request")
                response.close()
            stream, relay = socks_request(mixed_port, 3, ("0.0.0.0", 0))
            with stream, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                require(relay[0] == "127.0.0.1" and relay[1] != 0, "SOCKS UDP relay escaped the loopback fixture")
                client.settimeout(5)
                packet = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", udp_address[1]) + payload
                client.sendto(packet, relay)
                reply, sender = client.recvfrom(4096)
                require(sender == relay and reply == packet, "SOCKS UDP did not deliver the exact fixture datagram")
            require(udp_failures.empty(), "UDP fixture failed")
            require(process.poll() is None, "engine stopped during loopback checks")
            # This fixture verifies forced child cleanup only. Graceful owner
            # shutdown and OS proxy/TUN recovery require the product backend.
            process.kill()
            process.wait(timeout=10)
        assert_closed(mixed_port)
        assert_closed(api_port)
        return {"schema_version": 1, "product_source": manifest["product_source"],
                "engine_sha256": manifest["artifact"]["sha256"], "platform": platform.platform(),
                "valid_config_check": True, "invalid_config_rejected": True,
                "authenticated_controller": True, "unauthenticated_controller_rejected": True,
                "http_proxy": True, "socks_tcp": True, "socks_udp": True,
                "forced_termination_listener_cleanup": True, "graceful_shutdown_verified": False,
                "system_proxy_modified": False, "tun_installed": False, "release_accepted": False}
    finally:
        mixed_reservation.close()
        api_reservation.close()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        udp_stop.set()
        udp_thread.join(timeout=2)
        udp_server.close()
        http_server.shutdown()
        http_server.server_close()
        http_thread.join(timeout=2)
        require(not udp_thread.is_alive() and not http_thread.is_alive(), "fixture thread cleanup did not finish")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    arguments = parser.parse_args()
    artifacts = arguments.artifacts.resolve(strict=True)
    result = smoke(artifacts)
    (artifacts / "loopback-receipt.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
