"""Fail-closed client for the source-pinned physical-evidence Cloud Run services.

The module intentionally separates failures before a state-changing request from
failures after the one permitted POST begins.  A caller may retry a
``PreSendError`` after correcting local authentication or service drift.  An
``OutcomeUnknownError`` is terminal for that attempt: this client never follows
redirects and never retries a POST.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import http.client
import os
from pathlib import Path
import re
import selectors
import signal
import ssl
import stat
import subprocess
import time
from typing import Any, Callable, Literal, Protocol, Sequence
from urllib.parse import urlsplit

from scripts.harness.raw_artifacts import (
    RawArtifactError,
    canonical_json,
    exact_object,
    load_json_bytes,
    read_regular_file_bytes,
    require_sha256,
)


ENDPOINT_POLICY_PATH = Path(__file__).with_name("endpoints.json")
ENDPOINT_POLICY_SHA256 = (
    "76e5a84232c92f1332ad29abe31c2d8111a9ff151821b58b10ac3b760873ee5f"
)
ENDPOINT_POLICY_DOCUMENT = "cfw-physical-collector-endpoints-v1"
ENDPOINT_POLICY_SCHEMA_VERSION = 1

GCLOUD = Path("/opt/homebrew/bin/gcloud")
GCLOUD_TIMEOUT_SECONDS = 30.0
HTTPS_TIMEOUT_SECONDS = 30.0
MAX_ENDPOINT_POLICY_BYTES = 16 * 1024
MAX_GCLOUD_DESCRIBE_BYTES = 64 * 1024
MAX_GCLOUD_STDERR_BYTES = 4 * 1024
MAX_ID_TOKEN_BYTES = 16 * 1024
MAX_REQUEST_BYTES = 1 << 20
MAX_RESPONSE_BYTES = 1 << 20
READ_CHUNK_BYTES = 64 * 1024
USER_AGENT = "cfw-physical-capture/1"

EndpointRole = Literal["nonce_issuer", "receipt_signer"]

POLICY_FIELDS = {
    "schema_version",
    "document",
    "project",
    "region",
    "identity_service_account",
    "nonce_issuer",
    "receipt_signer",
}
ENDPOINT_FIELDS = {
    "service",
    "revision",
    "origin",
    "audience",
    "route",
    "success_status",
}
NONCE_REQUEST_FIELDS = {"schema_version", "candidate", "run"}
RECEIPT_REQUEST_FIELDS = {
    "schema_version",
    "candidate",
    "run",
    "reports",
    "raw_artifacts",
}
NONCE_RESPONSE_FIELDS = {"schema_version", "run_nonce", "expires_at"}
RECEIPT_RESPONSE_FIELDS = {
    "schema_version",
    "signed_at",
    "receipt_sha256",
    "signature",
}

PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
SERVICE_ACCOUNT_RE = re.compile(
    r"^[a-z][a-z0-9-]{4,28}[a-z0-9]@"
    r"(?P<project>[a-z][a-z0-9-]{4,28}[a-z0-9])\.iam\.gserviceaccount\.com$"
)
REGION_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
SERVICE_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
UTC_SECONDS_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")


class CloudRunClientError(RuntimeError):
    """Base class for physical-collector transport failures."""


class PreSendError(CloudRunClientError):
    """The client proved that the state-changing request did not begin."""


class OutcomeUnknownError(CloudRunClientError):
    """A POST began but no complete trusted success response was obtained."""


class _CommandError(RuntimeError):
    """A fixed local gcloud command failed without exposing its output."""


@dataclass(frozen=True)
class Endpoint:
    role: EndpointRole
    service: str
    revision: str
    origin: str
    audience: str
    route: str
    success_status: int
    host: str


@dataclass(frozen=True)
class EndpointPolicy:
    project: str
    region: str
    identity_service_account: str
    nonce_issuer: Endpoint
    receipt_signer: Endpoint
    sha256: str

    def endpoint(self, role: EndpointRole) -> Endpoint:
        if role == "nonce_issuer":
            return self.nonce_issuer
        if role == "receipt_signer":
            return self.receipt_signer
        raise PreSendError("collector endpoint role is unsupported")


@dataclass(frozen=True)
class NonceResponse:
    schema_version: int
    run_nonce: str = field(repr=False)
    expires_at: str

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_nonce": self.run_nonce,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class ReceiptResponse:
    schema_version: int
    signed_at: str
    receipt_sha256: str
    signature: str = field(repr=False)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "signed_at": self.signed_at,
            "receipt_sha256": self.receipt_sha256,
            "signature": self.signature,
        }


CollectorResponse = NonceResponse | ReceiptResponse


@dataclass(frozen=True)
class CommandOutput:
    """Bounded output from one fixed local gcloud invocation."""

    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)


class _Headers(Protocol):
    def get_all(self, name: str, failobj: object = None) -> list[str]: ...


class _Response(Protocol):
    status: int
    headers: _Headers

    def read(self, amount: int | None = None) -> bytes: ...

    def close(self) -> None: ...


class _Connection(Protocol):
    def request(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None: ...

    def getresponse(self) -> _Response: ...

    def close(self) -> None: ...


CommandRunner = Callable[[Sequence[str], int], CommandOutput]
ConnectionFactory = Callable[[str, int, float, ssl.SSLContext], _Connection]


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            raise _CommandError("fixed gcloud command could not be terminated") from error


def _gcloud_environment() -> dict[str, str]:
    home = Path.home()
    try:
        resolved_home = home.resolve(strict=True)
    except OSError as error:
        raise _CommandError("local gcloud credential home is unavailable") from error
    if not resolved_home.is_dir():
        raise _CommandError("local gcloud credential home is not a directory")
    return {
        "HOME": str(resolved_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
        "CLOUDSDK_PYTHON_SITEPACKAGES": "0",
    }


def _run_gcloud(
    command: Sequence[str], maximum_stdout_bytes: int
) -> CommandOutput:
    if (
        not command
        or command[0] != str(GCLOUD)
        or maximum_stdout_bytes < 1
        or maximum_stdout_bytes > MAX_GCLOUD_DESCRIBE_BYTES
    ):
        raise _CommandError("fixed gcloud invocation is invalid")
    try:
        executable = GCLOUD.resolve(strict=True)
        metadata = executable.stat()
    except OSError as error:
        raise _CommandError("fixed gcloud executable is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or not os.access(executable, os.X_OK):
        raise _CommandError("fixed gcloud executable is not executable")

    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_gcloud_environment(),
            start_new_session=True,
        )
    except OSError as error:
        raise _CommandError("fixed gcloud command could not start") from error
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        raise _CommandError("fixed gcloud command output pipes are unavailable")

    selector = selectors.DefaultSelector()
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    buffers = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    limits = {
        stdout_fd: maximum_stdout_bytes,
        stderr_fd: MAX_GCLOUD_STDERR_BYTES,
    }
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    deadline = time.monotonic() + GCLOUD_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _CommandError("fixed gcloud command timed out")
            for key, _events in selector.select(min(remaining, 1.0)):
                chunk = os.read(key.fd, READ_CHUNK_BYTES)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.fd].extend(chunk)
                if len(buffers[key.fd]) > limits[key.fd]:
                    raise _CommandError("fixed gcloud command output exceeded its bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _CommandError("fixed gcloud command timed out")
        returncode = process.wait(timeout=remaining)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        else:
            _kill_process_group(process)
            raise _CommandError("fixed gcloud command left a descendant process")
    except (OSError, subprocess.SubprocessError, _CommandError) as error:
        _kill_process_group(process)
        if isinstance(error, _CommandError):
            raise
        raise _CommandError("fixed gcloud command failed") from error
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()

    if returncode != 0:
        raise _CommandError("fixed gcloud command failed closed")
    return CommandOutput(
        stdout=bytes(buffers[stdout_fd]),
        stderr=bytes(buffers[stderr_fd]),
    )


def _default_connection_factory(
    host: str, port: int, timeout: float, context: ssl.SSLContext
) -> _Connection:
    return http.client.HTTPSConnection(
        host,
        port=port,
        timeout=timeout,
        context=context,
    )


def _parse_endpoint(role: EndpointRole, value: Any) -> Endpoint:
    raw = exact_object(value, ENDPOINT_FIELDS, f"endpoint policy.{role}")
    service = raw["service"]
    revision = raw["revision"]
    if not isinstance(service, str) or not SERVICE_RE.fullmatch(service):
        raise RawArtifactError(f"endpoint policy.{role}.service is invalid")
    if not isinstance(revision, str) or not re.fullmatch(
        re.escape(service) + r"-[0-9]{5}-[a-z0-9]{3}", revision
    ):
        raise RawArtifactError(f"endpoint policy.{role}.revision is invalid")

    origin = raw["origin"]
    audience = raw["audience"]
    if not isinstance(origin, str) or audience != origin:
        raise RawArtifactError(f"endpoint policy.{role} origin/audience differs")
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as error:
        raise RawArtifactError(f"endpoint policy.{role}.origin is invalid") from error
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or host is None
        or host != host.lower()
        or not host.endswith(".a.run.app")
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise RawArtifactError(
            f"endpoint policy.{role}.origin leaves the fixed Cloud Run HTTPS boundary"
        )

    expected_route = "/v1/nonces" if role == "nonce_issuer" else "/v1/receipts"
    expected_status = 201 if role == "nonce_issuer" else 200
    if raw["route"] != expected_route or raw["success_status"] != expected_status:
        raise RawArtifactError(f"endpoint policy.{role} route/status is invalid")
    return Endpoint(
        role=role,
        service=service,
        revision=revision,
        origin=origin,
        audience=audience,
        route=expected_route,
        success_status=expected_status,
        host=host,
    )


def load_endpoint_policy() -> EndpointPolicy:
    """Reopen and validate the sole source-pinned Cloud Run endpoint policy."""

    try:
        data = read_regular_file_bytes(
            ENDPOINT_POLICY_PATH, maximum=MAX_ENDPOINT_POLICY_BYTES
        )
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != ENDPOINT_POLICY_SHA256:
            raise RawArtifactError("physical collector endpoint policy digest drifted")
        value = load_json_bytes(data, "physical collector endpoint policy")
        if canonical_json(value) + b"\n" != data:
            raise RawArtifactError("physical collector endpoint policy is not canonical")
        policy = exact_object(value, POLICY_FIELDS, "physical collector endpoint policy")
        if (
            type(policy["schema_version"]) is not int
            or policy["schema_version"] != ENDPOINT_POLICY_SCHEMA_VERSION
            or policy["document"] != ENDPOINT_POLICY_DOCUMENT
        ):
            raise RawArtifactError("physical collector endpoint policy schema is unsupported")
        project = policy["project"]
        region = policy["region"]
        identity_service_account = policy["identity_service_account"]
        if not isinstance(project, str) or not PROJECT_RE.fullmatch(project):
            raise RawArtifactError("physical collector endpoint project is invalid")
        if not isinstance(region, str) or not REGION_RE.fullmatch(region):
            raise RawArtifactError("physical collector endpoint region is invalid")
        if not isinstance(identity_service_account, str):
            raise RawArtifactError(
                "physical collector identity service account is invalid"
            )
        service_account_match = SERVICE_ACCOUNT_RE.fullmatch(
            identity_service_account
        )
        if (
            service_account_match is None
            or service_account_match.group("project") != project
        ):
            raise RawArtifactError(
                "physical collector identity service account is outside the project"
            )
        return EndpointPolicy(
            project=project,
            region=region,
            identity_service_account=identity_service_account,
            nonce_issuer=_parse_endpoint("nonce_issuer", policy["nonce_issuer"]),
            receipt_signer=_parse_endpoint(
                "receipt_signer", policy["receipt_signer"]
            ),
            sha256=actual_sha256,
        )
    except (OSError, RawArtifactError, ValueError) as error:
        raise PreSendError("source-pinned collector endpoint policy is unavailable") from None


def _describe_command(policy: EndpointPolicy, endpoint: Endpoint) -> list[str]:
    return [
        str(GCLOUD),
        "run",
        "services",
        "describe",
        endpoint.service,
        f"--project={policy.project}",
        f"--region={policy.region}",
        "--format=json(metadata.name,status.url,status.latestReadyRevisionName,status.traffic)",
        "--quiet",
    ]


def _verify_live_revision(
    policy: EndpointPolicy, endpoint: Endpoint, runner: CommandRunner
) -> None:
    try:
        output = runner(
            _describe_command(policy, endpoint), MAX_GCLOUD_DESCRIBE_BYTES
        )
        if not isinstance(output, CommandOutput) or output.stderr:
            raise _CommandError("fixed gcloud service description emitted stderr")
        document = exact_object(
            load_json_bytes(
                output.stdout, "gcloud Cloud Run service description"
            ),
            {"metadata", "status"},
            "gcloud Cloud Run service description",
        )
        metadata = exact_object(
            document["metadata"], {"name"}, "gcloud service metadata"
        )
        status = exact_object(
            document["status"],
            {"url", "latestReadyRevisionName", "traffic"},
            "gcloud service status",
        )
        traffic = status["traffic"]
        if not isinstance(traffic, list) or len(traffic) != 1:
            raise RawArtifactError("gcloud service traffic is not a single target")
        target = exact_object(
            traffic[0],
            {"latestRevision", "percent", "revisionName"},
            "gcloud service traffic target",
        )
        if (
            metadata["name"] != endpoint.service
            or status["url"] != endpoint.origin
            or status["latestReadyRevisionName"] != endpoint.revision
            or target["latestRevision"] is not True
            or target["percent"] != 100
            or target["revisionName"] != endpoint.revision
        ):
            raise RawArtifactError("live Cloud Run service differs from endpoint policy")
    except (OSError, RawArtifactError, ValueError, _CommandError) as error:
        raise PreSendError(
            "live Cloud Run service does not match the source-pinned endpoint policy"
        ) from None


def _identity_token(
    policy: EndpointPolicy, endpoint: Endpoint, runner: CommandRunner
) -> str:
    command = [
        str(GCLOUD),
        "auth",
        "print-identity-token",
        f"--impersonate-service-account={policy.identity_service_account}",
        f"--audiences={endpoint.audience}",
        "--quiet",
    ]
    try:
        output = runner(command, MAX_ID_TOKEN_BYTES)
        if not isinstance(output, CommandOutput):
            raise _CommandError("fixed gcloud token command returned invalid output")
        expected_warning = (
            "WARNING: This command is using service account impersonation. "
            "All API calls will be executed as "
            f"[{policy.identity_service_account}].\n"
        ).encode("ascii")
        if output.stderr not in (b"", expected_warning):
            raise _CommandError("fixed gcloud token command emitted unexpected stderr")
        data = output.stdout
    except (OSError, ValueError, _CommandError) as error:
        raise PreSendError("Cloud Run identity token is unavailable") from None
    if data.endswith(b"\n"):
        data = data[:-1]
    if (
        not data
        or len(data) > MAX_ID_TOKEN_BYTES
        or b"\n" in data
        or b"\r" in data
    ):
        raise PreSendError("Cloud Run identity token is malformed")
    try:
        token = data.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise PreSendError("Cloud Run identity token is malformed") from None
    if len(token) < 32 or not JWT_RE.fullmatch(token):
        raise PreSendError("Cloud Run identity token is malformed")
    try:
        encoded_payload = token.split(".")[1].encode("ascii")
        padded_payload = encoded_payload + b"=" * (-len(encoded_payload) % 4)
        payload = base64.b64decode(
            padded_payload, altchars=b"-_", validate=True
        )
        claims = load_json_bytes(payload, "Cloud Run identity token payload")
    except (UnicodeEncodeError, ValueError, RawArtifactError):
        raise PreSendError("Cloud Run identity token is malformed") from None
    if not isinstance(claims, dict) or claims.get("aud") != endpoint.audience:
        raise PreSendError(
            "Cloud Run identity token audience differs from the pinned endpoint"
        )
    return token


def _request_bytes(role: EndpointRole, value: Any) -> bytes:
    try:
        fields = NONCE_REQUEST_FIELDS if role == "nonce_issuer" else RECEIPT_REQUEST_FIELDS
        request = exact_object(value, fields, f"{role} request")
        if type(request["schema_version"]) is not int or request["schema_version"] != 1:
            raise RawArtifactError(f"{role} request schema_version is unsupported")
        encoded = canonical_json(request) + b"\n"
        if len(encoded) > MAX_REQUEST_BYTES:
            raise RawArtifactError(f"{role} request exceeds its byte bound")
        return encoded
    except (RawArtifactError, TypeError, UnicodeEncodeError, ValueError) as error:
        raise PreSendError("collector request failed local strict validation") from None


def _header_values(response: _Response, name: str) -> list[str]:
    getter = getattr(response.headers, "get_all", None)
    if not callable(getter):
        raise ValueError("response headers are not inspectable")
    values = getter(name, [])
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise ValueError("response header is malformed")
    return values


def _one_header(response: _Response, name: str, *, required: bool) -> str | None:
    values = _header_values(response, name)
    if not values:
        if required:
            raise ValueError("required response header is absent")
        return None
    if len(values) != 1:
        raise ValueError("response header is repeated")
    return values[0]


def _read_bounded_response(response: _Response) -> bytes:
    declared = _one_header(response, "Content-Length", required=False)
    expected_length: int | None = None
    if declared is not None:
        if not DECIMAL_RE.fullmatch(declared):
            raise ValueError("response Content-Length is invalid")
        expected_length = int(declared)
        if expected_length < 1 or expected_length > MAX_RESPONSE_BYTES:
            raise ValueError("response Content-Length is outside its bound")

    result = bytearray()
    while True:
        remaining = MAX_RESPONSE_BYTES + 1 - len(result)
        if remaining <= 0:
            raise ValueError("response body exceeds its byte bound")
        chunk = response.read(min(READ_CHUNK_BYTES, remaining))
        if not isinstance(chunk, bytes):
            raise ValueError("response body reader returned non-bytes")
        if not chunk:
            break
        result.extend(chunk)
        if len(result) > MAX_RESPONSE_BYTES:
            raise ValueError("response body exceeds its byte bound")
    if not result or (expected_length is not None and len(result) != expected_length):
        raise ValueError("response body length is invalid")
    return bytes(result)


def _utc_seconds(value: Any, label: str) -> str:
    if not isinstance(value, str) or not UTC_SECONDS_RE.fullmatch(value):
        raise RawArtifactError(f"{label} is not a canonical UTC timestamp")
    try:
        time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise RawArtifactError(f"{label} is not a real UTC timestamp") from error
    return value


def _receipt_signature(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 512
        or not BASE64URL_RE.fullmatch(value)
    ):
        raise RawArtifactError("receipt signature is not canonical RSA-3072 base64url")
    try:
        decoded = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise RawArtifactError("receipt signature is not canonical base64url") from error
    if (
        len(decoded) != 384
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value
    ):
        raise RawArtifactError("receipt signature is not canonical RSA-3072 base64url")
    return value


def _response_document(endpoint: Endpoint, data: bytes) -> CollectorResponse:
    value = load_json_bytes(data, f"{endpoint.role} response")
    if endpoint.role == "nonce_issuer":
        response = exact_object(value, NONCE_RESPONSE_FIELDS, "nonce response")
        if type(response["schema_version"]) is not int or response["schema_version"] != 1:
            raise RawArtifactError("nonce response schema_version is unsupported")
        return NonceResponse(
            schema_version=1,
            run_nonce=require_sha256(response["run_nonce"], "nonce response.run_nonce"),
            expires_at=_utc_seconds(response["expires_at"], "nonce response.expires_at"),
        )

    response = exact_object(value, RECEIPT_RESPONSE_FIELDS, "receipt response")
    if type(response["schema_version"]) is not int or response["schema_version"] != 1:
        raise RawArtifactError("receipt response schema_version is unsupported")
    return ReceiptResponse(
        schema_version=1,
        signed_at=_utc_seconds(response["signed_at"], "receipt response.signed_at"),
        receipt_sha256=require_sha256(
            response["receipt_sha256"], "receipt response.receipt_sha256"
        ),
        signature=_receipt_signature(response["signature"]),
    )


def _validate_response(endpoint: Endpoint, response: _Response) -> CollectorResponse:
    if type(response.status) is not int or response.status != endpoint.success_status:
        raise ValueError("collector returned an unexpected HTTP status")
    if (
        _one_header(response, "Content-Type", required=True)
        != "application/json; charset=utf-8"
    ):
        raise ValueError("collector response Content-Type is invalid")
    if _one_header(response, "Content-Encoding", required=False) is not None:
        raise ValueError("collector response Content-Encoding is forbidden")
    data = _read_bounded_response(response)
    try:
        return _response_document(endpoint, data)
    except (RawArtifactError, ValueError) as error:
        raise ValueError("collector response failed strict JSON validation") from None


def _tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class CloudRunClient:
    """One-shot authenticated POST client with no redirect or retry path."""

    def __init__(
        self,
        *,
        command_runner: CommandRunner = _run_gcloud,
        connection_factory: ConnectionFactory = _default_connection_factory,
    ) -> None:
        self._policy = load_endpoint_policy()
        self._command_runner = command_runner
        self._connection_factory = connection_factory

    @property
    def endpoint_policy_sha256(self) -> str:
        return self._policy.sha256

    def issue_nonce(self, request: Any) -> NonceResponse:
        result = self._post_once("nonce_issuer", request)
        if not isinstance(result, NonceResponse):
            raise OutcomeUnknownError(
                "collector request outcome is unknown; automatic retry is forbidden"
            )
        return result

    def issue_receipt(self, request: Any) -> ReceiptResponse:
        result = self._post_once("receipt_signer", request)
        if not isinstance(result, ReceiptResponse):
            raise OutcomeUnknownError(
                "collector request outcome is unknown; automatic retry is forbidden"
            )
        return result

    def _post_once(self, role: EndpointRole, request: Any) -> CollectorResponse:
        endpoint = self._policy.endpoint(role)
        body = _request_bytes(role, request)
        _verify_live_revision(self._policy, endpoint, self._command_runner)
        token = _identity_token(self._policy, endpoint, self._command_runner)
        try:
            context = _tls_context()
            connection = self._connection_factory(
                endpoint.host, 443, HTTPS_TIMEOUT_SECONDS, context
            )
        except (OSError, ValueError, http.client.HTTPException):
            raise PreSendError(
                "collector HTTPS connection could not be prepared before send"
            ) from None

        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Authorization": f"Bearer {token}",
            "Connection": "close",
            "Content-Length": str(len(body)),
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }
        response: _Response | None = None
        try:
            # From this point onward a local exception cannot prove that no byte
            # reached Cloud Run.  There is deliberately no loop around this call.
            connection.request("POST", endpoint.route, body=body, headers=headers)
            response = connection.getresponse()
            result = _validate_response(endpoint, response)
            response.close()
            response = None
            connection.close()
            return result
        except (OSError, ValueError, http.client.HTTPException):
            if response is not None:
                try:
                    response.close()
                except (OSError, http.client.HTTPException):
                    pass
            try:
                connection.close()
            except (OSError, http.client.HTTPException):
                pass
            raise OutcomeUnknownError(
                "collector request outcome is unknown; automatic retry is forbidden"
            ) from None
