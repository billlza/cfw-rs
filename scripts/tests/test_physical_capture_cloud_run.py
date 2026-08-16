from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import ssl
import unittest
from unittest.mock import patch

from scripts.harness.raw_artifacts import canonical_json
from scripts.physical_capture import cloud_run
from scripts.physical_capture.cloud_run import (
    CloudRunClient,
    NonceResponse,
    OutcomeUnknownError,
    PreSendError,
    ReceiptResponse,
    load_endpoint_policy,
)


NONCE_ORIGIN = "https://physical-nonce-issuer-v040-z67iamdcvq-de.a.run.app"


def _token_for(audience: str) -> str:
    encoded_payload = base64.urlsafe_b64encode(
        canonical_json({"aud": audience})
    ).rstrip(b"=")
    return (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
        + encoded_payload.decode("ascii")
        + ".sourcepinnedidentitytokensignature"
    )


TOKEN = _token_for(NONCE_ORIGIN)
RECEIPT_SIGNATURE = base64.urlsafe_b64encode(b"s" * 384).rstrip(b"=").decode(
    "ascii"
)


def _nonce_request() -> dict[str, object]:
    return {"schema_version": 1, "candidate": {}, "run": {}}


def _receipt_request() -> dict[str, object]:
    return {
        "schema_version": 1,
        "candidate": {},
        "run": {},
        "reports": [],
        "raw_artifacts": [],
    }


def _nonce_response() -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "run_nonce": "d" * 64,
            "expires_at": "2026-08-02T10:00:00Z",
        },
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"


def _receipt_response() -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "signed_at": "2026-08-02T09:00:00Z",
            "receipt_sha256": "e" * 64,
            "signature": RECEIPT_SIGNATURE,
        },
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"


class FakeHeaders:
    def __init__(self, values: dict[str, list[str]]) -> None:
        self.values = {name.lower(): list(entries) for name, entries in values.items()}

    def get_all(self, name: str, failobj: object = None) -> list[str]:
        value = self.values.get(name.lower())
        if value is None:
            return failobj if isinstance(failobj, list) else []
        return list(value)


class FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status: int,
        headers: dict[str, list[str]] | None = None,
        read_error: Exception | None = None,
        close_error: Exception | None = None,
    ) -> None:
        self.body = body
        self.status = status
        self.headers = FakeHeaders(
            {
                "Content-Type": ["application/json; charset=utf-8"],
                "Content-Length": [str(len(body))],
            }
            if headers is None
            else headers
        )
        self.read_error = read_error
        self.close_error = close_error
        self.offset = 0
        self.close_calls = 0

    def read(self, amount: int | None = None) -> bytes:
        if self.read_error is not None:
            raise self.read_error
        if amount is None:
            amount = len(self.body) - self.offset
        chunk = self.body[self.offset : self.offset + amount]
        self.offset += len(chunk)
        return chunk

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class FakeConnection:
    def __init__(
        self,
        response: FakeResponse,
        *,
        request_error: Exception | None = None,
        response_error: Exception | None = None,
    ) -> None:
        self.response = response
        self.request_error = request_error
        self.response_error = response_error
        self.requests: list[tuple[str, str, bytes | None, dict[str, str]]] = []
        self.close_calls = 0

    def request(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.requests.append((method, url, body, dict(headers or {})))
        if self.request_error is not None:
            raise self.request_error

    def getresponse(self) -> FakeResponse:
        if self.response_error is not None:
            raise self.response_error
        return self.response

    def close(self) -> None:
        self.close_calls += 1


class FakeConnectionFactory:
    def __init__(
        self,
        response: FakeResponse,
        *,
        request_error: Exception | None = None,
        response_error: Exception | None = None,
        factory_error: Exception | None = None,
    ) -> None:
        self.response = response
        self.request_error = request_error
        self.response_error = response_error
        self.factory_error = factory_error
        self.calls: list[tuple[str, int, float, ssl.SSLContext]] = []
        self.connections: list[FakeConnection] = []

    def __call__(
        self, host: str, port: int, timeout: float, context: ssl.SSLContext
    ) -> FakeConnection:
        self.calls.append((host, port, timeout, context))
        if self.factory_error is not None:
            raise self.factory_error
        connection = FakeConnection(
            self.response,
            request_error=self.request_error,
            response_error=self.response_error,
        )
        self.connections.append(connection)
        return connection


class FakeRunner:
    def __init__(self) -> None:
        self.policy = load_endpoint_policy()
        self.calls: list[tuple[tuple[str, ...], int]] = []
        self.token: bytes | None = None
        self.token_stderr = (
            "WARNING: This command is using service account impersonation. "
            "All API calls will be executed as "
            f"[{self.policy.identity_service_account}].\n"
        ).encode("ascii")
        self.failure: Exception | None = None
        self.revision_override: str | None = None
        self.origin_override: str | None = None

    def __call__(self, command, maximum: int) -> cloud_run.CommandOutput:
        normalized = tuple(command)
        self.calls.append((normalized, maximum))
        if self.failure is not None:
            raise self.failure
        if normalized[1:4] == ("run", "services", "describe"):
            service = normalized[4]
            if service == self.policy.nonce_issuer.service:
                endpoint = self.policy.nonce_issuer
            elif service == self.policy.receipt_signer.service:
                endpoint = self.policy.receipt_signer
            else:
                raise AssertionError(f"unexpected service: {service}")
            revision = self.revision_override or endpoint.revision
            origin = self.origin_override or endpoint.origin
            return cloud_run.CommandOutput(
                stdout=json.dumps(
                    {
                        "metadata": {"name": endpoint.service},
                        "status": {
                            "url": origin,
                            "latestReadyRevisionName": revision,
                            "traffic": [
                                {
                                    "latestRevision": True,
                                    "percent": 100,
                                    "revisionName": revision,
                                }
                            ],
                        },
                    }
                ).encode("utf-8")
                + b"\n",
                stderr=b"",
            )
        if normalized[1:3] == ("auth", "print-identity-token"):
            audience_argument = next(
                argument
                for argument in normalized
                if argument.startswith("--audiences=")
            )
            token = self.token
            if token is None:
                token = (
                    _token_for(audience_argument.removeprefix("--audiences="))
                    .encode("ascii")
                    + b"\n"
                )
            return cloud_run.CommandOutput(
                stdout=token,
                stderr=self.token_stderr,
            )
        raise AssertionError(f"unexpected gcloud command: {normalized!r}")


class PhysicalCaptureCloudRunTests(unittest.TestCase):
    def test_endpoint_policy_is_canonical_source_pinned_and_exact(self) -> None:
        data = cloud_run.ENDPOINT_POLICY_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), cloud_run.ENDPOINT_POLICY_SHA256)
        self.assertEqual(canonical_json(json.loads(data)) + b"\n", data)
        policy = load_endpoint_policy()
        self.assertEqual(policy.project, "cfw-release-evidence-20260730")
        self.assertEqual(policy.region, "asia-east1")
        self.assertEqual(
            policy.identity_service_account,
            "physical-release-client@cfw-release-evidence-20260730.iam."
            "gserviceaccount.com",
        )
        self.assertEqual(
            policy.nonce_issuer.origin,
            "https://physical-nonce-issuer-v040-z67iamdcvq-de.a.run.app",
        )
        self.assertEqual(
            policy.nonce_issuer.revision,
            "physical-nonce-issuer-v040-00008-b58",
        )
        self.assertEqual(
            policy.receipt_signer.origin,
            "https://physical-receipt-signer-v040-z67iamdcvq-de.a.run.app",
        )
        self.assertEqual(
            policy.receipt_signer.revision,
            "physical-receipt-signer-v040-00008-gh7",
        )
        for endpoint in (policy.nonce_issuer, policy.receipt_signer):
            self.assertEqual(endpoint.audience, endpoint.origin)

    def test_nonce_uses_fixed_revision_token_audience_and_one_https_post(self) -> None:
        runner = FakeRunner()
        response = FakeResponse(_nonce_response(), status=201)
        factory = FakeConnectionFactory(response)
        with patch.dict(
            os.environ,
            {
                "HTTP_PROXY": "http://attacker.invalid:8080",
                "HTTPS_PROXY": "http://attacker.invalid:8080",
            },
        ):
            client = CloudRunClient(
                command_runner=runner, connection_factory=factory
            )
            result = client.issue_nonce(_nonce_request())

        self.assertIsInstance(result, NonceResponse)
        self.assertEqual(result.run_nonce, "d" * 64)
        self.assertNotIn(TOKEN, repr(result))
        self.assertNotIn(TOKEN, repr(client.__dict__))
        policy = runner.policy
        self.assertEqual(
            runner.calls[0],
            (
                (
                    "/opt/homebrew/bin/gcloud",
                    "run",
                    "services",
                    "describe",
                    policy.nonce_issuer.service,
                    f"--project={policy.project}",
                    f"--region={policy.region}",
                    "--format=json(metadata.name,status.url,"
                    "status.latestReadyRevisionName,status.traffic)",
                    "--quiet",
                ),
                cloud_run.MAX_GCLOUD_DESCRIBE_BYTES,
            ),
        )
        self.assertEqual(
            runner.calls[1],
            (
                (
                    "/opt/homebrew/bin/gcloud",
                    "auth",
                    "print-identity-token",
                    "--impersonate-service-account="
                    "physical-release-client@cfw-release-evidence-20260730.iam."
                    "gserviceaccount.com",
                    f"--audiences={policy.nonce_issuer.audience}",
                    "--quiet",
                ),
                cloud_run.MAX_ID_TOKEN_BYTES,
            ),
        )
        self.assertEqual(len(factory.calls), 1)
        host, port, timeout, context = factory.calls[0]
        self.assertEqual(host, policy.nonce_issuer.host)
        self.assertEqual(port, 443)
        self.assertEqual(timeout, cloud_run.HTTPS_TIMEOUT_SECONDS)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        connection = factory.connections[0]
        self.assertEqual(len(connection.requests), 1)
        method, route, body, headers = connection.requests[0]
        self.assertEqual((method, route), ("POST", "/v1/nonces"))
        self.assertEqual(body, canonical_json(_nonce_request()) + b"\n")
        self.assertEqual(headers["Authorization"], f"Bearer {TOKEN}")
        self.assertEqual(headers["Accept-Encoding"], "identity")
        self.assertEqual(headers["Connection"], "close")

    def test_receipt_has_distinct_fixed_service_and_typed_response(self) -> None:
        runner = FakeRunner()
        response = FakeResponse(_receipt_response(), status=200)
        factory = FakeConnectionFactory(response)
        client = CloudRunClient(command_runner=runner, connection_factory=factory)
        result = client.issue_receipt(_receipt_request())

        self.assertIsInstance(result, ReceiptResponse)
        self.assertEqual(result.receipt_sha256, "e" * 64)
        self.assertEqual(result.signature, RECEIPT_SIGNATURE)
        endpoint = runner.policy.receipt_signer
        self.assertEqual(runner.calls[0][0][4], endpoint.service)
        self.assertIn(f"--audiences={endpoint.audience}", runner.calls[1][0])
        self.assertEqual(factory.calls[0][0], endpoint.host)
        self.assertEqual(factory.connections[0].requests[0][1], "/v1/receipts")

    def test_revision_or_origin_drift_is_pre_send(self) -> None:
        for mutation in ("revision", "origin"):
            with self.subTest(mutation=mutation):
                runner = FakeRunner()
                if mutation == "revision":
                    runner.revision_override = "physical-nonce-issuer-v040-99999-bad"
                else:
                    runner.origin_override = "https://attacker.invalid"
                factory = FakeConnectionFactory(
                    FakeResponse(_nonce_response(), status=201)
                )
                client = CloudRunClient(
                    command_runner=runner, connection_factory=factory
                )
                with self.assertRaises(PreSendError):
                    client.issue_nonce(_nonce_request())
                self.assertEqual(len(runner.calls), 1)
                self.assertEqual(factory.calls, [])

    def test_token_failures_are_pre_send_and_never_echo_token_bytes(self) -> None:
        cases: tuple[bytes | Exception, ...] = (
            b"not-a-jwt\n",
            (b"x" * (cloud_run.MAX_ID_TOKEN_BYTES + 1)),
            _token_for("https://attacker.invalid").encode("ascii") + b"\n",
            OSError(f"credential failure containing {TOKEN}"),
        )
        for failure in cases:
            with self.subTest(failure=type(failure).__name__):
                runner = FakeRunner()
                if isinstance(failure, Exception):
                    original = runner.__call__

                    def fail_token(command, maximum):
                        if tuple(command)[1:3] == ("auth", "print-identity-token"):
                            raise failure
                        return original(command, maximum)

                    command_runner = fail_token
                else:
                    runner.token = failure
                    command_runner = runner
                factory = FakeConnectionFactory(
                    FakeResponse(_nonce_response(), status=201)
                )
                client = CloudRunClient(
                    command_runner=command_runner, connection_factory=factory
                )
                with self.assertRaises(PreSendError) as raised:
                    client.issue_nonce(_nonce_request())
                self.assertNotIn(TOKEN, str(raised.exception))
                self.assertEqual(factory.calls, [])

        runner = FakeRunner()
        runner.token_stderr = b"WARNING: unexpected token command behavior\n"
        factory = FakeConnectionFactory(
            FakeResponse(_nonce_response(), status=201)
        )
        client = CloudRunClient(
            command_runner=runner, connection_factory=factory
        )
        with self.assertRaises(PreSendError):
            client.issue_nonce(_nonce_request())
        self.assertEqual(factory.calls, [])

    def test_request_validation_fails_before_gcloud_or_https(self) -> None:
        cases = (
            {**_nonce_request(), "unknown": True},
            {**_nonce_request(), "schema_version": True},
            {
                "schema_version": 1,
                "candidate": {"oversize": "x" * cloud_run.MAX_REQUEST_BYTES},
                "run": {},
            },
        )
        for request in cases:
            with self.subTest(keys=sorted(request)):
                runner = FakeRunner()
                factory = FakeConnectionFactory(
                    FakeResponse(_nonce_response(), status=201)
                )
                client = CloudRunClient(
                    command_runner=runner, connection_factory=factory
                )
                with self.assertRaises(PreSendError):
                    client.issue_nonce(request)
                self.assertEqual(runner.calls, [])
                self.assertEqual(factory.calls, [])

    def test_connection_factory_failure_is_proven_pre_send(self) -> None:
        runner = FakeRunner()
        factory = FakeConnectionFactory(
            FakeResponse(_nonce_response(), status=201),
            factory_error=OSError("TLS setup failed"),
        )
        client = CloudRunClient(command_runner=runner, connection_factory=factory)
        with self.assertRaises(PreSendError):
            client.issue_nonce(_nonce_request())
        self.assertEqual(len(factory.calls), 1)

    def test_request_or_response_transport_failure_is_unknown_and_not_retried(self) -> None:
        for boundary in ("request", "response"):
            with self.subTest(boundary=boundary):
                runner = FakeRunner()
                error = OSError(f"transport failure accidentally contains {TOKEN}")
                factory = FakeConnectionFactory(
                    FakeResponse(_nonce_response(), status=201),
                    request_error=error if boundary == "request" else None,
                    response_error=error if boundary == "response" else None,
                )
                client = CloudRunClient(
                    command_runner=runner, connection_factory=factory
                )
                with self.assertRaises(OutcomeUnknownError) as raised:
                    client.issue_nonce(_nonce_request())
                self.assertNotIn(TOKEN, str(raised.exception))
                self.assertTrue(raised.exception.__suppress_context__)
                self.assertEqual(len(factory.calls), 1)
                self.assertEqual(len(factory.connections), 1)
                self.assertEqual(len(factory.connections[0].requests), 1)

    def test_redirect_and_all_unexpected_statuses_are_terminal_unknown(self) -> None:
        for status in (301, 302, 303, 307, 308, 400, 409, 500, 503):
            with self.subTest(status=status):
                runner = FakeRunner()
                factory = FakeConnectionFactory(
                    FakeResponse(_nonce_response(), status=status)
                )
                client = CloudRunClient(
                    command_runner=runner, connection_factory=factory
                )
                with self.assertRaises(OutcomeUnknownError):
                    client.issue_nonce(_nonce_request())
                self.assertEqual(len(factory.calls), 1)
                self.assertEqual(len(factory.connections[0].requests), 1)

    def test_response_headers_body_and_json_are_strict_and_not_retried(self) -> None:
        valid = _nonce_response()
        cases = (
            FakeResponse(
                valid,
                status=201,
                headers={
                    "Content-Type": ["application/json"],
                    "Content-Length": [str(len(valid))],
                },
            ),
            FakeResponse(
                valid,
                status=201,
                headers={
                    "Content-Type": ["application/json; charset=utf-8"],
                    "Content-Encoding": ["gzip"],
                    "Content-Length": [str(len(valid))],
                },
            ),
            FakeResponse(
                valid,
                status=201,
                headers={
                    "Content-Type": [
                        "application/json; charset=utf-8",
                        "application/json; charset=utf-8",
                    ],
                    "Content-Length": [str(len(valid))],
                },
            ),
            FakeResponse(
                valid,
                status=201,
                headers={
                    "Content-Type": ["application/json; charset=utf-8"],
                    "Content-Length": [str(len(valid) + 1)],
                },
            ),
            FakeResponse(
                b'{"schema_version":1,"schema_version":1,"run_nonce":"'
                + b"d" * 64
                + b'","expires_at":"2026-08-02T10:00:00Z"}\n',
                status=201,
            ),
            FakeResponse(
                b'{"schema_version":1,"run_nonce":"'
                + b"d" * 64
                + b'","expires_at":"2026-08-02T10:00:00Z","unknown":true}\n',
                status=201,
            ),
            FakeResponse(
                b"x" * (cloud_run.MAX_RESPONSE_BYTES + 1),
                status=201,
                headers={"Content-Type": ["application/json; charset=utf-8"]},
            ),
            FakeResponse(
                valid,
                status=201,
                read_error=OSError(f"read error containing {TOKEN}"),
            ),
        )
        for index, response in enumerate(cases):
            with self.subTest(case=index):
                runner = FakeRunner()
                factory = FakeConnectionFactory(response)
                client = CloudRunClient(
                    command_runner=runner, connection_factory=factory
                )
                with self.assertRaises(OutcomeUnknownError) as raised:
                    client.issue_nonce(_nonce_request())
                self.assertNotIn(TOKEN, str(raised.exception))
                self.assertEqual(len(factory.calls), 1)
                self.assertEqual(len(factory.connections[0].requests), 1)

    def test_receipt_signature_shape_is_strict(self) -> None:
        document = json.loads(_receipt_response())
        for signature in ("x" * 511, "x" * 511 + "=", RECEIPT_SIGNATURE + "="):
            with self.subTest(length=len(signature)):
                mutated = dict(document)
                mutated["signature"] = signature
                body = json.dumps(mutated, separators=(",", ":")).encode() + b"\n"
                runner = FakeRunner()
                factory = FakeConnectionFactory(FakeResponse(body, status=200))
                client = CloudRunClient(
                    command_runner=runner, connection_factory=factory
                )
                with self.assertRaises(OutcomeUnknownError):
                    client.issue_receipt(_receipt_request())
                self.assertEqual(len(factory.connections[0].requests), 1)


if __name__ == "__main__":
    unittest.main()
