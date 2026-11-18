"""Offline checks for the opt-in pinned HTTPS staging transport."""

from __future__ import annotations

import hashlib
import io
import unittest
from unittest.mock import MagicMock, patch

from sunderkey.authorized_http_runtime import HttpBackendFailure, HttpBackendRequest
from sunderkey.reference_http_adapter import ReferenceHttpBackend
from sunderkey.staging_pinned_https_transport import PinnedHttpsStagingTransport
from sunderkey.target_adapter_conformance import AdapterStopState

CERTIFICATE = b"synthetic DER certificate fixture"
PIN = "sha256:" + hashlib.sha256(CERTIFICATE).hexdigest()
ADDRESS = "203.0.113.17"
ORIGIN = "https://staging.example"


def transport(stop_state: AdapterStopState | None = None) -> PinnedHttpsStagingTransport:
    return PinnedHttpsStagingTransport(
        expected_origin=ORIGIN,
        expected_certificate_sha256=PIN,
        connect_addresses=(ADDRESS,),
        maximum_request_bytes=1024,
        maximum_response_bytes=1024,
        stop_state=stop_state or AdapterStopState(),
    )


def request(**overrides: object) -> HttpBackendRequest:
    values = {
        "method": "GET",
        "url": ORIGIN + "/path?x=1",
        "headers": (("Accept", "application/json"),),
        "body": b"",
        "connect_addresses": (ADDRESS,),
        "follow_redirects": False,
        "maximum_attempts": 1,
        "max_response_bytes": 16,
    }
    values.update(overrides)
    return HttpBackendRequest(**values)


class PinnedHttpsStagingTransportTests(unittest.TestCase):
    def _network_fakes(self, *, status: int = 200, body: bytes = b"ok") -> tuple[MagicMock, ...]:
        raw = MagicMock()
        raw.getpeername.return_value = (ADDRESS, 443)
        tls = MagicMock()
        tls.selected_alpn_protocol.return_value = "http/1.1"
        tls.getpeercert.return_value = CERTIFICATE
        context = MagicMock()
        context.wrap_socket.return_value = tls
        connection = MagicMock()
        response = MagicMock()
        response.status = status
        response.getheaders.return_value = [("Content-Type", "text/plain")]
        response.read.side_effect = io.BytesIO(body).read
        connection.getresponse.return_value = response
        return raw, tls, context, connection

    def test_exact_peer_and_literal_ip_send_once_without_dns(self) -> None:
        raw, tls, context, connection = self._network_fakes()
        with (
            patch("sunderkey.staging_pinned_https_transport.socket.socket", return_value=raw),
            patch(
                "sunderkey.staging_pinned_https_transport.ssl.create_default_context",
                return_value=context,
            ),
            patch(
                "sunderkey.staging_pinned_https_transport.http.client.HTTPSConnection",
                return_value=connection,
            ),
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS must not be called")),
        ):
            result = transport().exchange(request())
        raw.connect.assert_called_once_with((ADDRESS, 443))
        context.wrap_socket.assert_called_once_with(raw, server_hostname="staging.example")
        connection.request.assert_called_once_with(
            "GET", "/path?x=1", body=b"", headers={"Accept": "application/json"}
        )
        connection.close.assert_called_once()
        self.assertEqual(result.body, b"ok")
        self.assertTrue(result.body_complete)
        self.assertEqual(result.tls_peer.certificate_sha256, PIN)

    def test_stdlib_http_connection_uses_pinned_socket_without_dns(self) -> None:
        raw = MagicMock()
        raw.getpeername.return_value = (ADDRESS, 443)
        tls = MagicMock()
        tls.selected_alpn_protocol.return_value = "http/1.1"
        tls.getpeercert.return_value = CERTIFICATE
        tls.makefile.return_value = io.BytesIO(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        )
        context = MagicMock()
        context.wrap_socket.return_value = tls
        with (
            patch("sunderkey.staging_pinned_https_transport.socket.socket", return_value=raw),
            patch(
                "sunderkey.staging_pinned_https_transport.ssl.create_default_context",
                return_value=context,
            ),
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS must not be called")),
        ):
            result = transport().exchange(request())
        wire = b"".join(call.args[0] for call in tls.sendall.call_args_list)
        self.assertIn(b"GET /path?x=1 HTTP/1.1\r\n", wire)
        self.assertIn(b"Host: staging.example\r\n", wire)
        self.assertEqual(result.body, b"ok")
        tls.close.assert_called_once()

    def test_wrong_certificate_rejected_before_http_send(self) -> None:
        raw, tls, context, connection = self._network_fakes()
        tls.getpeercert.return_value = b"wrong certificate"
        with (
            patch("sunderkey.staging_pinned_https_transport.socket.socket", return_value=raw),
            patch(
                "sunderkey.staging_pinned_https_transport.ssl.create_default_context",
                return_value=context,
            ),
            patch(
                "sunderkey.staging_pinned_https_transport.http.client.HTTPSConnection",
                return_value=connection,
            ) as constructor,
            self.assertRaisesRegex(HttpBackendFailure, "tls_certificate_mismatch"),
        ):
            transport().exchange(request())
        constructor.assert_not_called()
        tls.close.assert_called_once()

    def test_request_substitution_and_unsafe_headers_rejected_before_socket(self) -> None:
        bad_requests = (
            request(url="https://other.example/path"),
            request(connect_addresses=("203.0.113.18",)),
            request(headers=(("Host", "other.example"),)),
            request(headers=(("Authorization", "Bearer value"),)),
            request(headers=(("X-Test", "a\r\nb"),)),
            request(headers=(("Accept", "one"), ("accept", "two"))),
            request(follow_redirects=True),
            request(maximum_attempts=2),
            request(method="CONNECT"),
            request(method=[]),
            request(connect_addresses=([ADDRESS],)),
        )
        with patch("sunderkey.staging_pinned_https_transport.socket.socket") as socket_factory:
            for bad in bad_requests:
                with self.subTest(bad=bad), self.assertRaises(HttpBackendFailure):
                    transport().exchange(bad)
        socket_factory.assert_not_called()

    def test_staging_hard_byte_limits_cannot_be_relaxed(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside the staging limit"):
            PinnedHttpsStagingTransport(
                expected_origin=ORIGIN,
                expected_certificate_sha256=PIN,
                connect_addresses=(ADDRESS,),
                maximum_request_bytes=1024 * 1024 + 1,
                maximum_response_bytes=1024,
                stop_state=AdapterStopState(),
            )

    def test_stop_after_tls_handshake_prevents_request(self) -> None:
        state = AdapterStopState()
        raw, tls, context, connection = self._network_fakes()
        context.wrap_socket.side_effect = lambda *_args, **_kwargs: (state.cancel(), tls)[1]
        with (
            patch("sunderkey.staging_pinned_https_transport.socket.socket", return_value=raw),
            patch(
                "sunderkey.staging_pinned_https_transport.ssl.create_default_context",
                return_value=context,
            ),
            patch(
                "sunderkey.staging_pinned_https_transport.http.client.HTTPSConnection",
                return_value=connection,
            ),
            self.assertRaisesRegex(HttpBackendFailure, "canceled"),
        ):
            transport(state).exchange(request())
        connection.request.assert_not_called()
        connection.close.assert_called_once()

    def test_redirect_is_reported_without_following(self) -> None:
        raw, tls, context, connection = self._network_fakes(status=302, body=b"")
        with (
            patch("sunderkey.staging_pinned_https_transport.socket.socket", return_value=raw),
            patch(
                "sunderkey.staging_pinned_https_transport.ssl.create_default_context",
                return_value=context,
            ),
            patch(
                "sunderkey.staging_pinned_https_transport.http.client.HTTPSConnection",
                return_value=connection,
            ),
        ):
            backend = ReferenceHttpBackend(
                expected_origin=ORIGIN,
                expected_certificate_sha256=PIN,
                maximum_request_bytes=1024,
                maximum_response_bytes=1024,
                transport=transport(),
                stop_state=AdapterStopState(),
            )
            result = backend.send(request())
        self.assertTrue(result.redirected)
        self.assertEqual(result.attempts, 1)
        connection.request.assert_called_once()

    def test_response_over_limit_is_not_returned_as_complete(self) -> None:
        raw, tls, context, connection = self._network_fakes(body=b"0123456789abcdefEXTRA")
        with (
            patch("sunderkey.staging_pinned_https_transport.socket.socket", return_value=raw),
            patch(
                "sunderkey.staging_pinned_https_transport.ssl.create_default_context",
                return_value=context,
            ),
            patch(
                "sunderkey.staging_pinned_https_transport.http.client.HTTPSConnection",
                return_value=connection,
            ),
        ):
            result = transport().exchange(request())
        self.assertEqual(len(result.body), 17)
        self.assertFalse(result.body_complete)
        connection.close.assert_called_once()

    def test_protocol_upgrade_response_is_rejected(self) -> None:
        raw, tls, context, connection = self._network_fakes(status=101, body=b"")
        with (
            patch("sunderkey.staging_pinned_https_transport.socket.socket", return_value=raw),
            patch(
                "sunderkey.staging_pinned_https_transport.ssl.create_default_context",
                return_value=context,
            ),
            patch(
                "sunderkey.staging_pinned_https_transport.http.client.HTTPSConnection",
                return_value=connection,
            ),
            self.assertRaisesRegex(HttpBackendFailure, "unsupported_protocol_upgrade"),
        ):
            transport().exchange(request())
        connection.close.assert_called_once()

    def test_post_send_failure_is_uncertain_and_never_retried(self) -> None:
        raw, tls, context, connection = self._network_fakes()
        connection.getresponse.side_effect = OSError("connection lost")
        with (
            patch("sunderkey.staging_pinned_https_transport.socket.socket", return_value=raw),
            patch(
                "sunderkey.staging_pinned_https_transport.ssl.create_default_context",
                return_value=context,
            ),
            patch(
                "sunderkey.staging_pinned_https_transport.http.client.HTTPSConnection",
                return_value=connection,
            ),
            self.assertRaisesRegex(HttpBackendFailure, "transport_after_send_uncertain"),
        ):
            transport().exchange(request())
        connection.request.assert_called_once()
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
