from __future__ import annotations

import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from hermes_installer.network import BoundedNetwork, HTTPResult, NetworkError, _urllib_request
from hermes_installer.preflight import _tls_probe


class _HeadResponse:
    status = 200

    def headers(self):
        return None

    class _Headers:
        @staticmethod
        def items():
            return [("Content-Length", "4321")]

    headers = _Headers()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        raise AssertionError("HEAD response body must not be read")


class BoundedHeadRequestTests(unittest.TestCase):
    def test_urllib_head_preserves_headers_without_reading_body(self) -> None:
        class Opener:
            @staticmethod
            def open(request, *, timeout):
                self.assertEqual(request.get_method(), "HEAD")
                self.assertGreater(timeout, 0)
                return _HeadResponse()

        with patch("hermes_installer.network.build_opener", return_value=Opener()):
            result = _urllib_request("https://github.com/", "HEAD", {}, None, 1.0, 1024)
        self.assertEqual(result, HTTPResult(200, {"Content-Length": "4321"}, b""))

    def test_preflight_uses_real_bounded_child_transport_for_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            observed = Path(temporary) / "method"

            def transport(url, method, headers, body, socket_timeout, max_bytes):
                observed.write_text(method, encoding="ascii")
                return HTTPResult(204, {}, b"")

            # No network object is injected: _tls_probe constructs the actual
            # BoundedNetwork, starts its bounded child, and only this final
            # transport seam is replaced by a deterministic fixture.
            with patch("hermes_installer.network._urllib_request", side_effect=transport):
                self.assertTrue(_tls_probe(timeout=1.0))

            self.assertEqual(observed.read_text(encoding="ascii"), "HEAD")

    def test_head_rejects_request_or_response_bodies_and_other_methods_stay_denied(self) -> None:
        network = BoundedNetwork(deadline_seconds=1.0, requester=lambda *_args: HTTPResult(200, {}, b""))
        with self.assertRaisesRegex(NetworkError, "cannot carry a body"):
            network.request("https://github.com/", method="HEAD", body=b"x")
        with self.assertRaisesRegex(NetworkError, "not allowed"):
            network.request("https://github.com/", method="OPTIONS")

        body_response = BoundedNetwork(
            deadline_seconds=1.0,
            requester=lambda *_args: HTTPResult(200, {}, b"unexpected"),
        )
        with self.assertRaisesRegex(NetworkError, "Invalid or oversized"):
            body_response.request("https://github.com/", method="HEAD")


if __name__ == "__main__":
    unittest.main()
