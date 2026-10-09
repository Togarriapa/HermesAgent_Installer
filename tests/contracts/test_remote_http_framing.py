import unittest

from hermes_installer.remote.http_framing import (
    HTTPFrameError, build_asset_request, parse_asset_response, read_asset_response,
)


def canonical(path):
    path = path.split("?", 1)[0]
    if path not in {"/client/index.html", "/client/js/Client.js"}:
        raise HTTPFrameError("not pinned")
    return path


class XpraHTTPFramingTests(unittest.TestCase):
    def test_request_contains_only_fixed_headers_and_exact_path(self):
        self.assertEqual(
            build_asset_request("GET", "/client/index.html", canonicalize=canonical),
            b"GET /client/index.html HTTP/1.1\r\nHost: 127.0.0.1:14500\r\n"
            b"Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        )
        for method, path in (("POST", "/client/index.html"),
                             ("GET", "/client/index.html?server=evil"),
                             ("GET", "/client/../etc/passwd")):
            with self.subTest(method=method, path=path), self.assertRaises(HTTPFrameError):
                build_asset_request(method, path, canonicalize=canonical)

    def test_content_length_response_is_bounded_and_filters_headers(self):
        result = parse_asset_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 4\r\n"
            b"Connection: close\r\nSet-Cookie: secret=x\r\n\r\ntest", method="GET")
        self.assertEqual(result.body, b"test")
        self.assertEqual(result.headers, {"content-type": "text/html"})
        for raw in (
            b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: http://evil/\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nno",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nxextra",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Encoding: gzip\r\n\r\nx",
        ):
            with self.subTest(raw=raw), self.assertRaises(HTTPFrameError):
                parse_asset_response(raw, method="GET")

    def test_chunked_response_is_decoded_and_trailers_are_denied(self):
        result = parse_asset_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"4\r\ntest\r\n0\r\n\r\n", method="GET")
        self.assertEqual(result.body, b"test")
        with self.assertRaises(HTTPFrameError):
            parse_asset_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"0\r\nX-Secret: leak\r\n\r\n", method="GET")

    def test_collector_handles_partial_connector_reads_without_accepting_trailing_frames(self):
        pieces = [b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n", b"te", b"st"]
        result = read_asset_response(lambda _n: pieces.pop(0), method="GET")
        self.assertEqual(result.body, b"test")
        with self.assertRaises(HTTPFrameError):
            read_asset_response(lambda _n: b"", method="GET")
        pieces = [b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                  b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"]
        with self.assertRaises(HTTPFrameError):
            read_asset_response(lambda _n: pieces.pop(0), method="GET")

    def test_head_response_keeps_metadata_and_rejects_body(self):
        result = parse_asset_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\nContent-Type: image/png\r\n\r\n",
            method="HEAD")
        self.assertEqual(result.body, b"")
        with self.assertRaises(HTTPFrameError):
            parse_asset_response(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx", method="HEAD")


if __name__ == "__main__":
    unittest.main()
