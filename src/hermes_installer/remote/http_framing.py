"""Strict, bounded HTTP framing for the fixed Xpra asset connector route.

Browser headers never cross this boundary. The caller supplies only a canonical,
pinned asset path and method; the connector accepts one complete request frame.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

MAX_HEADER_BYTES = 32 * 1024
MAX_BODY_BYTES = 2 * 1024 * 1024


class HTTPFrameError(ValueError):
    """An Xpra HTTP frame is ambiguous, unsupported, or outside fixed bounds."""


@dataclass(frozen=True, slots=True)
class AssetResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


def build_asset_request(method: str, raw_path: str, *, canonicalize: Callable[[str], str]) -> bytes:
    if method not in {"GET", "HEAD"}:
        raise HTTPFrameError("only GET and HEAD are allowed for Xpra assets")
    if not isinstance(raw_path, str) or any(c in raw_path for c in "?#\\\r\n\x00"):
        raise HTTPFrameError("asset request contains query or fragment data")
    path = canonicalize(raw_path)
    if not isinstance(path, str) or not path.startswith("/client/") or any(c in path for c in "?#\\\r\n\x00"):
        raise HTTPFrameError("asset path is not canonical")
    # These values are fixed. Never forward browser cookies, authorization,
    # Host, conditional, forwarding, or connection headers to Xpra.
    frame = (f"{method} {path} HTTP/1.1\r\n"
            "Host: 127.0.0.1:14500\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n").encode("ascii")
    if len(frame) > MAX_HEADER_BYTES:
        raise HTTPFrameError("asset request exceeds its bound")
    return frame


def _decode_chunked(data: bytes) -> tuple[bytes, int]:
    cursor = 0
    output = bytearray()
    while True:
        end = data.find(b"\r\n", cursor)
        if end < 0:
            raise HTTPFrameError("incomplete chunk length")
        line = data[cursor:end]
        if not line or b";" in line or len(line) > 16:
            raise HTTPFrameError("unsupported chunk extension")
        try:
            size = int(line, 16)
        except ValueError:
            raise HTTPFrameError("invalid chunk length") from None
        if size < 0 or len(output) + size > MAX_BODY_BYTES:
            raise HTTPFrameError("Xpra asset exceeds its body bound")
        cursor = end + 2
        if size == 0:
            # Permit only the terminating empty trailer section.
            if data[cursor:cursor + 2] != b"\r\n":
                raise HTTPFrameError("HTTP trailers are unsupported")
            return bytes(output), cursor + 2
        stop = cursor + size
        if len(data) < stop + 2:
            raise HTTPFrameError("incomplete chunk body")
        if data[stop:stop + 2] != b"\r\n":
            raise HTTPFrameError("invalid chunk terminator")
        output.extend(data[cursor:stop])
        cursor = stop + 2


def parse_asset_response(raw: bytes, *, method: str) -> AssetResponse:
    if method not in {"GET", "HEAD"} or not isinstance(raw, bytes):
        raise HTTPFrameError("invalid response input")
    if len(raw) > MAX_HEADER_BYTES + MAX_BODY_BYTES:
        raise HTTPFrameError("Xpra response exceeds its total bound")
    split = raw.find(b"\r\n\r\n")
    if split < 0 or split > MAX_HEADER_BYTES:
        raise HTTPFrameError("incomplete or oversized Xpra response headers")
    try:
        lines = raw[:split].decode("ascii", "strict").split("\r\n")
    except UnicodeDecodeError:
        raise HTTPFrameError("Xpra response headers are not ASCII") from None
    if not lines or len(lines[0]) > 128:
        raise HTTPFrameError("invalid Xpra status line")
    parts = lines[0].split(" ")
    if len(parts) < 2 or parts[0] not in {"HTTP/1.0", "HTTP/1.1"} or not parts[1].isdigit():
        raise HTTPFrameError("invalid Xpra status line")
    status = int(parts[1])
    if status != 200:
        # Redirects and non-success responses are never relayed to the browser.
        raise HTTPFrameError("Xpra asset request was not successful")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or line[0] in " \t" or ":" not in line:
            raise HTTPFrameError("malformed or folded Xpra header")
        name, value = line.split(":", 1)
        key = name.casefold()
        if not name or any(not (c.isalnum() or c == "-") for c in name):
            raise HTTPFrameError("invalid Xpra header name")
        if key in headers:
            raise HTTPFrameError("duplicate Xpra response header")
        headers[key] = value.strip(" \t")
    body = raw[split + 4:]
    transfer = headers.get("transfer-encoding")
    length = headers.get("content-length")
    if transfer is not None:
        if transfer.casefold() != "chunked" or length is not None:
            raise HTTPFrameError("ambiguous Xpra response framing")
        body, consumed = _decode_chunked(body)
        if consumed != len(raw) - split - 4:
            raise HTTPFrameError("trailing bytes after Xpra response")
    elif length is not None:
        if not length.isdecimal() or len(length) > 10:
            raise HTTPFrameError("invalid Xpra content length")
        expected = int(length)
        if expected > MAX_BODY_BYTES:
            raise HTTPFrameError("Xpra asset exceeds its body bound")
        if method == "HEAD":
            if body:
                raise HTTPFrameError("HEAD response unexpectedly contains a body")
        elif len(body) != expected:
            raise HTTPFrameError("incomplete or trailing Xpra response body")
    elif method == "HEAD":
        if body:
            raise HTTPFrameError("HEAD response unexpectedly contains a body")
    else:
        raise HTTPFrameError("Xpra response lacks bounded framing")
    encoding = headers.get("content-encoding", "identity").casefold()
    if encoding != "identity":
        raise HTTPFrameError("compressed Xpra responses are unsupported")
    # Keep only headers the public asset route needs; remove hop-by-hop and
    # origin-control metadata before returning a browser response.
    public = {name: headers[name] for name in ("content-type", "etag", "last-modified") if name in headers}
    return AssetResponse(status, public, body)


def _complete_response_size(raw: bytes, *, method: str) -> bool:
    """Return whether a response is complete; malformed input still raises."""
    split = raw.find(b"\r\n\r\n")
    if split < 0:
        if len(raw) > MAX_HEADER_BYTES:
            raise HTTPFrameError("incomplete or oversized Xpra response headers")
        return False
    header_lines = raw[:split].split(b"\r\n")
    transfer = None
    length = None
    seen = set()
    for line in header_lines[1:]:
        if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
            raise HTTPFrameError("malformed or folded Xpra header")
        name, value = line.split(b":", 1)
        key = name.decode("ascii", "strict").casefold()
        if key in seen:
            raise HTTPFrameError("duplicate Xpra response header")
        seen.add(key)
        value = value.strip(b" \t")
        if key == "transfer-encoding":
            transfer = value
        elif key == "content-length":
            length = value
    body_len = len(raw) - split - 4
    if transfer is not None:
        if transfer.casefold() != b"chunked" or length is not None:
            raise HTTPFrameError("ambiguous Xpra response framing")
        try:
            _decoded, consumed = _decode_chunked(raw[split + 4:])
        except HTTPFrameError as exc:
            if str(exc).startswith("incomplete "):
                return False
            raise
        return consumed == body_len
    if method == "HEAD" and length is None:
        return body_len == 0
    if length is None or not length.isdigit() or len(length) > 10:
        raise HTTPFrameError("Xpra response lacks bounded framing")
    expected = int(length)
    if expected > MAX_BODY_BYTES:
        raise HTTPFrameError("Xpra asset exceeds its body bound")
    if method == "HEAD":
        if body_len:
            raise HTTPFrameError("HEAD response unexpectedly contains a body")
        return True
    if body_len < expected:
        return False
    if body_len > expected:
        raise HTTPFrameError("trailing bytes after Xpra response body")
    return True


def read_asset_response(read: Callable[[int], bytes], *, method: str,
                        maximum_reads: int = 512) -> AssetResponse:
    """Collect one response from a bounded connector until its frame is complete."""
    if method not in {"GET", "HEAD"} or not callable(read):
        raise HTTPFrameError("invalid response reader")
    raw = bytearray()
    for _ in range(maximum_reads):
        if _complete_response_size(bytes(raw), method=method):
            return parse_asset_response(bytes(raw), method=method)
        chunk = read(min(65_536, MAX_HEADER_BYTES + MAX_BODY_BYTES + 1 - len(raw)))
        if not isinstance(chunk, bytes) or not chunk:
            raise HTTPFrameError("Xpra response ended before its frame was complete")
        raw.extend(chunk)
        if len(raw) > MAX_HEADER_BYTES + MAX_BODY_BYTES:
            raise HTTPFrameError("Xpra response exceeds its total bound")
    raise HTTPFrameError("Xpra response exceeded its read-call bound")
