"""Hard-deadline HTTPS requests isolated from resolver calls."""
from __future__ import annotations
import multiprocessing, ssl, time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

@dataclass(frozen=True)
class HTTPResult:
    status: int
    headers: dict[str, str]
    body: bytes

class NetworkError(RuntimeError):
    """Safe network failure without URLs, headers or response bodies."""

def _urllib_request(url, method, headers, body, socket_timeout, max_bytes):
    request = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=socket_timeout, context=ssl.create_default_context()) as response:
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise NetworkError("Response exceeded configured size limit")
            return HTTPResult(response.status, dict(response.headers.items()), data)
    except HTTPError as exc:
        data = exc.read(max_bytes + 1)
        if len(data) > max_bytes:
            data = b""
        return HTTPResult(exc.code, dict(exc.headers.items()), data)
    except (URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        raise NetworkError(f"HTTPS request failed ({type(exc).__name__})") from None

def _worker(send, fn, args):
    try:
        send.send((True, fn(*args)))
    except BaseException as exc:
        send.send((False, (type(exc).__name__, str(exc)[:240])))
    finally:
        send.close()

class BoundedNetwork:
    """Run work in a killable child so DNS/connect/read share one wall deadline."""
    def __init__(self, *, deadline_seconds=8.0, socket_timeout=4.0, max_response_bytes=1_048_576, requester=_urllib_request):
        if not 0.1 <= deadline_seconds <= 30 or not 0.1 <= socket_timeout <= deadline_seconds or not 1024 <= max_response_bytes <= 8_388_608:
            raise ValueError("Invalid network bounds")
        self.deadline_seconds, self.socket_timeout = deadline_seconds, socket_timeout
        self.max_response_bytes, self.requester = max_response_bytes, requester
    def request(self, url, *, method="GET", headers=None, body=None):
        if not isinstance(url, str) or not url.startswith("https://") or len(url) > 2048 or any(ord(c) < 32 for c in url):
            raise NetworkError("Only bounded HTTPS URLs are accepted")
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise NetworkError("HTTP method is not allowed")
        clean = {}
        for name, value in (headers or {}).items():
            if not isinstance(name, str) or not isinstance(value, str) or len(name) > 100 or len(value) > 8192 or "\r" in name + value or "\n" in name + value:
                raise NetworkError("Invalid HTTP header")
            clean[name] = value
        if body is not None and (not isinstance(body, bytes) or len(body) > 1_048_576):
            raise NetworkError("Request body exceeds configured limit")
        ctx = multiprocessing.get_context("fork")
        recv, send = ctx.Pipe(duplex=False)
        args = (url, method, clean, body, self.socket_timeout, self.max_response_bytes)
        proc = ctx.Process(target=_worker, args=(send, self.requester, args), daemon=True)
        started = time.monotonic()
        proc.start(); send.close()
        try:
            remaining = self.deadline_seconds - (time.monotonic() - started)
            if remaining <= 0 or not recv.poll(remaining):
                raise NetworkError("HTTPS request exceeded hard deadline")
            ok, result = recv.recv()
            proc.join(timeout=0.1)
            if not ok:
                kind, _ = result
                raise NetworkError(f"HTTPS request failed ({kind})")
            if not isinstance(result, HTTPResult) or len(result.body) > self.max_response_bytes:
                raise NetworkError("Invalid or oversized HTTP response")
            return result
        finally:
            if proc.is_alive():
                proc.terminate(); proc.join(timeout=0.5)
                if proc.is_alive() and hasattr(proc, "kill"):
                    proc.kill(); proc.join(timeout=0.5)
            recv.close()
