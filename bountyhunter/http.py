import json
import socket
import time
from dataclasses import dataclass
from http.client import HTTPResponse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body_sample: str
    elapsed_ms: int
    error: str = ""


def resolve(host: str) -> list[str]:
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    except socket.gaierror:
        return []


def fetch(url: str, timeout: float = 8, max_bytes: int = 65536) -> Response:
    started = time.monotonic()
    request = Request(url, headers={"User-Agent": "ScopeCrawl/0.1 (authorized-security-research)"})
    try:
        with urlopen(request, timeout=timeout) as raw:  # nosec B310 - URL comes from validated scope
            response: HTTPResponse = raw
            body = response.read(max_bytes).decode("utf-8", errors="replace")
            return Response(url, response.status, dict(response.headers.items()), body, int((time.monotonic() - started) * 1000))
    except HTTPError as exc:
        body = exc.read(max_bytes).decode("utf-8", errors="replace")
        return Response(url, exc.code, dict(exc.headers.items()), body, int((time.monotonic() - started) * 1000), str(exc))
    except (URLError, TimeoutError, OSError) as exc:
        return Response(url, 0, {}, "", int((time.monotonic() - started) * 1000), str(exc))


def safe_headers(headers: dict[str, str]) -> dict[str, str]:
    secret_names = {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}
    return {k: ("[REDACTED]" if k.lower() in secret_names else v) for k, v in headers.items()}


def compact_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, default=str)
