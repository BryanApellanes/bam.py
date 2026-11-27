"""Sends a request whose target reaches the wire exactly as it was signed."""
import http.client
import ssl
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit


@dataclass
class Response:
    """What came back. Header names are lower case."""

    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


class Transport(Protocol):
    """Sends one request. The target must go on the request line unchanged."""

    def send(self, method: str, target: str, headers: dict[str, str], body: bytes) -> Response: ...


class HttpTransport:
    """Talks to one origin with the standard library.

    http.client writes the target on the request line as given. A library that tidies the URL (resolves
    dot segments, re-encodes characters, drops an empty query) would break every request proof.
    """

    def __init__(self, origin: str, timeout: float = 30.0, context: ssl.SSLContext | None = None):
        parts = urlsplit(origin)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("The origin is a URL like https://api.example.com")
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise ValueError("The origin has no path, query or fragment. Put the path in each request's target.")
        self._secure = parts.scheme == "https"
        self._host = parts.hostname
        self._port = parts.port
        self._timeout = timeout
        self._context = context

    def send(self, method: str, target: str, headers: dict[str, str], body: bytes) -> Response:
        if self._secure:
            connection = http.client.HTTPSConnection(
                self._host, self._port, timeout=self._timeout, context=self._context or ssl.create_default_context()
            )
        else:
            connection = http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)
        try:
            connection.request(method, target, body=body, headers=headers)
            reply = connection.getresponse()
            return Response(
                status=reply.status,
                headers={name.lower(): value for name, value in reply.getheaders()},
                body=reply.read(),
            )
        finally:
            connection.close()
