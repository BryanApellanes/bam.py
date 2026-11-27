"""The actor client: register, get and renew a token, and send signed requests."""
import json
import threading
import time
from typing import Any, Callable

from .keys import ActorKeyStore
from .proof import ProofSigner
from .token import client_token, decode_token
from .transport import HttpTransport, Response, Transport

_JSON = "application/json"
# Renew this long before the server token expires, so a request in flight is not caught by the expiry.
_RENEW_MARGIN_SECONDS = 60


class BamError(Exception):
    """A request the host refused. status is the HTTP status; retry_after is in seconds when the host gave one."""

    def __init__(self, status: int, detail: str, retry_after: int | None = None):
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail
        self.retry_after = retry_after


def _field(document: Any, name: str) -> Any:
    """Reads a property without regard to the case of its name. A host can change how it writes names."""
    if isinstance(document, dict):
        for key, value in document.items():
            if isinstance(key, str) and key.lower() == name.lower():
                return value
    return None


def _error(response: Response) -> BamError:
    detail = response.body.decode("utf-8", errors="replace").strip()
    try:
        document = json.loads(detail)
        messages = _field(document, "messages")
        detail = _field(document, "detail") or (" ".join(messages) if isinstance(messages, list) else detail)
    except ValueError:
        pass
    retry_after = response.header("Retry-After")
    return BamError(response.status, detail or "The host gave no reason.",
                    int(retry_after) if retry_after and retry_after.isdigit() else None)


class ActorClient:
    """Calls one Bam host as one actor.

    origin is the host's address, like https://api.example.com, with no path.
    audience is the value the host's operator gave for client tokens, usually the host's public origin.
    With server_tokens off, for a host in client-signed-only mode, each request carries a fresh
    client-signed token and /actor/token is never called.
    """

    def __init__(
        self,
        origin: str,
        handle: str,
        key_store: ActorKeyStore,
        audience: str | None = None,
        transport: Transport | None = None,
        clock: Callable[[], float] = time.time,
        server_tokens: bool = True,
        register_path: str = "/actor/register",
        token_path: str = "/actor/token",
        invoke_path: str = "/invoke",
    ):
        self.handle = handle
        self._key_store = key_store
        self._audience = audience
        self._transport = transport or HttpTransport(origin)
        self._clock = clock
        self._server_tokens = server_tokens
        self._register_path = register_path
        self._token_path = token_path
        self._invoke_path = invoke_path
        self._proofs = ProofSigner(key_store, clock)
        self._lock = threading.Lock()
        self._token: str | None = None
        self._token_expires = 0.0

    def register(self, rsa_public_key_pem: str = "") -> str:
        """Registers the actor's public key under its handle and returns the handle.

        Registering grants nothing by itself: the host's operator admits the handle, and until then
        every other call is refused with 401. The fingerprint to give the operator is
        key_store.fingerprint().
        """
        body = json.dumps({
            "KeySetHandle": self.handle,
            "PublicRsaKeyPem": rsa_public_key_pem,
            "PublicEccKeyPem": self._key_store.public_key_pem(),
        }).encode("utf-8")
        response = self._transport.send("POST", self._register_path, {"Content-Type": _JSON}, body)
        if response.status != 200:
            raise _error(response)
        return _field(json.loads(response.body), "keySetHandle") or self.handle

    def token(self, renew: bool = False) -> str:
        """The bearer token for the next request, fetched or renewed when needed."""
        if not self._server_tokens:
            return client_token(self._key_store, self.handle, self._audience, now=self._clock())
        with self._lock:
            if renew or self._token is None or self._clock() >= self._token_expires - _RENEW_MARGIN_SECONDS:
                self._token, self._token_expires = self._fetch_token()
            return self._token

    def _fetch_token(self) -> tuple[str, float]:
        proof = client_token(self._key_store, self.handle, self._audience, now=self._clock())
        body = json.dumps({"ClientToken": proof}).encode("utf-8")
        response = self._transport.send("POST", self._token_path, {"Content-Type": _JSON}, body)
        if response.status != 200:
            raise _error(response)
        token = _field(json.loads(response.body), "token")
        if not isinstance(token, str):
            raise BamError(response.status, "The host answered without a token.")
        # The token's own exp claim says when it ends. It is read here only to know when to renew.
        return token, float(decode_token(token)["exp"])

    def send(
        self,
        method: str,
        target: str,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        proof: bool = True,
    ) -> Response:
        """Sends one request as the actor and returns whatever the host answered.

        target is the path and query exactly as it should go on the wire, starting with '/'.
        A 401 is tried once more with a new token and a new proof, which covers a token that expired
        or was replaced. Every other answer is returned as it came.
        """
        response = self._send_once(method, target, body, headers, proof, renew=False)
        if response.status == 401 and self._server_tokens:
            response = self._send_once(method, target, body, headers, proof, renew=True)
        return response

    def _send_once(self, method, target, body, headers, proof, renew) -> Response:
        sent = dict(headers or {})
        sent["Authorization"] = "Bearer " + self.token(renew=renew)
        if proof:
            sent.update(self._proofs.sign(method, target, body))
        return self._transport.send(method, target, sent, body)

    def invoke(self, operation: str, arguments: dict[str, Any] | None = None) -> Any:
        """Calls an operation the host serves and returns its result.

        operation is "<type full name>+<method name>, <assembly name>", for example
        "Sample.Greeter+Greet, Sample". Raises BamError for any answer but 200.
        """
        body = json.dumps({"OperationIdentifier": operation, "Arguments": arguments or {}}).encode("utf-8")
        response = self.send("POST", self._invoke_path, body, {"Content-Type": _JSON})
        if response.status != 200:
            raise _error(response)
        return json.loads(response.body) if response.body else None
