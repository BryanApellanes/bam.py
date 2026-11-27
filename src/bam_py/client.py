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
# Headers the client writes itself. A caller's header of the same name, in any case, is dropped.
_OWN_HEADERS = ("authorization", "x-bam-body-signature", "x-bam-body-signature-algorithm", "x-bam-timestamp",
                "x-bam-proof-nonce")


class BamError(Exception):
    """A request the host refused, or an answer the client could not read.

    status is the HTTP status; retry_after is in seconds when the host gave one.
    """

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
    """The error for a refusal. Never raises: a refusal's body may be JSON, text, or nothing."""
    text = response.body.decode("utf-8", errors="replace").strip()
    detail = text
    try:
        document = json.loads(text)
    except ValueError:
        document = None
    stated = _field(document, "detail")
    messages = _field(document, "messages")
    if isinstance(stated, str) and stated:
        detail = stated
    elif isinstance(messages, list) and any(isinstance(message, str) for message in messages):
        detail = " ".join(message for message in messages if isinstance(message, str))
    retry_after = response.header("Retry-After")
    seconds = int(retry_after) if retry_after and retry_after.isascii() and retry_after.isdigit() else None
    return BamError(response.status, detail or "The host gave no reason.", seconds)


def _read_json(response: Response, what: str) -> Any:
    """The JSON in a 200 answer, or BamError when it is not JSON."""
    try:
        return json.loads(response.body)
    except ValueError:
        raise BamError(response.status, f"The host's answer to {what} was not JSON.") from None


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
        handle = _field(_read_json(response, "the registration"), "keySetHandle")
        return handle if isinstance(handle, str) and handle else self.handle

    def token(self, renew: bool = False, refused: str | None = None) -> str:
        """The bearer token for the next request, fetched or renewed when needed.

        With refused, the token is renewed only if the refused one is still the current one, so several
        threads refused on the same token fetch one new token between them.
        """
        if not self._server_tokens:
            return client_token(self._key_store, self.handle, self._audience, now=self._clock())
        with self._lock:
            stale = self._token is None or self._clock() >= self._token_expires - _RENEW_MARGIN_SECONDS
            if stale or (renew and (refused is None or refused == self._token)):
                self._token, self._token_expires = self._fetch_token()
            return self._token

    def _fetch_token(self) -> tuple[str, float]:
        proof = client_token(self._key_store, self.handle, self._audience, now=self._clock())
        body = json.dumps({"ClientToken": proof}).encode("utf-8")
        response = self._transport.send("POST", self._token_path, {"Content-Type": _JSON}, body)
        if response.status != 200:
            raise _error(response)
        token = _field(_read_json(response, "the token request"), "token")
        if not isinstance(token, str):
            raise BamError(response.status, "The host answered without a token.")
        # The token's own exp claim says when it ends. It is read here only to know when to renew.
        try:
            return token, float(decode_token(token)["exp"])
        except ValueError:
            raise BamError(response.status, "The host answered with a token that cannot be read.") from None

    def send(
        self,
        method: str,
        target: str,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        proof: bool = True,
    ) -> Response:
        """Sends one request as the actor and returns the host's answer to it, whatever its status.

        target is the path and query exactly as it should go on the wire, starting with '/'.
        The method is sent in upper case, which is how it is signed.
        A 401 is tried once more with a new token and a new proof, which covers a token that expired
        or was replaced. If the host refuses to issue that new token, BamError is raised.
        Authorization and the proof headers are the client's: a header of the same name in headers is
        not sent.
        """
        method = method.upper()
        used, response = self._send_once(method, target, body, headers, proof, refused=None)
        if response.status == 401 and self._server_tokens:
            _, response = self._send_once(method, target, body, headers, proof, refused=used)
        return response

    def _send_once(self, method, target, body, headers, proof, refused) -> tuple[str, Response]:
        sent = {name: value for name, value in (headers or {}).items() if name.lower() not in _OWN_HEADERS}
        token = self.token(renew=refused is not None, refused=refused)
        sent["Authorization"] = "Bearer " + token
        if proof:
            sent.update(self._proofs.sign(method, target, body))
        return token, self._transport.send(method, target, sent, body)

    def invoke(self, operation: str, arguments: dict[str, Any] | None = None) -> Any:
        """Calls an operation the host serves and returns its result.

        operation is "<type full name>+<method name>, <assembly name>", for example
        "Sample.Greeter+Greet, Sample". Raises BamError for any answer but 200, and for a 200 whose
        body is not JSON. An empty 200 body gives None.
        """
        body = json.dumps({"OperationIdentifier": operation, "Arguments": arguments or {}}).encode("utf-8")
        response = self.send("POST", self._invoke_path, body, {"Content-Type": _JSON})
        if response.status != 200:
            raise _error(response)
        return _read_json(response, "the operation") if response.body.strip() else None
