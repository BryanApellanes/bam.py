"""The request proof: four headers that sign one request with the actor's key."""
import base64
import secrets
import time
from typing import Callable

from .canonical import compose
from .keys import ActorKeyStore

SIGNATURE_HEADER = "X-Bam-Body-Signature"
ALGORITHM_HEADER = "X-Bam-Body-Signature-Algorithm"
TIMESTAMP_HEADER = "X-Bam-Timestamp"
NONCE_HEADER = "X-Bam-Proof-Nonce"
ALGORITHM = "SHA256WITHECDSA"


class ProofSigner:
    """Signs requests for one actor key. Every call uses the current time and a nonce never used before."""

    def __init__(
        self,
        key_store: ActorKeyStore,
        clock: Callable[[], float] = time.time,
        nonce_source: Callable[[], str] | None = None,
    ):
        self._key_store = key_store
        self._clock = clock
        self._nonce_source = nonce_source or (lambda: secrets.token_hex(16))

    def sign(self, method: str, target: str, body: bytes = b"") -> dict[str, str]:
        """The proof headers for a request.

        target is the request target exactly as it will be sent: path and query, starting with '/'.
        body is the exact bytes that will be sent. A proof is good for one request; sign again to retry.
        """
        timestamp = int(self._clock())
        nonce = self._nonce_source()
        canonical = compose(method, target, timestamp, nonce, body)
        signature = self._key_store.sign(canonical.encode("utf-8"))
        return {
            SIGNATURE_HEADER: base64.b64encode(signature).decode("ascii"),
            ALGORITHM_HEADER: ALGORITHM,
            TIMESTAMP_HEADER: str(timestamp),
            NONCE_HEADER: nonce,
        }
