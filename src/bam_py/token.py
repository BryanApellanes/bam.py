"""Tokens: three base64url segments, signed with ECDSA P-256 in DER.

The header says ES256, but the signature is ASN.1 DER, not the raw r||s a JOSE library writes, so these
are made and checked here and not with a JWT library. See "Tokens" in bam.protocol's spec/actor-auth.md.
"""
import json
import secrets
import time
from typing import Callable

from cryptography.hazmat.primitives.asymmetric import ec

from .encoding import b64url_decode, b64url_encode
from .keys import ActorKeyStore, verify

_HEADER = '{"alg":"ES256","typ":"JWT"}'
DEFAULT_CLIENT_TOKEN_SECONDS = 120


def encode_token(claims: dict, sign: Callable[[bytes], bytes]) -> str:
    """Writes a token for the claims. sign returns a DER signature over the bytes it is given."""
    payload = json.dumps(claims, separators=(",", ":"))
    signing_input = b64url_encode(_HEADER.encode("ascii")) + "." + b64url_encode(payload.encode("utf-8"))
    return signing_input + "." + b64url_encode(sign(signing_input.encode("ascii")))


def decode_token(token: str) -> dict:
    """Reads a token's claims, as the host reads them. It does not check the signature.

    Raises ValueError for anything the host would not read: sub, sid, iss, iat and exp are all
    required, the first three as strings and the last two as JSON integers.
    """
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        raise ValueError("A token has three segments.")
    claims = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    if not isinstance(claims, dict):
        raise ValueError("A token's payload is a JSON object.")
    for name in ("sub", "sid", "iss"):
        if not isinstance(claims.get(name), str):
            raise ValueError(f"A token's {name} claim is a string.")
    for name in ("iat", "exp"):
        if type(claims.get(name)) is not int:
            raise ValueError(f"A token's {name} claim is a whole number.")
    return claims


def verify_token(token: str, public_key: ec.EllipticCurvePublicKey) -> bool:
    """Whether the token's signature is the key's, over the header and payload as written. Never raises."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        signature = b64url_decode(parts[2])
    except (ValueError, TypeError):
        return False
    return verify(public_key, (parts[0] + "." + parts[1]).encode("ascii"), signature)


def client_token(
    key_store: ActorKeyStore,
    handle: str,
    audience: str | None = None,
    lifetime_seconds: int = DEFAULT_CLIENT_TOKEN_SECONDS,
    now: float | None = None,
) -> str:
    """A short token the actor signs with its own key, to trade for a server token.

    The host refuses one that lives longer than five minutes, and one whose audience is not the host's.
    """
    issued = int(time.time() if now is None else now)
    claims = {
        "sub": handle,
        "sid": secrets.token_hex(16),
        "iss": "client",
        "iat": issued,
        "exp": issued + int(lifetime_seconds),
    }
    if audience:
        claims["aud"] = audience
    return encode_token(claims, key_store.sign)
