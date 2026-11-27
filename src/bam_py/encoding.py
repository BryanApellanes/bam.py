"""Byte encodings the wire uses: base64url without padding, and the two forms of an ECDSA signature."""
import base64

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

_COORDINATE_BYTES = 32


def b64url_encode(data: bytes) -> str:
    """Base64url without padding, as tokens use it."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    """Reads base64url with or without padding."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def der_to_raw(der: bytes) -> bytes:
    """Turns a DER ECDSA signature, as the wire carries it, into the 64-byte r||s form."""
    r, s = decode_dss_signature(der)
    return r.to_bytes(_COORDINATE_BYTES, "big") + s.to_bytes(_COORDINATE_BYTES, "big")


def raw_to_der(raw: bytes) -> bytes:
    """Turns a 64-byte r||s signature, as WebCrypto and JOSE write it, into the DER the wire carries."""
    if len(raw) != 2 * _COORDINATE_BYTES:
        raise ValueError("A raw P-256 signature is 64 bytes.")
    r = int.from_bytes(raw[:_COORDINATE_BYTES], "big")
    s = int.from_bytes(raw[_COORDINATE_BYTES:], "big")
    return encode_dss_signature(r, s)
