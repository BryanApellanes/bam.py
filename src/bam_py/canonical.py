"""The text a request proof signs. See "Request proof" in bam.protocol's spec/actor-auth.md."""
import hashlib

VERSION = "BAM-REQUEST-PROOF-1"
MINIMUM_NONCE_LENGTH = 16
MAXIMUM_NONCE_LENGTH = 128
_NONCE_CHARACTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def is_origin_form(target: str) -> bool:
    """A proof covers only a target that starts with '/' and holds no fragment."""
    return bool(target) and target[0] == "/" and "#" not in target


def split_target(target: str) -> tuple[str, str]:
    """Splits a request target at its first '?'. The query keeps its '?'. Nothing is decoded or normalised."""
    if not is_origin_form(target):
        raise ValueError("A request proof covers only a target that starts with '/' and has no fragment.")
    question = target.find("?")
    if question < 0:
        return target, ""
    return target[:question] or "/", target[question:]


def body_digest(body: bytes) -> str:
    """Lowercase hex SHA-256 of the exact body bytes."""
    return hashlib.sha256(body).hexdigest()


def is_well_formed_nonce(nonce: str) -> bool:
    """16 to 128 characters of A-Z, a-z, 0-9, '-' and '_'."""
    return (
        isinstance(nonce, str)
        and MINIMUM_NONCE_LENGTH <= len(nonce) <= MAXIMUM_NONCE_LENGTH
        and all(character in _NONCE_CHARACTERS for character in nonce)
    )


def compose(method: str, target: str, timestamp: int, nonce: str, body: bytes) -> str:
    """The seven fields joined by a line feed, with no line feed at the end."""
    if not method or not method.strip():
        raise ValueError("A method is required.")
    if not is_well_formed_nonce(nonce):
        raise ValueError("The nonce must be 16 to 128 characters of A-Z, a-z, 0-9, '-' or '_'.")
    if any(mark in method or mark in target for mark in ("\n", "\r")):
        raise ValueError("The method and target must not contain line breaks.")
    path, query = split_target(target)
    return "\n".join([VERSION, method.upper(), path, query, str(int(timestamp)), nonce, body_digest(body)])
