"""bam.py: call a Bam host as an authenticated actor.

The wire is described in bam.protocol's spec/actor-auth.md.
"""
from .canonical import body_digest, compose, is_origin_form, is_well_formed_nonce, split_target
from .client import ActorClient, BamError
from .encoding import b64url_decode, b64url_encode, der_to_raw, raw_to_der
from .keys import (
    ActorKeyStore,
    FileActorKeyStore,
    MemoryActorKeyStore,
    fingerprint_of,
    load_public_key,
    verify,
)
from .proof import ProofSigner
from .token import client_token, decode_token, encode_token, verify_token
from .transport import HttpTransport, Response, Transport

__version__ = "0.1.0"

__all__ = [
    "ActorClient",
    "ActorKeyStore",
    "BamError",
    "FileActorKeyStore",
    "HttpTransport",
    "MemoryActorKeyStore",
    "ProofSigner",
    "Response",
    "Transport",
    "b64url_decode",
    "b64url_encode",
    "body_digest",
    "client_token",
    "compose",
    "decode_token",
    "der_to_raw",
    "encode_token",
    "fingerprint_of",
    "is_origin_form",
    "is_well_formed_nonce",
    "load_public_key",
    "raw_to_der",
    "split_target",
    "verify",
    "verify_token",
]
