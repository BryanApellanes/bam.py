"""Where the actor's P-256 key lives, and what is done with it: signing, and naming its public half."""
import base64
import hashlib
import os
import tempfile
from typing import Protocol

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# The DER SubjectPublicKeyInfo of a P-256 key, named-curve form, up to its 65-byte uncompressed point.
_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def fingerprint_of(public_key: ec.EllipticCurvePublicKey) -> str:
    """Lowercase hex SHA-256 of the key's named-curve SubjectPublicKeyInfo with an uncompressed point.

    Every encoding of one key has this one fingerprint. It is what the host reports as KeyFingerprint.
    """
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("The actor-auth wire uses P-256 keys.")
    point = public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return hashlib.sha256(_SPKI_PREFIX + point).hexdigest()


# SubjectPublicKeyInfo for P-256 with the curve written out in full (explicit parameters, with the
# standard seed and cofactor) instead of named. What follows these bytes is the 65-byte point.
_EXPLICIT_P256_PREFIX = bytes.fromhex(
    "3082014b3082010306072a8648ce3d02013081f7020101302c06072a8648ce3d0101022100ffffffff00000001000000"
    "000000000000000000ffffffffffffffffffffffff305b0420ffffffff00000001000000000000000000000000ffffff"
    "fffffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b031500c49d"
    "360886e704936a6678e1139d26b7819f7e900441046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a139"
    "45d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5022100ffffffff00000000"
    "ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101034200")


def load_public_key(spki: bytes) -> ec.EllipticCurvePublicKey:
    """Reads a P-256 public key from DER or PEM SubjectPublicKeyInfo, in any of its encodings.

    A key with the curve written out in full is read here, because not every version of the
    cryptography package reads that form. Only P-256's own parameters are accepted that way.
    """
    der = spki
    if spki.lstrip().startswith(b"-----"):
        lines = [line.strip() for line in spki.strip().splitlines()]
        try:
            der = base64.b64decode(b"".join(line for line in lines if not line.startswith(b"-----")), validate=True)
        except ValueError:
            der = b""
    if len(der) == len(_EXPLICIT_P256_PREFIX) + 65 and der.startswith(_EXPLICIT_P256_PREFIX):
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), der[len(_EXPLICIT_P256_PREFIX):])
    try:
        if spki.lstrip().startswith(b"-----"):
            key = serialization.load_pem_public_key(spki)
        else:
            key = serialization.load_der_public_key(spki)
    except UnsupportedAlgorithm as unsupported:
        raise ValueError("Not a P-256 public key.") from unsupported
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("Not a P-256 public key.")
    return key


def verify(public_key: ec.EllipticCurvePublicKey, data: bytes, der_signature: bytes) -> bool:
    """Whether a DER signature is the key's ECDSA signature over SHA-256 of data. Never raises."""
    try:
        public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class ActorKeyStore(Protocol):
    """Keeps the actor's key pair. The private half is used here and never handed out."""

    def public_key(self) -> ec.EllipticCurvePublicKey: ...

    def public_key_pem(self) -> str: ...

    def fingerprint(self) -> str: ...

    def sign(self, data: bytes) -> bytes:
        """ECDSA over SHA-256 of data, as ASN.1 DER."""
        ...


class _KeyStore:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError("The actor-auth wire uses P-256 keys.")
        self._private_key = private_key

    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self._private_key.public_key()

    def public_key_pem(self) -> str:
        """The public key as PEM SubjectPublicKeyInfo, named-curve form, as registration sends it."""
        return self.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

    def fingerprint(self) -> str:
        return fingerprint_of(self.public_key())

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))


class MemoryActorKeyStore(_KeyStore):
    """A key that lives only in this process. For tests and short-lived actors."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None):
        super().__init__(private_key or ec.generate_private_key(ec.SECP256R1()))


class FileActorKeyStore(_KeyStore):
    """A key kept in a PEM file that only its owner can read.

    The file is created on first use, and a leading ~ in the path is the user home directory. On Unix it is created with mode 0600 and never exists with wider
    access. On Windows it inherits the access rules of its directory, so keep it in the user's profile.
    The file is not encrypted unless a password is given.
    """

    def __init__(self, path: str | os.PathLike, password: bytes | None = None):
        self.path = os.path.expanduser(os.fspath(path))
        if not os.path.exists(self.path):
            self._create(password)
        with open(self.path, "rb") as handle:
            private_key = serialization.load_pem_private_key(handle.read(), password=password)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError(f"{self.path} does not hold an EC private key.")
        super().__init__(private_key)

    def _create(self, password: bytes | None) -> None:
        encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
        )
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        # mkstemp makes the file for its owner only, under a name nothing else has. The key is complete
        # before it gets its real name, and linking refuses to replace a key that appeared meanwhile, so
        # two processes starting at once end up reading the same key.
        descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=".key-", suffix=".tmp")
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(pem)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, self.path)
            except FileExistsError:
                pass
        finally:
            os.remove(temporary)
