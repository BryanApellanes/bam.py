"""Writes signatures, tokens and request proofs made by bam.py with the test keys, for another
implementation to verify.

    python tools/produce_vectors.py <output file>

The output has the shape of bam.protocol's spec/vectors/csharp-produced.json, so the C# vector tests
can read it in that file's place. bam.py signs with a random nonce each time, so two runs differ.
"""
import base64
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ec

from bam_py import MemoryActorKeyStore, ProofSigner, compose, decode_token, encode_token

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "vectors")
NOW = 1790000000


def store(keys, name):
    return MemoryActorKeyStore(ec.derive_private_key(int(keys[name]["privateScalarHex"], 16), ec.SECP256R1()))


def main(path):
    with open(os.path.join(VECTORS, "keys.json"), encoding="utf-8") as handle:
        keys = {key["name"]: key for key in json.load(handle)["keys"]}
    actor, server, other = store(keys, "actor"), store(keys, "server"), store(keys, "other")
    text = compose("POST", "/invoke", NOW, "python-nonce-0001", b"{}")

    def signature(name, signer, verifies):
        return {"name": name, "key": "actor", "text": text, "algorithm": "SHA256WITHECDSA",
                "signatureBase64": base64.b64encode(signer.sign(text.encode("utf-8"))).decode("ascii"), "verifies": verifies}

    def token(name, key, signer, claims):
        encoded = encode_token(claims, signer.sign)
        assert decode_token(encoded) == claims
        return {"name": name, "key": key, "claims": claims, "signingInput": encoded.rsplit(".", 1)[0], "token": encoded}

    def proof(name, method, target, body):
        headers = ProofSigner(actor, clock=lambda: NOW).sign(method, target, body)
        return {"name": name, "method": method, "target": target, "bodyHex": body.hex(), "headers": headers, "verified": True}

    body = b'{"OperationIdentifier":"Sample.Greeter+Greet, Sample","Arguments":{"name":"Ada"}}'
    document = {
        "description": "Written by bam.py (tools/produce_vectors.py) with the keys in keys.json.",
        "signatures": [
            signature("signed by bam.py", actor, True),
            signature("signed by bam.py with another key", other, False),
        ],
        "tokens": [
            token("a client token from bam.py", "actor", actor,
                  {"sub": "ada", "sid": "0123456789abcdef0123456789abcdef", "iss": "client", "iat": NOW, "exp": NOW + 120,
                   "aud": "https://api.example.test"}),
            token("a server token from bam.py", "server", server,
                  {"sub": "ada", "sid": "00112233445566778899aabbccddeeff", "iss": "bam", "iat": NOW, "exp": NOW + 2700,
                   "kfp": keys["actor"]["fingerprint"]}),
        ],
        "requestProofs": {
            "nowUnixSeconds": NOW,
            "signingKey": "actor",
            "cases": [
                proof("a POST signed by bam.py", "POST", "/invoke?trace=1", body),
                proof("a GET signed by bam.py", "GET", "/things", b""),
                proof("an awkward target signed by bam.py", "PUT", "/a%20b/caf%C3%A9?x=%2F&y=a+b", b"x"),
            ],
            "replays": [proof("a bam.py proof sent twice", "POST", "/invoke", body)],
        },
    }
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
    print("wrote", path)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(sys.argv[1])
