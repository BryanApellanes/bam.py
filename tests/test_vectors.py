"""Holds bam.py to the known-answer vectors shared with the C# implementation.

The files in tests/vectors are copied from bam.protocol's spec/vectors; tests/vectors/SOURCE.md names
the commit. tools/sync_vectors.py refreshes them.
"""
import base64
import json
import os
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from bam_py import (
    MemoryActorKeyStore,
    body_digest,
    compose,
    decode_token,
    der_to_raw,
    encode_token,
    fingerprint_of,
    is_origin_form,
    is_well_formed_nonce,
    load_public_key,
    raw_to_der,
    split_target,
    verify,
    verify_token,
)
from standin import judge_proof

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")
ALLOWED = ("sha256withecdsa",)


def read(name):
    with open(os.path.join(VECTORS, name), encoding="utf-8") as handle:
        return json.load(handle)


KEYS = {key["name"]: key for key in read("keys.json")["keys"]}


def public_key(name):
    return load_public_key(base64.b64decode(KEYS[name]["spkiNamedCurveBase64"]))


def key_store(name):
    scalar = int(KEYS[name]["privateScalarHex"], 16)
    return MemoryActorKeyStore(ec.derive_private_key(scalar, ec.SECP256R1()))


class KeyVectors(unittest.TestCase):
    def test_every_encoding_of_a_key_has_its_one_fingerprint(self):
        document = read("keys.json")
        checked = 0
        for key in document["keys"] + document["publicOnly"]:
            for form in ("spkiNamedCurveBase64", "spkiExplicitParametersBase64", "spkiCompressedPointBase64"):
                with self.subTest(key=key["name"], form=form):
                    self.assertEqual(fingerprint_of(load_public_key(base64.b64decode(key[form]))), key["fingerprint"])
                    checked += 1
        self.assertEqual(checked, 12)

    def test_a_private_scalar_gives_its_public_key_and_fingerprint(self):
        for name, key in KEYS.items():
            with self.subTest(key=name):
                store = key_store(name)
                self.assertEqual(store.fingerprint(), key["fingerprint"])
                self.assertEqual(fingerprint_of(load_public_key(store.public_key_pem().encode("ascii"))), key["fingerprint"])


class CanonicalRequestVectors(unittest.TestCase):
    def setUp(self):
        self.document = read("canonical-request.json")

    def test_composes_the_recorded_text(self):
        self.assertGreaterEqual(len(self.document["cases"]), 9)
        for case in self.document["cases"]:
            with self.subTest(case=case["name"]):
                body = bytes.fromhex(case["bodyHex"])
                self.assertEqual(split_target(case["target"]), (case["path"], case["query"]))
                self.assertEqual(body_digest(body), case["bodySha256Hex"])
                text = compose(case["method"], case["target"], case["timestamp"], case["nonce"], body)
                self.assertEqual(text, case["canonical"])
                self.assertEqual(text.encode("utf-8").hex(), case["canonicalUtf8Hex"])

    def test_refuses_the_recorded_targets(self):
        self.assertGreaterEqual(len(self.document["refusedTargets"]), 6)
        for case in self.document["refusedTargets"]:
            with self.subTest(case=case["name"]):
                self.assertFalse(is_origin_form(case["target"]))
                with self.assertRaises(ValueError):
                    split_target(case["target"])

    def test_tells_well_formed_nonces_from_malformed_ones(self):
        for nonce in self.document["wellFormedNonces"]:
            self.assertTrue(is_well_formed_nonce(nonce), nonce)
        self.assertGreaterEqual(len(self.document["malformedNonces"]), 8)
        for case in self.document["malformedNonces"]:
            with self.subTest(case=case["name"]):
                self.assertFalse(is_well_formed_nonce(case["nonce"]))


class SignatureVectors(unittest.TestCase):
    def test_verifies_each_signature_as_recorded(self):
        cases = read("signatures.json")["cases"] + read("csharp-produced.json")["signatures"]
        self.assertGreaterEqual(len(cases), 13)
        for case in cases:
            with self.subTest(case=case["name"]):
                allowed = (case["algorithm"] or "SHA256WITHECDSA").lower() in ALLOWED
                signature = base64.b64decode(case["signatureBase64"])
                verified = allowed and verify(public_key(case["key"]), case["text"].encode("utf-8"), signature)
                self.assertEqual(verified, case["verifies"])

    def test_converts_a_signature_between_der_and_raw(self):
        cases = read("der-raw.json")["cases"]
        self.assertGreaterEqual(len(cases), 6)
        for case in cases:
            with self.subTest(case=case["name"]):
                self.assertEqual(der_to_raw(bytes.fromhex(case["derHex"])).hex(), case["rawHex"])
                self.assertEqual(raw_to_der(bytes.fromhex(case["rawHex"])).hex(), case["derHex"])

    def test_refuses_a_raw_signature_of_the_wrong_length(self):
        with self.assertRaises(ValueError):
            raw_to_der(b"\x01" * 63)


class TokenVectors(unittest.TestCase):
    def test_reads_and_verifies_each_recorded_token(self):
        cases = read("tokens.json")["cases"] + read("csharp-produced.json")["tokens"]
        self.assertGreaterEqual(len(cases), 6)
        for case in cases:
            with self.subTest(case=case["name"]):
                self.assertTrue(verify_token(case["token"], public_key(case["key"])))
                self.assertEqual(decode_token(case["token"]), case["claims"])

    def test_writes_tokens_the_recorded_key_verifies(self):
        for case in read("tokens.json")["cases"]:
            with self.subTest(case=case["name"]):
                token = encode_token(case["claims"], key_store(case["key"]).sign)
                self.assertTrue(verify_token(token, public_key(case["key"])))
                self.assertEqual(decode_token(token), case["claims"])
                self.assertFalse(verify_token(token, public_key("other")))

    def test_refuses_each_recorded_bad_token(self):
        cases = read("tokens.json")["refused"]
        self.assertGreaterEqual(len(cases), 5)
        for case in cases:
            with self.subTest(case=case["name"]):
                self.assertFalse(verify_token(case["token"], public_key(case["key"])))


    def test_reads_the_time_a_real_host_writes(self):
        """bam.py takes the expiry from the token, so the seven-digit fraction never has to be parsed."""
        issued = [json.loads(r["json"]) for r in read("messages.json")["responses"] if r["kind"] == "token"]
        self.assertTrue(any("." in answer["expiresUtc"] for answer in issued))


class RequestProofVectors(unittest.TestCase):
    """Holds the stand-in host's judgement to the real host's recorded verdicts."""

    def test_judges_each_request_as_recorded(self):
        checked = 0
        for document in (read("request-proof.json"), read("csharp-produced.json")["requestProofs"]):
            caller = public_key(document["signingKey"])
            for case in document["cases"]:
                with self.subTest(case=case["name"]):
                    headers = {name.lower(): value for name, value in case["headers"].items()}
                    verdict = judge_proof(case["method"], case["target"], bytes.fromhex(case["bodyHex"]), headers,
                                          caller, document["nowUnixSeconds"], set())
                    self.assertEqual(verdict, case["verified"])
                    checked += 1
            for case in document["replays"]:
                with self.subTest(case=case["name"]):
                    headers = {name.lower(): value for name, value in case["headers"].items()}
                    seen = set()
                    arguments = (case["method"], case["target"], bytes.fromhex(case["bodyHex"]), headers, caller,
                                 document["nowUnixSeconds"], seen)
                    self.assertTrue(judge_proof(*arguments))
                    self.assertFalse(judge_proof(*arguments))
                    checked += 1
        self.assertGreaterEqual(checked, 22)


class MessageVectors(unittest.TestCase):
    def test_the_recorded_bodies_are_the_ones_the_client_writes_and_reads(self):
        document = read("messages.json")
        register = json.loads(document["requests"][0]["json"])
        self.assertEqual(sorted(register), ["KeySetHandle", "PublicEccKeyPem", "PublicRsaKeyPem"])
        self.assertEqual(list(json.loads(document["requests"][3]["json"])), ["ClientToken"])
        issued = json.loads(document["responses"][1]["json"])
        self.assertEqual(sorted(issued), ["expiresUtc", "keyFingerprint", "token"])


if __name__ == "__main__":
    unittest.main()
