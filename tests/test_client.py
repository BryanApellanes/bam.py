"""The whole flow against the stand-in host, and each part of the client on its own."""
import json
import os
import stat
import sys
import tempfile
import unittest

from bam_py import (
    ActorClient,
    BamError,
    FileActorKeyStore,
    HttpTransport,
    MemoryActorKeyStore,
    ProofSigner,
    Response,
    client_token,
    compose,
    decode_token,
    load_public_key,
    verify,
    verify_token,
)
from standin import StandInHost, judge_proof

GREET = "Sample.Greeter+Greet, Sample"


class Clock:
    def __init__(self, now=1790000000.0):
        self.now = now

    def __call__(self):
        return self.now


class Flow(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.host = StandInHost(clock=self.clock)
        self.addCleanup(self.host.close)
        self.keys = MemoryActorKeyStore()
        self.client = ActorClient(self.host.origin, "ada", self.keys, audience=self.host.audience, clock=self.clock)

    def test_registers_is_admitted_and_invokes(self):
        self.assertEqual(self.client.register(), "ada")
        self.host.admit("ada")
        self.assertEqual(self.client.invoke(GREET, {"name": "Ada"}), {"Greeting": "Hello, Ada, from ada"})

    def test_is_refused_until_admitted(self):
        self.client.register()
        with self.assertRaises(BamError) as refused:
            self.client.invoke(GREET, {"name": "Ada"})
        self.assertEqual(refused.exception.status, 401)
        self.assertEqual(refused.exception.detail, "Authentication failed.")

    def test_registering_a_taken_handle_is_refused(self):
        self.client.register()
        with self.assertRaises(BamError) as refused:
            ActorClient(self.host.origin, "ada", MemoryActorKeyStore(), audience=self.host.audience).register()
        self.assertEqual(refused.exception.status, 400)
        self.assertEqual(refused.exception.detail, "Registration was not accepted.")

    def test_a_wrong_audience_is_refused(self):
        self.client.register()
        self.host.admit("ada")
        stranger = ActorClient(self.host.origin, "ada", self.keys, audience="https://elsewhere.test", clock=self.clock)
        with self.assertRaises(BamError) as refused:
            stranger.token()
        self.assertEqual(refused.exception.status, 401)

    def test_sends_the_target_exactly_as_signed(self):
        self.client.register()
        self.host.admit("ada")
        for target in ("/a%20b/caf%C3%A9?x=%2F&y=a+b", "/a/../b//c", "/a?", "/a?b=1?c=2"):
            with self.subTest(target=target):
                response = self.client.send("PUT", target, b"payload")
                self.assertEqual(response.status, 200, response.body)
                self.assertEqual(json.loads(response.body)["target"], target)
                self.assertEqual(self.host.request_lines[-1], "PUT %s HTTP/1.1" % target)

    def test_reuses_one_token_and_renews_it_before_it_expires(self):
        self.client.register()
        self.host.admit("ada")
        self.client.invoke(GREET, {"name": "Ada"})
        self.client.invoke(GREET, {"name": "Ada"})
        self.assertEqual(self.host.tokens_issued, 1)
        self.clock.now += self.host.token_seconds - 30
        self.client.invoke(GREET, {"name": "Ada"})
        self.assertEqual(self.host.tokens_issued, 2)

    def test_a_401_is_tried_once_more_with_a_new_token(self):
        self.client.register()
        self.host.admit("ada")
        self.client.invoke(GREET, {"name": "Ada"})
        self.host.server_key = MemoryActorKeyStore()
        self.assertEqual(self.client.invoke(GREET, {"name": "Ada"}), {"Greeting": "Hello, Ada, from ada"})
        self.assertEqual(self.host.tokens_issued, 2)

    def test_every_request_carries_a_new_nonce(self):
        self.client.register()
        self.host.admit("ada")
        for _ in range(5):
            self.assertEqual(self.client.send("GET", "/things").status, 200)
        self.assertEqual(len(self.host.nonces["ada"]), 5)

    def test_reports_the_status_reason_and_retry_after(self):
        self.client.register()
        self.host.admit("ada")
        self.host.refuse_next_with = 503
        with self.assertRaises(BamError) as refused:
            self.client.invoke(GREET, {"name": "Ada"})
        self.assertEqual((refused.exception.status, refused.exception.detail, refused.exception.retry_after),
                         (503, "retry later", 30))
        with self.assertRaises(BamError) as missing:
            self.client.invoke("Sample.Greeter+Nothing, Sample")
        self.assertEqual((missing.exception.status, missing.exception.detail), (461, "The operation is not available."))

    def test_a_clock_outside_the_window_is_refused(self):
        self.client.register()
        self.host.admit("ada")
        self.client.token()
        slow = ActorClient(self.host.origin, "ada", self.keys, audience=self.host.audience, clock=self.clock)
        slow._token, slow._token_expires = self.client._token, self.client._token_expires
        slow._proofs = ProofSigner(self.keys, clock=lambda: self.clock.now - 301)
        self.assertEqual(slow.send("GET", "/things").status, 401)


class RecordingTransport:
    def __init__(self, answers):
        self.answers = list(answers)
        self.sent = []

    def send(self, method, target, headers, body):
        self.sent.append((method, target, dict(headers), body))
        return self.answers.pop(0)


class Parts(unittest.TestCase):
    def test_a_proof_signs_the_request_it_names(self):
        keys = MemoryActorKeyStore()
        headers = ProofSigner(keys, clock=lambda: 1790000000, nonce_source=lambda: "fixed-nonce-0001").sign("post", "/a?b=1", b"{}")
        self.assertEqual(headers["X-Bam-Timestamp"], "1790000000")
        self.assertEqual(headers["X-Bam-Proof-Nonce"], "fixed-nonce-0001")
        self.assertEqual(headers["X-Bam-Body-Signature-Algorithm"], "SHA256WITHECDSA")
        lowered = {name.lower(): value for name, value in headers.items()}
        self.assertTrue(judge_proof("POST", "/a?b=1", b"{}", lowered, keys.public_key(), 1790000000, set()))
        self.assertFalse(judge_proof("POST", "/a?b=2", b"{}", lowered, keys.public_key(), 1790000000, set()))
        self.assertFalse(judge_proof("POST", "/a?b=1", b"{ }", lowered, keys.public_key(), 1790000000, set()))

    def test_two_proofs_of_one_request_differ(self):
        signer = ProofSigner(MemoryActorKeyStore())
        self.assertNotEqual(signer.sign("GET", "/a")["X-Bam-Proof-Nonce"], signer.sign("GET", "/a")["X-Bam-Proof-Nonce"])

    def test_a_proof_refuses_a_target_it_cannot_cover(self):
        signer = ProofSigner(MemoryActorKeyStore())
        for target in ("http://host/a", "a", "/a#top", "/a\nb"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                signer.sign("GET", target)

    def test_a_client_token_carries_the_claims_the_host_checks(self):
        keys = MemoryActorKeyStore()
        token = client_token(keys, "ada", "https://api.example.test", now=1790000000)
        claims = decode_token(token)
        self.assertEqual((claims["sub"], claims["iss"], claims["aud"]), ("ada", "client", "https://api.example.test"))
        self.assertEqual((claims["iat"], claims["exp"]), (1790000000, 1790000120))
        self.assertEqual(len(claims["sid"]), 32)
        self.assertTrue(verify_token(token, keys.public_key()))
        self.assertNotIn("aud", decode_token(client_token(keys, "ada")))

    def test_client_signed_mode_never_asks_for_a_server_token(self):
        keys = MemoryActorKeyStore()
        transport = RecordingTransport([Response(200, {}, b"{}")])
        client = ActorClient("https://api.example.test", "ada", keys, audience="aud", transport=transport, server_tokens=False)
        client.send("GET", "/things")
        self.assertEqual(len(transport.sent), 1)
        bearer = transport.sent[0][2]["Authorization"][7:]
        self.assertTrue(verify_token(bearer, keys.public_key()))
        self.assertEqual(decode_token(bearer)["aud"], "aud")

    def test_reads_response_names_without_regard_to_case(self):
        keys = MemoryActorKeyStore()
        token = client_token(keys, "ada", now=1790000000)
        transport = RecordingTransport([Response(200, {}, json.dumps({"Token": token}).encode()), Response(200, {}, b"{}")])
        client = ActorClient("https://api.example.test", "ada", keys, transport=transport, clock=lambda: 1789999000)
        client.send("GET", "/things", proof=False)
        self.assertEqual(transport.sent[1][2]["Authorization"], "Bearer " + token)
        self.assertNotIn("X-Bam-Body-Signature", transport.sent[1][2])

    def test_an_answer_without_a_token_is_an_error(self):
        client = ActorClient("https://api.example.test", "ada", MemoryActorKeyStore(), transport=RecordingTransport([Response(200, {}, b"{}")]))
        with self.assertRaises(BamError):
            client.token()

    def test_a_refusal_without_a_json_body_is_still_reported(self):
        answers = [Response(401, {}, b"Authentication failed."), Response(400, {}, b""), Response(415, {}, b"")]
        client = ActorClient("https://api.example.test", "ada", MemoryActorKeyStore(), transport=RecordingTransport(answers))
        with self.assertRaises(BamError) as plain:
            client.token()
        self.assertEqual((plain.exception.status, plain.exception.detail), (401, "Authentication failed."))
        with self.assertRaises(BamError) as empty:
            client.register()
        self.assertEqual((empty.exception.status, empty.exception.detail), (400, "The host gave no reason."))
        with self.assertRaises(BamError) as unsupported:
            client.register()
        self.assertEqual(unsupported.exception.status, 415)

    def test_requests_with_a_body_say_they_are_json(self):
        transport = RecordingTransport([Response(200, {}, b'{"keySetHandle":"ada"}')])
        ActorClient("https://api.example.test", "ada", MemoryActorKeyStore(), transport=transport).register()
        self.assertEqual(transport.sent[0][2]["Content-Type"], "application/json")

    def test_the_origin_must_be_an_origin(self):
        for origin in ("api.example.test", "ftp://api.example.test", "https://api.example.test/base", "https://api.example.test/?a=1"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                HttpTransport(origin)
        HttpTransport("https://api.example.test/")


class KeyFiles(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = os.path.join(self.directory.name, "keys", "actor.pem")

    def test_creates_a_key_and_reads_the_same_key_back(self):
        first = FileActorKeyStore(self.path)
        second = FileActorKeyStore(self.path)
        self.assertEqual(first.fingerprint(), second.fingerprint())
        signature = first.sign(b"hello")
        self.assertTrue(verify(second.public_key(), b"hello", signature))
        self.assertFalse(verify(second.public_key(), b"hello!", signature))
        self.assertEqual(os.listdir(os.path.dirname(self.path)), ["actor.pem"])

    def test_a_leading_tilde_is_the_home_directory(self):
        previous = {name: os.environ.get(name) for name in ("HOME", "USERPROFILE")}
        os.environ["HOME"] = os.environ["USERPROFILE"] = self.directory.name
        try:
            store = FileActorKeyStore("~/keys/home.pem")
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        self.assertEqual(os.path.normpath(store.path), os.path.normpath(os.path.join(self.directory.name, "keys", "home.pem")))
        self.assertTrue(os.path.exists(store.path))

    def test_the_public_pem_is_the_named_curve_form(self):
        store = FileActorKeyStore(self.path)
        pem = store.public_key_pem()
        self.assertTrue(pem.startswith("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"))
        self.assertEqual(load_public_key(pem.encode("ascii")).public_numbers(), store.public_key().public_numbers())

    def test_a_password_protects_the_file(self):
        FileActorKeyStore(self.path, password=b"correct horse")
        with open(self.path, "rb") as handle:
            self.assertIn(b"ENCRYPTED PRIVATE KEY", handle.read())
        FileActorKeyStore(self.path, password=b"correct horse")
        with self.assertRaises((ValueError, TypeError)):
            FileActorKeyStore(self.path)

    def test_a_file_that_is_not_an_ec_key_is_refused(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as handle:
            handle.write("not a key")
        os.chmod(self.path, 0o600)
        with self.assertRaises(ValueError):
            FileActorKeyStore(self.path)

    @unittest.skipIf(sys.platform == "win32", "file modes are a Unix concept")
    def test_the_key_file_is_owner_only_on_unix(self):
        previous = os.umask(0)
        try:
            FileActorKeyStore(self.path)
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
