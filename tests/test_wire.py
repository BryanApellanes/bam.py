"""What the client writes and reads, held to the recorded messages, and the stand-in host held to the
answers the specification lists for /actor/register and /actor/token.

A flow test only means something if the stand-in refuses what a real host refuses. The tests here pin
that, so a client that drops a required property or the Content-Type header fails the suite.
"""
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
    Response,
    b64url_decode,
    client_token,
    decode_token,
    encode_token,
    verify_token,
)
from standin import StandInHost
from test_vectors import key_store, public_key, read

JSON = {"content-type": "application/json"}


class RecordingTransport:
    def __init__(self, answers):
        self.answers = list(answers)
        self.sent = []

    def send(self, method, target, headers, body):
        self.sent.append((method, target, dict(headers), body))
        return self.answers.pop(0)


def issued(token):
    return Response(200, {}, json.dumps({"token": token, "expiresUtc": "2026-09-21T14:58:20.1234567+00:00",
                                         "keyFingerprint": "0" * 64}).encode())


class RecordedMessages(unittest.TestCase):
    def setUp(self):
        self.document = read("messages.json")
        self.keys = MemoryActorKeyStore()

    def recorded(self, kind, accepted):
        return [json.loads(request["json"]) for request in self.document["requests"]
                if request["kind"] == kind and request["accepted"] is accepted]

    def test_the_client_writes_the_recorded_registration(self):
        transport = RecordingTransport([Response(200, {}, b'{"keySetHandle":"ada"}')])
        ActorClient("https://api.example.test", "ada", self.keys, transport=transport).register()
        method, target, headers, body = transport.sent[0]
        written = json.loads(body)
        self.assertEqual((method, target, headers["Content-Type"]), ("POST", "/actor/register", "application/json"))
        self.assertEqual(sorted(written), sorted(self.recorded("register", True)[0]))
        self.assertEqual((written["KeySetHandle"], written["PublicRsaKeyPem"]), ("ada", ""))
        self.assertEqual(written["PublicEccKeyPem"], self.keys.public_key_pem())

    def test_the_client_writes_the_recorded_token_request(self):
        token = client_token(self.keys, "ada", now=1790000000)
        transport = RecordingTransport([issued(token)])
        ActorClient("https://api.example.test", "ada", self.keys, audience="aud", transport=transport).token()
        method, target, headers, body = transport.sent[0]
        written = json.loads(body)
        self.assertEqual((method, target, headers["Content-Type"]), ("POST", "/actor/token", "application/json"))
        self.assertEqual(sorted(written), sorted(self.recorded("token", True)[0]))
        self.assertTrue(verify_token(written["ClientToken"], self.keys.public_key()))
        self.assertEqual(decode_token(written["ClientToken"])["aud"], "aud")

    def test_the_client_writes_the_invocation_as_the_specification_shows_it(self):
        token = client_token(self.keys, "ada", now=1790000000)
        transport = RecordingTransport([issued(token), Response(200, {}, b"null")])
        client = ActorClient("https://api.example.test", "ada", self.keys, transport=transport, clock=lambda: 1790000000)
        client.invoke("Sample.Greeter+Greet, Sample", {"name": "Ada"})
        method, target, headers, body = transport.sent[1]
        self.assertEqual((method, target, headers["Content-Type"]), ("POST", "/invoke", "application/json"))
        self.assertEqual(json.loads(body), {"OperationIdentifier": "Sample.Greeter+Greet, Sample", "Arguments": {"name": "Ada"}})

    def test_the_client_reads_each_recorded_token_answer(self):
        """The expiry comes from the token, so the seven-digit fraction a real host writes is never parsed."""
        answers = [response for response in self.document["responses"] if response["kind"] == "token"]
        self.assertTrue(any("." in answer["expiresUtc"] for answer in answers))
        for answer in answers:
            with self.subTest(answer=answer["name"]):
                token = encode_token({"sub": "ada", "sid": "s", "iss": "bam", "iat": 1790000000, "exp": 1790002700},
                                     self.keys.sign)
                body = answer["json"].replace('"a.b.c"', json.dumps(token)).encode()
                transport = RecordingTransport([Response(200, {}, body)])
                client = ActorClient("https://api.example.test", "ada", self.keys, transport=transport, clock=lambda: 1790000000)
                self.assertEqual(client.token(), token)
                self.assertEqual(client._token_expires, 1790002700.0)

    def test_the_client_reads_the_recorded_registration_and_refusal(self):
        registered = [r for r in self.document["responses"] if r["kind"] == "register"][0]
        refused = [r for r in self.document["responses"] if r["kind"] == "failure"][0]
        transport = RecordingTransport([Response(200, {}, registered["json"].encode()), Response(401, {}, refused["json"].encode())])
        client = ActorClient("https://api.example.test", "someone", self.keys, transport=transport)
        self.assertEqual(client.register(), registered["keySetHandle"])
        with self.assertRaises(BamError) as error:
            client.token()
        self.assertEqual((error.exception.status, error.exception.detail), (401, refused["message"]))


class StandInStrictness(unittest.TestCase):
    """The stand-in host answers as the specification says a host does."""

    def setUp(self):
        self.host = StandInHost()
        self.addCleanup(self.host.close)
        self.document = read("messages.json")

    def test_each_recorded_request_is_accepted_or_refused_as_recorded(self):
        checked = 0
        for request in self.document["requests"]:
            with self.subTest(request=request["name"]):
                target = "/actor/register" if request["kind"] == "register" else "/actor/token"
                host = StandInHost()
                self.addCleanup(host.close)
                status, body = host.respond("POST", target, JSON, request["json"].encode())[:2]
                # A body the host can read gets to the handler, which answers with a JSON body of its own: the
                # recorded key and token are placeholders, so that answer is a refusal. A body it cannot read
                # is answered 400 with nothing, before the handler.
                self.assertEqual((status, body) != (400, b""), request["accepted"], (status, body))
                self.assertEqual(isinstance(body, dict), request["accepted"])
                checked += 1
        self.assertGreaterEqual(checked, 5)

    def test_a_request_without_a_content_type_is_415(self):
        for target in ("/actor/register", "/actor/token"):
            self.assertEqual(self.host.respond("POST", target, {}, b"{}")[:2], (415, b""))

    def test_a_request_that_is_not_json_is_refused(self):
        for target in ("/actor/register", "/actor/token"):
            self.assertEqual(self.host.respond("POST", target, JSON, b"not json")[:2], (400, b""))
            self.assertEqual(self.host.respond("POST", target, {"content-type": "text/plain"}, b"{}")[:2],
                             (401, b"Authentication failed."))

    def test_the_unreadable_tokens_are_refused_though_signed(self):
        cases = read("tokens.json")["unreadable"]
        self.assertGreaterEqual(len(cases), 5)
        self.host.registered["ada"] = public_key("actor")
        self.host.admit("ada")
        self.host.audience = "https://api.example.test"
        self.host.clock = lambda: 1790000000
        good = read("tokens.json")["cases"][0]["token"]
        self.assertEqual(self.host.respond("POST", "/actor/token", JSON, json.dumps({"ClientToken": good}).encode())[0], 200)
        for case in cases:
            with self.subTest(case=case["name"]):
                self.assertTrue(verify_token(case["token"], public_key("actor")))
                with self.assertRaises(ValueError):
                    decode_token(case["token"])
                body = json.dumps({"ClientToken": case["token"]}).encode()
                self.assertEqual(self.host.respond("POST", "/actor/token", JSON, body)[0], 401)


class UnreadableAnswers(unittest.TestCase):
    """Every answer the client cannot use is a BamError, so `except BamError` covers a call."""

    def client(self, *answers):
        keys = MemoryActorKeyStore()
        self.keys = keys
        return ActorClient("https://api.example.test", "ada", keys, transport=RecordingTransport(answers), clock=lambda: 1790000000)

    def token(self, **changes):
        claims = {"sub": "ada", "sid": "s", "iss": "bam", "iat": 1790000000, "exp": 1790002700}
        claims.update(changes)
        return encode_token({name: value for name, value in claims.items() if value is not None}, MemoryActorKeyStore().sign)

    def test_a_200_that_is_not_json(self):
        for body in (b"", b"<html>proxy</html>"):
            with self.subTest(body=body):
                with self.assertRaises(BamError):
                    self.client(Response(200, {}, body)).register()
                with self.assertRaises(BamError):
                    self.client(Response(200, {}, body)).token()
        with self.assertRaises(BamError):
            self.client(issued(self.token()), Response(200, {}, b"<html>proxy</html>")).invoke("A+B, C")
        self.assertIsNone(self.client(issued(self.token()), Response(200, {}, b"")).invoke("A+B, C"))

    def test_a_token_that_cannot_be_read(self):
        for token in ("not-a-token", "a.b.c", self.token(exp=None), self.token(exp="soon"), self.token(exp=1.5)):
            with self.subTest(token=token[:24]), self.assertRaises(BamError) as error:
                self.client(issued(token)).token()
            self.assertEqual(error.exception.status, 200)

    def test_a_refusal_with_odd_contents(self):
        cases = [
            (Response(401, {}, b'{"messages":[1,2]}'), '{"messages":[1,2]}', None),
            (Response(401, {}, b'{"messages":["a",3,"b"]}'), "a b", None),
            (Response(400, {}, b'{"detail":7}'), '{"detail":7}', None),
            (Response(400, {}, b"[1]"), "[1]", None),
            (Response(503, {"retry-after": "²"}, b""), "The host gave no reason.", None),
            (Response(503, {"retry-after": "12"}, b"\xff\xfe"), "��", 12),
        ]
        for response, detail, retry_after in cases:
            with self.subTest(body=response.body), self.assertRaises(BamError) as error:
                self.client(response).token()
            self.assertEqual((error.exception.detail, error.exception.retry_after), (detail, retry_after))

    def test_send_raises_when_the_renewal_after_a_401_is_refused(self):
        client = self.client(issued(self.token()), Response(401, {}, b"Authentication failed."),
                             Response(401, {}, b'{"messages":["Authentication failed."]}'))
        with self.assertRaises(BamError) as error:
            client.send("GET", "/things")
        self.assertEqual(error.exception.status, 401)


class RequestShape(unittest.TestCase):
    def test_the_clients_own_headers_win_whatever_the_case(self):
        keys = MemoryActorKeyStore()
        token = encode_token({"sub": "ada", "sid": "s", "iss": "bam", "iat": 1790000000, "exp": 1790002700}, keys.sign)
        transport = RecordingTransport([issued(token), Response(200, {}, b"")])
        client = ActorClient("https://api.example.test", "ada", keys, transport=transport, clock=lambda: 1790000000)
        client.send("GET", "/things", headers={"authorization": "Bearer mine", "X-BAM-TIMESTAMP": "1", "X-Trace": "t"})
        sent = transport.sent[1][2]
        self.assertEqual(sorted(name.lower() for name in sent),
                         ["authorization", "x-bam-body-signature", "x-bam-body-signature-algorithm",
                          "x-bam-proof-nonce", "x-bam-timestamp", "x-trace"])
        self.assertEqual(sent["Authorization"], "Bearer " + token)
        self.assertEqual(sent["X-Bam-Timestamp"], "1790000000")

    def test_the_method_is_sent_as_it_is_signed(self):
        keys = MemoryActorKeyStore()
        token = encode_token({"sub": "ada", "sid": "s", "iss": "bam", "iat": 1790000000, "exp": 1790002700}, keys.sign)
        transport = RecordingTransport([issued(token), Response(200, {}, b"")])
        ActorClient("https://api.example.test", "ada", keys, transport=transport, clock=lambda: 1790000000).send("put", "/a")
        self.assertEqual(transport.sent[1][0], "PUT")

    def test_one_refused_token_is_renewed_once(self):
        keys = MemoryActorKeyStore()
        first = encode_token({"sub": "ada", "sid": "1", "iss": "bam", "iat": 1790000000, "exp": 1790002700}, keys.sign)
        second = encode_token({"sub": "ada", "sid": "2", "iss": "bam", "iat": 1790000000, "exp": 1790002700}, keys.sign)
        transport = RecordingTransport([issued(first), issued(second)])
        client = ActorClient("https://api.example.test", "ada", keys, transport=transport, clock=lambda: 1790000000)
        self.assertEqual(client.token(), first)
        self.assertEqual(client.token(renew=True, refused=first), second)
        self.assertEqual(client.token(renew=True, refused=first), second)
        self.assertEqual(len(transport.sent), 2)

    def test_base64url_is_read_strictly(self):
        self.assertEqual(b64url_decode("aGk"), b"hi")
        for text in ("aGk=", "aG k", "aGk\n", "a", "aG+k", "aG/k"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                b64url_decode(text)
        keys = MemoryActorKeyStore()
        token = client_token(keys, "ada")
        self.assertFalse(verify_token(token + "=", keys.public_key()))
        self.assertFalse(verify_token(token + "!!", keys.public_key()))

    def test_plain_http_is_for_loopback_only(self):
        for origin in ("http://127.0.0.1:8080", "http://localhost", "http://[::1]:5000", "https://api.example.test"):
            HttpTransport(origin)
        for origin in ("http://api.example.test", "http://10.0.0.5:8080", "http://localhost.example.test"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                HttpTransport(origin)
        HttpTransport("http://10.0.0.5:8080", allow_plain_http=True)


class KeyFileSafety(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = os.path.join(self.directory.name, "keys", "actor.pem")

    def test_an_empty_password_is_refused_and_leaves_no_file(self):
        with self.assertRaises(ValueError):
            FileActorKeyStore(self.path, password=b"")
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(os.listdir(os.path.dirname(self.path)) if os.path.isdir(os.path.dirname(self.path)) else [], [])
        FileActorKeyStore(self.path, password=b"real")
        FileActorKeyStore(self.path, password=b"real")

    @unittest.skipIf(sys.platform == "win32", "file modes are a Unix concept")
    def test_a_key_file_others_can_reach_is_refused_on_unix(self):
        FileActorKeyStore(self.path)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.path)).st_mode) & 0o077, 0)
        os.chmod(self.path, 0o644)
        with self.assertRaises(PermissionError):
            FileActorKeyStore(self.path)
        os.chmod(self.path, 0o600)
        FileActorKeyStore(self.path)


if __name__ == "__main__":
    unittest.main()
