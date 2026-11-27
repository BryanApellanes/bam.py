"""A stand-in Bam host for tests. It judges tokens and request proofs by the rules in the specification.

test_vectors holds judge_proof to the verdicts recorded for the real host, so the flow tests that
use this host are not just the client agreeing with itself.
"""
import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from bam_py import (
    MemoryActorKeyStore,
    compose,
    decode_token,
    encode_token,
    fingerprint_of,
    is_origin_form,
    is_well_formed_nonce,
    load_public_key,
    verify,
    verify_token,
)

MAX_AGE_SECONDS = 300
ALLOWED_ALGORITHMS = ("sha256withecdsa",)


def judge_proof(method, target, body, headers, public_key, now, seen_nonces, max_age=MAX_AGE_SECONDS):
    """Whether a host with default settings accepts this request's proof. headers has lower-case names."""
    signature = headers.get("x-bam-body-signature", "")
    timestamp = headers.get("x-bam-timestamp", "")
    nonce = headers.get("x-bam-proof-nonce", "")
    algorithm = headers.get("x-bam-body-signature-algorithm") or "SHA256WITHECDSA"
    if not signature.strip() or not timestamp.isascii() or not timestamp.isdigit() or not is_well_formed_nonce(nonce):
        return False
    if abs(int(timestamp) - now) > max_age or not is_origin_form(target):
        return False
    if algorithm.strip().lower() not in ALLOWED_ALGORITHMS:
        return False
    try:
        der = base64.b64decode(signature, validate=True)
        canonical = compose(method, target, int(timestamp), nonce, body)
    except ValueError:
        return False
    if not verify(public_key, canonical.encode("utf-8"), der):
        return False
    if nonce in seen_nonces:
        return False
    seen_nonces.add(nonce)
    return True


class StandInHost:
    """Runs on a loopback port. Registered actors are admitted only when admit(handle) is called."""

    def __init__(self, audience="https://standin.test", clock=time.time, token_seconds=2700):
        self.audience = audience
        self.clock = clock
        self.token_seconds = token_seconds
        self.server_key = MemoryActorKeyStore()
        self.registered = {}
        self.admitted = set()
        self.nonces = {}
        self.request_lines = []
        self.tokens_issued = 0
        self.refuse_next_with = None
        host = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *arguments):
                pass

            def _answer(self, status, body, content_type="application/json", extra=None):
                data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
                self.send_response(status)
                if content_type is not None:
                    self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                for name, value in (extra or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(data)

            def _handle(self):
                host.request_lines.append(self.requestline)
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                headers = {name.lower(): value for name, value in self.headers.items()}
                status, answer, kind, extra = host.respond(self.command, self.path, headers, body)
                self._answer(status, answer, kind, extra)

            do_GET = do_POST = do_PUT = do_DELETE = _handle

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = "http://127.0.0.1:%d" % self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()

    def admit(self, handle):
        self.admitted.add(handle)

    def respond(self, method, target, headers, body):
        json_kind = "application/json"
        failure = (401, {"messages": ["Authentication failed."]}, json_kind, None)
        if target in ("/actor/register", "/actor/token"):
            # What the host answers before a handler runs: see "Answers before the handler" in the specification.
            content_type = headers.get("content-type")
            if content_type is None:
                return 415, b"", None, None
            if content_type.split(";")[0].strip().lower() != json_kind:
                return 401, b"Authentication failed.", "text/plain", None
            required = ("keysethandle", "publicrsakeypem", "publicecckeypem") if target == "/actor/register" else ("clienttoken",)
            try:
                request = {name.lower(): value for name, value in json.loads(body).items()}
            except (ValueError, AttributeError):
                return 400, b"", None, None
            if any(not isinstance(request.get(name), str) for name in required):
                return 400, b"", None, None
        if target == "/actor/register":
            handle = request["keysethandle"]
            if handle in self.registered:
                return 400, {"messages": ["Registration was not accepted."]}, json_kind, None
            try:
                self.registered[handle] = load_public_key(request["publicecckeypem"].encode("ascii"))
            except ValueError:
                return 400, {"messages": ["Registration was not accepted."]}, json_kind, None
            return 200, {"keySetHandle": handle}, json_kind, None
        if target == "/actor/token":
            actor = self._client_token_actor(request["clienttoken"])
            if actor is None:
                return failure
            return 200, self._issue(actor), json_kind, None

        actor = self._bearer_actor(headers.get("authorization", ""))
        if actor is None:
            return 401, b"Authentication failed.", "text/plain", None
        if self.refuse_next_with is not None:
            status, self.refuse_next_with = self.refuse_next_with, None
            return status, {"detail": "retry later"}, "application/problem+json", {"Retry-After": "30"}
        seen = self.nonces.setdefault(actor, set())
        if not judge_proof(method, target, body, headers, self.registered[actor], int(self.clock()), seen):
            return 401, {"detail": "Request proof failed."}, "application/problem+json", None
        if target.split("?")[0] == "/invoke":
            envelope = json.loads(body)
            if envelope.get("OperationIdentifier") != "Sample.Greeter+Greet, Sample":
                return 461, {"detail": "The operation is not available."}, "application/problem+json", None
            return 200, {"Greeting": "Hello, %s, from %s" % (envelope["Arguments"]["name"], actor)}, json_kind, None
        return 200, {"method": method, "target": target, "bytes": len(body)}, json_kind, None

    def _client_token_actor(self, token):
        try:
            claims = decode_token(token)
            handle = claims["sub"]
            times_ok = claims["exp"] - claims["iat"] <= 300 and claims["iat"] - 60 <= self.clock() <= claims["exp"] + 60
        except (ValueError, KeyError, TypeError):
            return None
        if not times_ok or claims.get("aud") != self.audience or handle not in self.registered:
            return None
        if not verify_token(token, self.registered[handle]) or handle not in self.admitted:
            return None
        return handle

    def _issue(self, handle):
        now = int(self.clock())
        fingerprint = fingerprint_of(self.registered[handle])
        claims = {"sub": handle, "sid": "%032x" % self.tokens_issued, "iss": "bam", "iat": now,
                  "exp": now + self.token_seconds, "kfp": fingerprint}
        self.tokens_issued += 1
        return {
            "token": encode_token(claims, self.server_key.sign),
            "expiresUtc": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now + self.token_seconds)),
            "keyFingerprint": fingerprint,
        }

    def _bearer_actor(self, authorization):
        if not authorization.lower().startswith("bearer "):
            return None
        token = authorization[7:].strip()
        if not verify_token(token, self.server_key.public_key()):
            return None
        claims = decode_token(token)
        handle = claims.get("sub")
        if claims.get("iss") != "bam" or handle not in self.registered or handle not in self.admitted:
            return None
        if not (claims["iat"] - 60 <= self.clock() <= claims["exp"] + 60):
            return None
        if claims.get("kfp") != fingerprint_of(self.registered[handle]):
            return None
        return handle
