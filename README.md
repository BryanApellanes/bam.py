# bam.py

Call a Bam host from Python as an authenticated actor.

A Bam host knows its callers by key. An actor registers a public key under a handle, the host's
operator admits it, and from then on every request is signed with the private key. bam.py does the
key handling, the tokens and the signing. The wire it speaks is written down in
[bam.protocol's `spec/actor-auth.md`](https://github.com/BryanApellanes/bam.protocol/blob/bam_protocol/spec/actor-auth.md).

Bodies are not encrypted by this library. Use HTTPS.

## Install

Not on PyPI yet. From a checkout:

    pip install .

It needs Python 3.10 or later and the `cryptography` package.

## A complete call

```python
from bam_py import ActorClient, FileActorKeyStore

keys = FileActorKeyStore("~/.bam/actor.pem")    # created the first time
client = ActorClient(
    "https://api.example.com",          # the host, with no path
    "ada",                              # your handle
    keys,
    audience="https://api.example.com", # the value the host's operator gave you
)

client.register()                       # once
print(keys.fingerprint())               # give this and your handle to the operator

# after the operator has admitted you:
result = client.invoke("Sample.Greeter+Greet, Sample", {"name": "Ada"})
```

`invoke` gets a token, renews it before it expires, and signs the request. To call any other
endpoint of the host:

```python
response = client.send("PUT", "/things/42?force=1", b'{"name":"x"}', {"Content-Type": "application/json"})
print(response.status, response.body)
```

## What you need to know

- **The key file.** `FileActorKeyStore` creates a P-256 key the first time and reads it afterwards.
  On Unix the file is owner-only (0600). On Windows it takes the access rules of its directory, so
  keep it in your user profile. Pass `password=` to encrypt it. Whoever can read the file can act
  as you.
- **Registering is not being admitted.** Until the operator admits your handle, every call but
  `register` raises `BamError` with status 401, and the host does not say why.
- **The target is sent as you write it.** The path and query are signed and sent byte for byte.
  Encode them yourself; nothing is normalised for you.
- **Your clock matters.** A request signed more than five minutes from the host's time is refused
  with 401.
- **Errors.** `invoke` raises `BamError` for any answer but 200. It carries `status`, `detail` and,
  when the host says to wait (429 or 503), `retry_after` in seconds. A retry needs no special
  handling: call again, and the request is signed again.
- **A host without server tokens.** For a host in client-signed-only mode, pass
  `server_tokens=False`.

## The parts

| Name | What it does |
|---|---|
| `ActorClient` | Registers, keeps a token, sends signed requests, invokes operations. |
| `FileActorKeyStore`, `MemoryActorKeyStore` | Hold the key pair and sign with it. |
| `ProofSigner` | Makes the four proof headers for one request. |
| `client_token`, `encode_token`, `decode_token`, `verify_token` | Tokens. |
| `compose`, `split_target`, `body_digest` | The text a proof signs. |
| `der_to_raw`, `raw_to_der` | The two forms of an ECDSA signature. |
| `fingerprint_of` | The name of a public key, as the host reports it. |
| `HttpTransport` | Sends a request without changing its target. Replace it by passing `transport=`. |

Tokens here say `ES256` in their header but carry DER signatures, so a JWT library cannot make or
check them. Use the functions above.

## Tests

    pip install -e .
    cd tests
    python -m unittest

- `tests/test_vectors.py` holds the library to the known-answer vectors that the C# implementation
  is also tested against. They are copied from bam.protocol into `tests/vectors`;
  `tests/vectors/SOURCE.md` names the commit, and `tools/sync_vectors.py` refreshes them.
- `tests/test_client.py` runs the whole flow against a stand-in host on a loopback port. The
  stand-in's judgement of request proofs is itself held to the vectors.

## Not here yet

- Sealed frames (encrypted requests and responses). They are designed and get their own
  specification first.
- Key rotation, and the RSA possession check.
- A test against a real C# host.
