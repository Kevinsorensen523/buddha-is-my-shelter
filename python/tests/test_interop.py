"""Cross-language interop tests. Loads the shared fixtures in ../../vectors/*.json
(generated once from each language's own implementation) and verifies this
package can consume tokens/hashes/ciphertexts produced by every other port."""

import base64
import json
from pathlib import Path

from securekit import CsrfTokenManager, PasswordHasher, SymmetricEncryptor, DecryptionError

VECTORS_DIR = Path(__file__).parent.parent.parent / "vectors"


def load_vectors(name):
    with open(VECTORS_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def test_password_hashes_interop():
    vecs = load_vectors("password_hashes.json")
    hasher = PasswordHasher()

    for lang, hash_ in vecs["hashes"].items():
        assert hasher.verify(vecs["password"], hash_), (
            f"{lang}: hash did not verify against shared password "
            "(PHC format not portable)"
        )


def test_csrf_tokens_interop():
    vecs = load_vectors("csrf_tokens.json")
    secret = base64.b64decode(vecs["secretBase64"])
    mgr = CsrfTokenManager(secret, ttl_seconds=0)  # ttl<=0: never expires, fixture-safe

    for lang, token in vecs["tokens"].items():
        assert mgr.verify(vecs["sessionId"], token), (
            f"{lang}: token did not verify (binary token format not portable)"
        )


def test_aead_interop_within_compatibility_group():
    vecs = load_vectors("aead_ciphertexts.json")
    key = base64.b64decode(vecs["keyBase64"])
    enc = SymmetricEncryptor()

    group = set(vecs["compatibilityGroups"]["chacha20poly1305-standalone"])

    for lang, ct_b64 in vecs["ciphertexts"].items():
        ct = base64.b64decode(ct_b64)
        if lang in group:
            plaintext = enc.decrypt(key, ct)
            assert plaintext.decode() == vecs["plaintext"], f"{lang}: plaintext mismatch"
        else:
            try:
                enc.decrypt(key, ct)
                assert False, (
                    f"{lang}: expected decrypt to fail (different AEAD construction), "
                    "but it succeeded"
                )
            except DecryptionError:
                pass
