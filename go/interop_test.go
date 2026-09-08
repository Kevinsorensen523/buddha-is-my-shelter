package securekit

// Cross-language interop tests. These load the shared fixtures in
// ../vectors/*.json (generated once from each language's own implementation)
// and verify this package can consume tokens/hashes produced by every other
// port. This is what actually proves the wire formats documented in the
// root README are portable, rather than just asserted by hand.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

type passwordHashVectors struct {
	Password string            `json:"password"`
	Hashes   map[string]string `json:"hashes"`
}

type csrfTokenVectors struct {
	SecretBase64 string            `json:"secretBase64"`
	SessionID    string            `json:"sessionId"`
	Tokens       map[string]string `json:"tokens"`
}

type aeadVectors struct {
	KeyBase64           string              `json:"keyBase64"`
	Plaintext           string              `json:"plaintext"`
	Ciphertexts         map[string]string   `json:"ciphertexts"`
	CompatibilityGroups map[string][]string `json:"compatibilityGroups"`
}

func loadVectors(t *testing.T, name string, v interface{}) {
	t.Helper()
	data, err := os.ReadFile("../vectors/" + name)
	if err != nil {
		t.Fatalf("reading vector file %s: %v", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("parsing vector file %s: %v", name, err)
	}
}

func TestInteropPasswordHashes(t *testing.T) {
	var vecs passwordHashVectors
	loadVectors(t, "password_hashes.json", &vecs)

	hasher := NewDefaultPasswordHasher()
	for lang, hash := range vecs.Hashes {
		ok, err := hasher.Verify(vecs.Password, hash)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", lang, err)
			continue
		}
		if !ok {
			t.Errorf("%s: hash did not verify against shared password (PHC format not portable)", lang)
		}
	}
}

func TestInteropCsrfTokens(t *testing.T) {
	var vecs csrfTokenVectors
	loadVectors(t, "csrf_tokens.json", &vecs)

	secret, err := base64.StdEncoding.DecodeString(vecs.SecretBase64)
	if err != nil {
		t.Fatalf("decoding secret: %v", err)
	}
	mgr := NewCsrfTokenManager(secret, 0) // ttl<=0: never expires, fixture-safe

	for lang, token := range vecs.Tokens {
		if !mgr.Verify(vecs.SessionID, token) {
			t.Errorf("%s: token did not verify (binary token format not portable)", lang)
		}
	}
}

func TestInteropAeadWithinCompatibilityGroup(t *testing.T) {
	var vecs aeadVectors
	loadVectors(t, "aead_ciphertexts.json", &vecs)

	key, err := base64.StdEncoding.DecodeString(vecs.KeyBase64)
	if err != nil {
		t.Fatalf("decoding key: %v", err)
	}
	enc := NewSymmetricEncryptor()

	// Go is documented to be in the "xchacha20poly1305" group. Every member
	// of that group must decrypt successfully; every language outside it
	// must fail -- this is the documented incompatibility, not a bug to
	// silently tolerate.
	group := vecs.CompatibilityGroups["xchacha20poly1305"]
	inGroup := make(map[string]bool)
	for _, lang := range group {
		inGroup[lang] = true
	}

	for lang, ctB64 := range vecs.Ciphertexts {
		ct, err := base64.StdEncoding.DecodeString(ctB64)
		if err != nil {
			t.Fatalf("%s: decoding ciphertext: %v", lang, err)
		}
		plaintext, err := enc.Decrypt(key, ct, nil)
		if inGroup[lang] {
			if err != nil {
				t.Errorf("%s: expected successful decrypt (same compatibility group), got %v", lang, err)
			} else if string(plaintext) != vecs.Plaintext {
				t.Errorf("%s: decrypted plaintext mismatch: got %q", lang, plaintext)
			}
		} else if err == nil {
			t.Errorf("%s: expected decrypt to fail (different AEAD construction), but it succeeded", lang)
		}
	}
}
