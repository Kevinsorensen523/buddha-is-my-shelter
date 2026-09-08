package securekit

import "testing"

// Native Go fuzz tests (go test -fuzz=...). These assert the package never
// panics on adversarial input, which matters most for parsers that face
// attacker-controlled data directly: email/filename validation, CSRF token
// decoding, and AEAD ciphertext decoding. A panic in any of these would be
// a denial-of-service bug even though it wouldn't leak secrets.

func FuzzValidateEmail(f *testing.F) {
	for _, seed := range []string{"user@example.com", "", "a@b", "not-an-email", "\r\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, email string) {
		_ = ValidateEmail(email) // must not panic
	})
}

func FuzzSanitizeFilename(f *testing.F) {
	for _, seed := range []string{"report.pdf", "../../etc/passwd", "", ".", "..", "a/b\\c"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		clean, err := SanitizeFilename(name)
		if err == nil {
			for _, c := range clean {
				if c == '/' || c == '\\' || c == 0 {
					t.Fatalf("sanitized filename %q still contains a path separator or NUL", clean)
				}
			}
		}
	})
}

func FuzzCsrfVerify(f *testing.F) {
	secret, _ := SecureRandomBytes(32)
	mgr := NewCsrfTokenManager(secret, 0)
	valid, _ := mgr.Generate("session-123")
	f.Add("session-123", valid)
	f.Add("session-123", "")
	f.Add("session-123", "not-base64!!")

	f.Fuzz(func(t *testing.T, sessionID, token string) {
		_ = mgr.Verify(sessionID, token) // must not panic regardless of input
	})
}

func FuzzSymmetricDecrypt(f *testing.F) {
	key, _ := SecureRandomBytes(32)
	enc := NewSymmetricEncryptor()
	blob, _ := enc.Encrypt(key, []byte("seed plaintext"), nil)
	f.Add(blob)
	f.Add([]byte{})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, blob []byte) {
		_, err := enc.Decrypt(key, blob, nil)
		if err != nil && err != ErrDecryptionFailed {
			t.Fatalf("expected only ErrDecryptionFailed on invalid input, got: %v", err)
		}
	})
}
