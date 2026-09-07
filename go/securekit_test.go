package securekit

import (
	"testing"
	"time"
)

func TestSecureRandomBytesLengthAndUniqueness(t *testing.T) {
	a, err := SecureRandomBytes(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(a) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(a))
	}
	b, _ := SecureRandomBytes(32)
	if string(a) == string(b) {
		t.Fatal("two random draws should not collide")
	}
}

func TestSecureRandomBytesRejectsNonPositive(t *testing.T) {
	if _, err := SecureRandomBytes(0); err == nil {
		t.Fatal("expected error for n=0")
	}
}

func TestPasswordHasherRoundTrip(t *testing.T) {
	h := NewDefaultPasswordHasher()
	hash, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}
	ok, err := h.Verify("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Fatalf("expected verify success, got ok=%v err=%v", ok, err)
	}
}

func TestPasswordHasherRejectsWrongPassword(t *testing.T) {
	h := NewDefaultPasswordHasher()
	hash, _ := h.Hash("correct-password")
	ok, err := h.Verify("wrong-password", hash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected verify to fail for wrong password")
	}
}

func TestPasswordHasherNeedsRehash(t *testing.T) {
	weak := NewPasswordHasher(Argon2Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32})
	hash, _ := weak.Hash("password")

	strong := NewDefaultPasswordHasher()
	if !strong.NeedsRehash(hash) {
		t.Fatal("expected weak hash to need rehash under stronger params")
	}
	if strong.NeedsRehash(mustHash(t, strong, "password")) {
		t.Fatal("hash produced with current params should not need rehash")
	}
}

func mustHash(t *testing.T, h *PasswordHasher, pw string) string {
	t.Helper()
	s, err := h.Hash(pw)
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}
	return s
}

func TestSymmetricEncryptorRoundTrip(t *testing.T) {
	enc := NewSymmetricEncryptor()
	key, _ := enc.GenerateKey()
	plaintext := []byte("attack at dawn")

	ciphertext, err := enc.Encrypt(key, plaintext, nil)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}
	decrypted, err := enc.Decrypt(key, ciphertext, nil)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("round trip mismatch: got %q", decrypted)
	}
}

func TestSymmetricEncryptorRejectsTamperedCiphertext(t *testing.T) {
	enc := NewSymmetricEncryptor()
	key, _ := enc.GenerateKey()
	ciphertext, _ := enc.Encrypt(key, []byte("secret"), nil)
	ciphertext[len(ciphertext)-1] ^= 0xFF

	if _, err := enc.Decrypt(key, ciphertext, nil); err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestSymmetricEncryptorNoncesDiffer(t *testing.T) {
	enc := NewSymmetricEncryptor()
	key, _ := enc.GenerateKey()
	c1, _ := enc.Encrypt(key, []byte("same message"), nil)
	c2, _ := enc.Encrypt(key, []byte("same message"), nil)
	if string(c1) == string(c2) {
		t.Fatal("two encryptions of the same plaintext must not produce identical ciphertext (nonce reuse)")
	}
}

func TestValidateEmail(t *testing.T) {
	valid := []string{"user@example.com", "a.b+c@sub.example.co.id"}
	invalid := []string{"not-an-email", "user@", "@example.com", "user@example.com\r\nBcc: x"}

	for _, e := range valid {
		if !ValidateEmail(e) {
			t.Errorf("expected %q to be valid", e)
		}
	}
	for _, e := range invalid {
		if ValidateEmail(e) {
			t.Errorf("expected %q to be invalid", e)
		}
	}
}

func TestValidateURL(t *testing.T) {
	if !ValidateURL("https://example.com/path") {
		t.Error("expected https URL to be valid")
	}
	for _, u := range []string{"javascript:alert(1)", "not a url", "ftp://example.com", "file:///etc/passwd"} {
		if ValidateURL(u) {
			t.Errorf("expected %q to be invalid", u)
		}
	}
}

func TestSanitizeFilenameRejectsTraversal(t *testing.T) {
	for _, name := range []string{"../../etc/passwd", "..\\..\\windows", "a/b", ""} {
		if _, err := SanitizeFilename(name); err == nil {
			t.Errorf("expected %q to be rejected", name)
		}
	}
	got, err := SanitizeFilename("report-2024.pdf")
	if err != nil || got != "report-2024.pdf" {
		t.Errorf("expected clean filename to pass through, got %q err=%v", got, err)
	}
}

func TestEscapeHTMLPreventsXSS(t *testing.T) {
	got := EscapeHTML(`<script>alert("xss")</script>`)
	if got == `<script>alert("xss")</script>` {
		t.Fatal("expected HTML to be escaped")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqualString("abc123", "abc123") {
		t.Error("expected equal strings to match")
	}
	if ConstantTimeEqualString("abc123", "abc124") {
		t.Error("expected different strings to not match")
	}
	if ConstantTimeEqualString("short", "muchlongerstring") {
		t.Error("expected different-length strings to not match")
	}
}

func TestCsrfTokenManagerRoundTrip(t *testing.T) {
	secret, _ := SecureRandomBytes(32)
	mgr := NewCsrfTokenManager(secret, time.Hour)

	token, err := mgr.Generate("session-123")
	if err != nil {
		t.Fatalf("generate error: %v", err)
	}
	if !mgr.Verify("session-123", token) {
		t.Fatal("expected token to verify for its own session")
	}
}

func TestCsrfTokenManagerRejectsWrongSession(t *testing.T) {
	secret, _ := SecureRandomBytes(32)
	mgr := NewCsrfTokenManager(secret, time.Hour)
	token, _ := mgr.Generate("session-A")
	if mgr.Verify("session-B", token) {
		t.Fatal("expected token bound to session-A to fail for session-B")
	}
}

func TestCsrfTokenManagerRejectsExpiredToken(t *testing.T) {
	secret, _ := SecureRandomBytes(32)
	mgr := NewCsrfTokenManager(secret, 1*time.Nanosecond)
	token, _ := mgr.Generate("session-123")
	time.Sleep(5 * time.Millisecond)
	if mgr.Verify("session-123", token) {
		t.Fatal("expected expired token to fail verification")
	}
}

func TestCsrfTokenManagerRejectsForgedToken(t *testing.T) {
	secret, _ := SecureRandomBytes(32)
	mgr := NewCsrfTokenManager(secret, time.Hour)
	if mgr.Verify("session-123", "forged.token.value") {
		t.Fatal("expected forged token to be rejected")
	}
}

func TestRateLimiterAllowsUnderLimitAndBlocksOver(t *testing.T) {
	rl := NewRateLimiter(NewMemoryStore(), 3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.Allow("client-1") {
			t.Fatalf("expected request %d to be allowed", i+1)
		}
	}
	if rl.Allow("client-1") {
		t.Fatal("expected 4th request to be blocked")
	}
}

func TestRateLimiterTracksKeysIndependently(t *testing.T) {
	rl := NewRateLimiter(NewMemoryStore(), 1, time.Minute)
	if !rl.Allow("client-A") {
		t.Fatal("expected first request for client-A to be allowed")
	}
	if !rl.Allow("client-B") {
		t.Fatal("expected first request for client-B to be allowed independently")
	}
}
