package securekit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"
)

// ErrCsrfInvalid is returned for any CSRF verification failure (expired,
// mismatched session binding, or forged token).
var ErrCsrfInvalid = errors.New("securekit: csrf token invalid")

// CsrfTokenManager issues and verifies CSRF tokens bound to a session ID and
// a secret key, using HMAC-SHA256 so tokens are stateless (no server-side
// token store required) yet cannot be forged without the secret.
type CsrfTokenManager struct {
	secret []byte
	ttl    time.Duration
}

// NewCsrfTokenManager constructs a manager. secret should be at least 32
// random bytes (see SecureRandomBytes) kept server-side; ttl is how long an
// issued token remains valid.
func NewCsrfTokenManager(secret []byte, ttl time.Duration) *CsrfTokenManager {
	return &CsrfTokenManager{secret: secret, ttl: ttl}
}

// Generate issues a new token bound to sessionID, encoding the issue time
// and an HMAC tag. Format: base64url(issuedUnixNano || nonce || tag).
func (m *CsrfTokenManager) Generate(sessionID string) (string, error) {
	nonce, err := SecureRandomBytes(16)
	if err != nil {
		return "", err
	}
	issuedAt := time.Now().UnixNano()
	payload := csrfPayload(sessionID, nonce, issuedAt)
	tag := m.sign(payload)

	out := append(nonce, tag...)
	out = append(itoaBytes(issuedAt), out...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Verify reports whether token is valid for sessionID: correctly signed,
// unexpired, and bound to this exact session. Comparison is constant-time.
func (m *CsrfTokenManager) Verify(sessionID, token string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) < 8+16+32 {
		return false
	}
	issuedAt := btoi64(raw[:8])
	nonce := raw[8:24]
	tag := raw[24:56]

	if m.ttl > 0 && time.Since(time.Unix(0, issuedAt)) > m.ttl {
		return false
	}
	expected := m.sign(csrfPayload(sessionID, nonce, issuedAt))
	return ConstantTimeEqual(expected, tag)
}

func (m *CsrfTokenManager) sign(payload []byte) []byte {
	h := hmac.New(sha256.New, m.secret)
	h.Write(payload)
	return h.Sum(nil)
}

func csrfPayload(sessionID string, nonce []byte, issuedAt int64) []byte {
	buf := append([]byte(sessionID), nonce...)
	return append(buf, itoaBytes(issuedAt)...)
}

func itoaBytes(v int64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

func btoi64(b []byte) int64 {
	var v int64
	for i := 0; i < 8; i++ {
		v = (v << 8) | int64(b[i])
	}
	return v
}
