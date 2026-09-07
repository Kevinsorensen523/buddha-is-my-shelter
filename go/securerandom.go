package securekit

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// SecureRandomBytes returns n cryptographically secure random bytes read
// from the OS CSPRNG (crypto/rand). It never falls back to a weaker source.
func SecureRandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("securekit: byte count must be positive")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("securekit: failed to read random bytes: %w", err)
	}
	return buf, nil
}

// SecureRandomToken returns a URL-safe, base64-encoded random token built
// from n bytes of CSPRNG entropy. Suitable for session IDs, API keys, etc.
func SecureRandomToken(n int) (string, error) {
	b, err := SecureRandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SecureRandomHex returns a lowercase hex-encoded random string built from
// n bytes of CSPRNG entropy (output length is 2*n characters).
func SecureRandomHex(n int) (string, error) {
	b, err := SecureRandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
