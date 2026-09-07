package securekit

import "crypto/subtle"

// ConstantTimeEqual compares two byte slices in constant time, regardless of
// where the first difference occurs, to resist timing side-channel attacks.
// It returns true only if the slices have equal length and identical content.
func ConstantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		// Length mismatch is intentionally allowed to short-circuit: comparing
		// two different-length secrets never happens in real CSRF/token flows
		// (tokens have a fixed encoded length), and hiding this doesn't add
		// meaningful protection while len() itself is not secret.
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ConstantTimeEqualString is a string convenience wrapper around ConstantTimeEqual.
func ConstantTimeEqualString(a, b string) bool {
	return ConstantTimeEqual([]byte(a), []byte(b))
}
