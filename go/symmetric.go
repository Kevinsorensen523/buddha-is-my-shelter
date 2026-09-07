package securekit

import (
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrDecryptionFailed is returned for any decryption failure. The message is
// intentionally generic (never distinguishes "too short" vs "tag mismatch")
// to avoid leaking oracle information to an attacker.
var ErrDecryptionFailed = errors.New("securekit: decryption failed")

const symmetricKeyLen = chacha20poly1305.KeySize // 32 bytes

// SymmetricEncryptor provides authenticated encryption (AEAD) using
// XChaCha20-Poly1305. Nonces are generated internally and are never exposed
// for the caller to choose, eliminating nonce-reuse misuse.
type SymmetricEncryptor struct{}

// NewSymmetricEncryptor constructs a SymmetricEncryptor.
func NewSymmetricEncryptor() *SymmetricEncryptor {
	return &SymmetricEncryptor{}
}

// GenerateKey returns a new random 256-bit key suitable for Encrypt/Decrypt.
func (SymmetricEncryptor) GenerateKey() ([]byte, error) {
	return SecureRandomBytes(symmetricKeyLen)
}

// Encrypt encrypts plaintext under key using XChaCha20-Poly1305 with a
// randomly generated 24-byte nonce, prepended to the returned ciphertext.
// aad (additional authenticated data) may be nil.
func (SymmetricEncryptor) Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != symmetricKeyLen {
		return nil, errors.New("securekit: key must be 32 bytes")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce, err := SecureRandomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts a blob produced by Encrypt (nonce prefix + ciphertext).
// On any failure (truncated input, wrong key, tampered ciphertext, wrong
// aad) it returns ErrDecryptionFailed with no further detail.
func (SymmetricEncryptor) Decrypt(key, blob, aad []byte) ([]byte, error) {
	if len(key) != symmetricKeyLen {
		return nil, ErrDecryptionFailed
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	if len(blob) < aead.NonceSize() {
		return nil, ErrDecryptionFailed
	}
	nonce, ciphertext := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// EncryptToString is a convenience wrapper returning base64 (standard,
// padded) instead of raw bytes, for easy storage/transport.
func (s SymmetricEncryptor) EncryptToString(key, plaintext, aad []byte) (string, error) {
	blob, err := s.Encrypt(key, plaintext, aad)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

// DecryptFromString is the inverse of EncryptToString.
func (s SymmetricEncryptor) DecryptFromString(key []byte, encoded string, aad []byte) ([]byte, error) {
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return s.Decrypt(key, blob, aad)
}
