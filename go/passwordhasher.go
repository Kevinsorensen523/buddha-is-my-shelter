package securekit

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params controls the cost factors used by PasswordHasher. Defaults
// follow OWASP Password Storage Cheat Sheet guidance (as of 2024) for
// Argon2id: memory=19MiB(min)-64MiB, iterations>=2, parallelism=1-4.
type Argon2Params struct {
	MemoryKiB   uint32 // memory cost in KiB
	Iterations  uint32 // time cost
	Parallelism uint8  // degree of parallelism
	SaltLen     uint32 // salt length in bytes
	KeyLen      uint32 // derived key length in bytes
}

// DefaultArgon2Params returns OWASP-recommended defaults: 64 MiB memory,
// 3 iterations, parallelism 4, 16-byte salt, 32-byte key.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		MemoryKiB:   64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		SaltLen:     16,
		KeyLen:      32,
	}
}

// PasswordHasher hashes and verifies passwords using Argon2id. There is no
// bcrypt fallback in Go because argon2 is a pure-Go implementation always
// available at compile time (unlike PHP/JS runtimes, which may lack it).
type PasswordHasher struct {
	params Argon2Params
}

// NewPasswordHasher constructs a PasswordHasher with the given parameters.
func NewPasswordHasher(params Argon2Params) *PasswordHasher {
	return &PasswordHasher{params: params}
}

// NewDefaultPasswordHasher constructs a PasswordHasher using DefaultArgon2Params.
func NewDefaultPasswordHasher() *PasswordHasher {
	return &PasswordHasher{params: DefaultArgon2Params()}
}

// Hash derives an Argon2id hash of password and returns it encoded in the
// standard PHC string format:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<base64 salt>$<base64 hash>
//
// This format is cross-compatible with the PHP, Python, Node, and Java
// ports of securekit.
func (h *PasswordHasher) Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("securekit: password must not be empty")
	}
	salt, err := SecureRandomBytes(int(h.params.SaltLen))
	if err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, h.params.Iterations, h.params.MemoryKiB, h.params.Parallelism, h.params.KeyLen)

	b64 := base64.RawStdEncoding
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.params.MemoryKiB, h.params.Iterations, h.params.Parallelism,
		b64.EncodeToString(salt),
		b64.EncodeToString(key),
	)
	return encoded, nil
}

// Verify reports whether password matches the given PHC-encoded Argon2id
// hash, using a constant-time comparison. It never returns detail about
// why a mismatch occurred.
func (h *PasswordHasher) Verify(password, encodedHash string) (bool, error) {
	params, salt, key, err := decodeArgon2Hash(encodedHash)
	if err != nil {
		return false, errors.New("securekit: invalid hash format")
	}
	candidate := argon2.IDKey([]byte(password), salt, params.Iterations, params.MemoryKiB, params.Parallelism, uint32(len(key)))
	return subtle.ConstantTimeCompare(candidate, key) == 1, nil
}

// NeedsRehash reports whether encodedHash was produced with parameters
// weaker than h's current parameters and should be re-hashed on next
// successful login.
func (h *PasswordHasher) NeedsRehash(encodedHash string) bool {
	params, salt, key, err := decodeArgon2Hash(encodedHash)
	if err != nil {
		return true
	}
	return params.MemoryKiB < h.params.MemoryKiB ||
		params.Iterations < h.params.Iterations ||
		params.Parallelism < h.params.Parallelism ||
		uint32(len(salt)) < h.params.SaltLen ||
		uint32(len(key)) < h.params.KeyLen
}

func decodeArgon2Hash(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// parts: ["", "argon2id", "v=19", "m=..,t=..,p=..", "<salt>", "<hash>"]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, errors.New("securekit: malformed argon2id hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Argon2Params{}, nil, nil, err
	}
	var p Argon2Params
	var mem, iter uint32
	var par uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iter, &par); err != nil {
		return Argon2Params{}, nil, nil, err
	}
	p.MemoryKiB, p.Iterations, p.Parallelism = mem, iter, par

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2Params{}, nil, nil, err
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2Params{}, nil, nil, err
	}
	p.SaltLen = uint32(len(salt))
	p.KeyLen = uint32(len(key))
	return p, salt, key, nil
}
