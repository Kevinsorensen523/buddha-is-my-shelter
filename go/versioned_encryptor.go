package securekit

import "sync"

// VersionedEncryptor wraps SymmetricEncryptor with key-ID-tagged ciphertexts,
// so keys can be rotated without losing the ability to decrypt data
// encrypted under a previous key. Without this, rotating the key passed
// directly to SymmetricEncryptor silently makes all previously-encrypted
// data undecryptable unless you track "which key encrypted what" yourself.
//
// Wire format: 1-byte key ID, followed by whatever SymmetricEncryptor.Encrypt
// produces (nonce || ciphertext). Supports up to 256 concurrently-known key
// versions, which comfortably covers any realistic rotation schedule.
type VersionedEncryptor struct {
	mu        sync.RWMutex
	inner     *SymmetricEncryptor
	keys      map[uint8][]byte
	currentID uint8
}

// NewVersionedEncryptor constructs a VersionedEncryptor. currentKeyID must
// be present in keys; it's the key new Encrypt calls use.
func NewVersionedEncryptor(keys map[uint8][]byte, currentKeyID uint8) (*VersionedEncryptor, error) {
	if _, ok := keys[currentKeyID]; !ok {
		return nil, ErrDecryptionFailed // reuse: "current key ID not found in key set" would leak detail
	}
	copied := make(map[uint8][]byte, len(keys))
	for id, k := range keys {
		copied[id] = k
	}
	return &VersionedEncryptor{
		inner:     NewSymmetricEncryptor(),
		keys:      copied,
		currentID: currentKeyID,
	}, nil
}

// AddKey registers a new key version (e.g. the newly-generated key during a
// rotation) without disturbing which key is currently used for encryption.
func (v *VersionedEncryptor) AddKey(id uint8, key []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keys[id] = key
}

// SetCurrentKeyID switches which registered key new Encrypt calls use. The
// key must already have been added via the constructor or AddKey.
func (v *VersionedEncryptor) SetCurrentKeyID(id uint8) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.keys[id]; !ok {
		return ErrDecryptionFailed
	}
	v.currentID = id
	return nil
}

// Encrypt encrypts plaintext under the current key and prepends its key ID.
func (v *VersionedEncryptor) Encrypt(plaintext, aad []byte) ([]byte, error) {
	v.mu.RLock()
	id := v.currentID
	key := v.keys[id]
	v.mu.RUnlock()

	blob, err := v.inner.Encrypt(key, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return append([]byte{id}, blob...), nil
}

// Decrypt reads the key ID prefix, looks up the matching key (which may be
// an old, rotated-out key, as long as it's still registered), and decrypts.
// Returns the same generic ErrDecryptionFailed on any failure, including an
// unrecognized key ID, to avoid leaking which key IDs are valid.
func (v *VersionedEncryptor) Decrypt(blob, aad []byte) ([]byte, error) {
	if len(blob) < 1 {
		return nil, ErrDecryptionFailed
	}
	id := blob[0]

	v.mu.RLock()
	key, ok := v.keys[id]
	v.mu.RUnlock()
	if !ok {
		return nil, ErrDecryptionFailed
	}
	return v.inner.Decrypt(key, blob[1:], aad)
}
