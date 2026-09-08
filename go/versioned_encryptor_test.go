package securekit

import "testing"

func TestVersionedEncryptorRoundTrip(t *testing.T) {
	key1, _ := SecureRandomBytes(32)
	ve, err := NewVersionedEncryptor(map[uint8][]byte{1: key1}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	blob, err := ve.Encrypt([]byte("secret"), nil)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}
	pt, err := ve.Decrypt(blob, nil)
	if err != nil || string(pt) != "secret" {
		t.Fatalf("decrypt mismatch: pt=%q err=%v", pt, err)
	}
}

func TestVersionedEncryptorSurvivesKeyRotation(t *testing.T) {
	key1, _ := SecureRandomBytes(32)
	key2, _ := SecureRandomBytes(32)
	ve, _ := NewVersionedEncryptor(map[uint8][]byte{1: key1}, 1)

	oldBlob, _ := ve.Encrypt([]byte("encrypted with v1"), nil)

	ve.AddKey(2, key2)
	if err := ve.SetCurrentKeyID(2); err != nil {
		t.Fatalf("unexpected error rotating: %v", err)
	}
	newBlob, _ := ve.Encrypt([]byte("encrypted with v2"), nil)

	// Old ciphertext (encrypted under the now-rotated-out key) must still decrypt.
	pt, err := ve.Decrypt(oldBlob, nil)
	if err != nil || string(pt) != "encrypted with v1" {
		t.Fatalf("old blob should still decrypt after rotation: pt=%q err=%v", pt, err)
	}
	pt2, err := ve.Decrypt(newBlob, nil)
	if err != nil || string(pt2) != "encrypted with v2" {
		t.Fatalf("new blob should decrypt with current key: pt=%q err=%v", pt2, err)
	}
}

func TestVersionedEncryptorRejectsUnknownKeyID(t *testing.T) {
	key1, _ := SecureRandomBytes(32)
	ve, _ := NewVersionedEncryptor(map[uint8][]byte{1: key1}, 1)
	blob, _ := ve.Encrypt([]byte("data"), nil)
	blob[0] = 99 // tamper with key ID to an unregistered one

	if _, err := ve.Decrypt(blob, nil); err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed for unknown key ID, got %v", err)
	}
}

func TestNewVersionedEncryptorRejectsMissingCurrentKey(t *testing.T) {
	key1, _ := SecureRandomBytes(32)
	if _, err := NewVersionedEncryptor(map[uint8][]byte{1: key1}, 5); err == nil {
		t.Fatal("expected error when currentKeyID is not in the key set")
	}
}
