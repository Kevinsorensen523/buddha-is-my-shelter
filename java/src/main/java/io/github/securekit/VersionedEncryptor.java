package io.github.securekit;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Wraps {@link SymmetricEncryptor} with key-ID-tagged ciphertexts, so keys
 * can be rotated without losing the ability to decrypt data encrypted
 * under a previous key. Wire format: 1-byte key ID followed by whatever
 * {@link SymmetricEncryptor#encrypt} produces. Supports up to 256
 * concurrently-known key versions.
 */
public final class VersionedEncryptor {

    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private final SymmetricEncryptor inner = new SymmetricEncryptor();
    private final Map<Integer, byte[]> keys;
    private int currentId;

    public VersionedEncryptor(Map<Integer, byte[]> keys, int currentKeyId) {
        if (!keys.containsKey(currentKeyId)) {
            throw new IllegalArgumentException("securekit: current key ID not found in key set");
        }
        this.keys = new HashMap<>(keys);
        this.currentId = currentKeyId;
    }

    /** Registers a new key version without changing which key is current. */
    public void addKey(int id, byte[] key) {
        lock.writeLock().lock();
        try {
            keys.put(id, key);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** Switches which registered key new {@link #encrypt} calls use. */
    public void setCurrentKeyId(int id) {
        lock.writeLock().lock();
        try {
            if (!keys.containsKey(id)) {
                throw new IllegalArgumentException("securekit: key ID not found in key set");
            }
            currentId = id;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public byte[] encrypt(byte[] plaintext, byte[] aad) {
        lock.readLock().lock();
        int id;
        byte[] key;
        try {
            id = currentId;
            key = keys.get(id);
        } finally {
            lock.readLock().unlock();
        }
        byte[] blob = inner.encrypt(key, plaintext, aad);
        byte[] out = new byte[1 + blob.length];
        out[0] = (byte) id;
        System.arraycopy(blob, 0, out, 1, blob.length);
        return out;
    }

    /**
     * Throws the generic {@link DecryptionException} on any failure,
     * including an unrecognized key ID, to avoid leaking which key IDs are
     * valid.
     */
    public byte[] decrypt(byte[] blob, byte[] aad) {
        if (blob.length < 1) {
            throw new DecryptionException();
        }
        int id = blob[0] & 0xFF;

        lock.readLock().lock();
        byte[] key;
        try {
            key = keys.get(id);
        } finally {
            lock.readLock().unlock();
        }
        if (key == null) {
            throw new DecryptionException();
        }
        byte[] rest = new byte[blob.length - 1];
        System.arraycopy(blob, 1, rest, 0, rest.length);
        return inner.decrypt(key, rest, aad);
    }
}
