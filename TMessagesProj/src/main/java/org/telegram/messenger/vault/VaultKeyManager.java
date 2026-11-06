package org.telegram.messenger.vault;

import java.io.IOException;
import java.util.Arrays;

/**
 * Owns the Vault's key hierarchy and its locked / unlocked state. Pure Java; the Android
 * Keystore layer and file storage are injected, so everything here is JVM-testable.
 *
 * <h3>Key hierarchy</h3>
 * <pre>
 *   password --PBKDF2-HMAC-SHA256(salt, iterations)--> KEK (key-encryption key)
 *   dataKey  = 32 random bytes, generated once when the vault is created
 *   header   = deviceWrap( "TGVH" | version | iterations | salt | AES-GCM(KEK, dataKey) )
 *   subkeys  = HKDF(dataKey, "messages" / "media" / ...)    // used by later phases
 * </pre>
 * The password is never stored, not even as a hash. A password is "correct" exactly when it
 * derives a KEK that authenticates the wrapped data key. Everything in the header except the
 * outer device layer is bound together as AES-GCM associated data, so changing the salt or
 * iteration count makes unlocking fail.
 *
 * <h3>No reset, no recovery</h3>
 * There is deliberately no way to open the vault without the password. If it is forgotten the
 * vault data is permanently unreadable. The only operations that do not need the password are
 * {@link #destroy()} (irreversible) and {@link #lock()}.
 *
 * <h3>Not handled here</h3>
 * Counting failed attempts, wiping after repeated failures, and auto-lock timers are separate
 * classes (Phase 3) that call {@link #unlock}, {@link #lock} and {@link #destroy}. This class
 * never rate-limits on its own.
 *
 * Thread-safe: all state changes are synchronised on the instance.
 */
public final class VaultKeyManager {

    /** Minimum length, in Unicode characters, enforced when a password is created. */
    public static final int MIN_PASSWORD_LENGTH = 8;
    /** Maximum accepted password length; bounds the work done per attempt. */
    public static final int MAX_PASSWORD_LENGTH = 256;

    static final int HEADER_VERSION = 1;
    /** Lowest iteration count accepted from a stored header. */
    static final int MIN_ACCEPTED_ITERATIONS = 1_000;

    private static final byte[] MAGIC = {'T', 'G', 'V', 'H'};
    private static final int ITERATIONS_OFFSET = MAGIC.length + 1;
    private static final int SALT_OFFSET = ITERATIONS_OFFSET + 4;
    /** Bytes that are authenticated as AAD: magic, version, iterations, salt. */
    private static final int PREFIX_LENGTH = SALT_OFFSET + VaultCrypto.SALT_BYTES;
    private static final int WRAPPED_KEY_LENGTH = VaultCrypto.NONCE_BYTES + VaultCrypto.KEY_BYTES + VaultCrypto.TAG_BYTES;
    static final int INNER_HEADER_LENGTH = PREFIX_LENGTH + WRAPPED_KEY_LENGTH;

    private final VaultHeaderStore store;
    private final DeviceKeyWrapper deviceKey;
    private final int iterations;

    /** Non-null exactly while unlocked. */
    private byte[] dataKey;

    public VaultKeyManager(VaultHeaderStore store, DeviceKeyWrapper deviceKey) {
        this(store, deviceKey, VaultCrypto.DEFAULT_PBKDF2_ITERATIONS);
    }

    /** Package-private: lets unit tests use a low iteration count so they run fast. */
    VaultKeyManager(VaultHeaderStore store, DeviceKeyWrapper deviceKey, int iterations) {
        if (store == null || deviceKey == null) {
            throw new IllegalArgumentException("store and deviceKey are required");
        }
        if (iterations < MIN_ACCEPTED_ITERATIONS || iterations > VaultCrypto.MAX_PBKDF2_ITERATIONS) {
            throw new IllegalArgumentException("iterations out of range");
        }
        this.store = store;
        this.deviceKey = deviceKey;
        this.iterations = iterations;
    }

    // ------------------------------------------------------------------ state

    /** True if a vault (password) has been set up on this device. */
    public synchronized boolean isInitialized() {
        return store.exists();
    }

    public synchronized boolean isUnlocked() {
        return dataKey != null;
    }

    // ------------------------------------------------------------------ create

    /**
     * First-use setup. Validates the password, generates the data key and writes the header.
     * On success the vault is left unlocked. On any failure nothing is stored and the vault stays locked.
     * The caller owns both arrays and should wipe them afterwards.
     */
    public synchronized void createVault(char[] password, char[] confirmation) throws VaultCryptoException {
        if (store.exists()) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "A vault already exists");
        }
        validateNewPassword(password, confirmation);

        byte[] salt = VaultCrypto.randomBytes(VaultCrypto.SALT_BYTES);
        byte[] newDataKey = VaultCrypto.randomBytes(VaultCrypto.KEY_BYTES);
        byte[] kek = null;
        boolean success = false;
        try {
            kek = VaultCrypto.deriveKey(password, salt, iterations);

            byte[] inner = new byte[INNER_HEADER_LENGTH];
            System.arraycopy(MAGIC, 0, inner, 0, MAGIC.length);
            inner[MAGIC.length] = HEADER_VERSION;
            writeInt(inner, ITERATIONS_OFFSET, iterations);
            System.arraycopy(salt, 0, inner, SALT_OFFSET, salt.length);

            byte[] wrappedKey = VaultCrypto.encrypt(kek, newDataKey, Arrays.copyOf(inner, PREFIX_LENGTH));
            System.arraycopy(wrappedKey, 0, inner, PREFIX_LENGTH, wrappedKey.length);

            byte[] outer = deviceKey.wrap(inner);
            try {
                store.write(outer);
            } catch (IOException e) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not store vault header", e);
            }
            VaultCrypto.wipe(inner);
            replaceDataKey(newDataKey);
            success = true;
        } finally {
            VaultCrypto.wipe(kek);
            VaultCrypto.wipe(salt);
            if (!success) {
                VaultCrypto.wipe(newDataKey);
            }
        }
    }

    private static void validateNewPassword(char[] password, char[] confirmation) throws VaultCryptoException {
        if (password == null || confirmation == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Password required");
        }
        int length = Character.codePointCount(password, 0, password.length);
        if (length < MIN_PASSWORD_LENGTH) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT,
                    "Password must be at least " + MIN_PASSWORD_LENGTH + " characters");
        }
        if (length > MAX_PASSWORD_LENGTH) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT,
                    "Password must be at most " + MAX_PASSWORD_LENGTH + " characters");
        }
        if (!Arrays.equals(password, confirmation)) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Passwords do not match");
        }
    }

    // ------------------------------------------------------------------ unlock / lock

    /**
     * Verifies the password and unlocks the vault.
     *
     * @throws VaultCryptoException WRONG_PASSWORD if the password is wrong (also if it is empty or
     *                              absurdly long); CORRUPTED if the stored header is damaged;
     *                              DEVICE_KEY_UNAVAILABLE if the device-bound key is gone;
     *                              INVALID_STATE if no vault exists; IO_ERROR on read failure.
     *                              The vault stays locked on every failure.
     */
    public synchronized void unlock(char[] password) throws VaultCryptoException {
        if (!store.exists()) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "No vault has been set up");
        }
        byte[] outer;
        try {
            outer = store.read();
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not read vault header", e);
        }
        byte[] inner = deviceKey.unwrap(outer);
        byte[] kek = null;
        try {
            if (inner == null || inner.length != INNER_HEADER_LENGTH || !startsWithMagic(inner) || inner[MAGIC.length] != HEADER_VERSION) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Vault header is damaged or unsupported");
            }
            int storedIterations = readInt(inner, ITERATIONS_OFFSET);
            if (storedIterations < MIN_ACCEPTED_ITERATIONS || storedIterations > VaultCrypto.MAX_PBKDF2_ITERATIONS) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Vault header has invalid parameters");
            }
            if (password == null || password.length == 0
                    || Character.codePointCount(password, 0, password.length) > MAX_PASSWORD_LENGTH) {
                throw new VaultCryptoException(VaultCryptoException.Reason.WRONG_PASSWORD, "Incorrect password");
            }

            byte[] salt = Arrays.copyOfRange(inner, SALT_OFFSET, SALT_OFFSET + VaultCrypto.SALT_BYTES);
            kek = VaultCrypto.deriveKey(password, salt, storedIterations);

            byte[] wrappedKey = Arrays.copyOfRange(inner, PREFIX_LENGTH, INNER_HEADER_LENGTH);
            byte[] recovered;
            try {
                recovered = VaultCrypto.decrypt(kek, wrappedKey, Arrays.copyOf(inner, PREFIX_LENGTH));
            } catch (VaultCryptoException e) {
                if (e.getReason() == VaultCryptoException.Reason.CORRUPTED) {
                    // The device layer already authenticated the header, so a failure here means the password is wrong.
                    throw new VaultCryptoException(VaultCryptoException.Reason.WRONG_PASSWORD, "Incorrect password", e);
                }
                throw e;
            }
            replaceDataKey(recovered);
        } finally {
            VaultCrypto.wipe(kek);
            VaultCrypto.wipe(inner);
        }
    }

    /** Discards the key from memory. Safe to call at any time, including when already locked. */
    public synchronized void lock() {
        replaceDataKey(null);
    }

    // ------------------------------------------------------------------ keys for other components

    /**
     * Returns a fresh copy of an independent 256-bit key for {@code purpose} (e.g. "messages", "media").
     * The same purpose always yields the same key for the same vault. The caller should wipe the copy
     * when finished. The master data key itself is never exposed.
     *
     * @throws VaultCryptoException INVALID_STATE if the vault is locked
     */
    public synchronized byte[] deriveSubkey(String purpose) throws VaultCryptoException {
        if (dataKey == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "Vault is locked");
        }
        return VaultCrypto.deriveSubkey(dataKey, purpose);
    }

    // ------------------------------------------------------------------ destroy

    /**
     * Irreversibly destroys the key material: locks, overwrites and deletes the header, and deletes
     * the device key. Encrypted vault data left on disk becomes permanently undecryptable. Does not
     * need the password. Both deletions are always attempted; the first failure is then reported.
     */
    public synchronized void destroy() throws VaultCryptoException {
        replaceDataKey(null);
        VaultCryptoException failure = null;
        try {
            store.delete();
        } catch (IOException e) {
            failure = new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not delete vault header", e);
        }
        try {
            deviceKey.deleteKey();
        } catch (VaultCryptoException e) {
            if (failure == null) {
                failure = e;
            }
        }
        if (failure != null) {
            throw failure;
        }
    }

    // ------------------------------------------------------------------ internals

    private void replaceDataKey(byte[] newKey) {
        VaultCrypto.wipe(dataKey);
        dataKey = newKey;
    }

    private static boolean startsWithMagic(byte[] data) {
        for (int i = 0; i < MAGIC.length; i++) {
            if (data[i] != MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    private static void writeInt(byte[] dst, int offset, int value) {
        dst[offset] = (byte) (value >>> 24);
        dst[offset + 1] = (byte) (value >>> 16);
        dst[offset + 2] = (byte) (value >>> 8);
        dst[offset + 3] = (byte) value;
    }

    private static int readInt(byte[] src, int offset) {
        return ((src[offset] & 0xFF) << 24) | ((src[offset + 1] & 0xFF) << 16)
                | ((src[offset + 2] & 0xFF) << 8) | (src[offset + 3] & 0xFF);
    }
}
