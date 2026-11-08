package org.telegram.messenger.vault;

import java.io.IOException;
import java.util.Arrays;

/**
 * Owns the Vault's key hierarchy and its locked / unlocked state. Pure Java; the Android Keystore
 * layer and file storage are injected, so everything here is JVM-testable.
 *
 * <h3>Key hierarchy (architecture v2)</h3>
 * <pre>
 *   VMK      = Vault Master Key: 32 random bytes, generated once per account on the first device
 *   password --PBKDF2-HMAC-SHA256(salt, iterations)--> KEK   (this DEVICE only; never uploaded)
 *   header   = deviceWrap( "TGVH" | 2 | iterations | salt | vaultId | bundleVersion
 *                          | AES-GCM(KEK, VMK) | bundle )
 *   bundle   = key bundle (see {@link VaultBundle}): VMK wrapped under the recovery key; uploaded
 *   subkeys  = HKDF(VMK, "messages" / "media" / "bundle-auth" / ...)
 * </pre>
 * The password is never stored, not even as a hash, and is NOT part of the uploaded bundle (approved
 * decision 2): it only protects this device's local copy. Each device may therefore have its own password.
 * The Android Keystore layer ({@link DeviceKeyWrapper}) wraps the whole local header and is no longer the
 * only way to get the VMK back: the recovery key and the bundle rebuild it ({@link #restoreFromBundle}).
 *
 * <h3>Setup is two steps</h3>
 * {@link #beginSetup} generates the VMK and the recovery key but writes nothing. Only after the user types
 * the recovery key back ({@link Setup#complete}) is the header written. A vault without a confirmed
 * recovery key therefore cannot exist (approved decision 3).
 *
 * <h3>Legacy (v1) headers</h3>
 * Headers written by Phases 1-2 (version 1) still unlock; their data key simply is the VMK. They report
 * {@link #isLegacyHeader()} until {@link #beginMigration} + {@link Setup#complete} upgrade them, without
 * re-encrypting any stored record or media file.
 *
 * <h3>Not handled here</h3>
 * Counting failed attempts, wiping after repeated failures, and auto-lock timers are separate classes that
 * call {@link #unlock}, {@link #lock} and {@link #destroy}. This class never rate-limits on its own.
 *
 * Thread-safe: all state changes are synchronised on the instance.
 */
public final class VaultKeyManager {

    /** Minimum length, in Unicode characters, enforced when a password is created or changed (decision 7). */
    public static final int MIN_PASSWORD_LENGTH = 12;
    /** Maximum accepted password length; bounds the work done per attempt. */
    public static final int MAX_PASSWORD_LENGTH = 256;

    static final int LEGACY_HEADER_VERSION = 1;
    static final int HEADER_VERSION = 2;
    /** Lowest iteration count accepted from a stored header. */
    static final int MIN_ACCEPTED_ITERATIONS = 1_000;

    private static final byte[] MAGIC = {'T', 'G', 'V', 'H'};
    private static final int VERSION_OFFSET = MAGIC.length;
    private static final int ITERATIONS_OFFSET = VERSION_OFFSET + 1;
    private static final int SALT_OFFSET = ITERATIONS_OFFSET + 4;
    /** v1: bytes authenticated as AAD: magic, version, iterations, salt. */
    private static final int PREFIX_V1 = SALT_OFFSET + VaultCrypto.SALT_BYTES;
    private static final int VAULT_ID_OFFSET = PREFIX_V1;
    private static final int BUNDLE_VERSION_OFFSET = VAULT_ID_OFFSET + VaultBundle.VAULT_ID_BYTES;
    /** v2: adds vault id and bundle version. */
    private static final int PREFIX_V2 = BUNDLE_VERSION_OFFSET + 4;
    private static final int WRAPPED_KEY_LENGTH = VaultCrypto.NONCE_BYTES + VaultCrypto.KEY_BYTES + VaultCrypto.TAG_BYTES;
    /** Length of a complete v1 inner header. */
    static final int LEGACY_INNER_HEADER_LENGTH = PREFIX_V1 + WRAPPED_KEY_LENGTH;

    /** What a freshly fetched remote bundle means for this device. */
    public enum BundleStatus {
        /** Same version as the one this device holds, and authentic. */
        CURRENT,
        /** Newer than this device's; it belongs to a newer key epoch and needs {@link #restoreFromBundle}. */
        NEWER
    }

    private final VaultHeaderStore store;
    private final DeviceKeyWrapper deviceKey;
    private final int iterations;

    /** Non-null exactly while unlocked. */
    private byte[] vmk;
    private byte[] vaultId;
    private int bundleVersion;
    private byte[] bundle;
    private boolean legacy;

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

    /** True if a vault has been set up on this device. */
    public synchronized boolean isInitialized() {
        return store.exists();
    }

    public synchronized boolean isUnlocked() {
        return vmk != null;
    }

    /** True while unlocked with a Phase 1-2 header that has not been migrated yet. */
    public synchronized boolean isLegacyHeader() {
        return vmk != null && legacy;
    }

    /** The vault id (16 bytes, copy). Only available while unlocked with a v2 header. */
    public synchronized byte[] getVaultId() throws VaultCryptoException {
        requireV2();
        return vaultId.clone();
    }

    public synchronized int getBundleVersion() throws VaultCryptoException {
        requireV2();
        return bundleVersion;
    }

    /** The key bundle to upload (a copy). It is ciphertext and may be stored anywhere. */
    public synchronized byte[] currentBundle() throws VaultCryptoException {
        requireV2();
        return bundle.clone();
    }

    // ------------------------------------------------------------------ create

    /**
     * First-use setup, step 1. Validates the password, generates the VMK and the recovery key, and derives
     * the key-encryption key. Writes NOTHING and leaves the vault locked: call {@link Setup#recoveryKey()}
     * to show the key and {@link Setup#complete} once the user has typed it back.
     */
    public synchronized Setup beginSetup(char[] password, char[] confirmation) throws VaultCryptoException {
        if (store.exists()) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "A vault already exists");
        }
        validateNewPassword(password, confirmation);
        byte[] newVmk = VaultCrypto.randomBytes(VaultCrypto.KEY_BYTES);
        return newSetup(Setup.Mode.CREATE, newVmk, VaultCrypto.randomBytes(VaultBundle.VAULT_ID_BYTES), 1, password);
    }

    /**
     * Upgrade step 1 for a vault written by Phases 1-2: the vault must be unlocked with a legacy header.
     * The old password is verified again, and the user picks a new password (at least
     * {@value #MIN_PASSWORD_LENGTH} characters). The stored VMK is the old data key, so no record or media
     * file is touched. Nothing is written until {@link Setup#complete}.
     */
    public synchronized Setup beginMigration(char[] oldPassword, char[] newPassword, char[] confirmation) throws VaultCryptoException {
        if (vmk == null || !legacy) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "Only an unlocked legacy vault can be migrated");
        }
        byte[] verified = unwrapStoredVmk(oldPassword);
        boolean same = VaultCrypto.constantTimeEquals(verified, vmk);
        VaultCrypto.wipe(verified);
        if (!same) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Stored key differs from the unlocked key");
        }
        validateNewPassword(newPassword, confirmation);
        return newSetup(Setup.Mode.MIGRATE, vmk.clone(), VaultCrypto.randomBytes(VaultBundle.VAULT_ID_BYTES), 1, newPassword);
    }

    private Setup newSetup(Setup.Mode mode, byte[] setupVmk, byte[] id, int version, char[] password) throws VaultCryptoException {
        byte[] salt = VaultCrypto.randomBytes(VaultCrypto.SALT_BYTES);
        byte[] kek = null;
        boolean ok = false;
        RecoveryKey recoveryKey = RecoveryKey.generate();
        try {
            kek = VaultCrypto.deriveKey(password, salt, iterations);
            byte[] newBundle = VaultBundle.create(setupVmk, id, version, recoveryKey);
            Setup setup = new Setup(this, mode, setupVmk, id, version, salt, kek, newBundle, recoveryKey);
            ok = true;
            return setup;
        } finally {
            if (!ok) {
                VaultCrypto.wipe(setupVmk);
                VaultCrypto.wipe(kek);
                recoveryKey.wipe();
            }
        }
    }

    /**
     * Convenience for tests and tools: begins and immediately completes a setup with the generated key.
     * Production UI must use {@link #beginSetup} so the user really sees and confirms the recovery key.
     *
     * @return the key bundle to upload
     */
    byte[] createVault(char[] password, char[] confirmation) throws VaultCryptoException {
        Setup setup = beginSetup(password, confirmation);
        return setup.complete(setup.recoveryKey().format());
    }

    /** A setup or migration waiting for the user to confirm the recovery key. Single use. */
    public static final class Setup {
        enum Mode {CREATE, MIGRATE}

        private final VaultKeyManager owner;
        private final Mode mode;
        private final byte[] vmk;
        private final byte[] vaultId;
        private final int bundleVersion;
        private final byte[] salt;
        private final byte[] kek;
        private final byte[] bundle;
        private final RecoveryKey recoveryKey;
        private boolean finished;

        private Setup(VaultKeyManager owner, Mode mode, byte[] vmk, byte[] vaultId, int bundleVersion, byte[] salt,
                      byte[] kek, byte[] bundle, RecoveryKey recoveryKey) {
            this.owner = owner;
            this.mode = mode;
            this.vmk = vmk;
            this.vaultId = vaultId;
            this.bundleVersion = bundleVersion;
            this.salt = salt;
            this.kek = kek;
            this.bundle = bundle;
            this.recoveryKey = recoveryKey;
        }

        /** The recovery key to show once. The caller must not log or persist it. */
        public synchronized RecoveryKey recoveryKey() {
            return recoveryKey;
        }

        /**
         * Step 2. The user types the recovery key back; only if it matches is the header written.
         * On success the vault is unlocked and the key bundle (to upload) is returned.
         *
         * @throws VaultCryptoException WRONG_RECOVERY_KEY if the typed key differs (the setup stays open so the
         *                              user may retry); INVALID_ARGUMENT if the text is not a valid key;
         *                              INVALID_STATE if finished already or the vault state changed
         */
        public synchronized byte[] complete(String typedRecoveryKey) throws VaultCryptoException {
            if (finished) {
                throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "Setup already finished");
            }
            RecoveryKey typed = RecoveryKey.parse(typedRecoveryKey);
            try {
                if (!recoveryKey.sameKeyAs(typed)) {
                    throw new VaultCryptoException(VaultCryptoException.Reason.WRONG_RECOVERY_KEY,
                            "The recovery key you typed does not match");
                }
            } finally {
                typed.wipe();
            }
            owner.finishSetup(this);
            finished = true;
            byte[] result = bundle.clone();
            wipeSecrets();
            return result;
        }

        /** Abandons the setup; nothing was written. */
        public synchronized void cancel() {
            finished = true;
            wipeSecrets();
        }

        private void wipeSecrets() {
            VaultCrypto.wipe(vmk);
            VaultCrypto.wipe(kek);
            recoveryKey.wipe();
        }
    }

    private void finishSetup(Setup setup) throws VaultCryptoException {
        synchronized (this) {
            if (setup.mode == Setup.Mode.CREATE) {
                if (store.exists()) {
                    throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "A vault already exists");
                }
            } else if (vmk == null || !legacy || !VaultCrypto.constantTimeEquals(vmk, setup.vmk)) {
                throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "Vault changed during migration");
            }
            writeHeaderV2(setup.salt, setup.kek, setup.vmk, setup.vaultId, setup.bundleVersion, setup.bundle);
            install(setup.vmk.clone(), setup.vaultId.clone(), setup.bundleVersion, setup.bundle.clone(), false);
        }
    }

    // ------------------------------------------------------------------ restore on a new / reset device

    /**
     * Rebuilds access from the key bundle and the recovery key, for a new device or after the Keystore key
     * was lost. Sets a NEW password for this device and unlocks.
     *
     * @param replaceExisting must be true if this device already has a header (it is then overwritten, which
     *                        makes any local data wrapped under the old VMK unreadable if the VMK differs)
     * @throws VaultCryptoException WRONG_RECOVERY_KEY, INVALID_ARGUMENT (bad key text / password),
     *                              CORRUPTED (bundle altered), INVALID_STATE (header exists, no permission)
     */
    public synchronized void restoreFromBundle(byte[] bundleBytes, String recoveryKeyText, char[] newPassword,
                                               char[] confirmation, boolean replaceExisting) throws VaultCryptoException {
        if (store.exists() && !replaceExisting) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "This device already has a vault");
        }
        validateNewPassword(newPassword, confirmation);
        RecoveryKey key = RecoveryKey.parse(recoveryKeyText);
        byte[] restored = null;
        byte[] salt = VaultCrypto.randomBytes(VaultCrypto.SALT_BYTES);
        byte[] kek = null;
        boolean ok = false;
        try {
            restored = VaultBundle.openWithRecoveryKey(bundleBytes, key);
            VaultBundle.Info info = VaultBundle.peek(bundleBytes);
            kek = VaultCrypto.deriveKey(newPassword, salt, iterations);
            writeHeaderV2(salt, kek, restored, info.vaultId, info.bundleVersion, bundleBytes);
            install(restored, info.vaultId, info.bundleVersion, bundleBytes.clone(), false);
            ok = true;
        } finally {
            key.wipe();
            VaultCrypto.wipe(kek);
            VaultCrypto.wipe(salt);
            if (!ok) {
                VaultCrypto.wipe(restored);
            }
        }
    }

    // ------------------------------------------------------------------ password change

    /**
     * Changes this device's password. The old password is verified again, a fresh salt is used, and the
     * header is rewritten atomically. The VMK, the vault id and the key bundle do not change, so nothing
     * is re-encrypted and nothing needs uploading.
     */
    public synchronized void changePassword(char[] oldPassword, char[] newPassword, char[] confirmation) throws VaultCryptoException {
        requireV2();
        byte[] verified = unwrapStoredVmk(oldPassword);
        boolean same = VaultCrypto.constantTimeEquals(verified, vmk);
        VaultCrypto.wipe(verified);
        if (!same) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Stored key differs from the unlocked key");
        }
        validateNewPassword(newPassword, confirmation);
        byte[] salt = VaultCrypto.randomBytes(VaultCrypto.SALT_BYTES);
        byte[] kek = null;
        try {
            kek = VaultCrypto.deriveKey(newPassword, salt, iterations);
            writeHeaderV2(salt, kek, vmk, vaultId, bundleVersion, bundle);
        } finally {
            VaultCrypto.wipe(kek);
            VaultCrypto.wipe(salt);
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
     *                              UNSUPPORTED_VERSION if it was written by a newer app;
     *                              DEVICE_KEY_UNAVAILABLE if the device-bound key is gone;
     *                              INVALID_STATE if no vault exists; IO_ERROR on read failure.
     *                              The vault stays locked on every failure.
     */
    public synchronized void unlock(char[] password) throws VaultCryptoException {
        Header h = readHeader();
        byte[] recovered = null;
        boolean ok = false;
        try {
            recovered = unwrap(h, password);
            if (h.version == HEADER_VERSION) {
                checkBundleMatchesHeader(h, recovered);
                install(recovered, h.vaultId, h.bundleVersion, h.bundle, false);
            } else {
                install(recovered, null, 0, null, true);
            }
            ok = true;
        } finally {
            if (!ok) {
                VaultCrypto.wipe(recovered);
            }
        }
    }

    /** Discards the key from memory. Safe to call at any time, including when already locked. */
    public synchronized void lock() {
        replaceKey(null);
        vaultId = null;
        bundle = null;
        bundleVersion = 0;
        legacy = false;
    }

    // ------------------------------------------------------------------ keys for other components

    /**
     * Returns a fresh copy of an independent 256-bit key for {@code purpose} (e.g. "messages", "media").
     * The same purpose always yields the same key for the same vault. The caller should wipe the copy
     * when finished. The master key itself is never exposed.
     *
     * @throws VaultCryptoException INVALID_STATE if the vault is locked
     */
    public synchronized byte[] deriveSubkey(String purpose) throws VaultCryptoException {
        if (vmk == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "Vault is locked");
        }
        return VaultCrypto.deriveSubkey(vmk, purpose);
    }

    // ------------------------------------------------------------------ remote bundle check

    /**
     * Compares a bundle fetched from the server with this device's. Requires the vault to be unlocked.
     *
     * @throws VaultCryptoException ROLLBACK_DETECTED if it is older than ours; INVALID_STATE if it belongs to
     *                              another vault; CORRUPTED if it fails authentication or differs from ours
     *                              at the same version
     */
    public synchronized BundleStatus checkRemoteBundle(byte[] remote) throws VaultCryptoException {
        requireV2();
        VaultBundle.Info info = VaultBundle.peek(remote);
        if (!VaultCrypto.constantTimeEquals(info.vaultId, vaultId)) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "Bundle belongs to a different vault");
        }
        if (info.bundleVersion < bundleVersion) {
            throw new VaultCryptoException(VaultCryptoException.Reason.ROLLBACK_DETECTED, "Server offered an older key bundle");
        }
        if (info.bundleVersion > bundleVersion) {
            return BundleStatus.NEWER; // cannot be authenticated with the old VMK; the caller restores with the recovery key
        }
        VaultBundle.verify(remote, vmk);
        if (!VaultCrypto.constantTimeEquals(remote, bundle)) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Remote bundle differs at the same version");
        }
        return BundleStatus.CURRENT;
    }

    // ------------------------------------------------------------------ destroy

    /**
     * Irreversibly destroys this device's key material: locks, overwrites and deletes the header, and deletes
     * the device key. Encrypted vault data left on disk becomes unreadable on this device (the uploaded key
     * bundle and the recovery key can still rebuild it elsewhere; remote data is not touched). Does not need
     * the password. Both deletions are always attempted; the first failure is then reported.
     */
    public synchronized void destroy() throws VaultCryptoException {
        lock();
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

    // ------------------------------------------------------------------ header encoding

    private static final class Header {
        int version;
        int iterations;
        byte[] salt;
        byte[] aad;
        byte[] wrapped;
        byte[] vaultId;
        int bundleVersion;
        byte[] bundle;
    }

    private Header readHeader() throws VaultCryptoException {
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
        try {
            return parseHeader(inner);
        } finally {
            VaultCrypto.wipe(inner);
        }
    }

    private static Header parseHeader(byte[] inner) throws VaultCryptoException {
        if (inner == null || inner.length < PREFIX_V1 + 1 || !startsWithMagic(inner)) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Vault header is damaged");
        }
        Header h = new Header();
        h.version = inner[VERSION_OFFSET] & 0xFF;
        if (h.version > HEADER_VERSION) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_VERSION, "Vault header was written by a newer app version");
        }
        if (h.version == LEGACY_HEADER_VERSION) {
            if (inner.length != LEGACY_INNER_HEADER_LENGTH) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Vault header is damaged");
            }
        } else if (h.version == HEADER_VERSION) {
            if (inner.length < PREFIX_V2 + WRAPPED_KEY_LENGTH + 2) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Vault header is damaged");
            }
        } else {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Vault header is damaged");
        }
        h.iterations = readInt(inner, ITERATIONS_OFFSET);
        if (h.iterations < MIN_ACCEPTED_ITERATIONS || h.iterations > VaultCrypto.MAX_PBKDF2_ITERATIONS) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Vault header has invalid parameters");
        }
        h.salt = Arrays.copyOfRange(inner, SALT_OFFSET, SALT_OFFSET + VaultCrypto.SALT_BYTES);
        if (h.version == LEGACY_HEADER_VERSION) {
            h.aad = Arrays.copyOf(inner, PREFIX_V1);
            h.wrapped = Arrays.copyOfRange(inner, PREFIX_V1, LEGACY_INNER_HEADER_LENGTH);
        } else {
            h.vaultId = Arrays.copyOfRange(inner, VAULT_ID_OFFSET, VAULT_ID_OFFSET + VaultBundle.VAULT_ID_BYTES);
            h.bundleVersion = readInt(inner, BUNDLE_VERSION_OFFSET);
            h.aad = Arrays.copyOf(inner, PREFIX_V2);
            h.wrapped = Arrays.copyOfRange(inner, PREFIX_V2, PREFIX_V2 + WRAPPED_KEY_LENGTH);
            int lenOffset = PREFIX_V2 + WRAPPED_KEY_LENGTH;
            int bundleLength = ((inner[lenOffset] & 0xFF) << 8) | (inner[lenOffset + 1] & 0xFF);
            if (bundleLength < 1 || lenOffset + 2 + bundleLength != inner.length) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Vault header is damaged");
            }
            h.bundle = Arrays.copyOfRange(inner, lenOffset + 2, inner.length);
        }
        return h;
    }

    private static byte[] unwrap(Header h, char[] password) throws VaultCryptoException {
        if (password == null || password.length == 0
                || Character.codePointCount(password, 0, password.length) > MAX_PASSWORD_LENGTH) {
            throw new VaultCryptoException(VaultCryptoException.Reason.WRONG_PASSWORD, "Incorrect password");
        }
        byte[] kek = VaultCrypto.deriveKey(password, h.salt, h.iterations);
        try {
            return VaultCrypto.decrypt(kek, h.wrapped, h.aad);
        } catch (VaultCryptoException e) {
            if (e.getReason() == VaultCryptoException.Reason.CORRUPTED) {
                // The device layer already authenticated the header, so a failure here means the password is wrong.
                throw new VaultCryptoException(VaultCryptoException.Reason.WRONG_PASSWORD, "Incorrect password", e);
            }
            throw e;
        } finally {
            VaultCrypto.wipe(kek);
        }
    }

    /** Re-reads the stored header and unwraps its key with {@code password}; the caller wipes the result. */
    private byte[] unwrapStoredVmk(char[] password) throws VaultCryptoException {
        return unwrap(readHeader(), password);
    }

    private static void checkBundleMatchesHeader(Header h, byte[] candidateVmk) throws VaultCryptoException {
        VaultBundle.Info info = VaultBundle.peek(h.bundle);
        if (!VaultCrypto.constantTimeEquals(info.vaultId, h.vaultId) || info.bundleVersion != h.bundleVersion) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Vault header and key bundle disagree");
        }
        VaultBundle.verify(h.bundle, candidateVmk);
    }

    private void writeHeaderV2(byte[] salt, byte[] kek, byte[] keyToWrap, byte[] id, int version, byte[] bundleBytes) throws VaultCryptoException {
        if (bundleBytes.length > 0xFFFF) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Bundle too large");
        }
        byte[] prefix = new byte[PREFIX_V2];
        System.arraycopy(MAGIC, 0, prefix, 0, MAGIC.length);
        prefix[VERSION_OFFSET] = HEADER_VERSION;
        writeInt(prefix, ITERATIONS_OFFSET, iterations);
        System.arraycopy(salt, 0, prefix, SALT_OFFSET, salt.length);
        System.arraycopy(id, 0, prefix, VAULT_ID_OFFSET, id.length);
        writeInt(prefix, BUNDLE_VERSION_OFFSET, version);
        byte[] wrapped = VaultCrypto.encrypt(kek, keyToWrap, prefix);

        byte[] inner = new byte[PREFIX_V2 + wrapped.length + 2 + bundleBytes.length];
        System.arraycopy(prefix, 0, inner, 0, PREFIX_V2);
        System.arraycopy(wrapped, 0, inner, PREFIX_V2, wrapped.length);
        int p = PREFIX_V2 + wrapped.length;
        inner[p] = (byte) (bundleBytes.length >>> 8);
        inner[p + 1] = (byte) bundleBytes.length;
        System.arraycopy(bundleBytes, 0, inner, p + 2, bundleBytes.length);
        try {
            byte[] outer = deviceKey.wrap(inner);
            try {
                store.write(outer);
            } catch (IOException e) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not store vault header", e);
            }
        } finally {
            VaultCrypto.wipe(inner);
        }
    }

    // ------------------------------------------------------------------ internals

    private void install(byte[] newVmk, byte[] id, int version, byte[] bundleBytes, boolean isLegacy) {
        replaceKey(newVmk);
        vaultId = id;
        bundleVersion = version;
        bundle = bundleBytes;
        legacy = isLegacy;
    }

    private void requireV2() throws VaultCryptoException {
        if (vmk == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "Vault is locked");
        }
        if (legacy) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "Vault must be migrated first");
        }
    }

    private void replaceKey(byte[] newKey) {
        VaultCrypto.wipe(vmk);
        vmk = newKey;
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
