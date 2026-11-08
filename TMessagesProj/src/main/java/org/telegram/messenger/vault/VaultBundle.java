package org.telegram.messenger.vault;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The key bundle: the small, non-secret-looking blob that is uploaded next to the Vault data so that a
 * new or reset device can rebuild the Vault Master Key (VMK). It holds the VMK wrapped under one or more
 * "slots". Decision 2 of the approved plan: there is NO password slot; the only slot type is the recovery
 * key slot. (Linking from another device is a protocol, not a slot.)
 *
 * <pre>
 *   "TGVB" | version(1) | vaultId(16) | bundleVersion(uint32) | slotCount(1)
 *          | slot* | HMAC-SHA256(32)
 *   slot = type(1) | length(uint16) | payload
 *   recovery slot (type 1) payload = AES-256-GCM(slotKey, VMK, aad = first 25 bytes | type)   // nonce12|ct32|tag16
 *   slotKey = HKDF-SHA256(recoveryKey, salt = vaultId, info = "tg-vault/v2/recovery-slot")
 *   HMAC key = HKDF(VMK, "bundle-auth") over every byte before the HMAC
 * </pre>
 * The slot's authenticated data binds it to the vault id and the bundle version, so a slot cannot be moved
 * to another vault or version. The HMAC covers the whole bundle (including unknown slot types a newer
 * app may add) and can only be checked by someone who holds the VMK.
 */
final class VaultBundle {

    static final int VERSION = 1;
    static final int SLOT_RECOVERY = 1;
    static final int VAULT_ID_BYTES = 16;
    static final int MAX_BUNDLE_BYTES = 4096;
    private static final int MAX_SLOTS = 8;
    private static final byte[] MAGIC = {'T', 'G', 'V', 'B'};
    private static final int VERSION_OFFSET = MAGIC.length;
    private static final int VAULT_ID_OFFSET = VERSION_OFFSET + 1;
    private static final int BUNDLE_VERSION_OFFSET = VAULT_ID_OFFSET + VAULT_ID_BYTES;
    private static final int SLOT_COUNT_OFFSET = BUNDLE_VERSION_OFFSET + 4;
    /** magic, version, vault id, bundle version. */
    private static final int PREFIX_LENGTH = SLOT_COUNT_OFFSET;
    private static final int HEADER_LENGTH = SLOT_COUNT_OFFSET + 1;
    private static final int MAC_BYTES = 32;
    private static final String PURPOSE_AUTH = "bundle-auth";
    private static final byte[] RECOVERY_SLOT_INFO = "tg-vault/v2/recovery-slot".getBytes(StandardCharsets.US_ASCII);

    private VaultBundle() {
    }

    /** Fields readable without any key. They are NOT authenticated until {@link #verify} succeeds. */
    static final class Info {
        final byte[] vaultId;
        final int bundleVersion;

        Info(byte[] vaultId, int bundleVersion) {
            this.vaultId = vaultId;
            this.bundleVersion = bundleVersion;
        }
    }

    static byte[] create(byte[] vmk, byte[] vaultId, int bundleVersion, RecoveryKey recoveryKey) throws VaultCryptoException {
        if (vmk == null || vmk.length != VaultCrypto.KEY_BYTES || vaultId == null || vaultId.length != VAULT_ID_BYTES
                || bundleVersion < 1 || recoveryKey == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Invalid bundle arguments");
        }
        byte[] prefix = new byte[PREFIX_LENGTH];
        System.arraycopy(MAGIC, 0, prefix, 0, MAGIC.length);
        prefix[VERSION_OFFSET] = VERSION;
        System.arraycopy(vaultId, 0, prefix, VAULT_ID_OFFSET, VAULT_ID_BYTES);
        writeInt(prefix, BUNDLE_VERSION_OFFSET, bundleVersion);

        byte[] rk = recoveryKey.toBytes();
        byte[] slotKey = null;
        byte[] authKey = null;
        try {
            slotKey = VaultCrypto.hkdfSha256(rk, vaultId, RECOVERY_SLOT_INFO, VaultCrypto.KEY_BYTES);
            byte[] wrapped = VaultCrypto.encrypt(slotKey, vmk, slotAad(prefix, SLOT_RECOVERY));

            byte[] body = new byte[HEADER_LENGTH + 3 + wrapped.length];
            System.arraycopy(prefix, 0, body, 0, PREFIX_LENGTH);
            body[SLOT_COUNT_OFFSET] = 1;
            int p = HEADER_LENGTH;
            body[p++] = SLOT_RECOVERY;
            body[p++] = (byte) (wrapped.length >>> 8);
            body[p++] = (byte) wrapped.length;
            System.arraycopy(wrapped, 0, body, p, wrapped.length);

            authKey = VaultCrypto.deriveSubkey(vmk, PURPOSE_AUTH);
            byte[] mac = VaultCrypto.hmacSha256(authKey, body);
            byte[] out = Arrays.copyOf(body, body.length + MAC_BYTES);
            System.arraycopy(mac, 0, out, body.length, MAC_BYTES);
            return out;
        } finally {
            VaultCrypto.wipe(rk);
            VaultCrypto.wipe(slotKey);
            VaultCrypto.wipe(authKey);
        }
    }

    /**
     * Structural parse only. Anything it returns may have been forged until {@link #verify} succeeds.
     *
     * @throws VaultCryptoException CORRUPTED if malformed, UNSUPPORTED_VERSION if written by a newer format
     */
    static Info peek(byte[] bundle) throws VaultCryptoException {
        parse(bundle);
        return new Info(Arrays.copyOfRange(bundle, VAULT_ID_OFFSET, VAULT_ID_OFFSET + VAULT_ID_BYTES),
                readInt(bundle, BUNDLE_VERSION_OFFSET));
    }

    /**
     * Opens the recovery slot and returns the VMK, after checking the HMAC with it.
     *
     * @throws VaultCryptoException WRONG_RECOVERY_KEY if the key does not open the slot; CORRUPTED if the
     *                              slot opens but the bundle HMAC fails (the bundle was altered)
     */
    static byte[] openWithRecoveryKey(byte[] bundle, RecoveryKey recoveryKey) throws VaultCryptoException {
        if (recoveryKey == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Recovery key required");
        }
        int[] slot = parse(bundle);
        byte[] rk = recoveryKey.toBytes();
        byte[] slotKey = null;
        byte[] vmk = null;
        boolean ok = false;
        try {
            if (slot[0] < 0) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Bundle has no recovery slot");
            }
            byte[] vaultId = Arrays.copyOfRange(bundle, VAULT_ID_OFFSET, VAULT_ID_OFFSET + VAULT_ID_BYTES);
            slotKey = VaultCrypto.hkdfSha256(rk, vaultId, RECOVERY_SLOT_INFO, VaultCrypto.KEY_BYTES);
            byte[] wrapped = Arrays.copyOfRange(bundle, slot[0], slot[0] + slot[1]);
            try {
                vmk = VaultCrypto.decrypt(slotKey, wrapped, slotAad(Arrays.copyOf(bundle, PREFIX_LENGTH), SLOT_RECOVERY));
            } catch (VaultCryptoException e) {
                if (e.getReason() == VaultCryptoException.Reason.CORRUPTED) {
                    throw new VaultCryptoException(VaultCryptoException.Reason.WRONG_RECOVERY_KEY, "Recovery key does not open this Vault", e);
                }
                throw e;
            }
            verify(bundle, vmk);
            ok = true;
            return vmk;
        } finally {
            VaultCrypto.wipe(rk);
            VaultCrypto.wipe(slotKey);
            if (!ok) {
                VaultCrypto.wipe(vmk);
            }
        }
    }

    /** Checks the whole-bundle HMAC with the VMK. */
    static void verify(byte[] bundle, byte[] vmk) throws VaultCryptoException {
        parse(bundle);
        byte[] authKey = VaultCrypto.deriveSubkey(vmk, PURPOSE_AUTH);
        try {
            byte[] expected = VaultCrypto.hmacSha256(authKey, Arrays.copyOf(bundle, bundle.length - MAC_BYTES));
            byte[] actual = Arrays.copyOfRange(bundle, bundle.length - MAC_BYTES, bundle.length);
            if (!VaultCrypto.constantTimeEquals(expected, actual)) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Key bundle failed authentication");
            }
        } finally {
            VaultCrypto.wipe(authKey);
        }
    }

    // ------------------------------------------------------------------ internals

    /** Validates the structure and returns {offset, length} of the recovery slot payload, or {-1, 0}. */
    private static int[] parse(byte[] b) throws VaultCryptoException {
        if (b == null || b.length < HEADER_LENGTH + MAC_BYTES || b.length > MAX_BUNDLE_BYTES) {
            throw corrupted("Key bundle has an invalid size");
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (b[i] != MAGIC[i]) {
                throw corrupted("Not a key bundle");
            }
        }
        int version = b[VERSION_OFFSET] & 0xFF;
        if (version > VERSION) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_VERSION, "Key bundle was written by a newer app version");
        }
        if (version < 1 || readInt(b, BUNDLE_VERSION_OFFSET) < 1) {
            throw corrupted("Key bundle has an invalid version");
        }
        int slots = b[SLOT_COUNT_OFFSET] & 0xFF;
        if (slots < 1 || slots > MAX_SLOTS) {
            throw corrupted("Key bundle has an invalid slot count");
        }
        int end = b.length - MAC_BYTES;
        int p = HEADER_LENGTH;
        int recoveryOffset = -1;
        int recoveryLength = 0;
        for (int i = 0; i < slots; i++) {
            if (p + 3 > end) {
                throw corrupted("Key bundle is truncated");
            }
            int type = b[p] & 0xFF;
            int len = ((b[p + 1] & 0xFF) << 8) | (b[p + 2] & 0xFF);
            p += 3;
            if (len > end - p) {
                throw corrupted("Key bundle slot overruns the bundle");
            }
            if (type == SLOT_RECOVERY) {
                if (recoveryOffset >= 0) {
                    throw corrupted("Key bundle has two recovery slots");
                }
                if (len != VaultCrypto.NONCE_BYTES + VaultCrypto.KEY_BYTES + VaultCrypto.TAG_BYTES) {
                    throw corrupted("Recovery slot has an invalid size");
                }
                recoveryOffset = p;
                recoveryLength = len;
            }
            p += len;
        }
        if (p != end) {
            throw corrupted("Key bundle has trailing bytes");
        }
        return new int[]{recoveryOffset, recoveryLength};
    }

    private static byte[] slotAad(byte[] prefix, int type) {
        byte[] aad = Arrays.copyOf(prefix, PREFIX_LENGTH + 1);
        aad[PREFIX_LENGTH] = (byte) type;
        return aad;
    }

    private static VaultCryptoException corrupted(String message) {
        return new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, message);
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
