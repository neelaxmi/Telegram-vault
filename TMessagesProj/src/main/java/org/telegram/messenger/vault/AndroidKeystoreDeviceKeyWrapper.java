package org.telegram.messenger.vault;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * {@link DeviceKeyWrapper} that encrypts the vault header with a device-bound AES-256-GCM key.
 * On a phone the key lives in the Android Keystore and cannot be exported (see
 * {@code AndroidKeystoreSecretStore}); this class holds only the logic around it and has no
 * Android imports, so it is unit-tested on the JVM against a software {@link DeviceKeyStore}.
 *
 * <h3>Blob format</h3>
 * {@code version(1) = 0x01 || iv(12) || AES-GCM ciphertext || tag(16)}, with the fixed AAD
 * {@code "tg-vault-device-wrap-v1"}. The IV is chosen by the key store (Android Keystore refuses
 * caller-supplied IVs for encryption), so it is read back with {@link Cipher#getIV()}.
 *
 * <h3>Failure mapping (the contract {@link VaultKeyManager} relies on)</h3>
 * <ul>
 *   <li>Key missing, invalidated, unrecoverable, or the key store errors for any reason
 *       -> {@code DEVICE_KEY_UNAVAILABLE}. {@link #unwrap} never creates a replacement key,
 *       because a fresh key could not open existing data and would hide the real problem.</li>
 *   <li>Blob truncated, unknown version, or authentication failure (modified data, or data
 *       wrapped by a different key, e.g. copied from another phone) -> {@code CORRUPTED}.</li>
 *   <li>Unexpected runtime errors from the key store fail closed as {@code DEVICE_KEY_UNAVAILABLE};
 *       nothing is ever returned in the clear on error.</li>
 * </ul>
 *
 * Thread-safe (synchronised).
 */
public final class AndroidKeystoreDeviceKeyWrapper implements DeviceKeyWrapper {

    static final byte FORMAT_VERSION = 1;
    private static final byte[] AAD = "tg-vault-device-wrap-v1".getBytes(StandardCharsets.US_ASCII);
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int MIN_BLOB_BYTES = 1 + IV_BYTES + TAG_BITS / 8;

    private final DeviceKeyStore keyStore;

    public AndroidKeystoreDeviceKeyWrapper(DeviceKeyStore keyStore) {
        if (keyStore == null) {
            throw new IllegalArgumentException("keyStore is required");
        }
        this.keyStore = keyStore;
    }

    @Override
    public synchronized byte[] wrap(byte[] data) throws VaultCryptoException {
        if (data == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Nothing to wrap");
        }
        SecretKey key = obtainKey(true);
        Cipher cipher = newCipher();
        try {
            // No IV parameter: the key store generates a fresh random IV for every encryption.
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipher.updateAAD(AAD);
            byte[] iv = cipher.getIV();
            byte[] ciphertext = cipher.doFinal(data);
            if (iv == null || iv.length != IV_BYTES) {
                throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_PLATFORM, "Unexpected GCM IV length");
            }
            byte[] out = new byte[1 + IV_BYTES + ciphertext.length];
            out[0] = FORMAT_VERSION;
            System.arraycopy(iv, 0, out, 1, IV_BYTES);
            System.arraycopy(ciphertext, 0, out, 1 + IV_BYTES, ciphertext.length);
            return out;
        } catch (GeneralSecurityException | RuntimeException e) {
            // Includes KeyPermanentlyInvalidatedException (an InvalidKeyException) and ProviderException.
            throw new VaultCryptoException(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, "Device key could not encrypt", e);
        }
    }

    @Override
    public synchronized byte[] unwrap(byte[] wrapped) throws VaultCryptoException {
        if (wrapped == null || wrapped.length < MIN_BLOB_BYTES || wrapped[0] != FORMAT_VERSION) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Wrapped data is damaged or unsupported");
        }
        SecretKey key = obtainKey(false);
        Cipher cipher = newCipher();
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, wrapped, 1, IV_BYTES));
            cipher.updateAAD(AAD);
            return cipher.doFinal(wrapped, 1 + IV_BYTES, wrapped.length - 1 - IV_BYTES);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            // AEADBadTagException: modified data, or wrapped under a different key (e.g. another device).
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Wrapped data failed authentication", e);
        } catch (GeneralSecurityException | RuntimeException e) {
            // InvalidKeyException (key invalidated), ProviderException (key store failure), etc.
            throw new VaultCryptoException(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, "Device key could not decrypt", e);
        }
    }

    @Override
    public synchronized void deleteKey() throws VaultCryptoException {
        try {
            keyStore.deleteKey();
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, "Device key could not be deleted", e);
        }
    }

    // ------------------------------------------------------------------ internals

    /** @param create true only for {@link #wrap}; {@link #unwrap} must never create a key. */
    private SecretKey obtainKey(boolean create) throws VaultCryptoException {
        SecretKey key;
        try {
            key = keyStore.getKey();
            if (key == null && create) {
                key = keyStore.createKey();
            }
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, "Device key is not usable", e);
        }
        if (key == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, "Device key does not exist");
        }
        return key;
    }

    private static Cipher newCipher() throws VaultCryptoException {
        try {
            return Cipher.getInstance(TRANSFORMATION);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_PLATFORM, "AES-GCM unavailable", e);
        }
    }
}
