package org.telegram.messenger.vault;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cryptographic primitives for the Protected Vault. Pure Java (JCA only, no Android
 * classes) so it can be unit-tested on a plain JVM.
 *
 * <ul>
 *   <li>Password to key: PBKDF2-HMAC-SHA256, implemented here on top of {@code HmacSHA256}
 *       instead of {@code SecretKeyFactory("PBKDF2WithHmacSHA256")}, because the latter does
 *       not exist on Android API 23-25 (this app's minSdk is 23) and providers differ in how
 *       they encode the password. Verified against RFC 7914 test vectors.</li>
 *   <li>Passwords are Unicode NFKC-normalised, then UTF-8 encoded, so the same password typed
 *       on different keyboards derives the same key.</li>
 *   <li>Authenticated encryption: AES-256-GCM, random 96-bit nonce per message, output layout
 *       {@code nonce(12) || ciphertext || tag(16)}. A random 96-bit nonce is safe for up to
 *       about 2^32 messages under one key; vault subkeys stay far below that.</li>
 *   <li>Key separation: HKDF-SHA256 (RFC 5869) derives independent subkeys.</li>
 * </ul>
 *
 * This class encrypts whole buffers, which is right for messages and metadata. Large media
 * files need a chunked scheme and are handled separately.
 */
public final class VaultCrypto {

    public static final int KEY_BYTES = 32;
    public static final int SALT_BYTES = 16;
    public static final int NONCE_BYTES = 12;
    public static final int TAG_BYTES = 16;

    /** OWASP's current minimum recommendation for PBKDF2-HMAC-SHA256. */
    public static final int DEFAULT_PBKDF2_ITERATIONS = 600_000;
    /** Upper bound so a corrupted stored value cannot make unlock run for hours. */
    public static final int MAX_PBKDF2_ITERATIONS = 10_000_000;

    private static final int HMAC_BYTES = 32;
    private static final String HMAC = "HmacSHA256";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final String SUBKEY_INFO_PREFIX = "tg-vault/v1/";

    private static final SecureRandom RANDOM = new SecureRandom();

    private VaultCrypto() {
    }

    // ------------------------------------------------------------------ randomness

    public static byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }

    // ------------------------------------------------------------------ password -> key

    /**
     * Derives a 256-bit key from a password.
     *
     * @param password   non-empty; not modified or retained (caller should wipe it)
     * @param salt       exactly {@link #SALT_BYTES} random bytes
     * @param iterations 1 .. {@link #MAX_PBKDF2_ITERATIONS}; production uses {@link #DEFAULT_PBKDF2_ITERATIONS}
     */
    public static byte[] deriveKey(char[] password, byte[] salt, int iterations) throws VaultCryptoException {
        if (password == null || password.length == 0) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Password is empty");
        }
        if (salt == null || salt.length != SALT_BYTES) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Salt must be " + SALT_BYTES + " bytes");
        }
        if (iterations < 1 || iterations > MAX_PBKDF2_ITERATIONS) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Iteration count out of range");
        }
        byte[] passwordBytes = passwordToBytes(password);
        try {
            return pbkdf2HmacSha256(passwordBytes, salt, iterations, KEY_BYTES);
        } finally {
            wipe(passwordBytes);
        }
    }

    /** NFKC-normalises and UTF-8 encodes a password, avoiding extra String copies when possible. */
    static byte[] passwordToBytes(char[] password) {
        CharBuffer chars = CharBuffer.wrap(password);
        CharBuffer normalized = null;
        char[] normalizedChars = null;
        try {
            if (!Normalizer.isNormalized(chars, Normalizer.Form.NFKC)) {
                // Unavoidable: Normalizer returns an immutable String. Only taken for unusual input.
                String s = Normalizer.normalize(chars, Normalizer.Form.NFKC);
                normalizedChars = s.toCharArray();
                normalized = CharBuffer.wrap(normalizedChars);
            } else {
                normalized = chars;
            }
            ByteBuffer encoded = StandardCharsets.UTF_8.encode(normalized);
            byte[] out = new byte[encoded.remaining()];
            encoded.get(out);
            if (encoded.hasArray()) {
                Arrays.fill(encoded.array(), (byte) 0);
            }
            return out;
        } finally {
            if (normalizedChars != null) {
                wipe(normalizedChars);
            }
        }
    }

    /** PBKDF2 (RFC 8018) with HMAC-SHA256. Package-private so tests can run the RFC vectors directly. */
    static byte[] pbkdf2HmacSha256(byte[] password, byte[] salt, int iterations, int dkLen) throws VaultCryptoException {
        if (password.length == 0) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Password is empty");
        }
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(password, HMAC));

            int blocks = (dkLen + HMAC_BYTES - 1) / HMAC_BYTES;
            byte[] out = new byte[dkLen];
            byte[] saltAndIndex = new byte[salt.length + 4];
            System.arraycopy(salt, 0, saltAndIndex, 0, salt.length);
            byte[] u = new byte[HMAC_BYTES];
            byte[] t = new byte[HMAC_BYTES];

            for (int block = 1; block <= blocks; block++) {
                saltAndIndex[salt.length] = (byte) (block >>> 24);
                saltAndIndex[salt.length + 1] = (byte) (block >>> 16);
                saltAndIndex[salt.length + 2] = (byte) (block >>> 8);
                saltAndIndex[salt.length + 3] = (byte) block;

                mac.update(saltAndIndex);
                mac.doFinal(u, 0);
                System.arraycopy(u, 0, t, 0, HMAC_BYTES);

                for (int i = 1; i < iterations; i++) {
                    mac.update(u);
                    mac.doFinal(u, 0);
                    for (int k = 0; k < HMAC_BYTES; k++) {
                        t[k] ^= u[k];
                    }
                }
                int offset = (block - 1) * HMAC_BYTES;
                System.arraycopy(t, 0, out, offset, Math.min(HMAC_BYTES, dkLen - offset));
            }
            wipe(u);
            wipe(t);
            return out;
        } catch (GeneralSecurityException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_PLATFORM, "HmacSHA256 unavailable", e);
        }
    }

    // ------------------------------------------------------------------ HKDF

    /**
     * Derives an independent 256-bit subkey for {@code purpose} (for example "messages" or "media")
     * from a master key, so one key is never used for two jobs.
     */
    public static byte[] deriveSubkey(byte[] masterKey, String purpose) throws VaultCryptoException {
        checkKey(masterKey);
        if (purpose == null || purpose.isEmpty()) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Purpose is empty");
        }
        return hkdfSha256(masterKey, new byte[0], (SUBKEY_INFO_PREFIX + purpose).getBytes(StandardCharsets.UTF_8), KEY_BYTES);
    }

    /** HMAC-SHA256 over the concatenation of {@code parts}. */
    public static byte[] hmacSha256(byte[] key, byte[]... parts) throws VaultCryptoException {
        if (key == null || key.length == 0) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "HMAC key is empty");
        }
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            for (byte[] part : parts) {
                mac.update(part);
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_PLATFORM, "HMAC-SHA256 unavailable", e);
        }
    }

    /** HKDF-SHA256 (RFC 5869). Package-private so tests can run the RFC vectors directly. */
    static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) throws VaultCryptoException {
        if (length < 1 || length > 255 * HMAC_BYTES) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "HKDF length out of range");
        }
        try {
            byte[] extractKey = (salt == null || salt.length == 0) ? new byte[HMAC_BYTES] : salt;
            Mac extract = Mac.getInstance(HMAC);
            extract.init(new SecretKeySpec(extractKey, HMAC));
            byte[] prk = extract.doFinal(ikm);

            Mac expand = Mac.getInstance(HMAC);
            expand.init(new SecretKeySpec(prk, HMAC));
            byte[] okm = new byte[length];
            byte[] previous = new byte[0];
            int produced = 0;
            for (int counter = 1; produced < length; counter++) {
                expand.update(previous);
                expand.update(info);
                expand.update((byte) counter);
                previous = expand.doFinal();
                int n = Math.min(previous.length, length - produced);
                System.arraycopy(previous, 0, okm, produced, n);
                produced += n;
            }
            wipe(prk);
            wipe(previous);
            return okm;
        } catch (GeneralSecurityException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_PLATFORM, "HmacSHA256 unavailable", e);
        }
    }

    // ------------------------------------------------------------------ AES-256-GCM

    /**
     * Encrypts and authenticates {@code plaintext}.
     *
     * @param key  256-bit key
     * @param aad  associated data that is authenticated but not encrypted (may be null); the same
     *             value must be supplied to {@link #decrypt}. Use it to bind a record to its context.
     * @return {@code nonce(12) || ciphertext || tag(16)}
     */
    public static byte[] encrypt(byte[] key, byte[] plaintext, byte[] aad) throws VaultCryptoException {
        return encryptWithNonce(key, randomBytes(NONCE_BYTES), plaintext, aad);
    }

    /** Package-private so tests can run known-answer vectors. Never call with a reused nonce in production code. */
    static byte[] encryptWithNonce(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) throws VaultCryptoException {
        checkKey(key);
        if (plaintext == null || nonce == null || nonce.length != NONCE_BYTES) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Bad plaintext or nonce");
        }
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BYTES * 8, nonce));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] out = new byte[NONCE_BYTES + ciphertext.length];
            System.arraycopy(nonce, 0, out, 0, NONCE_BYTES);
            System.arraycopy(ciphertext, 0, out, NONCE_BYTES, ciphertext.length);
            return out;
        } catch (GeneralSecurityException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_PLATFORM, "AES-GCM encryption failed", e);
        }
    }

    /**
     * Verifies and decrypts a blob produced by {@link #encrypt}.
     *
     * @throws VaultCryptoException with reason CORRUPTED if the blob is truncated, was modified,
     *                              was encrypted under another key, or the AAD does not match
     */
    public static byte[] decrypt(byte[] key, byte[] blob, byte[] aad) throws VaultCryptoException {
        checkKey(key);
        if (blob == null || blob.length < NONCE_BYTES + TAG_BYTES) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Encrypted data too short");
        }
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BYTES * 8, blob, 0, NONCE_BYTES));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(blob, NONCE_BYTES, blob.length - NONCE_BYTES);
        } catch (GeneralSecurityException e) {
            // AEADBadTagException lands here: wrong key, wrong AAD, or modified data.
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Authentication failed", e);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static void checkKey(byte[] key) throws VaultCryptoException {
        if (key == null || key.length != KEY_BYTES) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Key must be " + KEY_BYTES + " bytes");
        }
    }

    /** Constant-time comparison. */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return a != null && b != null && MessageDigest.isEqual(a, b);
    }

    public static void wipe(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

    public static void wipe(char[] data) {
        if (data != null) {
            Arrays.fill(data, '\0');
        }
    }
}
