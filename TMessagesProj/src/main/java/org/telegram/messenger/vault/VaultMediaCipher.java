package org.telegram.messenger.vault;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Streaming, chunked AES-256-GCM for Vault media (photos, videos, documents, thumbnails).
 * Pure Java; never holds more than one chunk in memory, so multi-gigabyte videos are fine.
 *
 * <h3>File format (version 1)</h3>
 * <pre>
 *   header (25 bytes):  "TGVM" | version=1 | chunkSize (uint32 BE) | fileSalt (16 random bytes)
 *   then one or more chunks, each:  AES-GCM ciphertext (up to chunkSize bytes) || tag (16 bytes)
 * </pre>
 * <ul>
 *   <li>Per-file key: {@code HKDF-SHA256(mediaKey, salt = fileSalt, info = "tg-vault/v1/media-file")}.
 *       Every file therefore has its own key, so nonces can never repeat across files.</li>
 *   <li>Nonce (12 bytes) for chunk i: {@code i as 8-byte big-endian || 0x000000 || finalFlag}, where
 *       finalFlag is 1 only for the last chunk. This makes the format detect
 *       <b>reordering</b> (index is in the nonce), <b>truncation</b> (the new last chunk was sealed
 *       with finalFlag 0, so it fails when treated as final) and <b>extension</b> (the old final chunk
 *       is no longer last, so it fails when treated as non-final).</li>
 *   <li>AAD for every chunk: the 25 header bytes followed by caller-supplied context (the Vault
 *       passes the media id), so a file cannot be moved to a different media id undetected.</li>
 *   <li>Every chunk except the last holds exactly chunkSize plaintext bytes. An empty file is a header plus one
 *       empty final chunk (just a tag), so an empty file is distinguishable from a missing one.</li>
 * </ul>
 *
 * <h3>Streaming caveat</h3>
 * {@link #decrypt} writes each chunk to the output only after that chunk is authenticated, but a
 * truncation or reorder can only be detected when it is reached. If it throws, the output may already
 * contain earlier authentic chunks; callers must discard that partial output (never display or
 * keep it as a complete file).
 *
 * Neither method closes the streams it is given.
 */
public final class VaultMediaCipher {

    public static final int DEFAULT_CHUNK_SIZE = 64 * 1024;
    public static final int MIN_CHUNK_SIZE = 16;
    public static final int MAX_CHUNK_SIZE = 4 * 1024 * 1024;
    public static final int HEADER_BYTES = 4 + 1 + 4 + VaultCrypto.SALT_BYTES;

    private static final byte[] MAGIC = {'T', 'G', 'V', 'M'};
    private static final byte VERSION = 1;
    private static final byte[] FILE_KEY_INFO = "tg-vault/v1/media-file".getBytes(StandardCharsets.US_ASCII);
    private static final int TAG_BYTES = VaultCrypto.TAG_BYTES;
    private static final int TAG_BITS = TAG_BYTES * 8;

    private VaultMediaCipher() {
    }

    // ------------------------------------------------------------------ encrypt

    /**
     * Encrypts everything readable from {@code in} to {@code out}.
     *
     * @param mediaKey  256-bit media key (from {@code VaultKeyManager.deriveSubkey("media")})
     * @param aad       context bound to every chunk, may be null
     * @param chunkSize plaintext bytes per chunk, {@link #MIN_CHUNK_SIZE}..{@link #MAX_CHUNK_SIZE}
     * @return number of plaintext bytes encrypted
     */
    public static long encrypt(InputStream in, OutputStream out, byte[] mediaKey, byte[] aad, int chunkSize)
            throws IOException, VaultCryptoException {
        return encryptWithSalt(in, out, mediaKey, aad, chunkSize, VaultCrypto.randomBytes(VaultCrypto.SALT_BYTES));
    }

    /** Package-private so tests can pin the format with known-answer vectors. Production code must use random salts. */
    static long encryptWithSalt(InputStream in, OutputStream out, byte[] mediaKey, byte[] aad, int chunkSize, byte[] salt)
            throws IOException, VaultCryptoException {
        if (in == null || out == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Streams required");
        }
        checkKey(mediaKey);
        checkChunkSize(chunkSize);
        if (salt == null || salt.length != VaultCrypto.SALT_BYTES) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Bad salt");
        }

        byte[] header = buildHeader(chunkSize, salt);
        byte[] chunkAad = concat(header, aad);
        byte[] fileKey = VaultCrypto.hkdfSha256(mediaKey, salt, FILE_KEY_INFO, VaultCrypto.KEY_BYTES);
        byte[] buf = new byte[chunkSize + 1];
        try {
            Cipher cipher = newCipher();
            SecretKeySpec keySpec = new SecretKeySpec(fileKey, "AES");
            out.write(header);

            long total = 0;
            long index = 0;
            // One byte of look-ahead tells us whether the chunk we hold is the last one.
            int have = readFully(in, buf, 0, chunkSize + 1);
            while (true) {
                if (have <= chunkSize) {
                    out.write(sealChunk(cipher, keySpec, chunkAad, index, true, buf, have));
                    total += have;
                    return total;
                }
                out.write(sealChunk(cipher, keySpec, chunkAad, index, false, buf, chunkSize));
                total += chunkSize;
                index++;
                buf[0] = buf[chunkSize];
                have = 1 + readFully(in, buf, 1, chunkSize);
            }
        } finally {
            VaultCrypto.wipe(fileKey);
            Arrays.fill(buf, (byte) 0);
        }
    }

    // ------------------------------------------------------------------ decrypt

    /**
     * Verifies and decrypts a stream produced by {@link #encrypt} into {@code out}.
     *
     * @return number of plaintext bytes written
     * @throws VaultCryptoException CORRUPTED if the data is truncated, extended, reordered, modified, has a
     *                              bad header, was sealed under another key, or the AAD differs.
     *                              The output may then hold earlier authentic chunks; discard it.
     * @throws IOException          if reading or writing the streams fails
     */
    public static long decrypt(InputStream in, OutputStream out, byte[] mediaKey, byte[] aad)
            throws IOException, VaultCryptoException {
        if (in == null || out == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Streams required");
        }
        checkKey(mediaKey);

        byte[] header = new byte[HEADER_BYTES];
        if (readFully(in, header, 0, HEADER_BYTES) != HEADER_BYTES) {
            throw corrupted("Encrypted media is truncated (header)");
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (header[i] != MAGIC[i]) {
                throw corrupted("Not an encrypted media file");
            }
        }
        if (header[4] != VERSION) {
            throw corrupted("Unsupported media format version");
        }
        long chunkSizeLong = ((header[5] & 0xFFL) << 24) | ((header[6] & 0xFFL) << 16) | ((header[7] & 0xFFL) << 8) | (header[8] & 0xFFL);
        if (chunkSizeLong < MIN_CHUNK_SIZE || chunkSizeLong > MAX_CHUNK_SIZE) {
            throw corrupted("Invalid chunk size");
        }
        int chunkSize = (int) chunkSizeLong;
        byte[] salt = Arrays.copyOfRange(header, 9, HEADER_BYTES);

        byte[] chunkAad = concat(header, aad);
        byte[] fileKey = VaultCrypto.hkdfSha256(mediaKey, salt, FILE_KEY_INFO, VaultCrypto.KEY_BYTES);
        int sealedSize = chunkSize + TAG_BYTES;
        byte[] buf = new byte[sealedSize + 1];
        try {
            Cipher cipher = newCipher();
            SecretKeySpec keySpec = new SecretKeySpec(fileKey, "AES");

            long total = 0;
            long index = 0;
            int have = readFully(in, buf, 0, sealedSize + 1);
            while (true) {
                if (have <= sealedSize) {
                    if (have < TAG_BYTES) {
                        throw corrupted("Encrypted media is truncated");
                    }
                    byte[] plain = openChunk(cipher, keySpec, chunkAad, index, true, buf, have);
                    out.write(plain);
                    total += plain.length;
                    Arrays.fill(plain, (byte) 0);
                    return total;
                }
                byte[] plain = openChunk(cipher, keySpec, chunkAad, index, false, buf, sealedSize);
                out.write(plain);
                total += plain.length;
                Arrays.fill(plain, (byte) 0);
                index++;
                buf[0] = buf[sealedSize];
                have = 1 + readFully(in, buf, 1, sealedSize);
            }
        } finally {
            VaultCrypto.wipe(fileKey);
            Arrays.fill(buf, (byte) 0);
        }
    }

    // ------------------------------------------------------------------ internals

    private static byte[] sealChunk(Cipher cipher, SecretKeySpec key, byte[] aad, long index, boolean last,
                                    byte[] data, int length) throws VaultCryptoException {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce(index, last)));
            cipher.updateAAD(aad);
            return cipher.doFinal(data, 0, length);
        } catch (GeneralSecurityException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_PLATFORM, "AES-GCM encryption failed", e);
        }
    }

    private static byte[] openChunk(Cipher cipher, SecretKeySpec key, byte[] aad, long index, boolean last,
                                    byte[] data, int length) throws VaultCryptoException {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce(index, last)));
            cipher.updateAAD(aad);
            return cipher.doFinal(data, 0, length);
        } catch (GeneralSecurityException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED,
                    "Encrypted media failed authentication (modified, truncated, reordered or wrong key)", e);
        }
    }

    private static byte[] nonce(long index, boolean last) {
        byte[] n = new byte[VaultCrypto.NONCE_BYTES];
        for (int i = 0; i < 8; i++) {
            n[i] = (byte) (index >>> (56 - 8 * i));
        }
        n[11] = (byte) (last ? 1 : 0);
        return n;
    }

    private static byte[] buildHeader(int chunkSize, byte[] salt) {
        byte[] h = new byte[HEADER_BYTES];
        System.arraycopy(MAGIC, 0, h, 0, MAGIC.length);
        h[4] = VERSION;
        h[5] = (byte) (chunkSize >>> 24);
        h[6] = (byte) (chunkSize >>> 16);
        h[7] = (byte) (chunkSize >>> 8);
        h[8] = (byte) chunkSize;
        System.arraycopy(salt, 0, h, 9, salt.length);
        return h;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        if (b == null || b.length == 0) {
            return a.clone();
        }
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** Reads until {@code length} bytes are read or the stream ends; returns bytes read. */
    private static int readFully(InputStream in, byte[] buf, int offset, int length) throws IOException {
        int read = 0;
        while (read < length) {
            int n = in.read(buf, offset + read, length - read);
            if (n < 0) {
                break;
            }
            read += n;
        }
        return read;
    }

    private static Cipher newCipher() throws VaultCryptoException {
        try {
            return Cipher.getInstance("AES/GCM/NoPadding");
        } catch (GeneralSecurityException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_PLATFORM, "AES-GCM unavailable", e);
        }
    }

    private static void checkKey(byte[] key) throws VaultCryptoException {
        if (key == null || key.length != VaultCrypto.KEY_BYTES) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Key must be 32 bytes");
        }
    }

    private static void checkChunkSize(int chunkSize) throws VaultCryptoException {
        if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Chunk size out of range");
        }
    }

    private static VaultCryptoException corrupted(String message) {
        return new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, message);
    }
}
