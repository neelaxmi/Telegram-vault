package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class VaultCryptoTest {

    // ------------------------------------------------------------ helpers

    static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] filled(int len, int value) {
        byte[] b = new byte[len];
        Arrays.fill(b, (byte) value);
        return b;
    }

    private static void assertReason(VaultCryptoException.Reason expected, ThrowingRunnable r) {
        try {
            r.run();
            fail("Expected VaultCryptoException(" + expected + ")");
        } catch (VaultCryptoException e) {
            assertEquals(expected, e.getReason());
        }
    }

    private interface ThrowingRunnable {
        void run() throws VaultCryptoException;
    }

    // ------------------------------------------------------------ PBKDF2

    @Test
    public void pbkdf2_rfcVectors() throws Exception {
        // Reference values computed independently with Python hashlib.pbkdf2_hmac;
        // the "passwd"/"salt" one is also RFC 7914 section 11.
        assertEquals("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
                toHex(VaultCrypto.pbkdf2HmacSha256(ascii("password"), ascii("salt"), 1, 32)));
        assertEquals("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
                toHex(VaultCrypto.pbkdf2HmacSha256(ascii("password"), ascii("salt"), 2, 32)));
        assertEquals("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
                toHex(VaultCrypto.pbkdf2HmacSha256(ascii("password"), ascii("salt"), 4096, 32)));
    }

    @Test
    public void pbkdf2_multiBlockOutput() throws Exception {
        // 64 bytes = two HMAC blocks; RFC 7914 test vector.
        assertEquals("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
                        + "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
                toHex(VaultCrypto.pbkdf2HmacSha256(ascii("passwd"), ascii("salt"), 1, 64)));
    }

    @Test
    public void deriveKey_unicodePassword_matchesIndependentImplementation() throws Exception {
        char[] password = "pässwörd-日本".toCharArray();
        byte[] salt = hex("000102030405060708090a0b0c0d0e0f");
        assertEquals("ad57f2336b6d813f6133cf3eaf9d5436f77ba49d08e0aadb756194b39c0271c4",
                toHex(VaultCrypto.deriveKey(password, salt, 1000)));
    }

    @Test
    public void deriveKey_normalisesUnicode() throws Exception {
        byte[] salt = filled(16, 7);
        byte[] composed = VaultCrypto.deriveKey("café-passw0rd".toCharArray(), salt, 1000);
        byte[] decomposed = VaultCrypto.deriveKey("café-passw0rd".toCharArray(), salt, 1000);
        assertArrayEquals(composed, decomposed);

        // NFKC also folds full-width letters to ASCII.
        byte[] ascii = VaultCrypto.deriveKey("ABCDEFGH".toCharArray(), salt, 1000);
        byte[] fullWidth = VaultCrypto.deriveKey(
                "ＡＢＣＤＥＦＧＨ".toCharArray(), salt, 1000);
        assertArrayEquals(ascii, fullWidth);
    }

    @Test
    public void deriveKey_isCaseSensitiveAndSaltSensitive() throws Exception {
        byte[] salt1 = filled(16, 1);
        byte[] salt2 = filled(16, 2);
        byte[] a = VaultCrypto.deriveKey("Password123".toCharArray(), salt1, 1000);
        assertFalse(Arrays.equals(a, VaultCrypto.deriveKey("password123".toCharArray(), salt1, 1000)));
        assertFalse(Arrays.equals(a, VaultCrypto.deriveKey("Password123".toCharArray(), salt2, 1000)));
        assertFalse(Arrays.equals(a, VaultCrypto.deriveKey("Password123".toCharArray(), salt1, 1001)));
        assertEquals(VaultCrypto.KEY_BYTES, a.length);
    }

    @Test
    public void deriveKey_doesNotModifyOrRetainCallersPassword() throws Exception {
        char[] password = "correct horse battery".toCharArray();
        char[] copy = password.clone();
        VaultCrypto.deriveKey(password, filled(16, 3), 1000);
        assertArrayEquals(copy, password);
    }

    @Test
    public void deriveKey_rejectsBadArguments() {
        final byte[] salt = filled(16, 1);
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.deriveKey(null, salt, 1000));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.deriveKey(new char[0], salt, 1000));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.deriveKey("x".toCharArray(), null, 1000));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.deriveKey("x".toCharArray(), filled(15, 1), 1000));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.deriveKey("x".toCharArray(), filled(17, 1), 1000));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.deriveKey("x".toCharArray(), salt, 0));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.deriveKey("x".toCharArray(), salt, -5));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> VaultCrypto.deriveKey("x".toCharArray(), salt, VaultCrypto.MAX_PBKDF2_ITERATIONS + 1));
    }

    @Test
    public void defaultIterationCount_meetsCurrentOwaspMinimum() {
        assertTrue(VaultCrypto.DEFAULT_PBKDF2_ITERATIONS >= 600_000);
    }

    // ------------------------------------------------------------ HKDF

    @Test
    public void hkdf_rfc5869_testCase1() throws Exception {
        byte[] okm = VaultCrypto.hkdfSha256(
                filled(22, 0x0b),
                hex("000102030405060708090a0b0c"),
                hex("f0f1f2f3f4f5f6f7f8f9"),
                42);
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                toHex(okm));
    }

    @Test
    public void hkdf_rfc5869_testCase3_emptySaltAndInfo() throws Exception {
        byte[] okm = VaultCrypto.hkdfSha256(filled(22, 0x0b), new byte[0], new byte[0], 42);
        assertEquals("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
                toHex(okm));
    }

    @Test
    public void hkdf_rejectsBadLength() {
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> VaultCrypto.hkdfSha256(filled(32, 1), new byte[0], new byte[0], 0));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> VaultCrypto.hkdfSha256(filled(32, 1), new byte[0], new byte[0], 255 * 32 + 1));
    }

    @Test
    public void deriveSubkey_isDeterministicAndSeparatedByPurposeAndMasterKey() throws Exception {
        byte[] master = filled(32, 9);
        byte[] messages1 = VaultCrypto.deriveSubkey(master, "messages");
        byte[] messages2 = VaultCrypto.deriveSubkey(master, "messages");
        byte[] media = VaultCrypto.deriveSubkey(master, "media");
        byte[] otherMaster = VaultCrypto.deriveSubkey(filled(32, 10), "messages");

        assertArrayEquals(messages1, messages2);
        assertFalse(Arrays.equals(messages1, media));
        assertFalse(Arrays.equals(messages1, otherMaster));
        assertFalse(Arrays.equals(messages1, master));
        assertEquals(32, messages1.length);
    }

    @Test
    public void deriveSubkey_rejectsBadArguments() {
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.deriveSubkey(filled(31, 1), "x"));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.deriveSubkey(null, "x"));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.deriveSubkey(filled(32, 1), ""));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.deriveSubkey(filled(32, 1), null));
    }

    // ------------------------------------------------------------ AES-GCM

    @Test
    public void aesGcm_knownAnswer_noAad() throws Exception {
        // AES-256-GCM: key = 0^256, nonce = 0^96, plaintext = 0^128 (NIST GCM spec test case 14);
        // value cross-checked with Python 'cryptography'.
        byte[] blob = VaultCrypto.encryptWithNonce(new byte[32], new byte[12], new byte[16], null);
        assertEquals("000000000000000000000000"
                        + "cea7403d4d606b6e074ec5d3baf39d18"
                        + "d0d1c8a799996bf0265b98b5d48ab919",
                toHex(blob));
    }

    @Test
    public void aesGcm_knownAnswer_withAad() throws Exception {
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) i;
        }
        byte[] nonce = hex("101112131415161718191a1b");
        byte[] plaintext = concat(ascii("vault test plaintext "), new byte[]{0, 1, 2});
        byte[] blob = VaultCrypto.encryptWithNonce(key, nonce, plaintext, ascii("tg-vault-aad"));
        assertEquals("101112131415161718191a1b"
                        + "0b9fed7a3de94ed6b901286d6318003da335367a3bc256b3db6a2b0ad2681e9a76a152fc36d4b658",
                toHex(blob));
        assertArrayEquals(plaintext, VaultCrypto.decrypt(key, blob, ascii("tg-vault-aad")));
    }

    @Test
    public void aesGcm_roundTrip_variousSizes() throws Exception {
        byte[] key = VaultCrypto.randomBytes(32);
        byte[] aad = ascii("context");
        for (int size : new int[]{0, 1, 15, 16, 17, 255, 4096, 1_000_000}) {
            byte[] plaintext = VaultCrypto.randomBytes(size);
            byte[] blob = VaultCrypto.encrypt(key, plaintext, aad);
            assertEquals(size + VaultCrypto.NONCE_BYTES + VaultCrypto.TAG_BYTES, blob.length);
            assertArrayEquals("size " + size, plaintext, VaultCrypto.decrypt(key, blob, aad));
        }
    }

    @Test
    public void aesGcm_nullAadAndEmptyAadAreEquivalent() throws Exception {
        byte[] key = VaultCrypto.randomBytes(32);
        byte[] blob = VaultCrypto.encrypt(key, ascii("hello"), null);
        assertArrayEquals(ascii("hello"), VaultCrypto.decrypt(key, blob, new byte[0]));
    }

    @Test
    public void aesGcm_ciphertextDoesNotContainPlaintext() throws Exception {
        byte[] key = VaultCrypto.randomBytes(32);
        byte[] plaintext = ascii("TOP-SECRET-VAULT-MESSAGE-0123456789");
        byte[] blob = VaultCrypto.encrypt(key, plaintext, null);
        assertEquals(-1, indexOf(blob, plaintext));
    }

    @Test
    public void aesGcm_freshNonceEveryTime() throws Exception {
        byte[] key = VaultCrypto.randomBytes(32);
        byte[] plaintext = ascii("same message");
        Set<String> nonces = new HashSet<>();
        Set<String> blobs = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            byte[] blob = VaultCrypto.encrypt(key, plaintext, null);
            nonces.add(toHex(Arrays.copyOf(blob, VaultCrypto.NONCE_BYTES)));
            blobs.add(toHex(blob));
        }
        assertEquals(500, nonces.size());
        assertEquals(500, blobs.size());
    }

    @Test
    public void aesGcm_everySingleByteModificationIsDetected() throws Exception {
        byte[] key = VaultCrypto.randomBytes(32);
        byte[] aad = ascii("aad");
        byte[] blob = VaultCrypto.encrypt(key, ascii("authentic message"), aad);
        for (int i = 0; i < blob.length; i++) {
            final byte[] tampered = blob.clone();
            tampered[i] ^= 0x01;
            assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultCrypto.decrypt(key, tampered, aad));
        }
    }

    @Test
    public void aesGcm_truncationAndExtensionAreDetected() throws Exception {
        final byte[] key = VaultCrypto.randomBytes(32);
        final byte[] blob = VaultCrypto.encrypt(key, ascii("authentic message"), null);
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultCrypto.decrypt(key, Arrays.copyOf(blob, blob.length - 1), null));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultCrypto.decrypt(key, Arrays.copyOf(blob, blob.length + 1), null));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultCrypto.decrypt(key, new byte[0], null));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultCrypto.decrypt(key, new byte[27], null));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultCrypto.decrypt(key, null, null));
    }

    @Test
    public void aesGcm_wrongKeyAndWrongAadAreRejected() throws Exception {
        final byte[] key = VaultCrypto.randomBytes(32);
        final byte[] blob = VaultCrypto.encrypt(key, ascii("secret"), ascii("record-1"));
        assertReason(VaultCryptoException.Reason.CORRUPTED,
                () -> VaultCrypto.decrypt(VaultCrypto.randomBytes(32), blob, ascii("record-1")));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultCrypto.decrypt(key, blob, ascii("record-2")));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultCrypto.decrypt(key, blob, null));
    }

    @Test
    public void aesGcm_rejectsBadKeyAndInputs() {
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.encrypt(null, ascii("x"), null));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.encrypt(new byte[16], ascii("x"), null));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.encrypt(new byte[32], null, null));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultCrypto.decrypt(new byte[31], new byte[64], null));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> VaultCrypto.encryptWithNonce(new byte[32], new byte[11], ascii("x"), null));
    }

    // ------------------------------------------------------------ misc

    @Test
    public void randomBytes_areDistinctAndRequestedLength() {
        byte[] a = VaultCrypto.randomBytes(32);
        byte[] b = VaultCrypto.randomBytes(32);
        assertEquals(32, a.length);
        assertNotEquals(toHex(a), toHex(b));
        assertEquals(0, VaultCrypto.randomBytes(0).length);
    }

    @Test
    public void wipe_zeroesArrays_andToleratesNull() {
        byte[] bytes = {1, 2, 3};
        char[] chars = {'a', 'b'};
        VaultCrypto.wipe(bytes);
        VaultCrypto.wipe(chars);
        VaultCrypto.wipe((byte[]) null);
        VaultCrypto.wipe((char[]) null);
        assertArrayEquals(new byte[3], bytes);
        assertArrayEquals(new char[2], chars);
    }

    @Test
    public void constantTimeEquals_behavesLikeEquals() {
        assertTrue(VaultCrypto.constantTimeEquals(new byte[]{1, 2}, new byte[]{1, 2}));
        assertFalse(VaultCrypto.constantTimeEquals(new byte[]{1, 2}, new byte[]{1, 3}));
        assertFalse(VaultCrypto.constantTimeEquals(new byte[]{1, 2}, new byte[]{1}));
        assertFalse(VaultCrypto.constantTimeEquals(null, new byte[]{1}));
        assertFalse(VaultCrypto.constantTimeEquals(new byte[]{1}, null));
    }

    // ------------------------------------------------------------ utilities

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
