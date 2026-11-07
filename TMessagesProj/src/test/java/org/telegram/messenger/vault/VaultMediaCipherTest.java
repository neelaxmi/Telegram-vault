package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

public class VaultMediaCipherTest {

    private static final byte[] KEY = sequence(32, 1, 0);
    private static final byte[] AAD = "media-aad".getBytes(StandardCharsets.US_ASCII);
    private static final int CHUNK = 16;
    private static final int HEADER = VaultMediaCipher.HEADER_BYTES;
    private static final int TAG = 16;

    // Independent reference vectors, produced by a separate Python implementation of the written format spec
    // (HKDF per-file key, nonce = index || 000000 || finalFlag, AAD = header || context).
    private static final String KAT_40_BYTES_THREE_CHUNKS =
            "5447564d0100000010a0a1a2a3a4a5a6a7a8a9aaabacadaeaf188937636ce693477351fcc30f43c680b4fcaf6329c058f68aa4294e3648059"
                    + "b7afc2190ff81af2a91c01fa7ef10337bc192e5554761d9b5a9b45cb9763c6468dc768e4d074d00e48afd1c64e8cc397c1706e7f603712a09";
    private static final String KAT_EMPTY =
            "5447564d0100000010a0a1a2a3a4a5a6a7a8a9aaabacadaeaf0ec96e7cc045628406200ae9db32c690";
    private static final String KAT_32_BYTES_TWO_FULL_CHUNKS =
            "5447564d0100000010a0a1a2a3a4a5a6a7a8a9aaabacadaeaf1a852d6b66daa157613d86ab655fe4a0ff16eb1d6c17e483c29837c53d8fcf2d"
                    + "1581cd11e329dec27be686adf4cbee72cb87fdd42184063666b4a03456988903";

    // ------------------------------------------------------------ helpers

    static byte[] sequence(int n, int mul, int add) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) (i * mul + add);
        }
        return b;
    }

    private static byte[] salt() {
        return sequence(16, 1, 0xa0);
    }

    private static byte[] enc(byte[] plain, int chunk) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        long n = VaultMediaCipher.encrypt(new ByteArrayInputStream(plain), out, KEY, AAD, chunk);
        assertEquals(plain.length, n);
        return out.toByteArray();
    }

    private static byte[] dec(byte[] sealed) throws Exception {
        return dec(sealed, KEY, AAD);
    }

    private static byte[] dec(byte[] sealed, byte[] key, byte[] aad) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        VaultMediaCipher.decrypt(new ByteArrayInputStream(sealed), out, key, aad);
        return out.toByteArray();
    }

    private interface Action {
        void run() throws Exception;
    }

    private static void assertCorrupted(String what, Action a) {
        try {
            a.run();
            fail(what + ": expected CORRUPTED but it was accepted");
        } catch (VaultCryptoException e) {
            assertEquals(what, VaultCryptoException.Reason.CORRUPTED, e.getReason());
        } catch (Exception e) {
            fail(what + ": unexpected " + e);
        }
    }

    private static void assertReason(VaultCryptoException.Reason reason, Action a) {
        try {
            a.run();
            fail("expected " + reason);
        } catch (VaultCryptoException e) {
            assertEquals(reason, e.getReason());
        } catch (Exception e) {
            fail("unexpected " + e);
        }
    }

    private static int expectedLength(int plainLength, int chunk) {
        int chunks = Math.max(1, (plainLength + chunk - 1) / chunk);
        return HEADER + plainLength + TAG * chunks;
    }

    // ------------------------------------------------------------ known-answer vectors

    @Test
    public void format_matchesIndependentReference_threeChunks() throws Exception {
        byte[] plain = sequence(40, 7, 3);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        VaultMediaCipher.encryptWithSalt(new ByteArrayInputStream(plain), out, KEY, AAD, CHUNK, salt());
        assertEquals(KAT_40_BYTES_THREE_CHUNKS, VaultCryptoTest.toHex(out.toByteArray()));
        assertArrayEquals(plain, dec(VaultCryptoTest.hex(KAT_40_BYTES_THREE_CHUNKS)));
    }

    @Test
    public void format_matchesIndependentReference_emptyFile() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        VaultMediaCipher.encryptWithSalt(new ByteArrayInputStream(new byte[0]), out, KEY, AAD, CHUNK, salt());
        assertEquals(KAT_EMPTY, VaultCryptoTest.toHex(out.toByteArray()));
        assertEquals(0, dec(VaultCryptoTest.hex(KAT_EMPTY)).length);
    }

    @Test
    public void format_matchesIndependentReference_exactMultipleOfChunkSize() throws Exception {
        // 32 bytes = exactly two full chunks: the second must be the one flagged final, with no extra empty chunk.
        byte[] plain = sequence(32, 5, 1);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        VaultMediaCipher.encryptWithSalt(new ByteArrayInputStream(plain), out, KEY, AAD, CHUNK, salt());
        assertEquals(KAT_32_BYTES_TWO_FULL_CHUNKS, VaultCryptoTest.toHex(out.toByteArray()));
        assertArrayEquals(plain, dec(VaultCryptoTest.hex(KAT_32_BYTES_TWO_FULL_CHUNKS)));
    }

    // ------------------------------------------------------------ round trips

    @Test
    public void roundTrip_aroundChunkBoundaries() throws Exception {
        int[] sizes = {0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 4095, 4096, 4097, 8192, 10_000};
        for (int chunk : new int[]{CHUNK, 4096}) {
            for (int size : sizes) {
                byte[] plain = VaultCrypto.randomBytes(size);
                byte[] sealed = enc(plain, chunk);
                assertEquals("length for size " + size + " chunk " + chunk, expectedLength(size, chunk), sealed.length);
                assertArrayEquals("size " + size + " chunk " + chunk, plain, dec(sealed));
            }
        }
    }

    @Test
    public void roundTrip_largeFileWithDefaultChunkSize() throws Exception {
        byte[] plain = VaultCrypto.randomBytes(8 * 1024 * 1024 + 123);
        byte[] sealed = enc(plain, VaultMediaCipher.DEFAULT_CHUNK_SIZE);
        assertEquals(expectedLength(plain.length, VaultMediaCipher.DEFAULT_CHUNK_SIZE), sealed.length);
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(plain),
                MessageDigest.getInstance("SHA-256").digest(dec(sealed)));
    }

    @Test
    public void roundTrip_withSlowStreamsReturningOneByteAtATime() throws Exception {
        byte[] plain = VaultCrypto.randomBytes(100);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        VaultMediaCipher.encrypt(new OneByteInputStream(plain), out, KEY, AAD, CHUNK);
        byte[] sealed = out.toByteArray();
        assertEquals(expectedLength(100, CHUNK), sealed.length);

        ByteArrayOutputStream back = new ByteArrayOutputStream();
        VaultMediaCipher.decrypt(new OneByteInputStream(sealed), back, KEY, AAD);
        assertArrayEquals(plain, back.toByteArray());
    }

    @Test
    public void emptyFile_isHeaderPlusOneEmptyFinalChunk() throws Exception {
        byte[] sealed = enc(new byte[0], CHUNK);
        assertEquals(HEADER + TAG, sealed.length);
        assertEquals(0, dec(sealed).length);
    }

    @Test
    public void encryptionIsRandomised_andNeverContainsPlaintext() throws Exception {
        byte[] marker = "PLAINTEXT-MARKER-0123456789".getBytes(StandardCharsets.US_ASCII);
        byte[] plain = new byte[marker.length * 200];
        for (int i = 0; i < 200; i++) {
            System.arraycopy(marker, 0, plain, i * marker.length, marker.length);
        }
        byte[] a = enc(plain, 256);
        byte[] b = enc(plain, 256);
        assertFalse(Arrays.equals(a, b));
        assertFalse("salts must differ",
                Arrays.equals(Arrays.copyOfRange(a, 9, HEADER), Arrays.copyOfRange(b, 9, HEADER)));
        assertEquals(-1, VaultCryptoTest.indexOf(a, marker));
        assertEquals(-1, VaultCryptoTest.indexOf(a, Arrays.copyOf(marker, 8)));
    }

    // ------------------------------------------------------------ tampering

    @Test
    public void everySingleBitFlipAtEveryByte_isDetected() throws Exception {
        byte[] sealed = enc(sequence(40, 7, 3), CHUNK);
        for (int mask : new int[]{0x01, 0x80}) {
            for (int i = 0; i < sealed.length; i++) {
                final byte[] t = sealed.clone();
                t[i] ^= (byte) mask;
                assertCorrupted("flip 0x" + Integer.toHexString(mask) + " at byte " + i, () -> dec(t));
            }
        }
        assertEquals(40, dec(sealed).length); // the untouched file still works
    }

    @Test
    public void everyTruncationLength_isDetected_includingChunkBoundaries() throws Exception {
        for (int plainSize : new int[]{40, 32, 0, 1}) {
            byte[] sealed = enc(sequence(plainSize, 7, 3), CHUNK);
            for (int len = 0; len < sealed.length; len++) {
                final byte[] t = Arrays.copyOf(sealed, len);
                assertCorrupted("plain " + plainSize + " truncated to " + len, () -> dec(t));
            }
        }
    }

    @Test
    public void appendedDataIsDetected() throws Exception {
        byte[] sealed = enc(sequence(40, 7, 3), CHUNK);
        for (int extra : new int[]{1, 15, 16, 17, 32, 48}) {
            final byte[] t = Arrays.copyOf(sealed, sealed.length + extra);
            assertCorrupted("appended zeros x" + extra, () -> dec(t));
        }
        // Appending a copy of an authentic chunk (a "duplicate last chunk" attack).
        byte[] lastChunk = Arrays.copyOfRange(sealed, sealed.length - 24, sealed.length);
        final byte[] dup = VaultCryptoTest.concat(sealed, lastChunk);
        assertCorrupted("duplicated final chunk appended", () -> dec(dup));
        // Appending a whole extra full-size chunk.
        final byte[] extraChunk = VaultCryptoTest.concat(sealed, Arrays.copyOfRange(sealed, HEADER, HEADER + 32));
        assertCorrupted("extra full chunk appended", () -> dec(extraChunk));
    }

    @Test
    public void reorderedDuplicatedOrRemovedChunks_areDetected() throws Exception {
        // 4 full chunks plus a short final one: sealed chunk size is 32, final is 8 + 16.
        byte[] sealed = enc(sequence(72, 3, 9), CHUNK);
        byte[] header = Arrays.copyOf(sealed, HEADER);
        byte[][] chunks = new byte[5][];
        for (int i = 0; i < 4; i++) {
            chunks[i] = Arrays.copyOfRange(sealed, HEADER + 32 * i, HEADER + 32 * (i + 1));
        }
        chunks[4] = Arrays.copyOfRange(sealed, HEADER + 128, sealed.length);
        assertEquals(24, chunks[4].length);

        assertCorrupted("swap chunks 0 and 1", () -> dec(join(header, chunks[1], chunks[0], chunks[2], chunks[3], chunks[4])));
        assertCorrupted("swap chunks 2 and 3", () -> dec(join(header, chunks[0], chunks[1], chunks[3], chunks[2], chunks[4])));
        assertCorrupted("duplicate chunk 1 over 2", () -> dec(join(header, chunks[0], chunks[1], chunks[1], chunks[3], chunks[4])));
        assertCorrupted("remove middle chunk", () -> dec(join(header, chunks[0], chunks[1], chunks[3], chunks[4])));
        assertCorrupted("remove first chunk", () -> dec(join(header, chunks[1], chunks[2], chunks[3], chunks[4])));
        assertCorrupted("remove final chunk", () -> dec(join(header, chunks[0], chunks[1], chunks[2], chunks[3])));
        assertCorrupted("final chunk moved into the middle", () -> dec(join(header, chunks[0], chunks[4], chunks[2], chunks[3])));
        assertArrayEquals(sequence(72, 3, 9), dec(join(header, chunks[0], chunks[1], chunks[2], chunks[3], chunks[4])));
    }

    @Test
    public void chunkSplicedFromAnotherFile_isDetected() throws Exception {
        byte[] plain = sequence(48, 3, 9);
        byte[] a = enc(plain, CHUNK);
        byte[] b = enc(plain, CHUNK); // identical plaintext, key and context, different random salt
        byte[] spliced = a.clone();
        System.arraycopy(b, HEADER + 32, spliced, HEADER + 32, 32);
        assertCorrupted("chunk 1 taken from another file", () -> dec(spliced));
        // Header of one file with the body of the other.
        byte[] frankenstein = VaultCryptoTest.concat(Arrays.copyOf(a, HEADER), Arrays.copyOfRange(b, HEADER, b.length));
        assertCorrupted("header from file A, body from file B", () -> dec(frankenstein));
    }

    @Test
    public void wrongKeyOrWrongContext_isRejected() throws Exception {
        byte[] sealed = enc(sequence(40, 7, 3), CHUNK);
        assertCorrupted("wrong key", () -> dec(sealed, VaultCrypto.randomBytes(32), AAD));
        assertCorrupted("wrong aad", () -> dec(sealed, KEY, "other-id".getBytes(StandardCharsets.US_ASCII)));
        assertCorrupted("missing aad", () -> dec(sealed, KEY, null));
        assertCorrupted("empty aad", () -> dec(sealed, KEY, new byte[0]));
        byte[] flippedKey = KEY.clone();
        flippedKey[31] ^= 1;
        assertCorrupted("key off by one bit", () -> dec(sealed, flippedKey, AAD));
    }

    @Test
    public void malformedHeaders_areRejectedWithoutHugeAllocations() throws Exception {
        byte[] sealed = enc(sequence(40, 7, 3), CHUNK);
        long start = System.nanoTime();

        byte[] badMagic = sealed.clone();
        badMagic[0] = 'X';
        assertCorrupted("bad magic", () -> dec(badMagic));

        byte[] badVersion = sealed.clone();
        badVersion[4] = 2;
        assertCorrupted("version 2", () -> dec(badVersion));
        badVersion[4] = 0;
        assertCorrupted("version 0", () -> dec(badVersion));

        for (long size : new long[]{0, 1, 15, VaultMediaCipher.MAX_CHUNK_SIZE + 1L, 0x7fffffffL, 0x80000000L, 0xffffffffL}) {
            final byte[] h = sealed.clone();
            h[5] = (byte) (size >>> 24);
            h[6] = (byte) (size >>> 16);
            h[7] = (byte) (size >>> 8);
            h[8] = (byte) size;
            assertCorrupted("chunk size " + size, () -> dec(h));
        }
        assertTrue("rejections must be immediate", System.nanoTime() - start < 5_000_000_000L);
    }

    @Test
    public void garbageInput_isRejected() throws Exception {
        assertCorrupted("empty", () -> dec(new byte[0]));
        assertCorrupted("random 1 KiB", () -> dec(VaultCrypto.randomBytes(1024)));
        assertCorrupted("zeros", () -> dec(new byte[500]));
    }

    @Test
    public void failureMidFile_leavesOnlyAuthenticPrefixInTheOutput() throws Exception {
        byte[] plain = sequence(80, 3, 9); // 5 chunks of 16
        byte[] sealed = enc(plain, CHUNK);
        sealed[HEADER + 32 * 3 + 5] ^= 1; // damage the 4th chunk
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            VaultMediaCipher.decrypt(new ByteArrayInputStream(sealed), out, KEY, AAD);
            fail("expected CORRUPTED");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.CORRUPTED, e.getReason());
        }
        byte[] partial = out.toByteArray();
        assertEquals("only chunks verified before the damage were released", 48, partial.length);
        assertArrayEquals(Arrays.copyOf(plain, 48), partial);
    }

    // ------------------------------------------------------------ I/O and arguments

    @Test
    public void ioErrorsPropagateAsIoExceptions_notAsCryptoErrors() throws Exception {
        byte[] sealed = enc(sequence(100, 3, 9), CHUNK);
        try {
            VaultMediaCipher.encrypt(new FailingInputStream(40), new ByteArrayOutputStream(), KEY, AAD, CHUNK);
            fail();
        } catch (IOException expected) {
            // ok
        }
        try {
            VaultMediaCipher.decrypt(new FailingInputStream2(sealed, 60), new ByteArrayOutputStream(), KEY, AAD);
            fail();
        } catch (IOException expected) {
            // ok
        }
        try {
            VaultMediaCipher.encrypt(new ByteArrayInputStream(new byte[100]), new FailingOutputStream(), KEY, AAD, CHUNK);
            fail();
        } catch (IOException expected) {
            // ok
        }
        try {
            VaultMediaCipher.decrypt(new ByteArrayInputStream(sealed), new FailingOutputStream(), KEY, AAD);
            fail();
        } catch (IOException expected) {
            // ok
        }
    }

    @Test
    public void streamsAreNotClosed() throws Exception {
        final boolean[] closed = new boolean[2];
        InputStream in = new ByteArrayInputStream(new byte[50]) {
            @Override
            public void close() throws IOException {
                closed[0] = true;
                super.close();
            }
        };
        OutputStream out = new ByteArrayOutputStream() {
            @Override
            public void close() throws IOException {
                closed[1] = true;
                super.close();
            }
        };
        VaultMediaCipher.encrypt(in, out, KEY, AAD, CHUNK);
        assertFalse(closed[0]);
        assertFalse(closed[1]);
    }

    @Test
    public void invalidArguments_areRejected() {
        final ByteArrayInputStream in = new ByteArrayInputStream(new byte[10]);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultMediaCipher.encrypt(null, out, KEY, AAD, CHUNK));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultMediaCipher.encrypt(in, null, KEY, AAD, CHUNK));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultMediaCipher.encrypt(in, out, null, AAD, CHUNK));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultMediaCipher.encrypt(in, out, new byte[31], AAD, CHUNK));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultMediaCipher.encrypt(in, out, KEY, AAD, 15));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> VaultMediaCipher.encrypt(in, out, KEY, AAD, VaultMediaCipher.MAX_CHUNK_SIZE + 1));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> VaultMediaCipher.encryptWithSalt(in, out, KEY, AAD, CHUNK, new byte[15]));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultMediaCipher.decrypt(null, out, KEY, AAD));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultMediaCipher.decrypt(in, null, KEY, AAD));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultMediaCipher.decrypt(in, out, new byte[16], AAD));
    }

    // ------------------------------------------------------------ test streams and utilities

    private static byte[] join(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.write(p, 0, p.length);
        }
        return out.toByteArray();
    }

    private static class OneByteInputStream extends InputStream {
        private final byte[] data;
        private int pos;

        OneByteInputStream(byte[] data) {
            this.data = data;
        }

        @Override
        public int read() {
            return pos < data.length ? data[pos++] & 0xFF : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            if (len == 0) {
                return 0;
            }
            int c = read();
            if (c < 0) {
                return -1;
            }
            b[off] = (byte) c;
            return 1;
        }
    }

    private static class FailingInputStream extends InputStream {
        private int remaining;

        FailingInputStream(int bytesBeforeFailure) {
            remaining = bytesBeforeFailure;
        }

        @Override
        public int read() throws IOException {
            if (remaining-- <= 0) {
                throw new IOException("disk read error");
            }
            return 7;
        }
    }

    private static class FailingInputStream2 extends InputStream {
        private final byte[] data;
        private final int failAt;
        private int pos;

        FailingInputStream2(byte[] data, int failAt) {
            this.data = data;
            this.failAt = failAt;
        }

        @Override
        public int read() throws IOException {
            if (pos >= failAt) {
                throw new IOException("disk read error");
            }
            return data[pos++] & 0xFF;
        }
    }

    private static class FailingOutputStream extends OutputStream {
        @Override
        public void write(int b) throws IOException {
            throw new IOException("disk full");
        }
    }
}
