package org.telegram.messenger.vault;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class VaultItemTest {

    private static final String ID = "0123456789abcdef0123456789abcdef";

    private interface Action {
        void run() throws Exception;
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

    private static VaultItem textItem(String text) {
        return new VaultItem(ID, VaultItem.Type.TEXT, 1_700_000_000_000L, 0, text, null, null, 0, 0, 0,
                null, null, null, 0, 0, 0, 0, null);
    }

    private static VaultItem fullMediaItem() {
        return new VaultItem(ID, VaultItem.Type.VIDEO, 1_700_000_123_456L, 1_699_999_000_000L,
                "caption é日本語 😀", "Alice مرحبا", "Channel Name",
                1_600_000_000_000L, -1001234567890L, 987654321L,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "holiday.mp4", "video/mp4", 5_000_000_000L, 1920, 1080, 93,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    }

    // ------------------------------------------------------------ encoding

    @Test
    public void roundTrip_textItemWithOptionalFieldsAbsent() throws Exception {
        VaultItem item = textItem("hello vault");
        VaultItem back = VaultItem.decodePadded(item.encodePadded());
        assertEquals(item, back);
        assertNull(back.senderName);
        assertNull(back.forwardedFromName);
        assertNull(back.mediaId);
        assertFalse(back.isForwarded());
    }

    @Test
    public void roundTrip_mediaItemWithEveryFieldSet() throws Exception {
        VaultItem item = fullMediaItem();
        VaultItem back = VaultItem.decodePadded(item.encodePadded());
        assertEquals(item, back);
        assertEquals(5_000_000_000L, back.mediaSize);
        assertEquals(-1001234567890L, back.sourceDialogId);
        assertTrue(back.isForwarded());
    }

    @Test
    public void roundTrip_unicodeAndExtremeText() throws Exception {
        for (String text : new String[]{
                "😀👍🏽 family 👨‍👩‍👧",
                "שלום مرحبا 你好 こんにちは",
                "line1\nline2\r\n\ttabbed\u0000with-nul",
                "x",
                repeat("a", VaultItem.MAX_TEXT_CHARS),
                repeat("日", VaultItem.MAX_TEXT_CHARS)}) {
            assertEquals(text, VaultItem.decodePadded(textItem(text).encodePadded()).text);
        }
    }

    @Test
    public void recordSizeIsPaddedToBuckets_hidingExactTextLength() throws Exception {
        // A record has roughly 140 bytes of fixed fields, so short texts share the first 256-byte bucket.
        int a = textItem("a").encodePadded().length;
        int b = textItem(repeat("b", 100)).encodePadded().length;
        int c = textItem(repeat("c", 400)).encodePadded().length;
        assertEquals(0, a % VaultItem.PAD_BLOCK);
        assertEquals("1 and 100 characters share a bucket", a, b);
        assertTrue("400 characters needs a bigger bucket", c > a);
        assertEquals(0, c % VaultItem.PAD_BLOCK);

        // Sizes only ever take multiples of 256, growing monotonically with the text.
        int previous = 0;
        java.util.Set<Integer> distinct = new java.util.HashSet<>();
        for (int len = 1; len <= 1200; len++) {
            int size = textItem(repeat("x", len)).encodePadded().length;
            assertEquals(0, size % VaultItem.PAD_BLOCK);
            assertTrue(size >= previous);
            previous = size;
            distinct.add(size);
        }
        assertTrue("1200 different lengths collapse into a handful of sizes", distinct.size() <= 6);
    }

    @Test
    public void paddingIsAllZeros_andContentDoesNotLeakIntoIt() throws Exception {
        byte[] encoded = textItem("secret words").encodePadded();
        int length = ((encoded[0] & 0xFF) << 24) | ((encoded[1] & 0xFF) << 16) | ((encoded[2] & 0xFF) << 8) | (encoded[3] & 0xFF);
        for (int i = 4 + length; i < encoded.length; i++) {
            assertEquals(0, encoded[i]);
        }
    }

    // ------------------------------------------------------------ corrupted encodings

    @Test
    public void decode_rejectsBadSizesAndLengths() throws Exception {
        byte[] good = textItem("hello").encodePadded();
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(null));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(new byte[0]));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(new byte[3]));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(new byte[256]));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(Arrays.copyOf(good, good.length - 1)));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(Arrays.copyOf(good, good.length + 1)));

        byte[] hugeLength = good.clone();
        hugeLength[0] = 0x7f;
        hugeLength[1] = (byte) 0xff;
        hugeLength[2] = (byte) 0xff;
        hugeLength[3] = (byte) 0xff;
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(hugeLength));

        byte[] negativeLength = good.clone();
        negativeLength[0] = (byte) 0x80;
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(negativeLength));

        byte[] tooShortLength = good.clone();
        tooShortLength[3] = 10; // payload cut off in the middle
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(tooShortLength));
    }

    @Test
    public void decode_rejectsNonZeroPaddingAndTrailingBytes() throws Exception {
        byte[] good = textItem("hello").encodePadded();
        byte[] dirtyPadding = good.clone();
        dirtyPadding[dirtyPadding.length - 1] = 1;
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(dirtyPadding));

        // Declared length one byte longer than the real payload: the extra (zero) byte is a trailing byte.
        byte[] trailing = good.clone();
        int len = ((trailing[0] & 0xFF) << 24) | ((trailing[1] & 0xFF) << 16) | ((trailing[2] & 0xFF) << 8) | (trailing[3] & 0xFF);
        trailing[3] = (byte) (len + 1);
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(trailing));
    }

    @Test
    public void decode_rejectsUnknownVersionTypeAndInvalidUtf8() throws Exception {
        byte[] good = textItem("AAAA").encodePadded();

        byte[] badVersion = good.clone();
        badVersion[4] = 9;
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(badVersion));

        byte[] badType = good.clone();
        badType[4 + 1 + 4 + 32] = 99; // version(1) + id string(4 + 32) precede the type byte
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(badType));

        byte[] badUtf8 = good.clone();
        int at = VaultCryptoTest.indexOf(badUtf8, "AAAA".getBytes(StandardCharsets.US_ASCII));
        badUtf8[at] = (byte) 0xC0;
        badUtf8[at + 1] = (byte) 0xC0;
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(badUtf8));
    }

    @Test
    public void decode_rejectsInconsistentMediaFields() {
        // A photo with no media id, a text item that claims media, and negative sizes can never be produced by the store.
        VaultItem photoWithoutMedia = new VaultItem(ID, VaultItem.Type.PHOTO, 1, 0, "", null, null, 0, 0, 0,
                null, null, null, 0, 0, 0, 0, null);
        VaultItem textWithMedia = new VaultItem(ID, VaultItem.Type.TEXT, 1, 0, "x", null, null, 0, 0, 0,
                ID, null, null, 0, 0, 0, 0, null);
        VaultItem negativeSize = new VaultItem(ID, VaultItem.Type.PHOTO, 1, 0, "", null, null, 0, 0, 0,
                ID, null, null, -5, 0, 0, 0, null);
        for (final VaultItem bad : new VaultItem[]{photoWithoutMedia, textWithMedia, negativeSize}) {
            assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultItem.decodePadded(bad.encodePadded()));
        }
    }

    // ------------------------------------------------------------ draft validation

    @Test
    public void draftValidation() throws Exception {
        new VaultItem.Draft(VaultItem.Type.TEXT).text("ok").validate();
        new VaultItem.Draft(VaultItem.Type.PHOTO).validate(); // caption may be empty for media

        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> new VaultItem.Draft(null).validate());
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> new VaultItem.Draft(VaultItem.Type.TEXT).validate());
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> new VaultItem.Draft(VaultItem.Type.TEXT).text(repeat("a", VaultItem.MAX_TEXT_CHARS + 1)).validate());
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> new VaultItem.Draft(VaultItem.Type.TEXT).text("x").senderName(repeat("n", VaultItem.MAX_NAME_CHARS + 1)).validate());
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> new VaultItem.Draft(VaultItem.Type.PHOTO).media(repeat("f", VaultItem.MAX_NAME_CHARS + 1), "image/jpeg", 1, 1, 0).validate());
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> new VaultItem.Draft(VaultItem.Type.PHOTO).media("a", "image/jpeg", -1, 1, 0).validate());
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> new VaultItem.Draft(VaultItem.Type.TEXT).text("x").originalDateMillis(-1).validate());
    }

    @Test
    public void textMayBeExactlyTheMaximumLength() throws Exception {
        new VaultItem.Draft(VaultItem.Type.TEXT).text(repeat("a", VaultItem.MAX_TEXT_CHARS)).validate();
    }

    // ------------------------------------------------------------ Object methods

    @Test
    public void toString_doesNotRevealContent() {
        String s = fullMediaItem().toString();
        assertFalse(s.contains("caption"));
        assertFalse(s.contains("Alice"));
        assertFalse(s.contains("holiday"));
        assertTrue(s.contains(ID));
    }

    @Test
    public void equalsAndHashCode() {
        assertEquals(fullMediaItem(), fullMediaItem());
        assertEquals(fullMediaItem().hashCode(), fullMediaItem().hashCode());
        assertFalse(fullMediaItem().equals(textItem("x")));
        assertFalse(textItem("x").equals(textItem("y")));
        assertFalse(textItem("x").equals(null));
    }

    private static String repeat(String s, int times) {
        StringBuilder sb = new StringBuilder(s.length() * times);
        for (int i = 0; i < times; i++) {
            sb.append(s);
        }
        return sb.toString();
    }
}
