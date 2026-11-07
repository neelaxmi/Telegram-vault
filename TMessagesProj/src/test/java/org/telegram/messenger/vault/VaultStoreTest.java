package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

public class VaultStoreTest {

    private static final String PASSWORD = "correct horse battery staple";
    private static final int CHUNK = 4096;

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private InMemoryHeaderStore headers;
    private TestDeviceKeyWrapper device;
    private VaultKeyManager manager;
    private File root;
    private long now;
    private VaultStore store;

    @Before
    public void setUp() throws Exception {
        headers = new InMemoryHeaderStore();
        device = new TestDeviceKeyWrapper();
        manager = new VaultKeyManager(headers, device, 1000);
        manager.createVault(PASSWORD.toCharArray(), PASSWORD.toCharArray());
        root = new File(tmp.getRoot(), "vault");
        now = 1_000_000L;
        store = newStore(root, manager);
    }

    private VaultStore newStore(File dir, VaultKeyManager m) {
        return new VaultStore(dir, m, new VaultStore.Clock() {
            @Override
            public long nowMillis() {
                now += 1000;
                return now;
            }
        }, CHUNK);
    }

    // ------------------------------------------------------------ helpers

    private interface Action {
        void run() throws Exception;
    }

    private static VaultCryptoException expect(VaultCryptoException.Reason reason, Action a) {
        try {
            a.run();
        } catch (VaultCryptoException e) {
            assertEquals(reason, e.getReason());
            return e;
        } catch (Exception e) {
            fail("expected " + reason + " but got " + e);
        }
        fail("expected " + reason + " but nothing was thrown");
        return null;
    }

    private static void expectCorrupted(String what, Action a) {
        try {
            a.run();
        } catch (VaultCryptoException e) {
            assertEquals(what, VaultCryptoException.Reason.CORRUPTED, e.getReason());
            return;
        } catch (Exception e) {
            fail(what + ": unexpected " + e);
        }
        fail(what + ": accepted but should be CORRUPTED");
    }

    private VaultItem addText(String text) throws Exception {
        return store.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text(text), null, null);
    }

    private VaultItem addMedia(VaultItem.Type type, String name, String mime, String caption, byte[] media, byte[] thumb) throws Exception {
        VaultItem.Draft d = new VaultItem.Draft(type).text(caption).media(name, mime, 640, 480, type == VaultItem.Type.VIDEO ? 12 : 0);
        return store.addItem(d, new ByteArrayInputStream(media), thumb);
    }

    private byte[] readMedia(String itemId) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        store.readMedia(itemId, out);
        return out.toByteArray();
    }

    private File recordFile(String id) {
        return new File(root, "items/" + id + ".vrec");
    }

    private File mediaFile(String id) {
        return new File(root, "media/" + id + ".vmed");
    }

    private static byte[] read(File f) throws IOException {
        return Files.readAllBytes(f.toPath());
    }

    private static void write(File f, byte[] data) throws IOException {
        Files.write(f.toPath(), data);
    }

    private static List<File> allFiles(File dir) {
        List<File> out = new ArrayList<>();
        File[] children = dir.listFiles();
        if (children != null) {
            for (File c : children) {
                if (c.isDirectory()) {
                    out.addAll(allFiles(c));
                } else {
                    out.add(c);
                }
            }
        }
        return out;
    }

    /** Sorted "relative path:size:hash" for every file, to detect any change at all. */
    private List<String> fileSnapshot() throws Exception {
        List<String> out = new ArrayList<>();
        for (File f : allFiles(root)) {
            out.add(root.toURI().relativize(f.toURI()).getPath() + ":" + f.length() + ":"
                    + VaultCryptoTest.toHex(MessageDigest.getInstance("SHA-256").digest(read(f))));
        }
        java.util.Collections.sort(out);
        return out;
    }

    private static String repeat(String s, int times) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < times; i++) {
            sb.append(s);
        }
        return sb.toString();
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------ text items and metadata

    @Test
    public void textItem_roundTrips_andStoresTheCreationTime() throws Exception {
        VaultItem item = addText("remember the milk");
        assertTrue(VaultStore.isValidId(item.id));
        assertEquals(VaultItem.Type.TEXT, item.type);
        assertEquals(1_001_000L, item.createdAtMillis);
        assertNull(item.mediaId);

        VaultItem back = store.get(item.id);
        assertEquals(item, back);
        assertEquals("remember the milk", back.text);
        assertEquals(1, store.count());
    }

    @Test
    public void forwardedMessageInformation_andSourceIdsAreKept() throws Exception {
        VaultItem item = store.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("fwd")
                .originalDateMillis(1_650_000_000_000L).senderName("Alice")
                .forwardedFrom("Daily News", 1_640_000_000_000L).source(-100123456L, 777L), null, null);
        VaultItem back = store.get(item.id);
        assertEquals("Alice", back.senderName);
        assertEquals("Daily News", back.forwardedFromName);
        assertEquals(1_640_000_000_000L, back.forwardedDateMillis);
        assertEquals(1_650_000_000_000L, back.originalDateMillis);
        assertEquals(-100123456L, back.sourceDialogId);
        assertEquals(777L, back.sourceMessageId);
        assertTrue(back.isForwarded());
    }

    @Test
    public void get_unknownId_returnsNull() throws Exception {
        assertNull(store.get("0123456789abcdef0123456789abcdef"));
        addText("x");
        assertNull(store.get("ffffffffffffffffffffffffffffffff"));
    }

    @Test
    public void list_isOrderedOldestFirst() throws Exception {
        VaultItem a = addText("first");
        VaultItem b = addText("second");
        VaultItem c = addText("third");
        VaultStore.Listing listing = store.list();
        assertEquals(Arrays.asList(a, b, c), listing.items);
        assertTrue(listing.corruptIds.isEmpty());
    }

    @Test
    public void list_onEmptyStore_isEmpty() throws Exception {
        assertTrue(store.list().items.isEmpty());
        assertEquals(0, store.count());
    }

    // ------------------------------------------------------------ media items

    @Test
    public void photoWithThumbnail_roundTrips() throws Exception {
        byte[] photo = VaultCrypto.randomBytes(50_000);
        byte[] thumb = VaultCrypto.randomBytes(2_000);
        VaultItem item = addMedia(VaultItem.Type.PHOTO, "beach.jpg", "image/jpeg", "Beach day", photo, thumb);

        assertNotNull(item.mediaId);
        assertNotNull(item.thumbnailId);
        assertNotEquals(item.mediaId, item.thumbnailId);
        assertEquals("mediaSize is measured by the store, not trusted from the caller", 50_000, item.mediaSize);
        assertEquals("beach.jpg", item.mediaName);
        assertEquals("image/jpeg", item.mimeType);
        assertEquals(640, item.width);

        VaultItem back = store.get(item.id);
        assertEquals(item, back);
        assertArrayEquals(photo, readMedia(item.id));
        assertArrayEquals(thumb, store.readThumbnail(item.id));
        assertEquals(2, new File(root, "media").list().length);
    }

    @Test
    public void videoAndDocument_roundTrip_withoutThumbnail() throws Exception {
        byte[] video = VaultCrypto.randomBytes(1_000_000); // ~245 chunks at 4 KiB
        VaultItem v = addMedia(VaultItem.Type.VIDEO, "clip.mp4", "video/mp4", "", video, null);
        assertNull(v.thumbnailId);
        assertNull(store.readThumbnail(v.id));
        assertEquals(12, store.get(v.id).durationSeconds);
        assertArrayEquals(video, readMedia(v.id));

        byte[] pdf = VaultCrypto.randomBytes(12_345);
        VaultItem d = addMedia(VaultItem.Type.DOCUMENT, "report.pdf", "application/pdf", "Q3", pdf, null);
        assertArrayEquals(pdf, readMedia(d.id));
    }

    @Test
    public void emptyDocument_isStoredAndReadBack() throws Exception {
        VaultItem d = addMedia(VaultItem.Type.DOCUMENT, "empty.txt", "text/plain", "", new byte[0], null);
        assertEquals(0, d.mediaSize);
        assertEquals(0, readMedia(d.id).length);
    }

    @Test
    public void largeMediaWithDefaultChunkSize_usingThePublicConstructor() throws Exception {
        VaultStore defaultStore = new VaultStore(new File(tmp.getRoot(), "default-chunks"), manager);
        byte[] big = VaultCrypto.randomBytes(3 * 1024 * 1024 + 17);
        VaultItem item = defaultStore.addItem(new VaultItem.Draft(VaultItem.Type.VIDEO).media("big.mp4", "video/mp4", 1, 1, 1),
                new ByteArrayInputStream(big), null);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        defaultStore.readMedia(item.id, out);
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(big), MessageDigest.getInstance("SHA-256").digest(out.toByteArray()));
        long onDisk = mediaFileIn(new File(tmp.getRoot(), "default-chunks"), item.mediaId).length();
        assertEquals(VaultMediaCipher.HEADER_BYTES + big.length + 16L * ((big.length + 65535) / 65536), onDisk);
    }

    private static File mediaFileIn(File dir, String id) {
        return new File(dir, "media/" + id + ".vmed");
    }

    // ------------------------------------------------------------ input validation

    @Test
    public void addItem_rejectsInvalidCombinations() throws Exception {
        final InputStream media = new ByteArrayInputStream(new byte[10]);
        expect(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> store.addItem(null, null, null));
        expect(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> store.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("x"), media, null));
        expect(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> store.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("x"), null, new byte[10]));
        expect(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> store.addItem(new VaultItem.Draft(VaultItem.Type.TEXT), null, null));
        expect(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> store.addItem(new VaultItem.Draft(VaultItem.Type.PHOTO), null, null));
        expect(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> store.addItem(new VaultItem.Draft(VaultItem.Type.PHOTO), media, new byte[0]));
        expect(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> store.addItem(new VaultItem.Draft(VaultItem.Type.PHOTO), media, new byte[VaultStore.MAX_THUMBNAIL_BYTES + 1]));
        assertEquals(0, store.count());
        assertTrue("invalid input must leave no files", allFiles(root).isEmpty());
    }

    @Test
    public void invalidIds_areRejectedEverywhere_includingPathTraversal() throws Exception {
        addText("something");
        for (final String bad : new String[]{null, "", "short", "../../etc/passwd", "../" + repeat("a", 29),
                repeat("A", 32), repeat("g", 32), repeat("a", 31) + "/", repeat("a", 33), "items/" + repeat("a", 26)}) {
            expect(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> store.get(bad));
            expect(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> store.delete(bad));
            expect(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> store.readMedia(bad, new ByteArrayOutputStream()));
            expect(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> store.readThumbnail(bad));
        }
    }

    @Test
    public void readMedia_onTextItemOrUnknownItem_isInvalidArgument() throws Exception {
        VaultItem t = addText("no media here");
        expect(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> store.readMedia(t.id, new ByteArrayOutputStream()));
        expect(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> store.readMedia(repeat("a", 32), new ByteArrayOutputStream()));
        assertNull(store.readThumbnail(t.id));
    }

    @Test
    public void constructor_validatesArguments() {
        try {
            new VaultStore(null, manager);
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
        try {
            new VaultStore(root, null);
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
        try {
            new VaultStore(root, manager, null, CHUNK);
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
        try {
            new VaultStore(root, manager, new VaultStore.Clock() {
                @Override
                public long nowMillis() {
                    return 0;
                }
            }, 8);
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }

    // ------------------------------------------------------------ search

    @Test
    public void search_matchesTextCaptionSenderForwardedNameAndFileName() throws Exception {
        VaultItem budget = addText("Meeting notes: Budget Q4");
        VaultItem photo = store.addItem(new VaultItem.Draft(VaultItem.Type.PHOTO).text("Sunset beach")
                .media("IMG_2024_Sunset.JPG", "image/jpeg", 10, 10, 0), new ByteArrayInputStream(new byte[100]), null);
        VaultItem doc = store.addItem(new VaultItem.Draft(VaultItem.Type.DOCUMENT)
                .media("tax-return.pdf", "application/pdf", 0, 0, 0), new ByteArrayInputStream(new byte[100]), null);
        VaultItem fwd = store.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("hello")
                .senderName("Zoë").forwardedFrom("Ünïcode Channel", 5), null, null);

        assertEquals(Arrays.asList(budget), store.search("budget"));
        assertEquals(Arrays.asList(budget), store.search("BUDGET"));
        assertEquals(Arrays.asList(budget), store.search("  budget  "));
        assertEquals("matches caption and file name of the same item only once", Arrays.asList(photo), store.search("SUNSET"));
        assertEquals(Arrays.asList(photo), store.search("beach"));
        assertEquals(Arrays.asList(doc), store.search("tax-return"));
        assertEquals(Arrays.asList(doc), store.search(".pdf"));
        assertEquals(Arrays.asList(fwd), store.search("zoË"));
        assertEquals(Arrays.asList(fwd), store.search("ünï"));
        assertEquals(Arrays.asList(fwd), store.search("channel"));
        assertEquals(Arrays.asList(budget, photo, doc, fwd), store.search(""));
        assertEquals(Arrays.asList(budget, photo, doc, fwd), store.search("   "));
        assertEquals(Arrays.asList(budget, photo, doc, fwd), store.search(null));
        assertTrue(store.search("no such thing").isEmpty());
        assertTrue("mime types and ids are not searchable", store.search("image/jpeg").isEmpty());
        // "t" occurs in the first three items only (Meeting notes, Sunset, tax-return) and not in the fourth.
        assertEquals("results keep oldest-first order", Arrays.asList(budget, photo, doc), store.search("t"));
    }

    // ------------------------------------------------------------ nothing readable on disk

    @Test
    public void noPlaintextAnywhereInTheVaultDirectory() throws Exception {
        String textMarker = "TEXT-MARKER-αβγ-7f3a1c";
        String captionMarker = "CAPTION-MARKER-9b2e44";
        String senderMarker = "SENDER-MARKER-Zoë-51d0";
        String fwdMarker = "FORWARD-MARKER-c93e07";
        String nameMarker = "secret-vacation-photo-MARKER.jpg";
        String mimeMarker = "image/x-mime-MARKER-42";
        byte[] mediaMarker = utf8("PLAINTEXT-MEDIA-MARKER-7f3a");
        byte[] thumbMarker = utf8("PLAINTEXT-THUMB-MARKER-18cc");

        byte[] media = new byte[mediaMarker.length * 400];
        for (int i = 0; i < 400; i++) {
            System.arraycopy(mediaMarker, 0, media, i * mediaMarker.length, mediaMarker.length);
        }
        byte[] thumb = new byte[thumbMarker.length * 20];
        for (int i = 0; i < 20; i++) {
            System.arraycopy(thumbMarker, 0, thumb, i * thumbMarker.length, thumbMarker.length);
        }

        store.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text(textMarker).senderName(senderMarker)
                .forwardedFrom(fwdMarker, 1), null, null);
        store.addItem(new VaultItem.Draft(VaultItem.Type.PHOTO).text(captionMarker)
                .media(nameMarker, mimeMarker, 1, 1, 0), new ByteArrayInputStream(media), thumb);
        store.addItem(new VaultItem.Draft(VaultItem.Type.DOCUMENT).media(nameMarker, mimeMarker, 0, 0, 0),
                new ByteArrayInputStream(media), null);
        store.removeOrphans();

        List<byte[]> markers = new ArrayList<>();
        for (String s : new String[]{textMarker, captionMarker, senderMarker, fwdMarker, nameMarker, mimeMarker}) {
            markers.add(utf8(s));
            markers.add(Arrays.copyOf(utf8(s), 8)); // even a short prefix must not appear
            markers.add(s.getBytes(StandardCharsets.UTF_16BE));
            markers.add(s.getBytes(StandardCharsets.UTF_16LE));
        }
        markers.add(mediaMarker);
        markers.add(Arrays.copyOf(mediaMarker, 10));
        markers.add(thumbMarker);
        markers.add(Arrays.copyOf(thumbMarker, 10));

        List<File> files = allFiles(root);
        assertEquals("3 records + photo media + thumbnail + document media", 6, files.size());
        for (File f : files) {
            String rel = root.toURI().relativize(f.toURI()).getPath();
            assertTrue("unexpected file name: " + rel, rel.matches("(items/[0-9a-f]{32}\\.vrec|media/[0-9a-f]{32}\\.vmed)"));
            byte[] content = read(f);
            for (byte[] marker : markers) {
                assertEquals("plaintext found in " + rel, -1, VaultCryptoTest.indexOf(content, marker));
            }
        }
        for (File f : root.listFiles()) {
            assertTrue(f.getName().equals("items") || f.getName().equals("media"));
        }
        assertFalse("original file name or extension must not appear in any path",
                allFiles(root).toString().contains("jpg"));
    }

    @Test
    public void scannerSanityCheck_wouldNoticeAPlaintextLeak() throws Exception {
        addText("anything");
        File leaked = new File(root, "media/leak.bin");
        write(leaked, utf8("PLAINTEXT-MEDIA-MARKER-7f3a"));
        boolean found = false;
        for (File f : allFiles(root)) {
            if (VaultCryptoTest.indexOf(read(f), utf8("PLAINTEXT-MEDIA-MARKER-7f3a")) >= 0) {
                found = true;
            }
        }
        assertTrue("the leak scanner has teeth", found);
        assertFalse(leaked.getName().matches("[0-9a-f]{32}\\.vmed"));
    }

    @Test
    public void noTemporaryFilesRemainAfterSuccessfulWrites() throws Exception {
        addText("a");
        addMedia(VaultItem.Type.PHOTO, "p.jpg", "image/jpeg", "", new byte[5000], new byte[100]);
        for (File f : allFiles(root)) {
            assertFalse(f.getName(), f.getName().endsWith(".tmp"));
        }
    }

    // ------------------------------------------------------------ key separation

    @Test
    public void messagesAndMediaUseSeparateHkdfDerivedKeys() throws Exception {
        VaultItem item = addMedia(VaultItem.Type.PHOTO, "p.jpg", "image/jpeg", "caption", VaultCrypto.randomBytes(3000), null);
        byte[] messagesKey = manager.deriveSubkey("messages");
        byte[] mediaKey = manager.deriveSubkey("media");
        assertFalse(Arrays.equals(messagesKey, mediaKey));

        // The record opens with the messages key (and the documented AAD) ...
        byte[] recordFile = read(recordFile(item.id));
        byte[] blob = Arrays.copyOfRange(recordFile, 5, recordFile.length);
        byte[] aad = utf8("tg-vault/record/v1/" + item.id);
        assertEquals(item, VaultItem.decodePadded(VaultCrypto.decrypt(messagesKey, blob, aad)));
        // ... and refuses the media key.
        expectCorrupted("record opened with media key", () -> VaultCrypto.decrypt(mediaKey, blob, aad));

        // The media opens with the media key (and the documented AAD) ...
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        VaultMediaCipher.decrypt(new ByteArrayInputStream(read(mediaFile(item.mediaId))), out, mediaKey, utf8("tg-vault/media/v1/" + item.mediaId));
        assertEquals(3000, out.size());
        // ... and refuses the messages key.
        expectCorrupted("media opened with messages key", () -> VaultMediaCipher.decrypt(
                new ByteArrayInputStream(read(mediaFile(item.mediaId))), new ByteArrayOutputStream(), messagesKey, utf8("tg-vault/media/v1/" + item.mediaId)));
    }

    // ------------------------------------------------------------ locked / wrong password / restart

    @Test
    public void everyOperationFailsWhileLocked_andLockingHidesExistingData() throws Exception {
        final VaultItem t = addText("secret");
        final VaultItem p = addMedia(VaultItem.Type.PHOTO, "p.jpg", "image/jpeg", "", new byte[100], new byte[10]);
        List<String> before = fileSnapshot();
        manager.lock();
        VaultCryptoException.Reason locked = VaultCryptoException.Reason.INVALID_STATE;
        expect(locked, () -> addText("more"));
        expect(locked, () -> store.get(t.id));
        expect(locked, () -> store.list());
        expect(locked, () -> store.search("secret"));
        expect(locked, () -> store.delete(t.id));
        expect(locked, () -> store.readMedia(p.id, new ByteArrayOutputStream()));
        expect(locked, () -> store.readThumbnail(p.id));
        expect(locked, () -> store.removeOrphans());
        assertEquals("rejected calls must not touch any file", before, fileSnapshot());

        manager.unlock(PASSWORD.toCharArray());
        assertEquals("secret", store.get(t.id).text);
    }

    @Test
    public void lockedAdd_doesNotEvenCreateTheDirectory() throws Exception {
        manager.lock();
        File fresh = new File(tmp.getRoot(), "never-created");
        final VaultStore lockedStore = newStore(fresh, manager);
        expect(VaultCryptoException.Reason.INVALID_STATE,
                () -> lockedStore.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("x"), null, null));
        assertFalse(fresh.exists());
    }

    @Test
    public void dataSurvivesRestart_andNeedsTheRightPassword() throws Exception {
        VaultItem t = addText("persist me");
        byte[] photo = VaultCrypto.randomBytes(9000);
        VaultItem p = addMedia(VaultItem.Type.PHOTO, "p.jpg", "image/jpeg", "cap", photo, new byte[50]);
        manager.lock();

        VaultKeyManager restarted = new VaultKeyManager(headers, device, 1000);
        final VaultStore restartedStore = newStore(root, restarted);
        expect(VaultCryptoException.Reason.INVALID_STATE, () -> restartedStore.list());
        expect(VaultCryptoException.Reason.WRONG_PASSWORD, () -> restarted.unlock("wrong password!".toCharArray()));
        expect(VaultCryptoException.Reason.INVALID_STATE, () -> restartedStore.get(t.id));

        restarted.unlock(PASSWORD.toCharArray());
        assertEquals(t, restartedStore.get(t.id));
        assertEquals(p, restartedStore.get(p.id));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        restartedStore.readMedia(p.id, out);
        assertArrayEquals(photo, out.toByteArray());
    }

    // ------------------------------------------------------------ tampering: records

    @Test
    public void everySingleByteFlipInARecordFile_isDetected() throws Exception {
        VaultItem keep = addText("untouched neighbour");
        VaultItem item = addText("authentic text");
        File file = recordFile(item.id);
        byte[] original = read(file);
        for (int i = 0; i < original.length; i++) {
            byte[] t = original.clone();
            t[i] ^= 0x01;
            write(file, t);
            final int pos = i;
            expectCorrupted("record byte " + pos, () -> store.get(item.id));
            VaultStore.Listing listing = store.list();
            assertEquals("byte " + pos, Arrays.asList(item.id), listing.corruptIds);
            assertEquals("the damaged record must not hide its neighbour", Arrays.asList(keep), listing.items);
        }
        write(file, original);
        assertEquals(item, store.get(item.id));
    }

    @Test
    public void everyTruncationOfARecordFile_isDetected() throws Exception {
        VaultItem item = addText("authentic text");
        File file = recordFile(item.id);
        byte[] original = read(file);
        for (int len = 0; len < original.length; len++) {
            write(file, Arrays.copyOf(original, len));
            final int l = len;
            expectCorrupted("record truncated to " + l, () -> store.get(item.id));
        }
        write(file, VaultCryptoTest.concat(original, new byte[]{0}));
        expectCorrupted("record with one extra byte", () -> store.get(item.id));
        write(file, original);
        assertEquals(item, store.get(item.id));
    }

    @Test
    public void swappingTwoRecordFiles_isDetectedBecauseRecordsAreBoundToTheirId() throws Exception {
        VaultItem a = addText("alpha");
        VaultItem b = addText("bravo");
        byte[] fa = read(recordFile(a.id));
        byte[] fb = read(recordFile(b.id));
        write(recordFile(a.id), fb);
        write(recordFile(b.id), fa);
        expectCorrupted("record A holding B's data", () -> store.get(a.id));
        expectCorrupted("record B holding A's data", () -> store.get(b.id));
        assertEquals(2, store.list().corruptIds.size());
    }

    @Test
    public void aRecordCopiedUnderANewId_isRejected() throws Exception {
        VaultItem a = addText("alpha");
        String forgedId = repeat("e", 32);
        write(recordFile(forgedId), read(recordFile(a.id)));
        expectCorrupted("copied record", () -> store.get(forgedId));
        assertEquals(Arrays.asList(forgedId), store.list().corruptIds);
    }

    @Test
    public void garbageAndForeignFilesInTheItemsDirectory_areHandled() throws Exception {
        VaultItem good = addText("good");
        write(new File(root, "items/" + repeat("c", 32) + ".vrec"), VaultCrypto.randomBytes(300));
        write(new File(root, "items/not-an-id.vrec"), new byte[10]);
        write(new File(root, "items/readme.txt"), new byte[10]);
        VaultStore.Listing listing = store.list();
        assertEquals(Arrays.asList(good), listing.items);
        assertEquals(Arrays.asList(repeat("c", 32)), listing.corruptIds);
        assertEquals("count ignores names that are not item ids", 2, store.count());
    }

    // ------------------------------------------------------------ tampering: media

    @Test
    public void everySingleByteFlipInAMediaFile_isDetected() throws Exception {
        byte[] media = VaultCrypto.randomBytes(100);
        VaultItem item = addMedia(VaultItem.Type.PHOTO, "p.jpg", "image/jpeg", "", media, VaultCrypto.randomBytes(40));
        File file = mediaFile(item.mediaId);
        byte[] original = read(file);
        for (int i = 0; i < original.length; i++) {
            byte[] t = original.clone();
            t[i] ^= 0x01;
            write(file, t);
            final int pos = i;
            expectCorrupted("media byte " + pos, () -> readMedia(item.id));
        }
        write(file, original);
        assertArrayEquals(media, readMedia(item.id));
    }

    @Test
    public void everySingleByteFlipInAThumbnailFile_isDetected() throws Exception {
        byte[] thumb = VaultCrypto.randomBytes(40);
        VaultItem item = addMedia(VaultItem.Type.PHOTO, "p.jpg", "image/jpeg", "", VaultCrypto.randomBytes(100), thumb);
        File file = mediaFile(item.thumbnailId);
        byte[] original = read(file);
        for (int i = 0; i < original.length; i++) {
            byte[] t = original.clone();
            t[i] ^= 0x01;
            write(file, t);
            final int pos = i;
            expectCorrupted("thumbnail byte " + pos, () -> store.readThumbnail(item.id));
        }
        write(file, original);
        assertArrayEquals(thumb, store.readThumbnail(item.id));
    }

    @Test
    public void everyTruncationOfAMediaFile_isDetected_includingChunkBoundaries() throws Exception {
        // 3 chunks of 4096 plus a short one, so there are several chunk boundaries to cut at.
        byte[] media = VaultCrypto.randomBytes(3 * CHUNK + 700);
        VaultItem item = addMedia(VaultItem.Type.VIDEO, "v.mp4", "video/mp4", "", media, null);
        File file = mediaFile(item.mediaId);
        byte[] original = read(file);
        Set<Integer> cuts = new HashSet<>();
        for (int len = 0; len <= 60; len++) {
            cuts.add(len);
        }
        for (int c = 0; c <= 4; c++) {
            int boundary = VaultMediaCipher.HEADER_BYTES + c * (CHUNK + 16);
            for (int delta = -2; delta <= 2; delta++) {
                cuts.add(boundary + delta);
            }
        }
        cuts.add(original.length - 1);
        cuts.add(original.length - 16);
        cuts.add(original.length - 17);
        for (int len : cuts) {
            if (len < 0 || len >= original.length) {
                continue;
            }
            write(file, Arrays.copyOf(original, len));
            final int l = len;
            expectCorrupted("media truncated to " + l, () -> readMedia(item.id));
        }
        write(file, VaultCryptoTest.concat(original, new byte[16]));
        expectCorrupted("media with 16 extra bytes", () -> readMedia(item.id));
        write(file, original);
        assertArrayEquals(media, readMedia(item.id));
    }

    @Test
    public void missingMediaFile_isReportedAsCorrupted_notAsCrash() throws Exception {
        VaultItem item = addMedia(VaultItem.Type.PHOTO, "p.jpg", "image/jpeg", "", new byte[100], new byte[10]);
        assertTrue(mediaFile(item.mediaId).delete());
        expectCorrupted("missing media", () -> readMedia(item.id));
        assertTrue(mediaFile(item.thumbnailId).delete());
        expectCorrupted("missing thumbnail", () -> store.readThumbnail(item.id));
        assertEquals("the record itself is still readable", item, store.get(item.id));
    }

    @Test
    public void swappingMediaFilesBetweenItems_isDetectedBecauseMediaIsBoundToItsId() throws Exception {
        VaultItem a = addMedia(VaultItem.Type.PHOTO, "a.jpg", "image/jpeg", "", VaultCrypto.randomBytes(100), null);
        VaultItem b = addMedia(VaultItem.Type.PHOTO, "b.jpg", "image/jpeg", "", VaultCrypto.randomBytes(100), null);
        byte[] fa = read(mediaFile(a.mediaId));
        byte[] fb = read(mediaFile(b.mediaId));
        write(mediaFile(a.mediaId), fb);
        write(mediaFile(b.mediaId), fa);
        expectCorrupted("A shows B's media", () -> readMedia(a.id));
        expectCorrupted("B shows A's media", () -> readMedia(b.id));
    }

    @Test
    public void swappingAnItemsMediaAndThumbnail_isDetected() throws Exception {
        VaultItem item = addMedia(VaultItem.Type.PHOTO, "a.jpg", "image/jpeg", "", VaultCrypto.randomBytes(100), VaultCrypto.randomBytes(100));
        byte[] media = read(mediaFile(item.mediaId));
        byte[] thumb = read(mediaFile(item.thumbnailId));
        write(mediaFile(item.mediaId), thumb);
        write(mediaFile(item.thumbnailId), media);
        expectCorrupted("thumbnail in the media slot", () -> readMedia(item.id));
        expectCorrupted("media in the thumbnail slot", () -> store.readThumbnail(item.id));
    }

    @Test
    public void recordDeclaringTheWrongMediaSize_isDetected() throws Exception {
        VaultItem item = addMedia(VaultItem.Type.PHOTO, "a.jpg", "image/jpeg", "", VaultCrypto.randomBytes(100), null);
        // Forge a perfectly authentic record (we hold the key) that lies about the size.
        VaultItem forged = new VaultItem(item.id, item.type, item.createdAtMillis, item.originalDateMillis, item.text,
                item.senderName, item.forwardedFromName, item.forwardedDateMillis, item.sourceDialogId, item.sourceMessageId,
                item.mediaId, item.mediaName, item.mimeType, item.mediaSize + 1, item.width, item.height, item.durationSeconds, null);
        byte[] key = manager.deriveSubkey("messages");
        byte[] blob = VaultCrypto.encrypt(key, forged.encodePadded(), utf8("tg-vault/record/v1/" + item.id));
        byte[] content = new byte[5 + blob.length];
        System.arraycopy(new byte[]{'T', 'G', 'V', 'R', 1}, 0, content, 0, 5);
        System.arraycopy(blob, 0, content, 5, blob.length);
        write(recordFile(item.id), content);

        assertEquals("the forged record itself is valid", item.mediaSize + 1, store.get(item.id).mediaSize);
        expectCorrupted("size mismatch", () -> readMedia(item.id));
    }

    // ------------------------------------------------------------ delete

    @Test
    public void delete_removesRecordMediaAndThumbnail() throws Exception {
        VaultItem keep = addText("keep");
        VaultItem gone = addMedia(VaultItem.Type.PHOTO, "p.jpg", "image/jpeg", "", new byte[5000], new byte[100]);
        assertEquals(4, allFiles(root).size());

        assertTrue(store.delete(gone.id));
        assertNull(store.get(gone.id));
        assertEquals(1, allFiles(root).size());
        assertFalse(store.delete(gone.id));
        assertEquals(Arrays.asList(keep), store.list().items);
        assertFalse(store.delete(repeat("d", 32)));
    }

    @Test
    public void delete_overwritesFilesWithZerosBeforeUnlinking() throws Exception {
        VaultItem item = addMedia(VaultItem.Type.PHOTO, "p.jpg", "image/jpeg", "", VaultCrypto.randomBytes(3000), VaultCrypto.randomBytes(100));
        File[] files = {recordFile(item.id), mediaFile(item.mediaId), mediaFile(item.thumbnailId)};
        File[] links = new File[files.length];
        long[] sizes = new long[files.length];
        for (int i = 0; i < files.length; i++) {
            links[i] = new File(tmp.getRoot(), "hardlink-" + i);
            sizes[i] = files[i].length();
            try {
                Files.createLink(links[i].toPath(), files[i].toPath());
            } catch (UnsupportedOperationException | IOException e) {
                return; // file system without hard links: nothing to inspect
            }
        }
        assertTrue(store.delete(item.id));
        for (int i = 0; i < files.length; i++) {
            assertFalse(files[i].exists());
            byte[] left = read(links[i]);
            assertEquals(sizes[i], left.length);
            assertArrayEquals("file " + i + " was zeroed before unlinking", new byte[left.length], left);
        }
    }

    @Test
    public void delete_ofADamagedRecord_works_andLeavesItsMediaForOrphanCleanup() throws Exception {
        VaultItem item = addMedia(VaultItem.Type.PHOTO, "p.jpg", "image/jpeg", "", new byte[500], null);
        byte[] damaged = read(recordFile(item.id));
        damaged[20] ^= 1;
        write(recordFile(item.id), damaged);

        assertTrue(store.delete(item.id));
        assertFalse(recordFile(item.id).exists());
        assertTrue("media of an unreadable record is kept until orphan cleanup", mediaFile(item.mediaId).exists());
        assertEquals(1, store.removeOrphans());
        assertFalse(mediaFile(item.mediaId).exists());
    }

    // ------------------------------------------------------------ failed writes leave nothing behind

    @Test
    public void failedMediaRead_duringAdd_leavesNoFilesAndTheStoreKeepsWorking() throws Exception {
        InputStream failing = new InputStream() {
            private int count;

            @Override
            public int read() throws IOException {
                if (count++ > 10_000) {
                    throw new IOException("source file vanished");
                }
                return 1;
            }
        };
        expect(VaultCryptoException.Reason.IO_ERROR, () -> store.addItem(
                new VaultItem.Draft(VaultItem.Type.VIDEO).media("v.mp4", "video/mp4", 1, 1, 1), failing, new byte[10]));
        assertTrue("no leftovers: " + allFiles(root), allFiles(root).isEmpty());
        assertEquals(0, store.count());

        VaultItem ok = addText("still works");
        assertEquals(ok, store.get(ok.id));
    }

    @Test
    public void failedRecordWrite_afterMediaWasStored_cleansUpTheMedia() throws Exception {
        final File itemsDir = new File(root, "items");
        // Sabotage: when the media source reaches its end, replace the items directory by a plain file,
        // so the record cannot be written even though the media already has been.
        InputStream sabotaging = new InputStream() {
            private int count;

            @Override
            public int read() throws IOException {
                if (count++ < 6000) {
                    return 7;
                }
                if (count == 6001) {
                    File[] children = itemsDir.listFiles();
                    if (children != null) {
                        for (File c : children) {
                            c.delete();
                        }
                    }
                    itemsDir.delete();
                    Files.write(itemsDir.toPath(), new byte[]{1});
                }
                return -1;
            }
        };
        expect(VaultCryptoException.Reason.IO_ERROR, () -> store.addItem(
                new VaultItem.Draft(VaultItem.Type.DOCUMENT).media("d.bin", "application/octet-stream", 0, 0, 0), sabotaging, new byte[10]));
        File[] mediaLeft = new File(root, "media").listFiles();
        assertTrue("encrypted media must be cleaned up when the record fails: " + Arrays.toString(mediaLeft),
                mediaLeft == null || mediaLeft.length == 0);
    }

    @Test
    public void unusableStorageLocation_failsCleanly() throws Exception {
        File blocker = new File(tmp.getRoot(), "blocker");
        write(blocker, new byte[]{1});
        final VaultStore broken = newStore(new File(blocker, "sub"), manager);
        expect(VaultCryptoException.Reason.IO_ERROR, () -> broken.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("x"), null, null));
    }

    // ------------------------------------------------------------ orphan cleanup and wipe

    @Test
    public void removeOrphans_cleansTemporaryAndUnreferencedFiles_only() throws Exception {
        byte[] photo = VaultCrypto.randomBytes(2000);
        VaultItem item = addMedia(VaultItem.Type.PHOTO, "p.jpg", "image/jpeg", "", photo, new byte[50]);
        File orphan = new File(root, "media/" + repeat("9", 32) + ".vmed");
        File tmpMedia = new File(root, "media/" + repeat("8", 32) + ".vmed.tmp");
        File tmpRecord = new File(root, "items/" + repeat("7", 32) + ".vrec.tmp");
        File foreign = new File(root, "media/notes.txt");
        write(orphan, VaultCrypto.randomBytes(100));
        write(tmpMedia, VaultCrypto.randomBytes(100));
        write(tmpRecord, VaultCrypto.randomBytes(100));
        write(foreign, new byte[3]);

        assertEquals(3, store.removeOrphans());
        assertFalse(orphan.exists());
        assertFalse(tmpMedia.exists());
        assertFalse(tmpRecord.exists());
        assertTrue("files that are not vault media are left alone", foreign.exists());
        assertArrayEquals(photo, readMedia(item.id));
        assertNotNull(store.readThumbnail(item.id));
        assertEquals(0, store.removeOrphans());
    }

    @Test
    public void removeOrphans_keepsUnreferencedMedia_whileAnyRecordIsUnreadable() throws Exception {
        VaultItem damaged = addText("will be damaged");
        File orphan = new File(root, "media/" + repeat("9", 32) + ".vmed");
        File tmpMedia = new File(root, "media/" + repeat("8", 32) + ".vmed.tmp");
        write(orphan, VaultCrypto.randomBytes(100));
        write(tmpMedia, VaultCrypto.randomBytes(100));
        byte[] bytes = read(recordFile(damaged.id));
        bytes[30] ^= 1;
        write(recordFile(damaged.id), bytes);

        assertEquals("only the temporary file is removed", 1, store.removeOrphans());
        assertTrue("the media might belong to the unreadable record", orphan.exists());
        assertFalse(tmpMedia.exists());
    }

    @Test
    public void deleteAllData_removesEverything_evenWhileLocked() throws Exception {
        addText("one");
        addMedia(VaultItem.Type.PHOTO, "p.jpg", "image/jpeg", "", new byte[1000], new byte[10]);
        manager.lock();
        store.deleteAllData();
        assertTrue(allFiles(root).isEmpty());
        assertFalse(new File(root, "items").exists());
        assertFalse(new File(root, "media").exists());
        assertEquals(0, store.count());
        store.deleteAllData(); // nothing left: must not fail

        manager.unlock(PASSWORD.toCharArray());
        assertTrue(store.list().items.isEmpty());
        assertEquals("the store is usable again afterwards", "again", addText("again").text);
    }

    @Test
    public void destroyingTheKey_makesLeftoverCiphertextUnreadableEvenWithTheSamePassword() throws Exception {
        VaultItem t = addText("old secret");
        VaultItem p = addMedia(VaultItem.Type.PHOTO, "p.jpg", "image/jpeg", "", VaultCrypto.randomBytes(500), null);
        // Simulate ciphertext surviving on flash: keep a copy, destroy the vault, then restore the files.
        File backup = new File(tmp.getRoot(), "backup");
        for (File f : allFiles(root)) {
            File dest = new File(backup, root.toURI().relativize(f.toURI()).getPath());
            dest.getParentFile().mkdirs();
            Files.copy(f.toPath(), dest.toPath());
        }
        manager.destroy();
        store.deleteAllData();

        InMemoryHeaderStore newHeaders = new InMemoryHeaderStore();
        final VaultKeyManager fresh = new VaultKeyManager(newHeaders, new TestDeviceKeyWrapper(), 1000);
        fresh.createVault(PASSWORD.toCharArray(), PASSWORD.toCharArray()); // same password, new random key
        final VaultStore freshStore = newStore(root, fresh);
        for (File f : allFiles(backup)) {
            File dest = new File(root, backup.toURI().relativize(f.toURI()).getPath());
            dest.getParentFile().mkdirs();
            Files.copy(f.toPath(), dest.toPath());
        }

        VaultStore.Listing listing = freshStore.list();
        assertTrue("nothing from the old vault can be read", listing.items.isEmpty());
        assertEquals(new HashSet<>(Arrays.asList(t.id, p.id)), new HashSet<>(listing.corruptIds));
        expectCorrupted("old record", () -> freshStore.get(t.id));
        expectCorrupted("old media", () -> freshStore.readMedia(p.id, new ByteArrayOutputStream()));
    }

    // ------------------------------------------------------------ padding and concurrency

    @Test
    public void shortTextRecords_haveIdenticalFileSizes() throws Exception {
        VaultItem one = addText("a");
        VaultItem eighty = addText(repeat("b", 80));
        VaultItem big = addText(repeat("c", 600));
        assertEquals(recordFile(one.id).length(), recordFile(eighty.id).length());
        assertTrue(recordFile(big.id).length() > recordFile(one.id).length());
    }

    @Test
    public void concurrentAddsAndReads_stayConsistent() throws Exception {
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread[] threads = new Thread[6];
        for (int t = 0; t < threads.length; t++) {
            final int n = t;
            threads[t] = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        for (int i = 0; i < 10; i++) {
                            VaultItem item = addText("thread " + n + " item " + i);
                            if (!store.get(item.id).text.equals("thread " + n + " item " + i)) {
                                throw new AssertionError("wrong content");
                            }
                            store.list();
                        }
                    } catch (Throwable e) {
                        failure.compareAndSet(null, e);
                    }
                }
            });
            threads[t].start();
        }
        for (Thread t : threads) {
            t.join(120_000);
        }
        if (failure.get() != null) {
            throw new AssertionError(failure.get());
        }
        VaultStore.Listing listing = store.list();
        assertEquals(60, listing.items.size());
        assertTrue(listing.corruptIds.isEmpty());
        Set<String> ids = new HashSet<>();
        for (VaultItem item : listing.items) {
            ids.add(item.id);
        }
        assertEquals(60, ids.size());
    }
}
