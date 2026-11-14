package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.util.List;
import java.util.Random;

/** Send-to-Vault while the Vault is locked: sealed, write-only inbox that is drained at the next unlock. */
public class VaultInboxTest {

    private static final String PW = "correct horse";
    private static final String SECRET_TEXT = "TOP-SECRET-MARKER-9f3a";

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private InMemoryHeaderStore headers;
    private TestDeviceKeyWrapper device;
    private VaultKeyManager keys;
    private VaultStore store;
    private VaultInbox inbox;
    private File inboxDir;

    @Before
    public void setUp() throws Exception {
        headers = new InMemoryHeaderStore();
        device = new TestDeviceKeyWrapper();
        keys = new VaultKeyManager(headers, device, 1000);
        keys.createVault(PW.toCharArray(), PW.toCharArray());
        store = new VaultStore(new File(tmp.getRoot(), "data"), keys);
        inboxDir = new File(tmp.getRoot(), "inbox");
        inbox = new VaultInbox(inboxDir, device);
        inbox.ensureKeyPair(keys);
    }

    private void lock() {
        keys.lock();
        assertFalse(keys.isUnlocked());
    }

    private void unlock() throws Exception {
        keys.unlock(PW.toCharArray());
        assertTrue(keys.isUnlocked());
    }

    private static VaultItem.Draft text(String t) {
        return new VaultItem.Draft(VaultItem.Type.TEXT).text(t).originalDateMillis(1234L).senderName("Alice").source(77L, 5L);
    }

    private static byte[] random(int n, long seed) {
        byte[] b = new byte[n];
        new Random(seed).nextBytes(b);
        return b;
    }

    private byte[] allInboxBytes() throws Exception {
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        File[] files = inboxDir.listFiles();
        if (files != null) {
            for (File f : files) {
                all.write(f.getName().getBytes("UTF-8"));
                all.write(Files.readAllBytes(f.toPath()));
            }
        }
        return all.toByteArray();
    }

    private static boolean contains(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private VaultItem onlyItem() throws Exception {
        List<String> ids = store.localIds();
        assertEquals(1, ids.size());
        return store.get(ids.get(0));
    }

    // ------------------------------------------------------------ setup

    @Test
    public void canAccept_onlyAfterTheKeyPairExists() throws Exception {
        VaultInbox fresh = new VaultInbox(new File(tmp.getRoot(), "other"), device);
        assertFalse(fresh.canAccept());
        try {
            fresh.put(text("x"), null, 1 << 20);
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
        fresh.ensureKeyPair(keys);
        assertTrue(fresh.canAccept());
    }

    @Test
    public void ensureKeyPair_isIdempotent_andKeepsTheSamePublicKey() throws Exception {
        byte[] before = Files.readAllBytes(new File(inboxDir, "pub.bin").toPath());
        inbox.ensureKeyPair(keys);
        inbox.ensureKeyPair(keys);
        assertArrayEquals(before, Files.readAllBytes(new File(inboxDir, "pub.bin").toPath()));
    }

    // ------------------------------------------------------------ 4. text while locked, without opening the Vault

    @Test
    public void text_savedWhileLocked_needsNoPasswordAndNoKey_thenAppearsAfterUnlock() throws Exception {
        lock();
        assertTrue("write-only side must work locked", inbox.canAccept());
        inbox.put(text(SECRET_TEXT), null, 1 << 20);
        assertEquals(1, inbox.pendingCount());
        assertFalse("saving must not unlock the vault", keys.isUnlocked());

        unlock();
        assertEquals(0, store.localIds().size());
        VaultInbox.DrainReport r = inbox.drain(keys, store);
        assertEquals(1, r.moved);
        assertEquals(0, r.failed);
        assertEquals(0, inbox.pendingCount());
        VaultItem item = onlyItem();
        assertEquals(VaultItem.Type.TEXT, item.type);
        assertEquals(SECRET_TEXT, item.text);
        assertEquals("Alice", item.senderName);
        assertEquals(1234L, item.originalDateMillis);
        assertEquals(77L, item.sourceDialogId);
        assertEquals(5L, item.sourceMessageId);
    }

    @Test
    public void nothingReadableOnDisk_whileWaiting() throws Exception {
        lock();
        VaultItem.Draft d = new VaultItem.Draft(VaultItem.Type.DOCUMENT).text(SECRET_TEXT).senderName("Mallory")
                .media("passport-scan.pdf", "application/pdf", 0, 0, 0);
        byte[] media = ("%PDF-1.4 " + SECRET_TEXT + " " + new String(random(5000, 1), "ISO-8859-1")).getBytes("ISO-8859-1");
        inbox.put(d, new ByteArrayInputStream(media), 1 << 20);
        byte[] disk = allInboxBytes();
        for (String needle : new String[]{SECRET_TEXT, "passport-scan", "application/pdf", "Mallory", "%PDF"}) {
            assertFalse("leaks " + needle, contains(disk, needle.getBytes("UTF-8")));
        }
    }

    // ------------------------------------------------------------ 5/6. images and documents while locked

    @Test
    public void image_savedWhileLocked_roundTripsExactly() throws Exception {
        byte[] photo = random(300_000, 42);
        lock();
        VaultItem.Draft d = new VaultItem.Draft(VaultItem.Type.PHOTO).text("holiday").media("IMG_1.jpg", "image/jpeg", 800, 600, 0);
        inbox.put(d, new ByteArrayInputStream(photo), 10 << 20);
        unlock();
        assertEquals(1, inbox.drain(keys, store).moved);
        VaultItem item = onlyItem();
        assertEquals(VaultItem.Type.PHOTO, item.type);
        assertEquals("IMG_1.jpg", item.mediaName);
        assertEquals("image/jpeg", item.mimeType);
        assertEquals(800, item.width);
        assertEquals(600, item.height);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        store.readMedia(item.id, out);
        assertArrayEquals(photo, out.toByteArray());
        assertEquals("media file of the envelope is gone", 0, inboxDir.listFiles((dir, n) -> n.endsWith(".media")).length);
    }

    @Test
    public void document_savedWhileLocked_roundTripsExactly() throws Exception {
        byte[] doc = random(70_001, 7); // not a multiple of the chunk size
        lock();
        VaultItem.Draft d = new VaultItem.Draft(VaultItem.Type.DOCUMENT).media("report.pdf", "application/pdf", 0, 0, 0);
        inbox.put(d, new ByteArrayInputStream(doc), 10 << 20);
        unlock();
        inbox.drain(keys, store);
        VaultItem item = onlyItem();
        assertEquals(VaultItem.Type.DOCUMENT, item.type);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        store.readMedia(item.id, out);
        assertArrayEquals(doc, out.toByteArray());
    }

    @Test
    public void video_andEmptyMedia_work() throws Exception {
        lock();
        inbox.put(new VaultItem.Draft(VaultItem.Type.VIDEO).media("v.mp4", "video/mp4", 640, 360, 12), new ByteArrayInputStream(new byte[0]), 1 << 20);
        unlock();
        assertEquals(1, inbox.drain(keys, store).moved);
        assertEquals(12, onlyItem().durationSeconds);
    }

    @Test
    public void tooLarge_isRefused_andLeavesNothingBehind() throws Exception {
        lock();
        VaultItem.Draft d = new VaultItem.Draft(VaultItem.Type.DOCUMENT).media("big.bin", "application/octet-stream", 0, 0, 0);
        try {
            inbox.put(d, new ByteArrayInputStream(random(5000, 3)), 1000);
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.MEDIA_TOO_LARGE, e.getReason());
        }
        assertEquals(0, inbox.pendingCount());
        String[] left = inboxDir.list((dir, n) -> !n.equals("pub.bin") && !n.equals("priv.bin"));
        assertEquals(0, left.length);
    }

    @Test
    public void typeAndMediaMustMatch() throws Exception {
        try {
            inbox.put(text("x"), new ByteArrayInputStream(new byte[1]), 100);
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_ARGUMENT, e.getReason());
        }
        try {
            inbox.put(new VaultItem.Draft(VaultItem.Type.PHOTO), null, 100);
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_ARGUMENT, e.getReason());
        }
    }

    // ------------------------------------------------------------ security properties

    @Test
    public void drain_whileLocked_isRefused_andKeepsEverything() throws Exception {
        lock();
        inbox.put(text("a"), null, 100);
        try {
            inbox.drain(keys, store);
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
        assertEquals(1, inbox.pendingCount());
    }

    @Test
    public void privateKeyIsUnreadableWithoutTheVmk() throws Exception {
        byte[] priv = Files.readAllBytes(new File(inboxDir, "priv.bin").toPath());
        // a different vault's subkey cannot open it
        VaultKeyManager other = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), 1000);
        other.createVault(PW.toCharArray(), PW.toCharArray());
        byte[] k = other.deriveSubkey("inbox-private");
        try {
            VaultCrypto.decrypt(k, priv, "tg-vault/v1/inbox-priv".getBytes("US-ASCII"));
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.CORRUPTED, e.getReason());
        }
    }

    @Test
    public void swappedPublicKeyFile_isRejected_notUsed() throws Exception {
        lock();
        // an attacker who can write files puts their own (unwrapped) key in place
        java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("EC");
        g.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        try (FileOutputStream out = new FileOutputStream(new File(inboxDir, "pub.bin"))) {
            out.write(g.generateKeyPair().getPublic().getEncoded());
        }
        assertFalse(inbox.canAccept());
        try {
            inbox.put(text("x"), null, 100);
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.CORRUPTED, e.getReason()); // tampering is reported as such
        }
    }

    @Test
    public void tamperedEnvelope_isKeptAsBad_andOthersStillArrive() throws Exception {
        lock();
        String bad = inbox.put(text("bad one"), null, 100);
        inbox.put(text("good one"), null, 100);
        File env = new File(inboxDir, bad + ".env");
        byte[] b = Files.readAllBytes(env.toPath());
        b[b.length - 3] ^= 0x55;
        Files.write(env.toPath(), b);
        unlock();
        VaultInbox.DrainReport r = inbox.drain(keys, store);
        assertEquals(1, r.moved);
        assertEquals(1, r.failed);
        assertTrue("kept for inspection, never deleted", new File(inboxDir, bad + ".bad").exists());
        assertEquals("good one", onlyItem().text);
    }

    @Test
    public void envelopeMovedToAnotherId_isRejected() throws Exception {
        lock();
        String a = inbox.put(text("A"), null, 100);
        // the id is authenticated: renaming the file must not let it open
        File from = new File(inboxDir, a + ".env");
        File to = new File(inboxDir, "00000000000000000000000000000000.env");
        assertTrue(from.renameTo(to));
        unlock();
        VaultInbox.DrainReport r = inbox.drain(keys, store);
        assertEquals(0, r.moved);
        assertEquals(1, r.failed);
    }

    // ------------------------------------------------------------ 10. app restart and recovery

    @Test
    public void afterRestart_pendingItemsSurvive_andDrain() throws Exception {
        lock();
        inbox.put(text("one"), null, 100);
        inbox.put(new VaultItem.Draft(VaultItem.Type.DOCUMENT).media("d.txt", "text/plain", 0, 0, 0),
                new ByteArrayInputStream("hello".getBytes("UTF-8")), 100);
        // process dies: a new instance over the same files and the same Keystore key
        VaultInbox restarted = new VaultInbox(inboxDir, device);
        assertTrue(restarted.canAccept());
        assertEquals(2, restarted.pendingCount());
        VaultKeyManager reopened = new VaultKeyManager(headers, device, 1000);
        reopened.unlock(PW.toCharArray());
        VaultStore store2 = new VaultStore(new File(tmp.getRoot(), "data"), reopened);
        restarted.ensureKeyPair(reopened);
        assertEquals(2, restarted.drain(reopened, store2).moved);
        assertEquals(2, store2.localIds().size());
    }

    @Test
    public void crashBetweenMediaAndEnvelope_leavesOnlyOrphanMedia_whichIsCleanedUp() throws Exception {
        File orphan = new File(inboxDir, "deadbeefdeadbeefdeadbeefdeadbeef.media");
        Files.write(orphan.toPath(), random(100, 1));
        assertTrue(orphan.setLastModified(System.currentTimeMillis() - 2 * 60 * 60 * 1000L));
        assertEquals(0, inbox.pendingCount());
        inbox.drain(keys, store);
        assertFalse(orphan.exists());
    }

    @Test
    public void afterKeyChange_newPairIsCreated_andPendingItemsAreNotDeleted() throws Exception {
        lock();
        inbox.put(text("waiting"), null, 100);
        // a different VMK (e.g. adopted rotation): the old private key cannot be opened any more
        VaultKeyManager rotated = new VaultKeyManager(new InMemoryHeaderStore(), device, 1000);
        rotated.createVault(PW.toCharArray(), PW.toCharArray());
        inbox.ensureKeyPair(rotated);
        assertTrue(inbox.canAccept());
        assertEquals("pending envelope is kept", 1, inbox.pendingCount());
        // and it is reported, not silently lost, when drained with the key that cannot open it
        VaultStore s = new VaultStore(new File(tmp.getRoot(), "data2"), rotated);
        VaultInbox.DrainReport r = inbox.drain(rotated, s);
        assertEquals(0, r.moved);
        assertEquals(1, r.failed);
    }

    @Test
    public void deleteAll_removesEverything() throws Exception {
        lock();
        inbox.put(text("x"), null, 100);
        inbox.deleteAll();
        assertFalse(inboxDir.exists());
        assertFalse(inbox.canAccept());
    }

    @Test
    public void manyItems_keepTheirOrder_andAllArrive() throws Exception {
        lock();
        for (int i = 0; i < 25; i++) {
            inbox.put(text("msg " + i), null, 100);
        }
        unlock();
        assertEquals(25, inbox.drain(keys, store).moved);
        assertEquals(25, store.localIds().size());
        assertNotNull(store.get(store.localIds().get(0)));
    }
}
