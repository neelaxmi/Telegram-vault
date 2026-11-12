package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Key rotation (decision 9): new master key and recovery key, re-encrypted data, crash safety, other devices. */
public class KeyRotationTest {

    private static final int ITER = 1000;
    private static final int CHUNK = 4096;
    private static final String PW = "device a password";
    private static final String PW_B = "device b password";
    private static final String PW_B2 = "device b new password";

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private FakeRemoteStore remote;
    private String recoveryKey;
    private byte[] bundle;
    private Dev a;
    private Dev b;
    private long now = 5_000_000;

    private final class Dev {
        final InMemoryHeaderStore header = new InMemoryHeaderStore();
        final TestDeviceKeyWrapper wrapper = new TestDeviceKeyWrapper();
        final File dir;
        VaultKeyManager keys;
        VaultStore store;
        VaultSyncEngine engine;

        Dev(String name) throws Exception {
            dir = tmp.newFolder(name);
            keys = new VaultKeyManager(header, wrapper, ITER);
        }

        void build() {
            store = new VaultStore(new File(dir, "vault"), keys, () -> now, CHUNK);
            engine = new VaultSyncEngine(store, keys, remote, new File(dir, "journal"), () -> now);
        }

        /** App restart: a new key manager over the same persisted header, unlocked with the password. */
        void restart(String password) throws Exception {
            keys = new VaultKeyManager(header, wrapper, ITER);
            keys.unlock(password.toCharArray());
            build();
        }
    }

    @Before
    public void setUp() throws Exception {
        remote = new FakeRemoteStore();
        a = new Dev("a");
        VaultKeyManager.Setup setup = a.keys.beginSetup(PW.toCharArray(), PW.toCharArray());
        recoveryKey = setup.recoveryKey().format();
        bundle = setup.complete(recoveryKey);
        a.build();
        b = new Dev("b");
        b.keys.restoreFromBundle(bundle, recoveryKey, PW_B.toCharArray(), PW_B.toCharArray(), false);
        b.build();
    }

    private static byte[] data(int n, int seed) {
        byte[] d = new byte[n];
        for (int i = 0; i < n; i++) {
            d[i] = (byte) (i * 7 + seed);
        }
        return d;
    }

    private static VaultItem addText(Dev d, String t) throws Exception {
        return d.engine.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text(t), null, null);
    }

    private static VaultItem addPhoto(Dev d, byte[] media, byte[] thumb) throws Exception {
        return d.engine.addItem(new VaultItem.Draft(VaultItem.Type.PHOTO).text("cap").media("p.jpg", "image/jpeg", 1, 1, 0),
                new ByteArrayInputStream(media), thumb);
    }

    private static byte[] media(Dev d, String id) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        d.engine.openMedia(id, out);
        return out.toByteArray();
    }

    private static String rotate(Dev d, String password) throws Exception {
        VaultSyncEngine.RotationPlan plan = d.engine.beginKeyRotation(password.toCharArray());
        String key = plan.recoveryKey().format();
        d.engine.finishKeyRotation(plan, key);
        return key;
    }

    private static List<String> ids(Dev d) throws Exception {
        List<String> r = new ArrayList<>();
        for (VaultItem i : d.store.list().items) {
            r.add(i.id);
        }
        Collections.sort(r);
        return r;
    }

    // ------------------------------------------------------------------ the happy path

    @Test
    public void rotation_keepsEverythingReadableAndMovesTheServerToTheNewKey() throws Exception {
        VaultItem t = addText(a, "hello");
        byte[] m = data(10000, 3);
        VaultItem p = addPhoto(a, m, data(300, 4));
        a.engine.sync();
        byte[] vaultId = a.keys.getVaultId();
        byte[] oldBundle = a.keys.currentBundle();
        List<String> before = remote.names();
        assertTrue(before.contains("b.1"));

        String newKey = rotate(a, PW);
        assertNotEquals(recoveryKey, newKey);
        assertEquals(2, a.keys.getBundleVersion());
        assertArrayEquals(vaultId, a.keys.getVaultId());

        // Readable right away, before the server has been touched.
        assertEquals("hello", a.store.get(t.id).text);
        assertArrayEquals(m, media(a, p.id));
        assertArrayEquals(data(300, 4), a.store.readThumbnail(p.id));
        assertEquals(2, a.engine.pendingCount()); // the text item and the photo

        VaultSyncEngine.SyncReport r = a.engine.sync();
        assertFalse(r.needsRestore);
        assertEquals(0, a.engine.pendingCount());
        assertTrue(r.remoteObjectsDeleted >= 5); // old bundle, record x2, media, thumbnail

        List<String> after = remote.names();
        Collections.sort(after);
        List<String> expected = new ArrayList<>(java.util.Arrays.asList("b.2", "m." + p.mediaId, "r." + p.id, "r." + t.id, "t." + p.thumbnailId));
        Collections.sort(expected);
        assertEquals(expected, after);
        assertTrue(after.contains("b.2"));
        assertFalse(after.contains("b.1"));
        for (String n : after) {
            assertEquals(n, 1, remote.count(n));
        }
        // The old bundle's bytes are really gone from the server.
        assertFalse(java.util.Arrays.equals(oldBundle, remote.bytesOf("b.2")));
    }

    @Test
    public void newDeviceRestoresWithTheNewKeyAndGetsAllData() throws Exception {
        VaultItem t = addText(a, "kept");
        VaultItem p = addPhoto(a, data(9000, 1), null);
        a.engine.sync();
        String newKey = rotate(a, PW);
        a.engine.sync();

        Dev c = new Dev("c");
        byte[] latest = RemoteBundle.fetchLatest(remote);
        c.keys.restoreFromBundle(latest, newKey, PW_B.toCharArray(), PW_B.toCharArray(), false);
        c.build();
        c.engine.sync();
        assertEquals("kept", c.store.get(t.id).text);
        assertArrayEquals(data(9000, 1), media(c, p.id));
    }

    @Test
    public void oldRecoveryKeyNoLongerOpensAnything() throws Exception {
        addText(a, "x");
        a.engine.sync();
        rotate(a, PW);
        a.engine.sync();
        byte[] latest = RemoteBundle.fetchLatest(remote);
        Dev c = new Dev("c");
        try {
            c.keys.restoreFromBundle(latest, recoveryKey, PW_B.toCharArray(), PW_B.toCharArray(), false);
            fail("the old recovery key must not open the new bundle");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.WRONG_RECOVERY_KEY, e.getReason());
        }
        // and the old bundle is no longer on the server
        assertEquals(0, remote.count("b.1"));
    }

    @Test
    public void rotatedItemsAreEncryptedWithTheNewKeyOnly() throws Exception {
        VaultItem t = addText(a, "secret text");
        a.engine.sync();
        byte[] oldRecord = remote.bytesOf("r." + t.id);
        rotate(a, PW);
        a.engine.sync();
        byte[] newRecord = remote.bytesOf("r." + t.id);
        assertFalse(java.util.Arrays.equals(oldRecord, newRecord));
        // a device that only has the old key cannot import the new record
        try {
            b.store.importRecord(t.id, newRecord);
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.CORRUPTED, e.getReason());
        }
    }

    // ------------------------------------------------------------------ guards

    @Test
    public void wrongPasswordStopsBeforeAnythingChanges() throws Exception {
        addText(a, "x");
        a.engine.sync();
        try {
            a.engine.beginKeyRotation("not the password!".toCharArray());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.WRONG_PASSWORD, e.getReason());
        }
        assertEquals(1, a.keys.getBundleVersion());
    }

    @Test
    public void wrongTypedRecoveryKeyStopsBeforeAnythingChanges() throws Exception {
        VaultItem t = addText(a, "x");
        a.engine.sync();
        VaultSyncEngine.RotationPlan plan = a.engine.beginKeyRotation(PW.toCharArray());
        try {
            a.engine.finishKeyRotation(plan, RecoveryKey.generate().format());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.WRONG_RECOVERY_KEY, e.getReason());
        }
        assertEquals(1, a.keys.getBundleVersion());
        assertEquals("x", a.store.get(t.id).text);
        assertFalse(new File(a.dir, "vault/rotation").exists());
        // the same plan can still be completed with the right key
        a.engine.finishKeyRotation(plan, plan.recoveryKey().format());
        assertEquals(2, a.keys.getBundleVersion());
    }

    @Test
    public void unreadableItemBlocksRotation() throws Exception {
        VaultItem t = addText(a, "x");
        addText(a, "y");
        a.engine.sync();
        File rec = new File(a.dir, "vault/items/" + t.id + ".vrec");
        byte[] bytes = java.nio.file.Files.readAllBytes(rec.toPath());
        bytes[bytes.length - 1] ^= 1;
        java.nio.file.Files.write(rec.toPath(), bytes);
        try {
            a.engine.beginKeyRotation(PW.toCharArray());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
        assertEquals(1, a.keys.getBundleVersion());
    }

    @Test
    public void anotherDeviceAlreadyRotatedBlocksUs() throws Exception {
        addText(a, "x");
        a.engine.sync();
        b.engine.sync();
        rotate(a, PW);
        a.engine.sync();
        try {
            b.engine.beginKeyRotation(PW_B.toCharArray());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
    }

    @Test
    public void evictedMediaIsDownloadedFirstSoNothingIsLost() throws Exception {
        VaultItem p = addPhoto(a, data(20000, 9), data(100, 1));
        a.engine.sync();
        a.store.evictMedia(p.id);
        assertFalse(a.store.hasMediaFile(p.mediaId));
        String newKey = rotate(a, PW);
        a.engine.sync();
        assertEquals(0, a.engine.pendingCount());
        Dev c = new Dev("c");
        c.keys.restoreFromBundle(RemoteBundle.fetchLatest(remote), newKey, PW_B.toCharArray(), PW_B.toCharArray(), false);
        c.build();
        c.engine.sync();
        assertArrayEquals(data(20000, 9), media(c, p.id));
    }

    private String lastKey;

    // ------------------------------------------------------------------ the other device

    @Test
    public void otherDeviceNoticesThenAdoptsTheNewKeysAndGetsTheData() throws Exception {
        VaultItem t = addText(a, "shared");
        a.engine.sync();
        b.engine.sync();
        assertEquals("shared", b.store.get(t.id).text);

        String newKey = rotate(a, PW);
        VaultItem later = addText(a, "after rotation");
        a.engine.sync();

        VaultSyncEngine.SyncReport r = b.engine.sync();
        assertTrue(r.needsRestore);
        assertEquals(0, remote.count("b.1"));

        byte[] latest = RemoteBundle.fetchLatest(remote);
        b.engine.adoptNewKeyEpoch(latest, newKey, PW_B2.toCharArray(), PW_B2.toCharArray());
        assertEquals(2, b.keys.getBundleVersion());
        assertEquals(0, b.store.count());
        VaultSyncEngine.SyncReport r2 = b.engine.sync();
        assertFalse(r2.needsRestore);
        assertFalse("the old journal must have been removed, not merely unreadable", r2.journalRebuilt);
        assertEquals("shared", b.store.get(t.id).text);
        assertEquals("after rotation", b.store.get(later.id).text);
        // it can unlock with the new password after a restart
        b.restart(PW_B2);
        assertEquals("shared", b.store.get(t.id).text);
    }

    @Test
    public void adoptingWithTheWrongRecoveryKeyDeletesNothing() throws Exception {
        VaultItem t = addText(a, "shared");
        a.engine.sync();
        b.engine.sync();
        rotate(a, PW);
        a.engine.sync();
        assertTrue(b.engine.sync().needsRestore);
        byte[] latest = RemoteBundle.fetchLatest(remote);
        try {
            b.engine.adoptNewKeyEpoch(latest, recoveryKey /* the OLD key */, PW_B2.toCharArray(), PW_B2.toCharArray());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.WRONG_RECOVERY_KEY, e.getReason());
        }
        assertEquals("shared", b.store.get(t.id).text);
        assertEquals(1, b.keys.getBundleVersion());
    }

    @Test
    public void adoptingWithABadPasswordDeletesNothing() throws Exception {
        VaultItem t = addText(a, "shared");
        a.engine.sync();
        b.engine.sync();
        String newKey = rotate(a, PW);
        a.engine.sync();
        assertTrue(b.engine.sync().needsRestore);
        byte[] latest = RemoteBundle.fetchLatest(remote);
        try {
            b.engine.adoptNewKeyEpoch(latest, newKey, "short".toCharArray(), "short".toCharArray());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_ARGUMENT, e.getReason());
        }
        assertEquals("shared", b.store.get(t.id).text);
    }

    @Test
    public void adoptingABundleThatIsNotNewerIsRefused() throws Exception {
        addText(a, "x");
        a.engine.sync();
        b.engine.sync();
        try {
            b.engine.adoptNewKeyEpoch(bundle, recoveryKey, PW_B2.toCharArray(), PW_B2.toCharArray());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
        assertEquals(1, b.store.count());
    }

    @Test
    public void objectFromAStaleDeviceAfterRotationIsRejectedNotImported() throws Exception {
        addText(a, "x");
        a.engine.sync();
        b.engine.sync();
        VaultItem staleItem = addText(b, "written by the stale device");
        byte[] staleRecord = java.nio.file.Files.readAllBytes(new File(b.dir, "vault/items/" + staleItem.id + ".vrec").toPath());
        rotate(a, PW);
        a.engine.sync();
        remote.inject("r." + staleItem.id, staleRecord);
        VaultSyncEngine.SyncReport r = a.engine.sync();
        assertTrue(r.rejectedRemote >= 1);
        assertEquals(1, a.store.count());
    }

    // ------------------------------------------------------------------ server trouble during the re-upload

    @Test
    public void interruptedReuploadResumesAndOldObjectsStayUntilTheNewOnesAreComplete() throws Exception {
        addText(a, "one");
        addText(a, "two");
        VaultItem p = addPhoto(a, data(9000, 2), data(200, 2));
        a.engine.sync();
        rotate(a, PW);
        List<String> oldNames = remote.names();

        // fail somewhere in the middle of the re-upload, several times
        for (int fail = 3; fail < 40 && a.engine.pendingCount() > 0; fail += 4) {
            remote.ops = 0;
            remote.failAtOp = fail;
            try {
                a.engine.sync();
            } catch (VaultCryptoException expected) {
                assertEquals(VaultCryptoException.Reason.IO_ERROR, expected.getReason());
            }
            remote.clearFaults();
            // while anything is still pending, the old copy must still be on the server
            if (a.engine.pendingCount() > 0) {
                assertTrue("old data must remain until the new copy is complete", remote.names().containsAll(oldNames));
            }
        }
        remote.clearFaults();
        a.engine.sync();
        assertEquals(0, a.engine.pendingCount());
        for (String n : remote.names()) {
            assertEquals(n, 1, remote.count(n));
        }
        assertEquals(6, remote.names().size()); // b.2, two records, and the photo's thumbnail, media and record
        assertTrue(remote.names().contains("m." + p.mediaId));
    }

    @Test
    public void lostAcknowledgementDuringReuploadDoesNotDuplicate() throws Exception {
        addText(a, "one");
        a.engine.sync();
        rotate(a, PW);
        remote.ops = 0;
        remote.failAtOp = 3;
        remote.failAfterEffect = true;
        try {
            a.engine.sync();
        } catch (VaultCryptoException ignored) {
            // expected
        }
        remote.clearFaults();
        remote.failAfterEffect = false;
        a.engine.sync();
        for (String n : remote.names()) {
            assertEquals(n, 1, remote.count(n));
        }
    }

    // ------------------------------------------------------------------ crash safety

    private void crashAt(final String stage) throws Exception {
        a.engine.rotationFault = s -> {
            if (s.equals(stage)) {
                throw new IllegalStateException("simulated crash at " + stage);
            }
        };
        VaultSyncEngine.RotationPlan plan = a.engine.beginKeyRotation(PW.toCharArray());
        lastKey = plan.recoveryKey().format();
        try {
            a.engine.finishKeyRotation(plan, lastKey);
            fail("crash expected");
        } catch (IllegalStateException expected) {
            // the process "died" here
        }
    }

    @Test
    public void crashAfterStaging_rollsBackAndKeepsTheOldKeys() throws Exception {
        VaultItem t = addText(a, "x");
        a.engine.sync();
        crashAt("staged");
        a.restart(PW);
        assertFalse(a.engine.recoverInterruptedRotation());
        assertEquals(1, a.keys.getBundleVersion());
        assertEquals("x", a.store.get(t.id).text);
        assertFalse(new File(a.dir, "vault/rotation").exists());
        a.engine.sync();
        assertEquals(0, a.engine.pendingCount());
    }

    @Test
    public void crashAfterMarkerBeforeHeader_rollsBack() throws Exception {
        VaultItem t = addText(a, "x");
        a.engine.sync();
        crashAt("marked");
        a.restart(PW);
        assertFalse(a.engine.recoverInterruptedRotation());
        assertEquals(1, a.keys.getBundleVersion());
        assertEquals("x", a.store.get(t.id).text);
    }

    @Test
    public void crashAfterHeaderBeforeSwap_isCompletedOnRestart() throws Exception {
        VaultItem t = addText(a, "x");
        VaultItem p = addPhoto(a, data(7000, 5), data(100, 5));
        a.engine.sync();
        crashAt("committed");
        // The header already holds the new key but the data directories still hold the old ciphertext.
        a.restart(PW);
        assertEquals(2, a.keys.getBundleVersion());
        assertTrue(a.engine.recoverInterruptedRotation());
        assertEquals("x", a.store.get(t.id).text);
        assertArrayEquals(data(7000, 5), media(a, p.id));
        assertFalse(new File(a.dir, "vault/rotation").exists());
        a.engine.sync();
        assertEquals(0, a.engine.pendingCount());
        assertEquals(0, remote.count("b.1"));
        assertEquals(1, remote.count("b.2"));
    }

    @Test
    public void crashInTheMiddleOfTheSwap_isCompletedOnRestart() throws Exception {
        VaultItem t = addText(a, "x");
        VaultItem p = addPhoto(a, data(7000, 6), null);
        a.engine.sync();
        crashAt("adopted");
        a.restart(PW);
        assertTrue(a.engine.recoverInterruptedRotation());
        assertEquals("x", a.store.get(t.id).text);
        assertArrayEquals(data(7000, 6), media(a, p.id));
        a.engine.sync();
        assertEquals(0, a.engine.pendingCount());
        assertEquals(0, remote.count("b.1"));
    }

    @Test
    public void engineCompletesAnInterruptedRotationBeforeEvenSyncing() throws Exception {
        VaultItem t = addText(a, "x");
        a.engine.sync();
        crashAt("committed");
        a.restart(PW);
        // the first thing an app does after unlocking is sync: it must work on the new key
        a.engine.recoverInterruptedRotation();
        a.engine.sync();
        assertEquals("x", a.store.get(t.id).text);
    }

    @Test
    public void staleStagingWithoutMarkerIsRemoved() throws Exception {
        addText(a, "x");
        a.engine.sync();
        File junk = new File(a.dir, "vault/rotation/items");
        assertTrue(junk.mkdirs());
        assertFalse(a.engine.recoverInterruptedRotation());
        assertFalse(new File(a.dir, "vault/rotation").exists());
    }

    @Test
    public void markerThatDoesNotMatchTheVaultIsReportedNotGuessed() throws Exception {
        addText(a, "x");
        a.engine.sync();
        File dir = new File(a.dir, "vault/rotation");
        assertTrue(dir.mkdirs());
        byte[] marker = {'R', 'O', 'T', '1', 0, 0, 0, 9};
        java.nio.file.Files.write(new File(dir, "COMMIT").toPath(), marker);
        try {
            a.engine.recoverInterruptedRotation();
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.CORRUPTED, e.getReason());
        }
    }

    // ------------------------------------------------------------------ rotating twice, journal format

    @Test
    public void canRotateTwiceInARow() throws Exception {
        VaultItem t = addText(a, "x");
        a.engine.sync();
        rotate(a, PW);
        a.engine.sync();
        String k3 = rotate(a, PW);
        a.engine.sync();
        assertEquals(3, a.keys.getBundleVersion());
        assertEquals("x", a.store.get(t.id).text);
        assertEquals(1, remote.names().size() - 1); // bundle b.3 + one record
        assertTrue(remote.names().contains("b.3"));
        Dev c = new Dev("c");
        c.keys.restoreFromBundle(RemoteBundle.fetchLatest(remote), k3, PW_B.toCharArray(), PW_B.toCharArray(), false);
        c.build();
        c.engine.sync();
        assertEquals("x", c.store.get(t.id).text);
    }

    @Test
    public void rotationAfterADeleteDoesNotResurrectTheItem() throws Exception {
        VaultItem keep = addText(a, "keep");
        VaultItem gone = addText(a, "gone");
        a.engine.sync();
        b.engine.sync();
        a.engine.deleteItem(gone.id);
        a.engine.sync();
        rotate(a, PW);
        a.engine.sync();
        assertEquals(java.util.Arrays.asList(keep.id), ids(a));
        assertEquals(0, remote.count("r." + gone.id));
        assertEquals(0, remote.count("x." + gone.id));
    }

    @Test
    public void journalWithRetiredRefsSurvivesARestart() throws Exception {
        addText(a, "x");
        a.engine.sync();
        rotate(a, PW);
        a.restart(PW);
        a.engine.sync();
        assertEquals(0, a.engine.pendingCount());
        assertEquals(0, remote.count("b.1"));
    }

    @Test
    public void journalOfTheOlderFormatIsStillReadable() throws Exception {
        SyncJournal j = new SyncJournal();
        j.cursor = 7;
        j.refs.put("r." + "a".repeat(32), "ref9");
        byte[] key = VaultCrypto.randomBytes(32);
        File f = tmp.newFile("old-journal");
        j.save(f, key);
        // turn it into a version-1 file: drop the trailing "retired" count and change the version byte
        byte[] content = java.nio.file.Files.readAllBytes(f.toPath());
        byte[] blob = java.util.Arrays.copyOfRange(content, 5, content.length);
        byte[] aad = "tg-vault/journal/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] payload = VaultCrypto.decrypt(key, blob, aad);
        byte[] shorter = java.util.Arrays.copyOf(payload, payload.length - 4);
        byte[] reblob = VaultCrypto.encrypt(key, shorter, aad);
        byte[] v1 = new byte[5 + reblob.length];
        System.arraycopy(content, 0, v1, 0, 5);
        v1[4] = 1;
        System.arraycopy(reblob, 0, v1, 5, reblob.length);
        java.nio.file.Files.write(f.toPath(), v1);
        SyncJournal loaded = SyncJournal.load(f, key);
        assertEquals(7, loaded.cursor);
        assertEquals("ref9", loaded.refs.get("r." + "a".repeat(32)));
        assertTrue(loaded.retired.isEmpty());
    }

    // ------------------------------------------------------------------ key manager level

    @Test
    public void keyManagerRefusesToCommitAnUnconfirmedRotation() throws Exception {
        VaultKeyManager.Rotation r = a.keys.beginRotation(PW.toCharArray());
        try {
            a.keys.commitRotation(r);
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
        assertEquals(1, a.keys.getBundleVersion());
        // a wrong confirmation does not unlock it either
        try {
            r.confirm(RecoveryKey.generate().format());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.WRONG_RECOVERY_KEY, e.getReason());
        }
        try {
            a.keys.commitRotation(r);
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
    }

    @Test
    public void aRotationCannotBeCommittedTwiceOrAfterTheVaultMovedOn() throws Exception {
        VaultKeyManager.Rotation r = a.keys.beginRotation(PW.toCharArray());
        r.confirm(r.recoveryKey().format());
        VaultKeyManager.Rotation stale = a.keys.beginRotation(PW.toCharArray());
        stale.confirm(stale.recoveryKey().format());
        a.keys.commitRotation(r);
        try {
            a.keys.commitRotation(r);
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
        try {
            a.keys.commitRotation(stale); // made for bundle version 2, but we are at 2 now
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
        assertEquals(2, a.keys.getBundleVersion());
    }

    @Test
    public void damagedMediaStopsTheRotationAndLeavesTheOldDataAlone() throws Exception {
        VaultItem p = addPhoto(a, data(20000, 3), data(100, 1));
        VaultItem t = addText(a, "x");
        a.engine.sync();
        File mediaFile = new File(a.dir, "vault/media/" + p.mediaId + ".vmed");
        byte[] bytes = java.nio.file.Files.readAllBytes(mediaFile.toPath());
        bytes[bytes.length / 2] ^= 1;
        java.nio.file.Files.write(mediaFile.toPath(), bytes);
        VaultSyncEngine.RotationPlan plan = a.engine.beginKeyRotation(PW.toCharArray());
        try {
            a.engine.finishKeyRotation(plan, plan.recoveryKey().format());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.CORRUPTED, e.getReason());
        }
        assertEquals(1, a.keys.getBundleVersion());
        assertEquals("x", a.store.get(t.id).text);
        assertFalse(new File(a.dir, "vault/rotation").exists());
    }

    @Test
    public void recoveryWorksWithoutAnEngine_asTheRuntimeDoesRightAfterUnlock() throws Exception {
        VaultItem t = addText(a, "x");
        a.engine.sync();
        crashAt("committed");
        a.restart(PW);
        assertTrue(VaultSyncEngine.recoverRotation(a.store, a.keys, new File(a.dir, "journal")));
        assertEquals("x", a.store.get(t.id).text);
        assertFalse(VaultSyncEngine.recoverRotation(a.store, a.keys, new File(a.dir, "journal")));
    }

    @Test
    public void localWipeAlsoRemovesAHalfFinishedRotationsStagedCopy() throws Exception {
        addText(a, "x");
        a.engine.sync();
        crashAt("marked");
        assertTrue(new File(a.dir, "vault/rotation").exists());
        a.store.deleteAllData();
        assertFalse(new File(a.dir, "vault/rotation").exists());
    }
}
