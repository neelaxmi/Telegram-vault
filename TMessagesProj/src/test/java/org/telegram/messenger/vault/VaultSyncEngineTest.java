package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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
import java.util.ArrayList;
import java.util.List;

/** Sync between two simulated devices over a fake server. Nothing here talks to Telegram. */
public class VaultSyncEngineTest {

    private static final int ITER = 1000;
    private static final int CHUNK = 4096;
    private static final String PW = "device a password";
    private static final String PW_B = "device b password";

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private FakeRemoteStore remote;
    private Device a;
    private Device b;
    private String recoveryKey;
    private byte[] bundle;
    private long now = 1_000_000;

    private final class Device {
        final VaultKeyManager keys;
        final VaultStore store;
        final VaultSyncEngine engine;

        Device(String name, VaultKeyManager keys) throws Exception {
            this(name, keys, remote);
        }

        Device(String name, VaultKeyManager keys, FakeRemoteStore server) throws Exception {
            this.keys = keys;
            File dir = tmp.newFolder(name);
            store = new VaultStore(new File(dir, "vault"), keys, () -> now, CHUNK);
            engine = new VaultSyncEngine(store, keys, server, new File(dir, "journal"), () -> now);
        }
    }

    @Before
    public void setUp() throws Exception {
        remote = new FakeRemoteStore();
        VaultKeyManager ka = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), ITER);
        VaultKeyManager.Setup setup = ka.beginSetup(PW.toCharArray(), PW.toCharArray());
        recoveryKey = setup.recoveryKey().format();
        bundle = setup.complete(recoveryKey);
        a = new Device("a", ka);
        b = newDeviceFromBundle("b");
    }

    private Device newDeviceFromBundle(String name) throws Exception {
        VaultKeyManager k = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), ITER);
        k.restoreFromBundle(bundle, recoveryKey, PW_B.toCharArray(), PW_B.toCharArray(), false);
        return new Device(name, k);
    }

    private static byte[] data(int n, int seed) {
        byte[] d = new byte[n];
        for (int i = 0; i < n; i++) {
            d[i] = (byte) (i * 13 + seed);
        }
        return d;
    }

    private static VaultItem.Draft text(String s) {
        return new VaultItem.Draft(VaultItem.Type.TEXT).text(s);
    }

    private VaultItem addPhoto(Device d, byte[] media, byte[] thumb) throws Exception {
        VaultItem.Draft draft = new VaultItem.Draft(VaultItem.Type.PHOTO).text("cap").media("p.jpg", "image/jpeg", 10, 10, 0);
        return d.engine.addItem(draft, new ByteArrayInputStream(media), thumb);
    }

    private static byte[] media(Device d, String id) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        d.engine.openMedia(id, out);
        return out.toByteArray();
    }

    private static List<String> ids(Device d) throws Exception {
        List<String> r = new ArrayList<>();
        for (VaultItem i : d.store.list().items) {
            r.add(i.id);
        }
        java.util.Collections.sort(r);
        return r;
    }

    private static void syncOk(Device d) throws Exception {
        d.engine.sync();
    }

    // ------------------------------------------------------------------ basics

    @Test
    public void textItem_roundTripsToSecondDevice() throws Exception {
        VaultItem item = a.engine.addItem(text("hello"), null, null);
        VaultSyncEngine.SyncReport up = a.engine.sync();
        assertTrue(up.uploadedObjects >= 2); // bundle + record
        VaultSyncEngine.SyncReport down = b.engine.sync();
        assertEquals(1, down.downloadedRecords);
        assertEquals("hello", b.store.get(item.id).text);
        assertEquals(0, b.engine.pendingCount());
    }

    @Test
    public void bundleIsUploadedFirst() throws Exception {
        a.engine.addItem(text("x"), null, null);
        a.engine.sync();
        assertEquals("b.1", remote.names().get(0));
    }

    @Test
    public void photoWithThumbnail_uploadsThumbMediaThenRecord() throws Exception {
        VaultItem item = addPhoto(a, data(10000, 1), data(500, 2));
        a.engine.sync();
        List<String> names = remote.names();
        assertEquals("b.1", names.get(0));
        assertEquals("t." + item.thumbnailId, names.get(1));
        assertEquals("m." + item.mediaId, names.get(2));
        assertEquals("r." + item.id, names.get(3));
    }

    @Test
    public void media_isDownloadedOnDemandOnly() throws Exception {
        byte[] m = data(20000, 5);
        VaultItem item = addPhoto(a, m, data(300, 6));
        a.engine.sync();
        b.engine.sync();
        assertFalse(b.store.hasMediaFile(item.mediaId));
        assertFalse(b.store.hasMediaFile(item.thumbnailId));
        assertArrayEquals(data(300, 6), b.engine.readThumbnail(item.id));
        assertArrayEquals(m, media(b, item.id));
        assertTrue(b.store.hasMediaFile(item.mediaId));
    }

    @Test
    public void secondSync_isNoOp() throws Exception {
        a.engine.addItem(text("x"), null, null);
        a.engine.sync();
        int uploads = remote.uploadCalls;
        VaultSyncEngine.SyncReport r = a.engine.sync();
        assertEquals(0, r.uploadedObjects);
        assertEquals(uploads, remote.uploadCalls);
    }

    @Test
    public void bothDevicesAdd_bothConverge() throws Exception {
        a.engine.addItem(text("from a"), null, null);
        b.engine.addItem(text("from b"), null, null);
        syncOk(a);
        syncOk(b);
        syncOk(a);
        assertEquals(ids(a), ids(b));
        assertEquals(2, ids(a).size());
    }

    @Test
    public void localFilesNotCreatedThroughEngine_areAdopted() throws Exception {
        VaultItem item = a.store.addItem(text("direct"), null, null); // e.g. Phase-2 data
        assertEquals(1, a.engine.pendingCount());
        syncOk(a);
        syncOk(b);
        assertEquals("direct", b.store.get(item.id).text);
    }

    // ------------------------------------------------------------------ deletes

    @Test
    public void delete_propagatesAndRemovesRemoteObjects() throws Exception {
        VaultItem item = addPhoto(a, data(9000, 1), data(100, 2));
        syncOk(a);
        syncOk(b);
        assertTrue(a.engine.deleteItem(item.id));
        syncOk(a);
        assertEquals(0, remote.count("r." + item.id));
        assertEquals(0, remote.count("m." + item.mediaId));
        assertEquals(0, remote.count("t." + item.thumbnailId));
        assertEquals(1, remote.count("x." + item.id));
        VaultSyncEngine.SyncReport r = b.engine.sync();
        assertEquals(1, r.tombstonesApplied);
        assertNull(b.store.get(item.id));
    }

    @Test
    public void deletedItem_neverReturns_evenIfOldDeviceReuploads() throws Exception {
        VaultItem item = a.engine.addItem(text("secret"), null, null);
        syncOk(a);
        // b has it, then a deletes
        syncOk(b);
        a.engine.deleteItem(item.id);
        syncOk(a);
        // b is offline during the delete, then syncs: record is already gone from the server
        syncOk(b);
        assertNull(b.store.get(item.id));
        syncOk(b);
        syncOk(a);
        assertNull(a.store.get(item.id));
        assertNull(b.store.get(item.id));
    }

    @Test
    public void deleteBeforeFirstUpload_leavesNoTrace() throws Exception {
        VaultItem item = a.engine.addItem(text("oops"), null, null);
        assertTrue(a.engine.deleteItem(item.id));
        syncOk(a);
        assertEquals(0, remote.count("x." + item.id));
        assertEquals(0, remote.count("r." + item.id));
    }

    @Test
    public void tombstoneArrivingBeforeRecord_isRemembered() throws Exception {
        VaultItem item = a.engine.addItem(text("t"), null, null);
        syncOk(a);
        byte[] record = remote.bytesOf("r." + item.id);
        a.engine.deleteItem(item.id);
        syncOk(a);
        // an old copy of the record is re-injected after the tombstone
        remote.inject("r." + item.id, record);
        VaultSyncEngine.SyncReport r = b.engine.sync();
        assertNull(b.store.get(item.id));
        assertEquals(0, r.downloadedRecords);
        // and it is cleaned up again
        assertEquals(0, remote.count("r." + item.id));
    }

    // ------------------------------------------------------------------ hostile server

    @Test
    public void forgedRecord_isRejected() throws Exception {
        a.engine.addItem(text("real"), null, null);
        syncOk(a);
        String fakeId = "0123456789abcdef0123456789abcdef";
        remote.inject("r." + fakeId, data(200, 9));
        VaultSyncEngine.SyncReport r = b.engine.sync();
        assertEquals(1, r.rejectedRemote);
        assertEquals(1, ids(b).size());
    }

    @Test
    public void tamperedRecord_isRejected() throws Exception {
        VaultItem item = a.engine.addItem(text("real"), null, null);
        syncOk(a);
        remote.tamper("r." + item.id);
        VaultSyncEngine.SyncReport r = b.engine.sync();
        assertEquals(1, r.rejectedRemote);
        assertNull(b.store.get(item.id));
    }

    @Test
    public void forgedTombstone_isRejected() throws Exception {
        VaultItem item = a.engine.addItem(text("keep me"), null, null);
        syncOk(a);
        syncOk(b);
        remote.inject("x." + item.id, data(80, 3));
        VaultSyncEngine.SyncReport r = b.engine.sync();
        assertEquals(1, r.rejectedRemote);
        assertEquals("keep me", b.store.get(item.id).text);
    }

    @Test
    public void tombstoneForOtherId_isRejected() throws Exception {
        VaultItem one = a.engine.addItem(text("one"), null, null);
        VaultItem two = a.engine.addItem(text("two"), null, null);
        syncOk(a);
        a.engine.deleteItem(one.id);
        syncOk(a);
        remote.inject("x." + two.id, remote.bytesOf("x." + one.id)); // replayed under another name
        VaultSyncEngine.SyncReport r = b.engine.sync();
        assertEquals(1, r.rejectedRemote);
        assertEquals("two", b.store.get(two.id).text);
    }

    @Test
    public void oversizedRecord_isRejectedNotStored() throws Exception {
        a.engine.addItem(text("x"), null, null);
        syncOk(a);
        remote.inject("r.fedcba9876543210fedcba9876543210", new byte[9 * 1024 * 1024]);
        VaultSyncEngine.SyncReport r = b.engine.sync();
        assertEquals(1, r.rejectedRemote);
        assertTrue("download must stop at the cap", remote.maxDelivered < 9L * 1024 * 1024);
    }

    @Test
    public void unknownObjectNames_areIgnored() throws Exception {
        a.engine.addItem(text("x"), null, null);
        syncOk(a);
        remote.inject("zzz", data(10, 1));
        remote.inject("q.0123456789abcdef0123456789abcdef", data(10, 1));
        VaultSyncEngine.SyncReport r = b.engine.sync();
        assertEquals(2, r.ignoredUnknown);
    }

    @Test
    public void tamperedMedia_isRejectedOnOpen() throws Exception {
        VaultItem item = addPhoto(a, data(9000, 1), null);
        syncOk(a);
        syncOk(b);
        remote.tamper("m." + item.mediaId);
        try {
            media(b, item.id);
            fail("expected failure");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.CORRUPTED, e.getReason());
        }
        assertFalse(b.store.hasMediaFile(item.mediaId));
    }

    // ------------------------------------------------------------------ bundle

    @Test
    public void newerBundle_setsNeedsRestoreAndPushesNothing() throws Exception {
        a.engine.addItem(text("x"), null, null);
        syncOk(a);
        // A future epoch built by someone holding the same VMK: simulate with a bundle of higher version.
        byte[] newer = VaultBundle.create(VaultCrypto.randomBytes(32), a.keys.getVaultId(), 5, RecoveryKey.generate());
        remote.inject("b.5", newer);
        a.engine.addItem(text("later"), null, null);
        int uploads = remote.uploadCalls;
        VaultSyncEngine.SyncReport r = a.engine.sync();
        assertTrue(r.needsRestore);
        assertEquals(uploads, remote.uploadCalls);
    }

    @Test
    public void forgedBundle_isRejectedByAuthentication() throws Exception {
        a.engine.addItem(text("x"), null, null);
        syncOk(a);
        byte[] forged = bundle.clone();
        forged[forged.length - 1] ^= 1;
        remote.inject("b.9", forged);
        try {
            b.engine.sync();
            fail("expected CORRUPTED");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.CORRUPTED, e.getReason());
        }
    }

    @Test
    public void legacyVault_cannotSync() throws Exception {
        InMemoryHeaderStore hs = new InMemoryHeaderStore();
        TestDeviceKeyWrapper w = new TestDeviceKeyWrapper();
        LegacyHeaders.write(hs, w, "old pass".toCharArray(), ITER);
        VaultKeyManager k = new VaultKeyManager(hs, w, ITER);
        k.unlock("old pass".toCharArray());
        Device legacy = new Device("legacy", k);
        try {
            legacy.engine.sync();
            fail("expected INVALID_STATE");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
        assertEquals(0, remote.uploadCalls);
    }

    // ------------------------------------------------------------------ journal, verify, cache, limits

    @Test
    public void corruptedJournal_isRebuiltWithoutDuplicates() throws Exception {
        VaultItem item = addPhoto(a, data(5000, 1), data(100, 2));
        syncOk(a);
        syncOk(b);
        File journal = new File(tmp.getRoot(), "a/journal");
        assertTrue(journal.isFile());
        java.nio.file.Files.write(journal.toPath(), data(100, 9));
        VaultSyncEngine.SyncReport r = a.engine.sync();
        assertTrue(r.journalRebuilt);
        for (String n : remote.names()) {
            assertEquals(n, 1, remote.count(n));
        }
        assertEquals(0, a.engine.pendingCount());
        syncOk(b);
        assertEquals(ids(a), ids(b));
        assertNotNull(a.store.get(item.id));
    }

    @Test
    public void verifyRemote_requeuesObjectsThatVanished() throws Exception {
        VaultItem item = addPhoto(a, data(5000, 1), data(100, 2));
        syncOk(a);
        remote.removeByName("r." + item.id);
        remote.removeByName("m." + item.mediaId);
        VaultSyncEngine.SyncReport v = a.engine.verifyRemote();
        assertEquals(1, v.reuploadQueued.size());
        a.engine.sync();
        assertEquals(1, remote.count("r." + item.id));
        assertEquals(1, remote.count("m." + item.mediaId));
        syncOk(b);
        assertArrayEquals(data(5000, 1), media(b, item.id));
    }

    @Test
    public void verifyRemote_reportsLostMedia() throws Exception {
        VaultItem item = addPhoto(a, data(5000, 1), null);
        syncOk(a);
        a.store.evictMedia(item.id);
        remote.removeByName("m." + item.mediaId);
        VaultSyncEngine.SyncReport v = a.engine.verifyRemote();
        assertEquals(1, v.lostMedia.size());
        assertEquals(0, v.reuploadQueued.size());
    }

    @Test
    public void trimCache_evictsOldestSyncedFirst_andKeepsUnsynced() throws Exception {
        VaultItem old = addPhoto(a, data(8000, 1), null);
        VaultItem recent = addPhoto(a, data(8000, 2), null);
        syncOk(a);
        now += 1000;
        media(a, recent.id); // touch
        VaultItem unsynced = addPhoto(a, data(8000, 3), null);
        long one = a.store.mediaCipherFile(old.mediaId).length();
        long freed = a.engine.trimCache(one * 2); // three files held; must drop exactly one
        assertEquals(one, freed);
        assertFalse(a.store.hasMediaFile(old.mediaId));
        assertTrue(a.store.hasMediaFile(recent.mediaId));
        assertTrue(a.store.hasMediaFile(unsynced.mediaId));
        // evicted media comes back from the server
        assertArrayEquals(data(8000, 1), media(a, old.id));
        // even a zero budget never evicts what the server does not have
        a.engine.trimCache(0);
        assertTrue(a.store.hasMediaFile(unsynced.mediaId));
        assertFalse(a.store.hasMediaFile(old.mediaId));
    }

    @Test
    public void mediaLimit_refusesLargerFilesAndAcceptsExactLimit() throws Exception {
        a.store.setMaxUploadBytes(1024 * 1024);
        int max = (int) a.store.maxPlaintextBytes();
        assertTrue(max < 1024 * 1024 && max > 1024 * 1024 - 8192);
        VaultItem.Draft d = new VaultItem.Draft(VaultItem.Type.DOCUMENT).media("f.bin", "application/octet-stream", 0, 0, 0);
        VaultItem ok = a.engine.addItem(d, new ByteArrayInputStream(data(max, 1)), null);
        assertNotNull(ok);
        assertEquals(1024 * 1024, a.store.mediaCipherFile(ok.mediaId).length() + 0 * max, 0); // exactly at the limit
        try {
            a.engine.addItem(new VaultItem.Draft(VaultItem.Type.DOCUMENT).media("f.bin", "x/y", 0, 0, 0),
                    new ByteArrayInputStream(data(max + 1, 1)), null);
            fail("expected MEDIA_TOO_LARGE");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.MEDIA_TOO_LARGE, e.getReason());
        }
        assertEquals(1, a.store.list().items.size());
        assertEquals(1, a.store.localIds().size());
    }

    @Test
    public void importRecord_neverOverwritesExisting() throws Exception {
        VaultItem item = a.engine.addItem(text("orig"), null, null);
        byte[] bytes = java.nio.file.Files.readAllBytes(a.store.recordCipherFile(item.id).toPath());
        assertFalse(a.store.importRecord(item.id, bytes));
        assertEquals("orig", a.store.get(item.id).text);
    }

    @Test
    public void lockedVault_cannotSync() throws Exception {
        a.engine.addItem(text("x"), null, null);
        a.keys.lock();
        try {
            a.engine.sync();
            fail("expected INVALID_STATE");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
        assertEquals(0, remote.uploadCalls);
    }

    @Test
    public void lostAck_isDedupedByTokenEvenWhenListingLags() throws Exception {
        a.engine.addItem(text("x"), null, null);
        remote.listBlind = true;
        remote.failAtOp = 3; // list, upload(bundle), upload(record): the record's ack is lost
        remote.failAfterEffect = true;
        try {
            a.engine.sync();
            fail("expected IO_ERROR");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.IO_ERROR, e.getReason());
        }
        remote.clearFaults();
        a.engine.sync();
        remote.listBlind = false;
        for (String n : remote.names()) {
            assertEquals(n, 1, remote.count(n));
        }
        assertEquals(2, remote.names().size());
    }

    // ------------------------------------------------------------------ faults

    /** Every possible interruption point, with and without a lost acknowledgement. */
    @Test
    public void interruptionAtEveryStep_isRecoveredWithoutDuplicates() throws Exception {
        // Measure how many remote operations a full cycle takes.
        int total;
        {
            FakeRemoteStore probe = new FakeRemoteStore();
            Scenario s = new Scenario(probe);
            s.populate();
            s.syncUntilDone();
            total = probe.ops;
        }
        assertTrue(total > 10);
        for (int step = 1; step <= total; step++) {
            for (boolean afterEffect : new boolean[]{false, true}) {
                FakeRemoteStore r = new FakeRemoteStore();
                Scenario s = new Scenario(r);
                s.populate();
                r.failAtOp = step;
                r.failAfterEffect = afterEffect;
                try {
                    s.a.engine.sync();
                } catch (VaultCryptoException e) {
                    assertEquals("step " + step, VaultCryptoException.Reason.IO_ERROR, e.getReason());
                }
                r.clearFaults();
                s.syncUntilDone();
                String label = "step " + step + " afterEffect=" + afterEffect;
                for (String n : r.names()) {
                    assertEquals(label + " duplicate " + n, 1, r.count(n));
                }
                s.assertConverged(label);
            }
        }
    }

    @Test
    public void interruptionDuringDelete_isRecovered() throws Exception {
        int total;
        {
            FakeRemoteStore probe = new FakeRemoteStore();
            Scenario s = new Scenario(probe);
            s.populate();
            s.syncUntilDone();
            int before = probe.ops;
            s.a.engine.deleteItem(s.photo.id);
            s.a.engine.sync();
            total = probe.ops - before;
        }
        assertTrue(total >= 4);
        for (int step = 1; step <= total; step++) {
            for (boolean afterEffect : new boolean[]{false, true}) {
                FakeRemoteStore r = new FakeRemoteStore();
                Scenario s = new Scenario(r);
                s.populate();
                s.syncUntilDone();
                s.a.engine.deleteItem(s.photo.id);
                r.ops = 0;
                r.failAtOp = step;
                r.failAfterEffect = afterEffect;
                try {
                    s.a.engine.sync();
                } catch (VaultCryptoException e) {
                    assertEquals(VaultCryptoException.Reason.IO_ERROR, e.getReason());
                }
                r.clearFaults();
                s.syncUntilDone();
                String label = "delete step " + step + " afterEffect=" + afterEffect;
                assertEquals(label, 0, r.count("r." + s.photo.id));
                assertEquals(label, 0, r.count("m." + s.photo.mediaId));
                assertEquals(label, 0, r.count("t." + s.photo.thumbnailId));
                assertEquals(label, 1, r.count("x." + s.photo.id));
                assertNull(label, s.b.store.get(s.photo.id));
            }
        }
    }

    /** Two devices plus a fixed set of items, on a given server. */
    private final class Scenario {
        final FakeRemoteStore server;
        final Device a;
        final Device b;
        VaultItem photo;

        Scenario(FakeRemoteStore server) throws Exception {
            this.server = server;
            VaultKeyManager ka = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), ITER);
            VaultKeyManager.Setup setup = ka.beginSetup(PW.toCharArray(), PW.toCharArray());
            String rk = setup.recoveryKey().format();
            byte[] bun = setup.complete(rk);
            VaultKeyManager kb = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), ITER);
            kb.restoreFromBundle(bun, rk, PW_B.toCharArray(), PW_B.toCharArray(), false);
            this.a = new Device("sa" + System.nanoTime(), ka, server);
            this.b = new Device("sb" + System.nanoTime(), kb, server);
        }

        void populate() throws Exception {
            a.engine.addItem(text("one"), null, null);
            photo = addPhoto(a, data(9000, 4), data(200, 5));
            a.engine.addItem(text("two"), null, null);
        }

        void syncUntilDone() throws Exception {
            for (int i = 0; i < 3; i++) {
                a.engine.sync();
                b.engine.sync();
            }
        }

        void assertConverged(String label) throws Exception {
            assertEquals(label, ids(a), ids(b));
            assertEquals(label, 3, ids(a).size());
            assertEquals(label, 0, a.engine.pendingCount());
            assertEquals(label, 0, b.engine.pendingCount());
            assertArrayEquals(label, data(9000, 4), media(b, photo.id));
        }
    }
}
