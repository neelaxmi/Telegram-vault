package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;

/** Data written by Phases 1-2 must survive the move to the account-wide key architecture untouched. */
public class VaultMigrationTest {

    private static final int ITER = 1000;
    private static final int CHUNK = 4096;
    private static final String OLD = "old pass";
    private static final String NEW = "a brand new password";

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private InMemoryHeaderStore headers;
    private TestDeviceKeyWrapper device;
    private VaultKeyManager manager;
    private File root;

    @Before
    public void setUp() throws Exception {
        headers = new InMemoryHeaderStore();
        device = new TestDeviceKeyWrapper();
        LegacyHeaders.write(headers, device, OLD.toCharArray(), ITER);
        manager = new VaultKeyManager(headers, device, ITER);
        manager.unlock(OLD.toCharArray());
        root = new File(tmp.getRoot(), "vault");
    }

    private VaultStore storeFor(File dir, VaultKeyManager m) {
        return new VaultStore(dir, m, System::currentTimeMillis, CHUNK);
    }

    private static byte[] media(int size) {
        byte[] b = new byte[size];
        for (int i = 0; i < size; i++) {
            b[i] = (byte) (i * 31 + 7);
        }
        return b;
    }

    private static byte[] readAll(VaultStore s, String id) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        s.readMedia(id, out);
        return out.toByteArray();
    }

    private static Map<String, String> snapshot(File dir) throws Exception {
        Map<String, String> out = new TreeMap<>();
        collect(dir, dir, out);
        return out;
    }

    private static void collect(File base, File f, Map<String, String> out) throws Exception {
        File[] children = f.listFiles();
        if (children == null) {
            return;
        }
        for (File c : children) {
            if (c.isDirectory()) {
                collect(base, c, out);
            } else {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                out.put(base.toURI().relativize(c.toURI()).getPath(), Arrays.toString(md.digest(Files.readAllBytes(c.toPath()))));
            }
        }
    }

    private static void copyTree(File from, File to) throws IOException {
        to.mkdirs();
        File[] children = from.listFiles();
        if (children == null) {
            return;
        }
        for (File c : children) {
            File target = new File(to, c.getName());
            if (c.isDirectory()) {
                copyTree(c, target);
            } else {
                Files.copy(c.toPath(), target.toPath());
            }
        }
    }

    @Test
    public void migration_doesNotTouchASingleStoredByte_andAllItemsStayReadable() throws Exception {
        VaultStore store = storeFor(root, manager);
        VaultItem text = store.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("old secret note"), null, null);
        byte[] photo = media(10_000);
        VaultItem pic = store.addItem(new VaultItem.Draft(VaultItem.Type.PHOTO).text("caption").media("p.jpg", "image/jpeg", 10, 10, 0),
                new ByteArrayInputStream(photo), new byte[]{1, 2, 3, 4});
        byte[] video = media(3 * CHUNK + 17);
        VaultItem vid = store.addItem(new VaultItem.Draft(VaultItem.Type.VIDEO).media("v.mp4", "video/mp4", 640, 480, 9),
                new ByteArrayInputStream(video), null);
        Map<String, String> before = snapshot(root);
        assertFalse(before.isEmpty());

        VaultKeyManager.Setup setup = manager.beginMigration(OLD.toCharArray(), NEW.toCharArray(), NEW.toCharArray());
        String recoveryText = setup.recoveryKey().format();
        byte[] bundle = setup.complete(recoveryText);

        assertEquals("not one vault file changed", before, snapshot(root));
        assertEquals(3, store.list().items.size());
        assertEquals("old secret note", store.get(text.id).text);
        assertArrayEquals(photo, readAll(store, pic.id));
        assertArrayEquals(video, readAll(store, vid.id));
        assertArrayEquals(new byte[]{1, 2, 3, 4}, store.readThumbnail(pic.id));

        // After an app restart: new password on the same header store and device key.
        VaultKeyManager restarted = new VaultKeyManager(headers, device, ITER);
        restarted.unlock(NEW.toCharArray());
        VaultStore reopened = storeFor(root, restarted);
        assertEquals(3, reopened.list().items.size());
        assertArrayEquals(video, readAll(reopened, vid.id));

        // A second device with a copy of the encrypted files, the bundle and the recovery key.
        File copy = new File(tmp.getRoot(), "second-device");
        copyTree(root, copy);
        VaultKeyManager second = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), ITER);
        second.restoreFromBundle(bundle, recoveryText, "another device pass".toCharArray(), "another device pass".toCharArray(), false);
        VaultStore secondStore = storeFor(copy, second);
        assertEquals("old secret note", secondStore.get(text.id).text);
        assertArrayEquals(photo, readAll(secondStore, pic.id));
        assertArrayEquals(video, readAll(secondStore, vid.id));
    }

    @Test
    public void filesCopiedWithoutBundleOrRecoveryKey_stayUnreadable() throws Exception {
        VaultStore store = storeFor(root, manager);
        VaultItem text = store.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("private"), null, null);
        VaultKeyManager.Setup setup = manager.beginMigration(OLD.toCharArray(), NEW.toCharArray(), NEW.toCharArray());
        setup.complete(setup.recoveryKey().format());

        File copy = new File(tmp.getRoot(), "stolen");
        copyTree(root, copy);
        // An attacker creates their own vault: different keys, nothing opens.
        VaultKeyManager attacker = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), ITER);
        attacker.createVault(NEW.toCharArray(), NEW.toCharArray());
        VaultStore attackerStore = storeFor(copy, attacker);
        VaultStore.Listing listing = attackerStore.list();
        assertTrue(listing.items.isEmpty());
        assertEquals(Arrays.asList(text.id), listing.corruptIds);
    }

    @Test
    public void interruptedMigration_leavesTheOldVaultFullyUsable() throws Exception {
        VaultStore store = storeFor(root, manager);
        VaultItem text = store.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("survives"), null, null);
        VaultKeyManager.Setup setup = manager.beginMigration(OLD.toCharArray(), NEW.toCharArray(), NEW.toCharArray());
        String recoveryText = setup.recoveryKey().format();
        headers.failWrites = true;
        try {
            setup.complete(recoveryText);
            fail("write failure expected");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.IO_ERROR, e.getReason());
        }
        headers.failWrites = false;
        VaultKeyManager restarted = new VaultKeyManager(headers, device, ITER);
        restarted.unlock(OLD.toCharArray());
        assertTrue(restarted.isLegacyHeader());
        assertEquals("survives", storeFor(root, restarted).get(text.id).text);
    }

    // ------------------------------------------------------------ records from a newer app version

    private VaultItem seedFutureRecord(VaultStore store, boolean outerVersion) throws Exception {
        VaultItem item = store.addItem(new VaultItem.Draft(VaultItem.Type.PHOTO).text("future").media("f.jpg", "image/jpeg", 1, 1, 0),
                new ByteArrayInputStream(media(500)), null);
        File record = new File(root, "items/" + item.id + ".vrec");
        byte[] content = Files.readAllBytes(record.toPath());
        if (outerVersion) {
            content[4] = 2; // container format version
        } else {
            byte[] key = manager.deriveSubkey("messages");
            byte[] aad = ("tg-vault/record/v1/" + item.id).getBytes(StandardCharsets.US_ASCII);
            byte[] padded = VaultCrypto.decrypt(key, Arrays.copyOfRange(content, 5, content.length), aad);
            padded[4] = 9; // item format version inside the encrypted payload
            byte[] blob = VaultCrypto.encrypt(key, padded, aad);
            content = Arrays.copyOf(content, 5 + blob.length);
            System.arraycopy(blob, 0, content, 5, blob.length);
        }
        Files.write(record.toPath(), content);
        return item;
    }

    @Test
    public void recordsFromANewerAppVersion_areReportedAsUnsupported_notCorrupted() throws Exception {
        VaultStore store = storeFor(root, manager);
        VaultItem normal = store.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("normal"), null, null);
        VaultItem innerNewer = seedFutureRecord(store, false);
        VaultItem outerNewer = seedFutureRecord(store, true);

        VaultStore.Listing listing = store.list();
        assertEquals(1, listing.items.size());
        assertEquals(normal.id, listing.items.get(0).id);
        assertTrue(listing.corruptIds.isEmpty());
        assertEquals(2, listing.unsupportedIds.size());
        assertTrue(listing.unsupportedIds.contains(innerNewer.id));
        assertTrue(listing.unsupportedIds.contains(outerNewer.id));
    }

    @Test
    public void unsupportedRecords_andTheirMedia_areNeverCleanedUpOrDeleted() throws Exception {
        VaultStore store = storeFor(root, manager);
        VaultItem future = seedFutureRecord(store, false);
        Map<String, String> before = snapshot(root);

        assertEquals("no unreferenced-media cleanup while a record cannot be read", 0, store.removeOrphans());
        try {
            store.delete(future.id);
            fail("deleting a record this app cannot read must not silently succeed");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.UNSUPPORTED_VERSION, e.getReason());
        }
        assertEquals(before, snapshot(root));
    }
}
