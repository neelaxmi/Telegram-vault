package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class FileVaultHeaderStoreTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private FileVaultHeaderStore newStore() throws IOException {
        return new FileVaultHeaderStore(new File(tmp.getRoot(), "vault/header.bin"));
    }

    @Test
    public void emptyStore_doesNotExist_andReadFails() throws Exception {
        FileVaultHeaderStore store = newStore();
        assertFalse(store.exists());
        try {
            store.read();
            fail("expected IOException");
        } catch (IOException expected) {
            // ok
        }
    }

    @Test
    public void writeThenRead_roundTrips_andCreatesParentDirectories() throws Exception {
        FileVaultHeaderStore store = newStore();
        byte[] data = new byte[85];
        Arrays.fill(data, (byte) 0x5a);
        store.write(data);
        assertTrue(store.exists());
        assertArrayEquals(data, store.read());
    }

    @Test
    public void write_replacesPreviousContent_andLeavesNoTempFile() throws Exception {
        FileVaultHeaderStore store = newStore();
        store.write(new byte[]{1, 2, 3});
        store.write(new byte[]{9, 8, 7, 6});
        assertArrayEquals(new byte[]{9, 8, 7, 6}, store.read());
        String[] files = new File(tmp.getRoot(), "vault").list();
        assertEquals(Arrays.toString(files), 1, files.length);
        assertEquals("header.bin", files[0]);
    }

    @Test
    public void delete_removesHeader_andIsIdempotent() throws Exception {
        FileVaultHeaderStore store = newStore();
        store.write(new byte[]{1, 2, 3});
        store.delete();
        assertFalse(store.exists());
        store.delete(); // second delete must not fail
        assertFalse(store.exists());
        assertEquals(0, new File(tmp.getRoot(), "vault").list().length);
    }

    @Test
    public void delete_overwritesContentBeforeUnlinking() throws Exception {
        File file = new File(tmp.getRoot(), "vault/header.bin");
        FileVaultHeaderStore store = new FileVaultHeaderStore(file);
        store.write(new byte[]{1, 2, 3, 4, 5, 6, 7, 8});
        // A second hard link keeps the inode alive after delete(), exposing what was left in the data blocks.
        File link = new File(tmp.getRoot(), "vault/link.bin");
        try {
            java.nio.file.Files.createLink(link.toPath(), file.toPath());
        } catch (UnsupportedOperationException | IOException e) {
            return; // filesystem without hard links: nothing to verify
        }
        store.delete();
        assertFalse(file.exists());
        assertArrayEquals(new byte[8], java.nio.file.Files.readAllBytes(link.toPath()));
    }

    @Test
    public void read_rejectsEmptyAndOversizedFiles() throws Exception {
        File file = new File(tmp.getRoot(), "vault/header.bin");
        FileVaultHeaderStore store = new FileVaultHeaderStore(file);
        assertTrue(file.getParentFile().mkdirs());

        assertTrue(file.createNewFile()); // zero bytes
        try {
            store.read();
            fail("expected IOException for empty file");
        } catch (IOException expected) {
            // ok
        }

        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(new byte[64 * 1024 + 1]);
        }
        try {
            store.read();
            fail("expected IOException for oversized file");
        } catch (IOException expected) {
            // ok
        }
    }
}
