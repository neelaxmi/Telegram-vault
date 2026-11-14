package org.telegram.messenger.vault;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;

public class VaultTempFilesTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void create_keepsNameAndExtension_inItsOwnFolder() throws Exception {
        VaultTempFiles t = new VaultTempFiles(new File(tmp.getRoot(), "open"));
        File a = t.create("Report 2026.pdf");
        File b = t.create("Report 2026.pdf");
        assertEquals("Report 2026.pdf", a.getName());
        assertNotEquals(a.getParentFile(), b.getParentFile());
        assertTrue(a.getParentFile().getParentFile().equals(t.directory()));
    }

    @Test
    public void wipeAll_overwritesAndRemovesEverything() throws Exception {
        VaultTempFiles t = new VaultTempFiles(new File(tmp.getRoot(), "open"));
        File a = t.create("a.mp4");
        try (FileOutputStream o = new FileOutputStream(a)) {
            o.write(new byte[200_000]);
        }
        assertFalse(t.isEmpty());
        t.wipeAll();
        assertFalse(a.exists());
        assertTrue(t.isEmpty());
        t.wipeAll(); // twice is fine
    }

    @Test
    public void wipeAll_whenFolderDoesNotExist_isFine() {
        new VaultTempFiles(new File(tmp.getRoot(), "none")).wipeAll();
    }

    @Test
    public void unsafeNames_cannotEscapeTheFolder() throws Exception {
        assertEquals("_.._.._x", VaultTempFiles.safeName("/../../x")); // separators become underscores
        assertEquals("passwd", VaultTempFiles.safeName("...passwd"));
        assertEquals("file", VaultTempFiles.safeName(""));
        assertEquals("file", VaultTempFiles.safeName(null));
        assertEquals("file", VaultTempFiles.safeName("..."));
        assertEquals(100, VaultTempFiles.safeName(new String(new char[300]).replace('\0', 'a')).length());
        VaultTempFiles t = new VaultTempFiles(new File(tmp.getRoot(), "open"));
        File f = t.create("../../evil.sh");
        assertTrue(f.getCanonicalPath().startsWith(t.directory().getCanonicalPath() + File.separator));
    }

    @Test
    public void release_removesOnlyThatCopy_andIgnoresForeignFiles() throws Exception {
        VaultTempFiles t = new VaultTempFiles(new File(tmp.getRoot(), "open"));
        File a = t.create("a.mp3");
        File b = t.create("b.mp3");
        t.release(a);
        assertFalse(a.exists());
        assertTrue(b.exists());
        File foreign = tmp.newFile("keep.txt");
        t.release(foreign);
        assertTrue(foreign.exists());
        t.release(null);
    }
}
