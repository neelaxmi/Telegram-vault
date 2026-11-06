package org.telegram.messenger.vault;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * File-backed {@link VaultHeaderStore}. Writes go to a temporary sibling file that is
 * fsynced and then renamed over the target, so a crash cannot leave a half-written header.
 * The file should live in app-private storage (e.g. {@code getFilesDir()/vault/}).
 */
public class FileVaultHeaderStore implements VaultHeaderStore {

    /** Upper bound on header size we are willing to read; the real header is under 200 bytes. */
    private static final int MAX_HEADER_BYTES = 64 * 1024;

    private final File file;
    private final File tmpFile;

    public FileVaultHeaderStore(File file) {
        this.file = file;
        this.tmpFile = new File(file.getParentFile(), file.getName() + ".tmp");
    }

    @Override
    public synchronized boolean exists() {
        return file.isFile();
    }

    @Override
    public synchronized byte[] read() throws IOException {
        long length = file.length();
        if (!file.isFile() || length <= 0 || length > MAX_HEADER_BYTES) {
            throw new IOException("Vault header missing or invalid size");
        }
        byte[] data = new byte[(int) length];
        try (FileInputStream in = new FileInputStream(file)) {
            int off = 0;
            while (off < data.length) {
                int n = in.read(data, off, data.length - off);
                if (n < 0) {
                    throw new IOException("Vault header truncated");
                }
                off += n;
            }
        }
        return data;
    }

    @Override
    public synchronized void write(byte[] data) throws IOException {
        File dir = file.getParentFile();
        if (dir != null && !dir.isDirectory() && !dir.mkdirs() && !dir.isDirectory()) {
            throw new IOException("Cannot create vault directory");
        }
        try (FileOutputStream out = new FileOutputStream(tmpFile)) {
            out.write(data);
            out.flush();
            out.getFD().sync();
        }
        if (!tmpFile.renameTo(file)) {
            // Some filesystems refuse to rename over an existing file.
            if (file.exists() && !file.delete()) {
                tmpFile.delete();
                throw new IOException("Cannot replace vault header");
            }
            if (!tmpFile.renameTo(file)) {
                tmpFile.delete();
                throw new IOException("Cannot move vault header into place");
            }
        }
    }

    @Override
    public synchronized void delete() throws IOException {
        // Best-effort overwrite before unlinking. Flash storage may still keep old blocks, which is
        // why vault destruction also deletes the device key (see DeviceKeyWrapper#deleteKey).
        overwriteWithZeros(tmpFile);
        overwriteWithZeros(file);
        if (tmpFile.exists() && !tmpFile.delete()) {
            throw new IOException("Cannot delete temporary vault header");
        }
        if (file.exists() && !file.delete()) {
            throw new IOException("Cannot delete vault header");
        }
    }

    private static void overwriteWithZeros(File f) {
        if (!f.isFile()) {
            return;
        }
        try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
            // Overwrite in place (no truncation) across the file's real length.
            raf.seek(0);
            raf.write(new byte[(int) Math.min(f.length(), MAX_HEADER_BYTES)]);
            raf.getFD().sync();
        } catch (IOException ignored) {
            // Deletion below still proceeds and reports the real failure.
        }
    }
}
