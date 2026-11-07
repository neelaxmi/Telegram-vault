package org.telegram.messenger.vault;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;

/** File helpers shared by the Vault store. Package-private; no Android dependencies. */
final class VaultFiles {

    private VaultFiles() {
    }

    /** Writes {@code data} to a sibling temp file, fsyncs it, then renames it over {@code target}. */
    static void writeAtomically(File target, byte[] data) throws IOException {
        File tmp = new File(target.getParentFile(), target.getName() + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(data);
            out.flush();
            out.getFD().sync();
        }
        renameOver(tmp, target);
    }

    static void renameOver(File tmp, File target) throws IOException {
        if (!tmp.renameTo(target)) {
            if (target.exists() && !target.delete()) {
                tmp.delete();
                throw new IOException("Cannot replace file");
            }
            if (!tmp.renameTo(target)) {
                tmp.delete();
                throw new IOException("Cannot move file into place");
            }
        }
    }

    /** Reads a whole file, refusing files larger than {@code maxBytes}. */
    static byte[] readBounded(File file, long maxBytes) throws IOException {
        long length = file.length();
        if (!file.isFile() || length > maxBytes) {
            throw new IOException("File missing or too large");
        }
        byte[] data = new byte[(int) length];
        try (FileInputStream in = new FileInputStream(file)) {
            int off = 0;
            while (off < data.length) {
                int n = in.read(data, off, data.length - off);
                if (n < 0) {
                    throw new IOException("File truncated while reading");
                }
                off += n;
            }
        }
        return data;
    }

    /**
     * Overwrites a file with zeros in place, then deletes it. Best effort only: flash storage and
     * journaling file systems may keep old blocks, so this lowers but does not remove the chance
     * that deleted ciphertext can be recovered. No-op if the file does not exist.
     */
    static void secureDelete(File file) throws IOException {
        if (!file.exists()) {
            return;
        }
        if (file.isFile()) {
            try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
                byte[] zeros = new byte[64 * 1024];
                long remaining = raf.length();
                raf.seek(0);
                while (remaining > 0) {
                    int n = (int) Math.min(zeros.length, remaining);
                    raf.write(zeros, 0, n);
                    remaining -= n;
                }
                raf.getFD().sync();
            } catch (IOException ignored) {
                // Still try to delete below, which reports the real failure.
            }
        }
        if (!file.delete() && file.exists()) {
            throw new IOException("Cannot delete file");
        }
    }

    /** Secure-deletes every file under {@code dir}, then the directories. Reports the first failure after trying everything. */
    static void secureDeleteTree(File dir) throws IOException {
        if (!dir.exists()) {
            return;
        }
        IOException failure = null;
        File[] children = dir.isDirectory() ? dir.listFiles() : null;
        if (children != null) {
            for (File child : children) {
                try {
                    if (child.isDirectory()) {
                        secureDeleteTree(child);
                    } else {
                        secureDelete(child);
                    }
                } catch (IOException e) {
                    if (failure == null) {
                        failure = e;
                    }
                }
            }
        }
        if (!dir.delete() && dir.exists() && failure == null) {
            failure = new IOException("Cannot delete directory");
        }
        if (failure != null) {
            throw failure;
        }
    }

    static void deleteQuietly(File file) {
        if (file != null && file.exists()) {
            file.delete();
        }
    }
}
