package org.telegram.messenger.vault;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.SecureRandom;

/**
 * The only place where decrypted Vault media ever touches the disk: a short-lived copy needed so that Android's
 * video/audio players and other apps (to open a document) can read a file. The directory is private to the app,
 * each copy sits in its own random sub-folder (so the original file name and extension are kept for "open with"),
 * and everything is overwritten and deleted when the Vault locks, when the viewer closes, and at every start.
 *
 * Photos are decrypted in memory only and never use this class.
 */
public final class VaultTempFiles {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final File dir;

    public VaultTempFiles(File dir) {
        if (dir == null) {
            throw new IllegalArgumentException("dir required");
        }
        this.dir = dir;
    }

    public File directory() {
        return dir;
    }

    /** A new, empty file called {@code name} (made safe) inside its own random folder. */
    public synchronized File create(String name) throws IOException {
        if (!dir.isDirectory() && !dir.mkdirs() && !dir.isDirectory()) {
            throw new IOException("Cannot create the temp folder");
        }
        byte[] r = new byte[12];
        RANDOM.nextBytes(r);
        StringBuilder id = new StringBuilder();
        for (byte b : r) {
            id.append(String.format("%02x", b & 0xFF));
        }
        File sub = new File(dir, id.toString());
        if (!sub.mkdir()) {
            throw new IOException("Cannot create the temp folder");
        }
        File f = new File(sub, safeName(name));
        if (!f.createNewFile()) {
            throw new IOException("Cannot create the temp file");
        }
        return f;
    }

    /** Overwrites and deletes every copy. Safe to call at any time, also when nothing exists. */
    public synchronized void wipeAll() {
        File[] subs = dir.listFiles();
        if (subs == null) {
            return;
        }
        for (File s : subs) {
            secureDelete(s);
        }
    }

    /** Overwrites and deletes the copy {@code f} made by {@link #create} (and its folder). Anything else is ignored. */
    public synchronized void release(File f) {
        if (f == null) {
            return;
        }
        File sub = f.getParentFile();
        if (sub != null && dir.equals(sub.getParentFile())) {
            secureDelete(sub);
        }
    }

    public synchronized boolean isEmpty() {
        String[] n = dir.list();
        return n == null || n.length == 0;
    }

    /** No path separators, no control characters, no leading dots, at most 100 characters; never empty. */
    public static String safeName(String name) {
        if (name == null) {
            return "file";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < name.length() && sb.length() < 100; i++) {
            char c = name.charAt(i);
            if (c == '/' || c == '\\' || c < 0x20 || c == 0x7F || c == ':') {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        int start = 0;
        while (start < sb.length() && sb.charAt(start) == '.') {
            start++;
        }
        String s = sb.substring(start).trim();
        return s.isEmpty() ? "file" : s;
    }

    static void secureDelete(File f) {
        if (f.isDirectory()) {
            File[] kids = f.listFiles();
            if (kids != null) {
                for (File k : kids) {
                    secureDelete(k);
                }
            }
            f.delete();
            return;
        }
        try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
            long len = raf.length();
            byte[] zeros = new byte[64 * 1024];
            raf.seek(0);
            for (long done = 0; done < len; done += zeros.length) {
                raf.write(zeros, 0, (int) Math.min(zeros.length, len - done));
            }
            raf.getFD().sync();
        } catch (IOException ignored) {
            // best effort: the file is deleted below either way
        }
        f.delete();
    }
}
