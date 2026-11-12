package org.telegram.messenger.vault;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The device's memory of what the server holds and what still has to be sent. Encrypted with the "journal"
 * subkey and written atomically after every step, so a crash or a killed app can be resumed exactly.
 * It never holds item content: only random ids, object names and the server's opaque references.
 *
 * <pre>
 *   file    = "TGVJ" | 1 | AES-GCM(journalKey, payload, aad "tg-vault/journal/v1")
 *   payload = cursor | bundleUploadedVersion | refs | items | skipped
 * </pre>
 */
final class SyncJournal {

    enum State {
        /** Exists locally; some of its objects are not on the server yet. */
        PENDING_UPLOAD((byte) 1),
        /** Every object of the item is on the server. */
        SYNCED((byte) 2),
        /** Deleted locally; the tombstone and the removal of its server objects are not finished. */
        DELETE_PENDING((byte) 3),
        /** Deleted everywhere. Kept forever so the id can never come back. */
        DELETED((byte) 4);

        final byte code;

        State(byte code) {
            this.code = code;
        }

        static State of(byte code) throws VaultCryptoException {
            for (State s : values()) {
                if (s.code == code) {
                    return s;
                }
            }
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Journal has an unknown state");
        }
    }

    static final class ItemState {
        State state;
        long lastAccessMillis;
        /** Object names that belong to the item, in upload order (thumbnail, media, record). */
        List<String> parts = new ArrayList<>();

        ItemState(State state) {
            this.state = state;
        }
    }

    private static final byte[] MAGIC = {'T', 'G', 'V', 'J'};
    private static final byte VERSION = 2;
    private static final byte VERSION_V1 = 1;
    private static final byte[] AAD = "tg-vault/journal/v1".getBytes(StandardCharsets.US_ASCII);
    private static final long MAX_FILE_BYTES = 64L * 1024 * 1024;
    private static final int MAX_COUNT = 5_000_000;

    long cursor;
    long bundleUploadedVersion;
    /** Object name -> server reference, for every object this device knows to exist on the server. */
    final Map<String, String> refs = new LinkedHashMap<>();
    final Map<String, ItemState> items = new TreeMap<>();
    /** Server records written by a newer app that could not be imported yet: name -> reference. */
    final Map<String, String> skipped = new LinkedHashMap<>();
    /**
     * Server references from an earlier key epoch (before a key rotation) that must be deleted once the
     * re-encrypted objects are on the server. They are never downloaded or trusted.
     */
    final java.util.Set<String> retired = new java.util.LinkedHashSet<>();

    /** @return an empty journal if the file does not exist; CORRUPTED if it exists but cannot be authenticated or parsed */
    static SyncJournal load(File file, byte[] key) throws VaultCryptoException {
        if (!file.isFile()) {
            return new SyncJournal();
        }
        byte[] content;
        try {
            content = VaultFiles.readBounded(file, MAX_FILE_BYTES);
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Journal unreadable", e);
        }
        if (content.length < MAGIC.length + 1 || (content[MAGIC.length] != VERSION && content[MAGIC.length] != VERSION_V1)) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Journal header invalid");
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (content[i] != MAGIC[i]) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Not a journal");
            }
        }
        byte[] blob = new byte[content.length - MAGIC.length - 1];
        System.arraycopy(content, MAGIC.length + 1, blob, 0, blob.length);
        byte[] payload = VaultCrypto.decrypt(key, blob, AAD);
        try {
            return parse(payload, content[MAGIC.length] == VERSION);
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Journal malformed", e);
        } finally {
            VaultCrypto.wipe(payload);
        }
    }

    void save(File file, byte[] key) throws VaultCryptoException {
        byte[] payload;
        try {
            payload = serialize();
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not serialise journal", e);
        }
        byte[] blob = VaultCrypto.encrypt(key, payload, AAD);
        VaultCrypto.wipe(payload);
        byte[] content = new byte[MAGIC.length + 1 + blob.length];
        System.arraycopy(MAGIC, 0, content, 0, MAGIC.length);
        content[MAGIC.length] = VERSION;
        System.arraycopy(blob, 0, content, MAGIC.length + 1, blob.length);
        try {
            File dir = file.getParentFile();
            if (dir != null && !dir.isDirectory() && !dir.mkdirs() && !dir.isDirectory()) {
                throw new IOException("Cannot create journal directory");
            }
            VaultFiles.writeAtomically(file, content);
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not write journal", e);
        }
    }

    private byte[] serialize() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeLong(cursor);
        out.writeLong(bundleUploadedVersion);
        out.writeInt(refs.size());
        for (Map.Entry<String, String> e : refs.entrySet()) {
            out.writeUTF(e.getKey());
            out.writeUTF(e.getValue());
        }
        out.writeInt(items.size());
        for (Map.Entry<String, ItemState> e : items.entrySet()) {
            out.writeUTF(e.getKey());
            out.writeByte(e.getValue().state.code);
            out.writeLong(e.getValue().lastAccessMillis);
            out.writeInt(e.getValue().parts.size());
            for (String part : e.getValue().parts) {
                out.writeUTF(part);
            }
        }
        out.writeInt(skipped.size());
        for (Map.Entry<String, String> e : skipped.entrySet()) {
            out.writeUTF(e.getKey());
            out.writeUTF(e.getValue());
        }
        out.writeInt(retired.size());
        for (String ref : retired) {
            out.writeUTF(ref);
        }
        out.flush();
        return bytes.toByteArray();
    }

    private static SyncJournal parse(byte[] payload, boolean hasRetired) throws IOException, VaultCryptoException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload));
        SyncJournal j = new SyncJournal();
        j.cursor = in.readLong();
        j.bundleUploadedVersion = in.readLong();
        if (j.cursor < 0 || j.bundleUploadedVersion < 0) {
            throw new IOException("negative value");
        }
        int refCount = count(in);
        for (int i = 0; i < refCount; i++) {
            j.refs.put(in.readUTF(), in.readUTF());
        }
        int itemCount = count(in);
        for (int i = 0; i < itemCount; i++) {
            String id = in.readUTF();
            ItemState s = new ItemState(State.of(in.readByte()));
            s.lastAccessMillis = in.readLong();
            int parts = count(in);
            for (int p = 0; p < parts; p++) {
                s.parts.add(in.readUTF());
            }
            j.items.put(id, s);
        }
        int skippedCount = count(in);
        for (int i = 0; i < skippedCount; i++) {
            j.skipped.put(in.readUTF(), in.readUTF());
        }
        if (hasRetired) {
            int retiredCount = count(in);
            for (int i = 0; i < retiredCount; i++) {
                j.retired.add(in.readUTF());
            }
        }
        if (in.available() != 0) {
            throw new IOException("trailing bytes");
        }
        return j;
    }

    private static int count(DataInputStream in) throws IOException {
        int n = in.readInt();
        if (n < 0 || n > MAX_COUNT) {
            throw new IOException("bad count");
        }
        return n;
    }
}
