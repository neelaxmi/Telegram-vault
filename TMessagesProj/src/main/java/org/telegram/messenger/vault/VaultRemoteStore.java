package org.telegram.messenger.vault;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

/**
 * The server side of the sync, as the sync engine sees it: an ordered, append-only list of opaque blobs.
 * The real implementation (Phase 6) keeps them as messages in a private Telegram channel; tests use an
 * in-memory fake. Nothing that crosses this interface is plaintext: names are random ids and file contents
 * are ciphertext produced by the Vault.
 *
 * <p>All methods block and may throw {@link IOException} for any transient failure; the engine keeps its
 * journal consistent so the same call can simply be repeated.
 *
 * <h3>Names</h3>
 * {@code r.<itemId>} record, {@code m.<mediaId>} media, {@code t.<thumbId>} thumbnail, {@code x.<itemId>}
 * tombstone, {@code b.<n>} key bundle version n.
 */
public interface VaultRemoteStore {

    /** One stored object. {@code seq} increases strictly with upload order within the channel. */
    final class Entry {
        public final long seq;
        public final String name;
        public final long size;
        /** Opaque handle used to download or delete this object (for Telegram: the channel message id). */
        public final String ref;

        public Entry(long seq, String name, long size, String ref) {
            this.seq = seq;
            this.name = name;
            this.size = size;
            this.ref = ref;
        }
    }

    /**
     * Uploads {@code file} under {@code name}. {@code clientToken} identifies this exact upload: if an
     * upload with the same token already succeeded (for example the acknowledgement was lost), the existing
     * entry is returned instead of storing a second copy.
     */
    Entry upload(String name, String clientToken, File file) throws IOException;

    /** Entries with {@code seq > afterSeq}, ascending by seq, at most {@code limit}; empty when caught up. */
    List<Entry> list(long afterSeq, int limit) throws IOException;

    /** Streams the object's bytes into {@code out}. */
    void download(String ref, OutputStream out) throws IOException;

    /** Deletes an object. Deleting something that is already gone is not an error. */
    void delete(String ref) throws IOException;
}
