package org.telegram.messenger.vault;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Encrypted on-disk storage for Vault items. Pure Java; no Android dependencies.
 *
 * <h3>Layout under {@code rootDir}</h3>
 * <pre>
 *   items/&lt;32 hex&gt;.vrec   one encrypted record per item (text + metadata)
 *   media/&lt;32 hex&gt;.vmed   one encrypted media file per photo/video/document/thumbnail
 * </pre>
 * File names are random ids, never original names or extensions. Nothing in the directory is plaintext:
 * records and media are encrypted before they touch disk (media is encrypted while streaming; a plaintext
 * copy is never written). Original file names, MIME types and captions exist only inside encrypted records.
 *
 * <h3>Keys</h3>
 * Records use {@code deriveSubkey("messages")}, media uses {@code deriveSubkey("media")}: two independent
 * HKDF-derived keys. The store holds no keys itself; each operation derives what it needs from the
 * {@link VaultKeyManager} and wipes it afterwards, so locking the manager immediately disables the store
 * (operations then fail with INVALID_STATE).
 *
 * <h3>Binding</h3>
 * Each record is authenticated together with its own id, and each media file together with its media id,
 * so renaming, swapping or copying encrypted files between ids is detected.
 *
 * <h3>What this does NOT protect against</h3>
 * <ul>
 *   <li>An attacker with file access can see how many items exist, roughly how large they are (records are
 *       padded to 256-byte buckets, media sizes are visible) and when files were modified.</li>
 *   <li>Deleting or rolling back whole files (replacing a record with an older copy of itself) is not
 *       detected; only modification and substitution between ids are.</li>
 *   <li>Deletion overwrites files with zeros first, but flash storage may keep old blocks.</li>
 *   <li>It does not delete the key header (kept by {@link VaultKeyManager}'s header store); see {@link #deleteAllData()}.</li>
 * </ul>
 *
 * Thread-safe: public methods are synchronised on the instance.
 */
public final class VaultStore {

    /** Time source, injectable for tests. */
    public interface Clock {
        long nowMillis();
    }

    /**
     * Result of {@link #list()}: readable items, ids of records that failed to decrypt or parse, and ids of
     * records written by a newer app version (intact as far as we know, shown as "update the app", never
     * treated as damaged and never deleted automatically).
     */
    public static final class Listing {
        public final List<VaultItem> items;
        public final List<String> corruptIds;
        public final List<String> unsupportedIds;

        Listing(List<VaultItem> items, List<String> corruptIds, List<String> unsupportedIds) {
            this.items = items;
            this.corruptIds = corruptIds;
            this.unsupportedIds = unsupportedIds;
        }
    }

    public static final String PURPOSE_MESSAGES = "messages";
    public static final String PURPOSE_MEDIA = "media";
    public static final int MAX_THUMBNAIL_BYTES = 1024 * 1024;

    static final String ITEMS_DIR = "items";
    static final String MEDIA_DIR = "media";
    static final String RECORD_EXT = ".vrec";
    static final String MEDIA_EXT = ".vmed";
    static final String TMP_EXT = ".tmp";

    private static final byte[] RECORD_MAGIC = {'T', 'G', 'V', 'R'};
    private static final byte RECORD_VERSION = 1;
    private static final int RECORD_HEADER_BYTES = RECORD_MAGIC.length + 1;
    private static final long MAX_RECORD_FILE_BYTES = 8L * 1024 * 1024;
    private static final long MAX_THUMBNAIL_FILE_BYTES = MAX_THUMBNAIL_BYTES + 1024;

    private static final Clock SYSTEM_CLOCK = new Clock() {
        @Override
        public long nowMillis() {
            return System.currentTimeMillis();
        }
    };

    private final File rootDir;
    private final VaultKeyManager keys;
    private final Clock clock;
    private final int chunkSize;
    private long maxUploadBytes = DEFAULT_MAX_UPLOAD_BYTES;

    /** Telegram's default per-file limit (FileLoader.DEFAULT_MAX_FILE_SIZE, 2000 MiB); Premium accounts get twice that. */
    public static final long DEFAULT_MAX_UPLOAD_BYTES = 2000L * 1024 * 1024;

    public VaultStore(File rootDir, VaultKeyManager keys) {
        this(rootDir, keys, SYSTEM_CLOCK, VaultMediaCipher.DEFAULT_CHUNK_SIZE);
    }

    /** Package-private: tests use a fake clock and small chunks. */
    VaultStore(File rootDir, VaultKeyManager keys, Clock clock, int chunkSize) {
        if (rootDir == null || keys == null || clock == null) {
            throw new IllegalArgumentException("rootDir, keys and clock are required");
        }
        if (chunkSize < VaultMediaCipher.MIN_CHUNK_SIZE || chunkSize > VaultMediaCipher.MAX_CHUNK_SIZE) {
            throw new IllegalArgumentException("chunkSize out of range");
        }
        this.rootDir = rootDir;
        this.keys = keys;
        this.clock = clock;
        this.chunkSize = chunkSize;
    }

    /**
     * Sets the largest encrypted file Telegram will accept for this account (decision 6). Media whose
     * encrypted size would exceed it is refused with MEDIA_TOO_LARGE before anything is stored.
     */
    public synchronized void setMaxUploadBytes(long bytes) {
        if (bytes < 1024 * 1024) {
            throw new IllegalArgumentException("limit too small");
        }
        this.maxUploadBytes = bytes;
    }

    /** Largest plaintext whose encrypted form (header + 16 bytes of tag per chunk) fits {@code maxUploadBytes}. */
    long maxPlaintextBytes() {
        long perChunk = chunkSize + 16L;
        long fullChunks = (maxUploadBytes - VaultMediaCipher.HEADER_BYTES) / perChunk;
        long rest = (maxUploadBytes - VaultMediaCipher.HEADER_BYTES) - fullChunks * perChunk;
        // The final chunk may be partial: it adds its own 16-byte tag, so it holds rest - 16 bytes of data.
        return fullChunks * chunkSize + Math.max(0, rest - 16);
    }

    // ------------------------------------------------------------------ add

    /**
     * Saves a new item. The media stream (if any) is encrypted while it is read; its plaintext is never
     * written to disk. On any failure nothing is left behind.
     *
     * @param draft     item fields
     * @param media     plaintext media for PHOTO / VIDEO / DOCUMENT items; must be null for TEXT. Not closed.
     * @param thumbnail optional small preview image bytes (at most {@link #MAX_THUMBNAIL_BYTES}); media items only
     * @throws VaultCryptoException INVALID_STATE if the vault is locked; INVALID_ARGUMENT for bad input; IO_ERROR on storage failure
     */
    public synchronized VaultItem addItem(VaultItem.Draft draft, InputStream media, byte[] thumbnail) throws VaultCryptoException {
        if (draft == null) {
            throw invalid("Draft required");
        }
        draft.validate();
        if (draft.type.hasMedia() && media == null) {
            throw invalid("Media items need media");
        }
        if (!draft.type.hasMedia() && (media != null || thumbnail != null)) {
            throw invalid("Text items cannot have media");
        }
        if (thumbnail != null && (thumbnail.length == 0 || thumbnail.length > MAX_THUMBNAIL_BYTES)) {
            throw invalid("Thumbnail size out of range");
        }

        byte[] messageKey = null;
        byte[] mediaKey = null;
        List<File> created = new ArrayList<>();
        boolean success = false;
        try {
            messageKey = keys.deriveSubkey(PURPOSE_MESSAGES); // throws INVALID_STATE if locked, before any file is touched
            mediaKey = keys.deriveSubkey(PURPOSE_MEDIA);
            ensureDirs();

            String id = newId();
            String mediaId = null;
            String thumbnailId = null;
            long mediaSize = 0;
            if (media != null) {
                mediaId = newId();
                mediaSize = writeMedia(mediaKey, mediaId, media, created);
            }
            if (thumbnail != null) {
                thumbnailId = newId();
                writeMedia(mediaKey, thumbnailId, new ByteArrayInputStream(thumbnail), created);
            }
            VaultItem item = draft.toItem(id, clock.nowMillis(), mediaId, mediaSize, thumbnailId);
            writeRecord(messageKey, item, created);
            success = true;
            return item;
        } finally {
            VaultCrypto.wipe(messageKey);
            VaultCrypto.wipe(mediaKey);
            if (!success) {
                for (File f : created) {
                    VaultFiles.deleteQuietly(f);
                }
            }
        }
    }

    // ------------------------------------------------------------------ read

    /** @return the item, or null if no such item exists */
    public synchronized VaultItem get(String id) throws VaultCryptoException {
        checkId(id);
        byte[] messageKey = keys.deriveSubkey(PURPOSE_MESSAGES);
        try {
            File file = recordFile(id);
            if (!file.isFile()) {
                return null;
            }
            return readRecord(messageKey, id, file);
        } finally {
            VaultCrypto.wipe(messageKey);
        }
    }

    /**
     * All readable items, oldest first (ties broken by id). Records that fail to decrypt are not thrown
     * about; their ids are reported in {@link Listing#corruptIds} so one damaged file cannot hide the rest.
     * Wrong-state errors (locked vault) are still thrown.
     */
    public synchronized Listing list() throws VaultCryptoException {
        byte[] messageKey = keys.deriveSubkey(PURPOSE_MESSAGES);
        try {
            List<VaultItem> items = new ArrayList<>();
            List<String> corrupt = new ArrayList<>();
            List<String> unsupported = new ArrayList<>();
            for (String id : recordIds()) {
                try {
                    items.add(readRecord(messageKey, id, recordFile(id)));
                } catch (VaultCryptoException e) {
                    if (e.getReason() == VaultCryptoException.Reason.CORRUPTED) {
                        corrupt.add(id);
                    } else if (e.getReason() == VaultCryptoException.Reason.UNSUPPORTED_VERSION) {
                        unsupported.add(id);
                    } else {
                        throw e;
                    }
                }
            }
            Collections.sort(items, new Comparator<VaultItem>() {
                @Override
                public int compare(VaultItem a, VaultItem b) {
                    int c = Long.compare(a.createdAtMillis, b.createdAtMillis);
                    return c != 0 ? c : a.id.compareTo(b.id);
                }
            });
            Collections.sort(corrupt);
            Collections.sort(unsupported);
            return new Listing(items, corrupt, unsupported);
        } finally {
            VaultCrypto.wipe(messageKey);
        }
    }

    /**
     * Case-insensitive substring search over text/caption, sender, forwarded-from name and media file name.
     * A null or blank query returns every readable item. Runs in memory over decrypted records.
     */
    public synchronized List<VaultItem> search(String query) throws VaultCryptoException {
        List<VaultItem> all = list().items;
        if (query == null || query.trim().isEmpty()) {
            return all;
        }
        String needle = query.trim().toLowerCase(Locale.ROOT);
        List<VaultItem> result = new ArrayList<>();
        for (VaultItem item : all) {
            if (contains(item.text, needle) || contains(item.senderName, needle)
                    || contains(item.forwardedFromName, needle) || contains(item.mediaName, needle)) {
                result.add(item);
            }
        }
        return result;
    }

    public synchronized int count() {
        return recordIds().size();
    }

    /**
     * Decrypts the media of {@code itemId} into {@code out}. Each chunk is authenticated before it is
     * written, but if this throws, {@code out} may hold a partial result and must be discarded.
     *
     * @throws VaultCryptoException INVALID_ARGUMENT if the item has no media or does not exist; CORRUPTED if
     *                              the media is missing, modified, truncated, swapped, or of the wrong size
     */
    public synchronized void readMedia(String itemId, OutputStream out) throws VaultCryptoException {
        VaultItem item = requireItem(itemId);
        if (item.mediaId == null) {
            throw invalid("Item has no media");
        }
        byte[] mediaKey = keys.deriveSubkey(PURPOSE_MEDIA);
        try {
            File file = mediaFile(item.mediaId);
            if (!file.isFile()) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Media file is missing");
            }
            long written;
            try (InputStream in = new FileInputStream(file)) {
                written = VaultMediaCipher.decrypt(in, out, mediaKey, mediaAad(item.mediaId));
            } catch (IOException e) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not read media", e);
            }
            if (written != item.mediaSize) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Media size does not match record");
            }
        } finally {
            VaultCrypto.wipe(mediaKey);
        }
    }

    /** @return the decrypted preview image bytes, or null if the item has no thumbnail */
    public synchronized byte[] readThumbnail(String itemId) throws VaultCryptoException {
        VaultItem item = requireItem(itemId);
        if (item.thumbnailId == null) {
            return null;
        }
        byte[] mediaKey = keys.deriveSubkey(PURPOSE_MEDIA);
        try {
            File file = mediaFile(item.thumbnailId);
            if (!file.isFile() || file.length() > MAX_THUMBNAIL_FILE_BYTES) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Thumbnail missing or oversized");
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (InputStream in = new FileInputStream(file)) {
                VaultMediaCipher.decrypt(in, out, mediaKey, mediaAad(item.thumbnailId));
            } catch (IOException e) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not read thumbnail", e);
            }
            return out.toByteArray();
        } finally {
            VaultCrypto.wipe(mediaKey);
        }
    }

    // ------------------------------------------------------------------ delete / maintenance

    /**
     * Deletes an item and its media files (overwriting them with zeros first). A damaged record can still be
     * deleted; its media files are then left for {@link #removeOrphans()}.
     *
     * @return true if the item existed
     */
    public synchronized boolean delete(String id) throws VaultCryptoException {
        checkId(id);
        byte[] messageKey = keys.deriveSubkey(PURPOSE_MESSAGES); // must be unlocked to delete
        try {
            File file = recordFile(id);
            if (!file.isFile()) {
                return false;
            }
            VaultItem item = null;
            try {
                item = readRecord(messageKey, id, file);
            } catch (VaultCryptoException e) {
                if (e.getReason() != VaultCryptoException.Reason.CORRUPTED) {
                    throw e;
                }
            }
            try {
                VaultFiles.secureDelete(file); // record first: a crash leaves invisible orphans, never a broken item
                if (item != null) {
                    if (item.mediaId != null) {
                        VaultFiles.secureDelete(mediaFile(item.mediaId));
                    }
                    if (item.thumbnailId != null) {
                        VaultFiles.secureDelete(mediaFile(item.thumbnailId));
                    }
                }
            } catch (IOException e) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not delete item files", e);
            }
            return true;
        } finally {
            VaultCrypto.wipe(messageKey);
        }
    }

    /**
     * Crash recovery: removes leftover temporary files, and media files that no record refers to.
     * Unreferenced media is only removed when every record could be read, because an unreadable record
     * might still own media; in that case just temporary files are cleaned.
     *
     * @return number of files removed
     */
    public synchronized int removeOrphans() throws VaultCryptoException {
        Listing listing = list();
        int removed = 0;
        try {
            for (File dir : new File[]{itemsDir(), mediaDir()}) {
                File[] files = dir.listFiles();
                if (files == null) {
                    continue;
                }
                for (File f : files) {
                    if (f.isFile() && f.getName().endsWith(TMP_EXT)) {
                        VaultFiles.secureDelete(f);
                        removed++;
                    }
                }
            }
            if (listing.corruptIds.isEmpty() && listing.unsupportedIds.isEmpty()) {
                Set<String> referenced = new HashSet<>();
                for (VaultItem item : listing.items) {
                    if (item.mediaId != null) {
                        referenced.add(item.mediaId);
                    }
                    if (item.thumbnailId != null) {
                        referenced.add(item.thumbnailId);
                    }
                }
                File[] files = mediaDir().listFiles();
                if (files != null) {
                    for (File f : files) {
                        String name = f.getName();
                        if (f.isFile() && name.endsWith(MEDIA_EXT)) {
                            String id = name.substring(0, name.length() - MEDIA_EXT.length());
                            if (isValidId(id) && !referenced.contains(id)) {
                                VaultFiles.secureDelete(f);
                                removed++;
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not remove orphaned files", e);
        }
        return removed;
    }

    /**
     * Deletes every record and media file, overwriting with zeros first. Does not need the password
     * and works while locked. Does NOT remove the key header; for a full wipe call
     * {@link VaultKeyManager#destroy()} as well (Phase 3's wipe policy does both).
     */
    public synchronized void deleteAllData() throws VaultCryptoException {
        try {
            VaultFiles.secureDeleteTree(itemsDir());
            VaultFiles.secureDeleteTree(mediaDir());
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not delete vault data", e);
        }
    }

    // ------------------------------------------------------------------ sync support

    /** Ids of every record file on disk (readable or not), sorted. Used to find items the sync journal does not know yet. */
    public synchronized List<String> localIds() {
        List<String> ids = recordIds();
        Collections.sort(ids);
        return ids;
    }

    /** The encrypted record file, exactly the bytes that are uploaded. May not exist. */
    synchronized File recordCipherFile(String id) throws VaultCryptoException {
        checkId(id);
        return recordFile(id);
    }

    /** The encrypted media or thumbnail file, exactly the bytes that are uploaded. May not exist (evicted or not downloaded). */
    synchronized File mediaCipherFile(String mediaId) throws VaultCryptoException {
        checkId(mediaId);
        return mediaFile(mediaId);
    }

    public synchronized boolean hasMediaFile(String mediaId) throws VaultCryptoException {
        checkId(mediaId);
        return mediaFile(mediaId).isFile();
    }

    /**
     * Stores a record that came from the server. The bytes must authenticate under this vault's key for
     * exactly this id, otherwise nothing is stored. A record written by a newer app version is stored
     * (so it is kept and re-synced) as long as it authenticates. An existing record is never overwritten.
     *
     * @return true if it was stored, false if a record with this id already exists
     * @throws VaultCryptoException CORRUPTED if the bytes are not an authentic record of this vault;
     *                              UNSUPPORTED_VERSION if the container version is unknown (not stored)
     */
    public synchronized boolean importRecord(String id, byte[] content) throws VaultCryptoException {
        checkId(id);
        if (content == null || content.length > MAX_RECORD_FILE_BYTES) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Remote record has an invalid size");
        }
        byte[] messageKey = keys.deriveSubkey(PURPOSE_MESSAGES);
        File tmp = null;
        try {
            ensureDirs();
            if (recordFile(id).isFile()) {
                return false;
            }
            tmp = new File(itemsDir(), id + RECORD_EXT + TMP_EXT);
            try {
                VaultFiles.writeAtomically(tmp, content);
            } catch (IOException e) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not store remote record", e);
            }
            try {
                readRecord(messageKey, id, tmp);
            } catch (VaultCryptoException e) {
                // A record from a newer app is authentic but unreadable here: keep it. Everything else is rejected.
                if (e.getReason() != VaultCryptoException.Reason.UNSUPPORTED_VERSION || !authenticates(messageKey, id, content)) {
                    throw e;
                }
            }
            try {
                VaultFiles.renameOver(tmp, recordFile(id));
            } catch (IOException e) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not store remote record", e);
            }
            tmp = null;
            return true;
        } finally {
            VaultCrypto.wipe(messageKey);
            if (tmp != null) {
                VaultFiles.deleteQuietly(tmp);
            }
        }
    }

    /** True if {@code content} is a record container whose AES-GCM blob authenticates for {@code id}. */
    private static boolean authenticates(byte[] messageKey, String id, byte[] content) {
        if (content.length < RECORD_HEADER_BYTES) {
            return false;
        }
        for (int i = 0; i < RECORD_MAGIC.length; i++) {
            if (content[i] != RECORD_MAGIC[i]) {
                return false;
            }
        }
        try {
            byte[] blob = new byte[content.length - RECORD_HEADER_BYTES];
            System.arraycopy(content, RECORD_HEADER_BYTES, blob, 0, blob.length);
            VaultCrypto.wipe(VaultCrypto.decrypt(messageKey, blob, recordAad(id)));
            return true;
        } catch (VaultCryptoException e) {
            return false;
        }
    }

    /**
     * Stores media or a thumbnail that was downloaded from the server. The whole stream is authenticated
     * (header, every chunk, end marker) before the file becomes visible, so a truncated or altered download
     * leaves nothing behind.
     *
     * @param mediaId       id taken from the record (media id or thumbnail id)
     * @param expectedBytes plaintext size the record promises, or -1 to skip the size check (thumbnails)
     */
    public synchronized void importMedia(String mediaId, InputStream encrypted, long expectedBytes) throws VaultCryptoException {
        checkId(mediaId);
        byte[] mediaKey = keys.deriveSubkey(PURPOSE_MEDIA);
        File tmp = null;
        boolean ok = false;
        try {
            ensureDirs();
            tmp = new File(mediaDir(), mediaId + MEDIA_EXT + TMP_EXT);
            try (FileOutputStream fos = new FileOutputStream(tmp);
                 BufferedOutputStream bos = new BufferedOutputStream(fos, 64 * 1024)) {
                byte[] buffer = new byte[64 * 1024];
                int n;
                while ((n = encrypted.read(buffer)) > 0) {
                    bos.write(buffer, 0, n);
                }
                bos.flush();
                fos.getFD().sync();
            } catch (IOException e) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not store downloaded media", e);
            }
            long plain;
            try (InputStream in = new FileInputStream(tmp)) {
                plain = VaultMediaCipher.decrypt(in, new NullOutputStream(), mediaKey, mediaAad(mediaId));
            } catch (IOException e) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not verify downloaded media", e);
            }
            if (expectedBytes >= 0 && plain != expectedBytes) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Downloaded media has the wrong size");
            }
            try {
                VaultFiles.renameOver(tmp, mediaFile(mediaId));
            } catch (IOException e) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not store downloaded media", e);
            }
            ok = true;
        } finally {
            VaultCrypto.wipe(mediaKey);
            if (!ok && tmp != null) {
                VaultFiles.deleteQuietly(tmp);
            }
        }
    }

    /**
     * Removes the local copy of an item's media (not its record or thumbnail) to free space. The caller must
     * know the media is safely on the server. @return bytes freed, 0 if there was nothing to evict.
     */
    public synchronized long evictMedia(String itemId) throws VaultCryptoException {
        VaultItem item = requireItem(itemId);
        if (item.mediaId == null) {
            return 0;
        }
        File f = mediaFile(item.mediaId);
        long size = f.length();
        if (!f.isFile()) {
            return 0;
        }
        try {
            VaultFiles.secureDelete(f);
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not evict media", e);
        }
        return size;
    }

    // ------------------------------------------------------------------ key rotation support

    /**
     * Re-encrypts every record, thumbnail and media file under new keys into {@code stageRoot/items} and
     * {@code stageRoot/media}, leaving the live files untouched. Everything staged is read back and
     * authenticated with the new keys before this returns. Plaintext media never touches the disk.
     *
     * Refuses (and cleans up) if any record cannot be read, or if an item's media or thumbnail is not on this
     * device: those would be lost by a rotation.
     *
     * @return number of items staged
     */
    synchronized int stageReencrypted(File stageRoot, byte[] newMessageKey, byte[] newMediaKey) throws VaultCryptoException {
        byte[] oldMessageKey = keys.deriveSubkey(PURPOSE_MESSAGES);
        byte[] oldMediaKey = keys.deriveSubkey(PURPOSE_MEDIA);
        boolean ok = false;
        try {
            File stageItems = new File(stageRoot, ITEMS_DIR);
            File stageMedia = new File(stageRoot, MEDIA_DIR);
            if (!stageItems.isDirectory() && !stageItems.mkdirs() || !stageMedia.isDirectory() && !stageMedia.mkdirs()) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not create staging directory");
            }
            int count = 0;
            for (String id : recordIds()) {
                VaultItem item;
                try {
                    item = readRecord(oldMessageKey, id, recordFile(id));
                } catch (VaultCryptoException e) {
                    if (e.getReason() == VaultCryptoException.Reason.CORRUPTED
                            || e.getReason() == VaultCryptoException.Reason.UNSUPPORTED_VERSION) {
                        throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE,
                                "An item cannot be read, so the keys cannot be rotated safely", e);
                    }
                    throw e;
                }
                if (item.mediaId != null) {
                    reencryptMedia(mediaFile(item.mediaId), new File(stageMedia, item.mediaId + MEDIA_EXT),
                            oldMediaKey, newMediaKey, mediaAad(item.mediaId), item.mediaSize);
                }
                if (item.thumbnailId != null) {
                    reencryptMedia(mediaFile(item.thumbnailId), new File(stageMedia, item.thumbnailId + MEDIA_EXT),
                            oldMediaKey, newMediaKey, mediaAad(item.thumbnailId), -1);
                }
                writeRecordFile(newMessageKey, item, new File(stageItems, id + RECORD_EXT));
                VaultItem back = readRecord(newMessageKey, id, new File(stageItems, id + RECORD_EXT));
                if (!back.equals(item)) {
                    throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Re-encrypted record does not match");
                }
                count++;
            }
            ok = true;
            return count;
        } finally {
            VaultCrypto.wipe(oldMessageKey);
            VaultCrypto.wipe(oldMediaKey);
            if (!ok) {
                try {
                    VaultFiles.secureDeleteTree(stageRoot);
                } catch (IOException ignored) {
                    // best effort: the staged files are ciphertext under a key that is discarded with the rotation
                }
            }
        }
    }

    /**
     * Replaces the live {@code items} and {@code media} directories with the staged ones. Safe to run again
     * after a crash: each directory that is still staged is swapped in, the others are left alone.
     */
    synchronized void adoptStaged(File stageRoot) throws VaultCryptoException {
        try {
            for (String name : new String[]{ITEMS_DIR, MEDIA_DIR}) {
                File staged = new File(stageRoot, name);
                if (!staged.isDirectory()) {
                    continue;
                }
                File live = new File(rootDir, name);
                VaultFiles.secureDeleteTree(live);
                if (!staged.renameTo(live)) {
                    throw new IOException("Could not move staged " + name + " into place");
                }
            }
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not switch to the re-encrypted data", e);
        }
    }

    /** Directory under which a rotation stages its re-encrypted copy (same file system as the live data, so it can be renamed in). */
    File stagingRoot() {
        return rootDir;
    }

    private void reencryptMedia(final File source, File dest, final byte[] oldKey, byte[] newKey, final byte[] aad,
                                final long expectedPlain) throws VaultCryptoException {
        if (!source.isFile()) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE,
                    "A file is not stored on this device, so the keys cannot be rotated yet");
        }
        final java.io.PipedInputStream pipeIn = new java.io.PipedInputStream(128 * 1024);
        final java.io.PipedOutputStream pipeOut;
        try {
            pipeOut = new java.io.PipedOutputStream(pipeIn);
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not start re-encryption", e);
        }
        final Throwable[] failure = new Throwable[1];
        final long[] plain = new long[]{-1};
        Thread reader = new Thread(new Runnable() {
            @Override
            public void run() {
                try (InputStream in = new FileInputStream(source)) {
                    plain[0] = VaultMediaCipher.decrypt(in, pipeOut, oldKey, aad);
                } catch (Throwable t) {
                    failure[0] = t;
                } finally {
                    try {
                        pipeOut.close();
                    } catch (IOException ignored) {
                        // nothing left to do
                    }
                }
            }
        }, "vault-rotate-media");
        reader.start();
        VaultCryptoException problem = null;
        try (FileOutputStream fos = new FileOutputStream(dest);
             BufferedOutputStream bos = new BufferedOutputStream(fos, 64 * 1024)) {
            VaultMediaCipher.encrypt(pipeIn, bos, newKey, aad, chunkSize);
            bos.flush();
            fos.getFD().sync();
        } catch (VaultCryptoException e) {
            problem = e;
        } catch (IOException e) {
            problem = new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not re-encrypt media", e);
        } finally {
            try {
                pipeIn.close(); // unblocks the reader if the writer gave up
            } catch (IOException ignored) {
                // nothing left to do
            }
        }
        try {
            reader.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Interrupted while re-encrypting media", e);
        }
        // The reader's verdict wins: a decryption failure there would otherwise look like a short, valid file.
        if (failure[0] != null) {
            if (failure[0] instanceof VaultCryptoException) {
                throw (VaultCryptoException) failure[0];
            }
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not read media", failure[0]);
        }
        if (problem != null) {
            throw problem;
        }
        if (expectedPlain >= 0 && plain[0] != expectedPlain) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Media size does not match record");
        }
        // Read the staged file back with the new key: it must authenticate completely and have the same size.
        try (InputStream in = new FileInputStream(dest)) {
            long check = VaultMediaCipher.decrypt(in, new NullOutputStream(), newKey, aad);
            if (check != plain[0]) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Re-encrypted media does not match");
            }
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not verify re-encrypted media", e);
        }
    }

    private void writeRecordFile(byte[] messageKey, VaultItem item, File target) throws VaultCryptoException {
        byte[] padded = item.encodePadded();
        byte[] blob = VaultCrypto.encrypt(messageKey, padded, recordAad(item.id));
        VaultCrypto.wipe(padded);
        byte[] content = new byte[RECORD_HEADER_BYTES + blob.length];
        System.arraycopy(RECORD_MAGIC, 0, content, 0, RECORD_MAGIC.length);
        content[RECORD_MAGIC.length] = RECORD_VERSION;
        System.arraycopy(blob, 0, content, RECORD_HEADER_BYTES, blob.length);
        try {
            VaultFiles.writeAtomically(target, content);
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not store item", e);
        }
    }

    private static final class NullOutputStream extends OutputStream {
        @Override
        public void write(int b) {
        }

        @Override
        public void write(byte[] b, int off, int len) {
        }
    }

    // ------------------------------------------------------------------ internals: records

    private void writeRecord(byte[] messageKey, VaultItem item, List<File> created) throws VaultCryptoException {
        byte[] padded = item.encodePadded();
        byte[] blob = VaultCrypto.encrypt(messageKey, padded, recordAad(item.id));
        VaultCrypto.wipe(padded);
        byte[] content = new byte[RECORD_HEADER_BYTES + blob.length];
        System.arraycopy(RECORD_MAGIC, 0, content, 0, RECORD_MAGIC.length);
        content[RECORD_MAGIC.length] = RECORD_VERSION;
        System.arraycopy(blob, 0, content, RECORD_HEADER_BYTES, blob.length);

        File target = recordFile(item.id);
        created.add(target);
        created.add(new File(target.getParentFile(), target.getName() + TMP_EXT));
        try {
            VaultFiles.writeAtomically(target, content);
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not store item", e);
        }
    }

    private VaultItem readRecord(byte[] messageKey, String id, File file) throws VaultCryptoException {
        byte[] content;
        try {
            content = VaultFiles.readBounded(file, MAX_RECORD_FILE_BYTES);
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Record unreadable", e);
        }
        if (content.length < RECORD_HEADER_BYTES) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Record too short");
        }
        for (int i = 0; i < RECORD_MAGIC.length; i++) {
            if (content[i] != RECORD_MAGIC[i]) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Not a vault record");
            }
        }
        if (content[RECORD_MAGIC.length] != RECORD_VERSION) {
            if ((content[RECORD_MAGIC.length] & 0xFF) > RECORD_VERSION) {
                throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_VERSION, "Record was written by a newer app version");
            }
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Unsupported record version");
        }
        byte[] blob = new byte[content.length - RECORD_HEADER_BYTES];
        System.arraycopy(content, RECORD_HEADER_BYTES, blob, 0, blob.length);
        byte[] padded = VaultCrypto.decrypt(messageKey, blob, recordAad(id));
        try {
            VaultItem item = VaultItem.decodePadded(padded);
            if (!id.equals(item.id)) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Record id mismatch");
            }
            return item;
        } finally {
            VaultCrypto.wipe(padded);
        }
    }

    private VaultItem requireItem(String id) throws VaultCryptoException {
        VaultItem item = get(id);
        if (item == null) {
            throw invalid("No such item");
        }
        return item;
    }

    // ------------------------------------------------------------------ internals: media

    private long writeMedia(byte[] mediaKey, String mediaId, InputStream source, List<File> created) throws VaultCryptoException {
        File tmp = new File(mediaDir(), mediaId + MEDIA_EXT + TMP_EXT);
        File dest = mediaFile(mediaId);
        created.add(tmp);
        created.add(dest);
        try {
            long size;
            try (FileOutputStream fos = new FileOutputStream(tmp);
                 BufferedOutputStream bos = new BufferedOutputStream(fos, 64 * 1024)) {
                size = VaultMediaCipher.encrypt(new LimitedInputStream(source, maxPlaintextBytes()), bos,
                        mediaKey, mediaAad(mediaId), chunkSize);
                bos.flush();
                fos.getFD().sync();
            }
            VaultFiles.renameOver(tmp, dest);
            return size;
        } catch (TooLargeException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.MEDIA_TOO_LARGE,
                    "This file is larger than Telegram allows, so it cannot be saved to the Vault", e);
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not store media", e);
        }
    }

    private static final class TooLargeException extends IOException {
        private static final long serialVersionUID = 1L;
    }

    /** Fails with {@link TooLargeException} as soon as more than {@code limit} bytes have been read. */
    private static final class LimitedInputStream extends InputStream {
        private final InputStream in;
        private final long limit;
        private long read;

        LimitedInputStream(InputStream in, long limit) {
            this.in = in;
            this.limit = limit;
        }

        @Override
        public int read() throws IOException {
            int b = in.read();
            if (b >= 0 && ++read > limit) {
                throw new TooLargeException();
            }
            return b;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            int n = in.read(buffer, offset, length);
            if (n > 0) {
                read += n;
                if (read > limit) {
                    throw new TooLargeException();
                }
            }
            return n;
        }
    }

    // ------------------------------------------------------------------ internals: paths and ids

    private File itemsDir() {
        return new File(rootDir, ITEMS_DIR);
    }

    private File mediaDir() {
        return new File(rootDir, MEDIA_DIR);
    }

    private File recordFile(String id) {
        return new File(itemsDir(), id + RECORD_EXT);
    }

    private File mediaFile(String id) {
        return new File(mediaDir(), id + MEDIA_EXT);
    }

    private void ensureDirs() throws VaultCryptoException {
        for (File dir : new File[]{itemsDir(), mediaDir()}) {
            if (!dir.isDirectory() && !dir.mkdirs() && !dir.isDirectory()) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Cannot create vault directory");
            }
        }
    }

    private List<String> recordIds() {
        List<String> ids = new ArrayList<>();
        File[] files = itemsDir().listFiles();
        if (files != null) {
            for (File f : files) {
                String name = f.getName();
                if (f.isFile() && name.endsWith(RECORD_EXT)) {
                    String id = name.substring(0, name.length() - RECORD_EXT.length());
                    if (isValidId(id)) {
                        ids.add(id);
                    }
                }
            }
        }
        return ids;
    }

    private static String newId() {
        byte[] r = VaultCrypto.randomBytes(16);
        StringBuilder sb = new StringBuilder(32);
        for (byte b : r) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /** Ids are exactly 32 lowercase hex characters, which also rules out any path tricks like "../". */
    static boolean isValidId(String id) {
        if (id == null || id.length() != 32) {
            return false;
        }
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    private static void checkId(String id) throws VaultCryptoException {
        if (!isValidId(id)) {
            throw invalid("Invalid id");
        }
    }

    private static byte[] recordAad(String id) {
        return ("tg-vault/record/v1/" + id).getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] mediaAad(String id) {
        return ("tg-vault/media/v1/" + id).getBytes(StandardCharsets.US_ASCII);
    }

    private static boolean contains(String haystack, String lowerNeedle) {
        return haystack != null && haystack.toLowerCase(Locale.ROOT).contains(lowerNeedle);
    }

    private static VaultCryptoException invalid(String message) {
        return new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, message);
    }
}
