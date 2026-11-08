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
                size = VaultMediaCipher.encrypt(source, bos, mediaKey, mediaAad(mediaId), chunkSize);
                bos.flush();
                fos.getFD().sync();
            }
            VaultFiles.renameOver(tmp, dest);
            return size;
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not store media", e);
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
