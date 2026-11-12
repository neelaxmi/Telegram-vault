package org.telegram.messenger.vault;

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
import java.util.Map;
import java.util.Set;

/**
 * Mirrors the local {@link VaultStore} to a {@link VaultRemoteStore}. Pure Java.
 *
 * <h3>Rules</h3>
 * <ul>
 *   <li><b>Add-only set + tombstones.</b> Items are immutable and have random ids, so two devices can never
 *       conflict on content. A delete is a tombstone object; a tombstoned id never comes back.</li>
 *   <li><b>Commit order.</b> Thumbnail, then media, then the record LAST. Other devices only see an item
 *       once its record exists, so a half-uploaded item is invisible, never broken.</li>
 *   <li><b>Idempotent retries.</b> Every upload carries a deterministic token (HMAC of the object name), so
 *       a repeat after a lost acknowledgement cannot store a second copy.</li>
 *   <li><b>Journal after every step.</b> A crash or killed app resumes exactly where it stopped.</li>
 *   <li><b>The pull order is the server order.</b> The cursor only moves past an entry once it is handled.</li>
 *   <li><b>Nothing from the server is trusted.</b> Records, tombstones and media must authenticate under this
 *       vault's keys; anything else is counted and ignored, never stored.</li>
 *   <li><b>Bundle first.</b> The key bundle is uploaded before any data, so a new device can always restore.</li>
 * </ul>
 * Thread-safe: public methods are synchronised, so only one sync step runs at a time.
 */
public final class VaultSyncEngine {

    /** What a call did; useful for the UI and for tests. */
    public static final class SyncReport {
        public int uploadedObjects;
        public int downloadedRecords;
        public int tombstonesApplied;
        public int tombstonesPublished;
        public int remoteObjectsDeleted;
        /** Server objects that did not authenticate as belonging to this vault (ignored, never stored). */
        public int rejectedRemote;
        /** Records from a newer app version that are kept aside until this app is updated. */
        public int skippedUnsupported;
        public int ignoredUnknown;
        /** Local records that could not be read, so they were not uploaded. */
        public int skippedUnreadableLocal;
        /** Items with an object missing locally that cannot be completed. */
        public int incompleteLocal;
        public boolean journalRebuilt;
        /** The server holds a key bundle of a newer key epoch: this device must restore with the recovery key. */
        public boolean needsRestore;
        public final List<String> reuploadQueued = new ArrayList<>();
        public final List<String> lostMedia = new ArrayList<>();
    }

    static final int PAGE_SIZE = 100;
    private static final int MAX_RECORD_DOWNLOAD = 8 * 1024 * 1024;
    private static final int MAX_SMALL_DOWNLOAD = 64 * 1024;
    private static final byte[] TOMBSTONE_MAGIC = {'T', 'G', 'V', 'X'};
    private static final String PURPOSE_JOURNAL = "journal";
    private static final String PURPOSE_DEDUP = "dedup";

    private final VaultStore store;
    private final VaultKeyManager keys;
    private final VaultRemoteStore remote;
    private final File journalFile;
    private final File workDir;
    private final VaultStore.Clock clock;

    public VaultSyncEngine(VaultStore store, VaultKeyManager keys, VaultRemoteStore remote, File journalFile) {
        this(store, keys, remote, journalFile, new VaultStore.Clock() {
            @Override
            public long nowMillis() {
                return System.currentTimeMillis();
            }
        });
    }

    VaultSyncEngine(VaultStore store, VaultKeyManager keys, VaultRemoteStore remote, File journalFile, VaultStore.Clock clock) {
        if (store == null || keys == null || remote == null || journalFile == null || clock == null) {
            throw new IllegalArgumentException("all arguments are required");
        }
        this.store = store;
        this.keys = keys;
        this.remote = remote;
        this.journalFile = journalFile;
        this.workDir = journalFile.getAbsoluteFile().getParentFile();
        this.clock = clock;
    }

    // ------------------------------------------------------------------ names

    static String recordName(String id) {
        return "r." + id;
    }

    static String mediaName(String id) {
        return "m." + id;
    }

    static String thumbName(String id) {
        return "t." + id;
    }

    static String tombstoneName(String id) {
        return "x." + id;
    }

    static String bundleName(int version) {
        return "b." + version;
    }

    // ------------------------------------------------------------------ local operations

    /** Saves an item locally and queues it for upload. */
    public synchronized VaultItem addItem(VaultItem.Draft draft, InputStream media, byte[] thumbnail) throws VaultCryptoException {
        Session s = open();
        try {
            VaultItem item = store.addItem(draft, media, thumbnail);
            s.journal.items.put(item.id, new SyncJournal.ItemState(SyncJournal.State.PENDING_UPLOAD));
            s.save();
            return item;
        } finally {
            s.close();
        }
    }

    /**
     * Deletes an item. It disappears locally at once; the tombstone and the removal of its server objects
     * happen in {@link #sync()} (and are retried until they succeed).
     *
     * @return true if the item existed
     */
    public synchronized boolean deleteItem(String id) throws VaultCryptoException {
        Session s = open();
        try {
            if (!VaultStore.isValidId(id)) {
                throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Invalid id");
            }
            SyncJournal.ItemState state = s.journal.items.get(id);
            boolean existed = store.recordCipherFile(id).isFile();
            if (!existed && state == null) {
                return false;
            }
            if (state == null || state.state == SyncJournal.State.PENDING_UPLOAD && !hasRemoteObjects(s.journal, state, id)) {
                // Never reached the server: nothing to announce, just forget it.
                store.delete(id);
                s.journal.items.remove(id);
                s.save();
                return existed;
            }
            if (state.state != SyncJournal.State.DELETED) {
                List<String> parts = partsOf(s.journal, id);
                state.state = SyncJournal.State.DELETE_PENDING;
                state.parts = parts;
                s.save(); // announce intent first: a crash after this still finishes the delete
            }
            store.delete(id);
            return existed;
        } finally {
            s.close();
        }
    }

    // ------------------------------------------------------------------ sync

    /** Pulls what is new on the server, then pushes what is pending. Safe to call again after any failure. */
    public synchronized SyncReport sync() throws VaultCryptoException {
        Session s = open();
        SyncReport report = new SyncReport();
        report.journalRebuilt = s.rebuilt;
        try {
            if (keys.isLegacyHeader()) {
                throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "Vault must be migrated before syncing");
            }
            pull(s, report);
            push(s, report);
            return report;
        } finally {
            s.close();
        }
    }

    /**
     * Lists the whole server and compares it with the journal. Items whose objects have vanished from the
     * server (deleted by hand, channel cleared) are queued for upload again from the local copy; media that
     * is gone from both places is reported in {@link SyncReport#lostMedia}. Call {@link #sync()} afterwards.
     */
    public synchronized SyncReport verifyRemote() throws VaultCryptoException {
        Session s = open();
        SyncReport report = new SyncReport();
        try {
            Map<String, String> onServer = new java.util.HashMap<>();
            long after = 0;
            while (true) {
                List<VaultRemoteStore.Entry> page = listPage(after);
                if (page.isEmpty()) {
                    break;
                }
                for (VaultRemoteStore.Entry e : page) {
                    onServer.put(e.name, e.ref);
                    after = e.seq;
                }
            }
            for (Map.Entry<String, SyncJournal.ItemState> e : new ArrayList<>(s.journal.items.entrySet())) {
                SyncJournal.ItemState st = e.getValue();
                if (st.state != SyncJournal.State.SYNCED) {
                    continue;
                }
                List<String> missing = new ArrayList<>();
                for (String part : st.parts) {
                    if (!onServer.containsKey(part)) {
                        missing.add(part);
                    }
                }
                if (missing.isEmpty()) {
                    continue;
                }
                boolean canRestore = true;
                VaultItem item = null;
                try {
                    item = store.get(e.getKey());
                } catch (VaultCryptoException ex) {
                    if (ex.getReason() != VaultCryptoException.Reason.CORRUPTED
                            && ex.getReason() != VaultCryptoException.Reason.UNSUPPORTED_VERSION) {
                        throw ex;
                    }
                }
                if (item == null) {
                    continue; // nothing local to upload from
                }
                for (String part : missing) {
                    if (part.startsWith("m.") && !store.hasMediaFile(item.mediaId)) {
                        report.lostMedia.add(e.getKey());
                        canRestore = false;
                    }
                }
                if (canRestore) {
                    for (String part : st.parts) {
                        s.journal.refs.remove(part);
                    }
                    st.state = SyncJournal.State.PENDING_UPLOAD;
                    report.reuploadQueued.add(e.getKey());
                }
            }
            s.save();
            return report;
        } finally {
            s.close();
        }
    }

    // ------------------------------------------------------------------ cache

    /** Decrypts an item's media into {@code out}, downloading it first if this device does not hold it. */
    public synchronized void openMedia(String itemId, OutputStream out) throws VaultCryptoException {
        Session s = open();
        try {
            VaultItem item = store.get(itemId);
            if (item == null || item.mediaId == null) {
                throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Item has no media");
            }
            ensureLocal(s, mediaName(item.mediaId), item.mediaId, item.mediaSize);
            SyncJournal.ItemState st = s.journal.items.get(itemId);
            if (st != null) {
                st.lastAccessMillis = clock.nowMillis();
                s.save();
            }
            store.readMedia(itemId, out);
        } finally {
            s.close();
        }
    }

    /** The preview image, downloaded first if needed. Null if the item has none. */
    public synchronized byte[] readThumbnail(String itemId) throws VaultCryptoException {
        Session s = open();
        try {
            VaultItem item = store.get(itemId);
            if (item == null) {
                throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "No such item");
            }
            if (item.thumbnailId == null) {
                return null;
            }
            ensureLocal(s, thumbName(item.thumbnailId), item.thumbnailId, -1);
            return store.readThumbnail(itemId);
        } finally {
            s.close();
        }
    }

    /**
     * Evicts the least recently opened media of fully synced items until the local media files take up at
     * most {@code maxBytes}. Media that is not confirmed on the server is never evicted.
     *
     * @return bytes freed
     */
    public synchronized long trimCache(long maxBytes) throws VaultCryptoException {
        Session s = open();
        try {
            final Map<String, SyncJournal.ItemState> items = s.journal.items;
            List<String> candidates = new ArrayList<>();
            long total = 0;
            for (VaultItem item : store.list().items) {
                if (item.mediaId == null || !store.hasMediaFile(item.mediaId)) {
                    continue;
                }
                total += store.mediaCipherFile(item.mediaId).length();
                SyncJournal.ItemState st = items.get(item.id);
                if (st != null && st.state == SyncJournal.State.SYNCED && s.journal.refs.containsKey(mediaName(item.mediaId))) {
                    candidates.add(item.id);
                }
            }
            Collections.sort(candidates, new Comparator<String>() {
                @Override
                public int compare(String a, String b) {
                    int c = Long.compare(items.get(a).lastAccessMillis, items.get(b).lastAccessMillis);
                    return c != 0 ? c : a.compareTo(b);
                }
            });
            long freed = 0;
            for (String id : candidates) {
                if (total - freed <= maxBytes) {
                    break;
                }
                freed += store.evictMedia(id);
            }
            return freed;
        } finally {
            s.close();
        }
    }

    // ------------------------------------------------------------------ status

    /** Items that still have something to send (upload or delete). */
    public synchronized int pendingCount() throws VaultCryptoException {
        Session s = open();
        try {
            int n = 0;
            for (SyncJournal.ItemState st : s.journal.items.values()) {
                if (st.state == SyncJournal.State.PENDING_UPLOAD || st.state == SyncJournal.State.DELETE_PENDING) {
                    n++;
                }
            }
            for (String id : store.localIds()) {
                if (!s.journal.items.containsKey(id)) {
                    n++;
                }
            }
            return n;
        } finally {
            s.close();
        }
    }

    // ------------------------------------------------------------------ pull

    private void pull(Session s, SyncReport report) throws VaultCryptoException {
        retrySkipped(s, report);
        int newestBundle = -1;
        VaultRemoteStore.Entry newestBundleEntry = null;
        while (true) {
            List<VaultRemoteStore.Entry> page = listPage(s.journal.cursor);
            if (page.isEmpty()) {
                break;
            }
            for (VaultRemoteStore.Entry e : page) {
                if (e.seq <= s.journal.cursor) {
                    throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Server returned entries out of order");
                }
                if (s.journal.retired.contains(e.ref)) {
                    // An object from before a key rotation, waiting to be deleted: never read, never trusted.
                } else if (e.name != null && e.name.startsWith("b.")) {
                    int version = parseVersion(e.name);
                    if (version > newestBundle) {
                        newestBundle = version;
                        newestBundleEntry = e;
                    }
                } else {
                    handleEntry(s, e, report);
                }
                s.journal.cursor = e.seq;
                s.save();
            }
        }
        if (newestBundleEntry != null) {
            checkBundle(s, newestBundleEntry, report);
        }
    }

    private void handleEntry(Session s, VaultRemoteStore.Entry e, SyncReport report) throws VaultCryptoException {
        String name = e.name;
        int dot = name == null ? -1 : name.indexOf('.');
        if (dot != 1 || !VaultStore.isValidId(name.substring(2))) {
            report.ignoredUnknown++;
            return;
        }
        char kind = name.charAt(0);
        String id = name.substring(2);
        switch (kind) {
            case 'm':
            case 't':
                s.journal.refs.put(name, e.ref);
                break;
            case 'r':
                handleRecord(s, e, id, report);
                break;
            case 'x':
                handleTombstone(s, e, id, report);
                break;
            default:
                report.ignoredUnknown++;
        }
    }

    private void handleRecord(Session s, VaultRemoteStore.Entry e, String id, SyncReport report) throws VaultCryptoException {
        SyncJournal j = s.journal;
        SyncJournal.ItemState st = j.items.get(id);
        j.refs.put(e.name, e.ref);
        if (st != null && (st.state == SyncJournal.State.DELETED || st.state == SyncJournal.State.DELETE_PENDING)) {
            // Deleted already: whatever is left on the server must go.
            st.state = SyncJournal.State.DELETE_PENDING;
            if (!st.parts.contains(e.name)) {
                st.parts.add(e.name);
            }
            return;
        }
        if (store.recordCipherFile(id).isFile()) {
            if (st == null) {
                SyncJournal.ItemState created = new SyncJournal.ItemState(SyncJournal.State.SYNCED);
                created.parts = partsOf(j, id);
                j.items.put(id, created);
            }
            return;
        }
        byte[] bytes = downloadBytes(e.ref, MAX_RECORD_DOWNLOAD);
        if (bytes == null) {
            report.rejectedRemote++;
            return;
        }
        try {
            store.importRecord(id, bytes);
        } catch (VaultCryptoException ex) {
            if (ex.getReason() == VaultCryptoException.Reason.CORRUPTED) {
                report.rejectedRemote++;
                j.refs.remove(e.name);
                return;
            }
            if (ex.getReason() == VaultCryptoException.Reason.UNSUPPORTED_VERSION) {
                j.skipped.put(e.name, e.ref);
                report.skippedUnsupported++;
                return;
            }
            throw ex;
        }
        SyncJournal.ItemState created = new SyncJournal.ItemState(SyncJournal.State.SYNCED);
        created.parts = partsOf(j, id);
        j.items.put(id, created);
        report.downloadedRecords++;
    }

    private void handleTombstone(Session s, VaultRemoteStore.Entry e, String id, SyncReport report) throws VaultCryptoException {
        byte[] bytes = downloadBytes(e.ref, MAX_SMALL_DOWNLOAD);
        if (bytes == null || !authenticTombstone(bytes, id)) {
            report.rejectedRemote++;
            return;
        }
        SyncJournal j = s.journal;
        j.refs.put(e.name, e.ref);
        SyncJournal.ItemState st = j.items.get(id);
        List<String> parts = st != null && !st.parts.isEmpty() ? st.parts : partsOf(j, id);
        if (st == null) {
            st = new SyncJournal.ItemState(SyncJournal.State.DELETED);
            j.items.put(id, st);
        }
        if (store.recordCipherFile(id).isFile()) {
            store.delete(id);
            report.tombstonesApplied++;
        }
        boolean leftovers = false;
        for (String part : parts) {
            if (j.refs.containsKey(part)) {
                leftovers = true;
            }
        }
        st.parts = new ArrayList<>(parts);
        st.state = leftovers ? SyncJournal.State.DELETE_PENDING : SyncJournal.State.DELETED;
    }

    private void retrySkipped(Session s, SyncReport report) throws VaultCryptoException {
        for (Map.Entry<String, String> e : new ArrayList<>(s.journal.skipped.entrySet())) {
            String id = e.getKey().substring(2);
            byte[] bytes = downloadBytes(e.getValue(), MAX_RECORD_DOWNLOAD);
            if (bytes == null) {
                s.journal.skipped.remove(e.getKey());
                continue;
            }
            try {
                store.importRecord(id, bytes);
                s.journal.skipped.remove(e.getKey());
                SyncJournal.ItemState st = new SyncJournal.ItemState(SyncJournal.State.SYNCED);
                st.parts = partsOf(s.journal, id);
                s.journal.items.put(id, st);
                report.downloadedRecords++;
            } catch (VaultCryptoException ex) {
                if (ex.getReason() == VaultCryptoException.Reason.CORRUPTED) {
                    s.journal.skipped.remove(e.getKey());
                } else if (ex.getReason() != VaultCryptoException.Reason.UNSUPPORTED_VERSION) {
                    throw ex;
                }
            }
        }
        s.save();
    }

    private void checkBundle(Session s, VaultRemoteStore.Entry e, SyncReport report) throws VaultCryptoException {
        byte[] bytes = downloadBytes(e.ref, VaultBundle.MAX_BUNDLE_BYTES);
        if (bytes == null) {
            report.rejectedRemote++;
            return;
        }
        if (parseVersion(e.name) < keys.getBundleVersion() && s.journal.bundleUploadedVersion < keys.getBundleVersion()) {
            // We rotated our keys and have not published the new bundle yet, so an older one on the server is
            // expected. The push step uploads ours next; until then nothing is taken from this one.
            return;
        }
        VaultKeyManager.BundleStatus status = keys.checkRemoteBundle(bytes); // throws ROLLBACK_DETECTED / CORRUPTED / INVALID_STATE
        if (status == VaultKeyManager.BundleStatus.NEWER) {
            report.needsRestore = true;
        }
        s.journal.refs.put(e.name, e.ref);
        s.journal.bundleUploadedVersion = Math.max(s.journal.bundleUploadedVersion, parseVersion(e.name));
        s.save();
    }

    // ------------------------------------------------------------------ push

    private void push(Session s, SyncReport report) throws VaultCryptoException {
        SyncJournal j = s.journal;
        if (report.needsRestore) {
            return; // our keys are out of date: sending anything now would be sending the wrong epoch
        }
        int bundleVersion = keys.getBundleVersion();
        if (j.bundleUploadedVersion < bundleVersion) {
            uploadBytes(s, bundleName(bundleVersion), keys.currentBundle(), report);
            j.bundleUploadedVersion = bundleVersion;
            s.save();
        }
        for (String id : store.localIds()) {
            if (!j.items.containsKey(id)) {
                j.items.put(id, new SyncJournal.ItemState(SyncJournal.State.PENDING_UPLOAD));
            }
        }
        s.save();
        for (Map.Entry<String, SyncJournal.ItemState> e : new ArrayList<>(j.items.entrySet())) {
            SyncJournal.ItemState st = e.getValue();
            if (st.state == SyncJournal.State.PENDING_UPLOAD) {
                uploadItem(s, e.getKey(), st, report);
            } else if (st.state == SyncJournal.State.DELETE_PENDING) {
                finishDelete(s, e.getKey(), st, report);
            }
        }
        removeRetired(s, report);
    }

    /**
     * After a key rotation: deletes the server objects of the old key epoch, but only once the new bundle and
     * every item are on the server under the new key, so the server always holds a complete copy.
     */
    private void removeRetired(Session s, SyncReport report) throws VaultCryptoException {
        SyncJournal j = s.journal;
        if (j.retired.isEmpty() || j.bundleUploadedVersion < keys.getBundleVersion() || report.incompleteLocal > 0
                || report.skippedUnreadableLocal > 0) {
            return;
        }
        for (SyncJournal.ItemState st : j.items.values()) {
            if (st.state == SyncJournal.State.PENDING_UPLOAD || st.state == SyncJournal.State.DELETE_PENDING) {
                return;
            }
        }
        for (String ref : new ArrayList<>(j.retired)) {
            try {
                remote.delete(ref);
            } catch (IOException e) {
                s.save();
                throw io("Could not delete an old server object", e);
            }
            j.retired.remove(ref);
            report.remoteObjectsDeleted++;
            s.save();
        }
    }

    private void uploadItem(Session s, String id, SyncJournal.ItemState st, SyncReport report) throws VaultCryptoException {
        VaultItem item;
        try {
            item = store.get(id);
        } catch (VaultCryptoException e) {
            if (e.getReason() == VaultCryptoException.Reason.CORRUPTED || e.getReason() == VaultCryptoException.Reason.UNSUPPORTED_VERSION) {
                report.skippedUnreadableLocal++;
                return;
            }
            throw e;
        }
        if (item == null) {
            s.journal.items.remove(id); // deleted locally before it was ever sent
            s.save();
            return;
        }
        List<String> parts = new ArrayList<>();
        List<File> files = new ArrayList<>();
        if (item.thumbnailId != null) {
            parts.add(thumbName(item.thumbnailId));
            files.add(store.mediaCipherFile(item.thumbnailId));
        }
        if (item.mediaId != null) {
            parts.add(mediaName(item.mediaId));
            files.add(store.mediaCipherFile(item.mediaId));
        }
        parts.add(recordName(id));
        files.add(store.recordCipherFile(id));
        for (int i = 0; i < parts.size(); i++) {
            if (!files.get(i).isFile() && !s.journal.refs.containsKey(parts.get(i))) {
                report.incompleteLocal++;
                return; // cannot finish this item; leave it pending
            }
        }
        for (int i = 0; i < parts.size(); i++) {
            String name = parts.get(i);
            if (s.journal.refs.containsKey(name)) {
                continue;
            }
            VaultRemoteStore.Entry entry = upload(s, name, files.get(i));
            s.journal.refs.put(name, entry.ref);
            s.journal.cursor = s.journal.cursor; // the pull step owns the cursor; our own uploads are recognised when listed
            report.uploadedObjects++;
            s.save();
        }
        st.parts = parts;
        st.state = SyncJournal.State.SYNCED;
        s.save();
    }

    private void finishDelete(Session s, String id, SyncJournal.ItemState st, SyncReport report) throws VaultCryptoException {
        SyncJournal j = s.journal;
        if (store.recordCipherFile(id).isFile()) {
            store.delete(id);
        }
        String tomb = tombstoneName(id);
        if (!j.refs.containsKey(tomb)) {
            byte[] blob = buildTombstone(id);
            uploadBytes(s, tomb, blob, report);
            report.tombstonesPublished++;
        }
        // Record first, then media: a crash in between leaves an orphan, never an item that looks complete.
        List<String> ordered = new ArrayList<>(st.parts);
        Collections.sort(ordered, new Comparator<String>() {
            @Override
            public int compare(String a, String b) {
                return Integer.compare(a.startsWith("r.") ? 0 : 1, b.startsWith("r.") ? 0 : 1);
            }
        });
        for (String part : ordered) {
            String ref = j.refs.get(part);
            if (ref != null) {
                try {
                    remote.delete(ref);
                } catch (IOException e) {
                    s.save();
                    throw io("Could not delete a server object", e);
                }
                j.refs.remove(part);
                report.remoteObjectsDeleted++;
                s.save();
            }
        }
        st.state = SyncJournal.State.DELETED;
        st.parts = new ArrayList<>();
        s.save();
    }

    // ------------------------------------------------------------------ key rotation

    /** Test seam: called at named points of a rotation; a test throws a RuntimeException to simulate a crash. Null in production. */
    interface RotationFault {
        void at(String stage);
    }

    RotationFault rotationFault;

    private void fault(String stage) {
        RotationFault f = rotationFault;
        if (f != null) {
            f.at(stage);
        }
    }

    private static final String ROTATION_DIR = "rotation";
    private static final String ROTATION_JOURNAL = "journal.bin";
    private static final String ROTATION_MARKER = "COMMIT";

    /** A rotation that has been prepared; the user must now confirm the new recovery key. */
    public static final class RotationPlan {
        private final VaultKeyManager.Rotation rotation;

        private RotationPlan(VaultKeyManager.Rotation rotation) {
            this.rotation = rotation;
        }

        /** The new recovery key to show once. */
        public RecoveryKey recoveryKey() {
            return rotation.recoveryKey();
        }

        public void cancel() {
            rotation.cancel();
        }
    }

    /**
     * Rotation step 1: makes sure this device is fully in step with the server and holds every file, then
     * creates the new keys. Nothing is changed yet. Needs the password again.
     *
     * Refuses (INVALID_STATE / UNSUPPORTED_VERSION) if the server holds a newer key epoch, records from a newer
     * app, unreadable items or media that is neither here nor on the server: rotating then would lose data.
     */
    public synchronized RotationPlan beginKeyRotation(char[] password) throws VaultCryptoException {
        recoverInterruptedRotation();
        prepareForRotation();
        return new RotationPlan(keys.beginRotation(password));
    }

    /**
     * Rotation step 2: after the user typed the new recovery key back. Re-encrypts everything on this device
     * under the new key, switches over atomically (a crash is finished or rolled back at the next unlock) and
     * queues the re-upload. Call {@link #sync()} afterwards: it publishes the new bundle, uploads every item
     * under the new key and only then deletes the old server objects.
     */
    public synchronized void finishKeyRotation(RotationPlan plan, String typedRecoveryKey) throws VaultCryptoException {
        plan.rotation.confirm(typedRecoveryKey);
        recoverInterruptedRotation();
        prepareForRotation(); // pulls anything that arrived since step 1
        File dir = new File(store.stagingRoot(), ROTATION_DIR);
        Session s = open();
        byte[] newMessageKey = null;
        byte[] newMediaKey = null;
        byte[] newJournalKey = null;
        boolean committed = false;
        try {
            // Items deleted but not announced yet: their server objects are retired below, nothing to announce.
            for (Map.Entry<String, SyncJournal.ItemState> e : s.journal.items.entrySet()) {
                if (e.getValue().state == SyncJournal.State.DELETE_PENDING && store.recordCipherFile(e.getKey()).isFile()) {
                    store.delete(e.getKey());
                }
            }
            SyncJournal next = new SyncJournal();
            next.cursor = s.journal.cursor;
            next.bundleUploadedVersion = 0;
            next.retired.addAll(s.journal.retired);
            next.retired.addAll(s.journal.refs.values());
            for (Map.Entry<String, SyncJournal.ItemState> e : s.journal.items.entrySet()) {
                SyncJournal.State old = e.getValue().state;
                boolean gone = old == SyncJournal.State.DELETED || old == SyncJournal.State.DELETE_PENDING;
                SyncJournal.ItemState st = new SyncJournal.ItemState(gone ? SyncJournal.State.DELETED : SyncJournal.State.PENDING_UPLOAD);
                st.lastAccessMillis = e.getValue().lastAccessMillis;
                next.items.put(e.getKey(), st);
            }
            for (String id : store.localIds()) {
                if (!next.items.containsKey(id)) {
                    next.items.put(id, new SyncJournal.ItemState(SyncJournal.State.PENDING_UPLOAD));
                }
            }

            deleteTree(dir);
            newMessageKey = plan.rotation.deriveSubkey(VaultStore.PURPOSE_MESSAGES);
            newMediaKey = plan.rotation.deriveSubkey(VaultStore.PURPOSE_MEDIA);
            newJournalKey = plan.rotation.deriveSubkey(PURPOSE_JOURNAL);
            store.stageReencrypted(dir, newMessageKey, newMediaKey);
            next.save(new File(dir, ROTATION_JOURNAL), newJournalKey);
            fault("staged");
            writeMarker(dir, plan.rotation.bundleVersion());
            fault("marked");

            keys.commitRotation(plan.rotation); // the point of no return: the header now holds the new key
            committed = true;
            fault("committed");
            completeRotation(dir);
        } catch (VaultCryptoException e) {
            if (!committed) {
                deleteTree(dir); // nothing was switched; the old data is untouched
            }
            throw e;
        } finally {
            VaultCrypto.wipe(newMessageKey);
            VaultCrypto.wipe(newMediaKey);
            VaultCrypto.wipe(newJournalKey);
            s.close();
        }
    }

    /**
     * For a device whose keys were replaced by a rotation on another device (the server holds a newer key
     * bundle). The recovery key must open that bundle and the password is checked BEFORE anything is deleted.
     * Then this device's local copy (encrypted under the old key and no longer readable) is wiped and the
     * device is set up again under the new key with a new password; the next sync downloads everything.
     * Items that were saved here but never reached the server are lost.
     */
    public synchronized void adoptNewKeyEpoch(byte[] newerBundle, String recoveryKeyText, char[] newPassword,
                                              char[] confirmation) throws VaultCryptoException {
        VaultKeyManager.validateNewPassword(newPassword, confirmation);
        RecoveryKey key = RecoveryKey.parse(recoveryKeyText);
        try {
            VaultCrypto.wipe(VaultBundle.openWithRecoveryKey(newerBundle, key));
        } finally {
            key.wipe();
        }
        if (keys.checkRemoteBundle(newerBundle) != VaultKeyManager.BundleStatus.NEWER) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "That key bundle is not newer than this device's");
        }
        store.deleteAllData();
        deleteTree(new File(store.stagingRoot(), ROTATION_DIR));
        if (journalFile.exists() && !journalFile.delete()) {
            throw io("Could not remove the old sync journal", new IOException("delete failed"));
        }
        keys.restoreFromBundle(newerBundle, recoveryKeyText, newPassword, confirmation, true);
    }

    /**
     * Finishes or rolls back a rotation that a crash interrupted. Needs the vault unlocked. Called
     * automatically before every rotation step and by the runtime right after unlocking.
     *
     * @return true if an interrupted rotation was completed
     */
    public synchronized boolean recoverInterruptedRotation() throws VaultCryptoException {
        return recoverRotation(store, keys, journalFile, rotationFault);
    }

    /**
     * Same as {@link #recoverInterruptedRotation()} without needing an engine (so it works before the Vault
     * channel is attached). The runtime calls it right after unlocking.
     */
    public static boolean recoverRotation(VaultStore store, VaultKeyManager keys, File journalFile) throws VaultCryptoException {
        return recoverRotation(store, keys, journalFile, null);
    }

    static boolean recoverRotation(VaultStore store, VaultKeyManager keys, File journalFile, RotationFault fault) throws VaultCryptoException {
        File dir = new File(store.stagingRoot(), ROTATION_DIR);
        if (!dir.exists()) {
            return false;
        }
        int target = readMarker(dir);
        if (target < 0) {
            deleteTree(dir); // staging was never completed: nothing was switched
            return false;
        }
        int have = keys.getBundleVersion();
        if (have == target) {
            completeRotation(store, journalFile, dir, fault);
            return true;
        }
        if (have == target - 1) {
            deleteTree(dir); // the header was never switched: keep the old data
            return false;
        }
        throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Interrupted rotation does not match the vault");
    }

    private void completeRotation(File dir) throws VaultCryptoException {
        completeRotation(store, journalFile, dir, rotationFault);
    }

    private static void completeRotation(VaultStore store, File journalFile, File dir, RotationFault fault) throws VaultCryptoException {
        store.adoptStaged(dir);
        if (fault != null) {
            fault.at("adopted");
        }
        try {
            VaultFiles.renameOver(new File(dir, ROTATION_JOURNAL), journalFile);
        } catch (IOException e) {
            throw io("Could not switch the sync journal", e);
        }
        deleteTree(dir);
    }

    private void prepareForRotation() throws VaultCryptoException {
        SyncReport report = sync();
        if (report.needsRestore) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE,
                    "Another device already changed the keys. Restore with the recovery key first.");
        }
        if (report.skippedUnsupported > 0) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_VERSION,
                    "Some items were saved by a newer app version. Update the app before rotating the keys.");
        }
        if (report.incompleteLocal > 0 || report.skippedUnreadableLocal > 0 || !report.lostMedia.isEmpty()) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE,
                    "Some items are damaged or incomplete, so the keys cannot be rotated safely.");
        }
        Session s = open();
        try {
            if (!s.journal.skipped.isEmpty()) {
                throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_VERSION,
                        "Some items were saved by a newer app version. Update the app before rotating the keys.");
            }
            VaultStore.Listing listing = store.list();
            if (!listing.corruptIds.isEmpty() || !listing.unsupportedIds.isEmpty()) {
                throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE,
                        "Some items are damaged, so the keys cannot be rotated safely.");
            }
            for (VaultItem item : listing.items) {
                if (item.thumbnailId != null) {
                    ensureLocal(s, thumbName(item.thumbnailId), item.thumbnailId, -1);
                }
                if (item.mediaId != null) {
                    ensureLocal(s, mediaName(item.mediaId), item.mediaId, item.mediaSize);
                }
            }
        } finally {
            s.close();
        }
    }

    private void writeMarker(File dir, int targetVersion) throws VaultCryptoException {
        byte[] data = new byte[8];
        data[0] = 'R';
        data[1] = 'O';
        data[2] = 'T';
        data[3] = '1';
        data[4] = (byte) (targetVersion >>> 24);
        data[5] = (byte) (targetVersion >>> 16);
        data[6] = (byte) (targetVersion >>> 8);
        data[7] = (byte) targetVersion;
        try {
            VaultFiles.writeAtomically(new File(dir, ROTATION_MARKER), data);
        } catch (IOException e) {
            throw io("Could not record the rotation", e);
        }
    }

    /** @return the target bundle version, or -1 if there is no valid marker */
    private static int readMarker(File dir) {
        File f = new File(dir, ROTATION_MARKER);
        if (!f.isFile()) {
            return -1;
        }
        try {
            byte[] d = VaultFiles.readBounded(f, 64);
            if (d.length != 8 || d[0] != 'R' || d[1] != 'O' || d[2] != 'T' || d[3] != '1') {
                return -1;
            }
            int v = ((d[4] & 0xFF) << 24) | ((d[5] & 0xFF) << 16) | ((d[6] & 0xFF) << 8) | (d[7] & 0xFF);
            return v < 2 ? -1 : v;
        } catch (IOException e) {
            return -1;
        }
    }

    private static void deleteTree(File dir) throws VaultCryptoException {
        try {
            VaultFiles.secureDeleteTree(dir);
        } catch (IOException e) {
            throw io("Could not remove temporary rotation files", e);
        }
    }

    // ------------------------------------------------------------------ helpers

    private boolean hasRemoteObjects(SyncJournal j, SyncJournal.ItemState st, String id) {
        for (String part : st.parts) {
            if (j.refs.containsKey(part)) {
                return true;
            }
        }
        return j.refs.containsKey(recordName(id));
    }

    /** Object names of an item: from the local record if readable, else from what the journal already knows. */
    private List<String> partsOf(SyncJournal j, String id) throws VaultCryptoException {
        List<String> parts = new ArrayList<>();
        try {
            VaultItem item = store.get(id);
            if (item != null) {
                if (item.thumbnailId != null) {
                    parts.add(thumbName(item.thumbnailId));
                }
                if (item.mediaId != null) {
                    parts.add(mediaName(item.mediaId));
                }
                parts.add(recordName(id));
                return parts;
            }
        } catch (VaultCryptoException e) {
            if (e.getReason() != VaultCryptoException.Reason.CORRUPTED
                    && e.getReason() != VaultCryptoException.Reason.UNSUPPORTED_VERSION) {
                throw e;
            }
        }
        SyncJournal.ItemState st = j.items.get(id);
        if (st != null && !st.parts.isEmpty()) {
            return new ArrayList<>(st.parts);
        }
        parts.add(recordName(id));
        return parts;
    }

    private void ensureLocal(Session s, String name, String fileId, long expectedBytes) throws VaultCryptoException {
        if (store.hasMediaFile(fileId)) {
            return;
        }
        String ref = s.journal.refs.get(name);
        if (ref == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Media is not on this device or on the server");
        }
        File tmp = new File(workDir, "dl-" + VaultCrypto.randomBytes(8).length + System.nanoTime() + ".tmp");
        try {
            try (OutputStream out = new FileOutputStream(tmp)) {
                remote.download(ref, out);
            } catch (IOException e) {
                throw io("Could not download media", e);
            }
            try (InputStream in = new FileInputStream(tmp)) {
                store.importMedia(fileId, in, expectedBytes);
            } catch (IOException e) {
                throw io("Could not read downloaded media", e);
            }
        } finally {
            try {
                VaultFiles.secureDelete(tmp);
            } catch (IOException ignored) {
                VaultFiles.deleteQuietly(tmp);
            }
        }
    }

    private VaultRemoteStore.Entry upload(Session s, String name, File file) throws VaultCryptoException {
        try {
            return remote.upload(name, token(s, name), file);
        } catch (IOException e) {
            s.save();
            throw io("Upload failed", e);
        }
    }

    private void uploadBytes(Session s, String name, byte[] bytes, SyncReport report) throws VaultCryptoException {
        File tmp = new File(workDir, "up-" + System.nanoTime() + ".tmp");
        try {
            try (OutputStream out = new FileOutputStream(tmp)) {
                out.write(bytes);
            } catch (IOException e) {
                throw io("Could not stage upload", e);
            }
            VaultRemoteStore.Entry entry = upload(s, name, tmp);
            s.journal.refs.put(name, entry.ref);
            report.uploadedObjects++;
            s.save();
        } finally {
            VaultFiles.deleteQuietly(tmp);
        }
    }

    private String token(Session s, String name) throws VaultCryptoException {
        byte[] mac = VaultCrypto.hmacSha256(s.dedupKey, name.getBytes(StandardCharsets.US_ASCII));
        StringBuilder sb = new StringBuilder(32);
        for (int i = 0; i < 16; i++) {
            sb.append(Character.forDigit((mac[i] >> 4) & 0xF, 16)).append(Character.forDigit(mac[i] & 0xF, 16));
        }
        return sb.toString();
    }

    private List<VaultRemoteStore.Entry> listPage(long after) throws VaultCryptoException {
        try {
            List<VaultRemoteStore.Entry> page = remote.list(after, PAGE_SIZE);
            return page == null ? new ArrayList<VaultRemoteStore.Entry>() : page;
        } catch (IOException e) {
            throw io("Could not list the server", e);
        }
    }

    /** Downloads at most {@code max} bytes; returns null if the object is larger (it cannot be one of ours). */
    private byte[] downloadBytes(String ref, final int max) throws VaultCryptoException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        OutputStream bounded = new OutputStream() {
            private int count;

            @Override
            public void write(int b) throws IOException {
                if (++count > max) {
                    throw new TooBig();
                }
                buffer.write(b);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                count += len;
                if (count > max) {
                    throw new TooBig();
                }
                buffer.write(b, off, len);
            }
        };
        try {
            remote.download(ref, bounded);
        } catch (TooBig e) {
            return null;
        } catch (IOException e) {
            throw io("Download failed", e);
        }
        return buffer.toByteArray();
    }

    private static final class TooBig extends IOException {
        private static final long serialVersionUID = 1L;
    }

    private static int parseVersion(String name) {
        try {
            long v = Long.parseLong(name.substring(2));
            return v < 1 || v > Integer.MAX_VALUE ? -1 : (int) v;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private byte[] buildTombstone(String id) throws VaultCryptoException {
        byte[] key = keys.deriveSubkey(VaultStore.PURPOSE_MESSAGES);
        try {
            byte[] idBytes = id.getBytes(StandardCharsets.US_ASCII);
            byte[] payload = new byte[idBytes.length + 8];
            System.arraycopy(idBytes, 0, payload, 0, idBytes.length);
            long now = clock.nowMillis();
            for (int i = 0; i < 8; i++) {
                payload[idBytes.length + i] = (byte) (now >>> (56 - 8 * i));
            }
            byte[] blob = VaultCrypto.encrypt(key, payload, tombstoneAad(id));
            byte[] out = new byte[TOMBSTONE_MAGIC.length + 1 + blob.length];
            System.arraycopy(TOMBSTONE_MAGIC, 0, out, 0, TOMBSTONE_MAGIC.length);
            out[TOMBSTONE_MAGIC.length] = 1;
            System.arraycopy(blob, 0, out, TOMBSTONE_MAGIC.length + 1, blob.length);
            return out;
        } finally {
            VaultCrypto.wipe(key);
        }
    }

    private boolean authenticTombstone(byte[] bytes, String id) throws VaultCryptoException {
        if (bytes.length < TOMBSTONE_MAGIC.length + 1 + 32) {
            return false;
        }
        for (int i = 0; i < TOMBSTONE_MAGIC.length; i++) {
            if (bytes[i] != TOMBSTONE_MAGIC[i]) {
                return false;
            }
        }
        if (bytes[TOMBSTONE_MAGIC.length] != 1) {
            return false;
        }
        byte[] key = keys.deriveSubkey(VaultStore.PURPOSE_MESSAGES);
        try {
            byte[] blob = new byte[bytes.length - TOMBSTONE_MAGIC.length - 1];
            System.arraycopy(bytes, TOMBSTONE_MAGIC.length + 1, blob, 0, blob.length);
            byte[] payload = VaultCrypto.decrypt(key, blob, tombstoneAad(id));
            boolean ok = payload.length == 40 && new String(payload, 0, 32, StandardCharsets.US_ASCII).equals(id);
            VaultCrypto.wipe(payload);
            return ok;
        } catch (VaultCryptoException e) {
            if (e.getReason() == VaultCryptoException.Reason.CORRUPTED) {
                return false;
            }
            throw e;
        } finally {
            VaultCrypto.wipe(key);
        }
    }

    private static byte[] tombstoneAad(String id) {
        return ("tg-vault/tombstone/v1/" + id).getBytes(StandardCharsets.US_ASCII);
    }

    private static VaultCryptoException io(String message, IOException e) {
        return new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, message, e);
    }

    // ------------------------------------------------------------------ session

    /** Journal + keys for one public call. Keys are wiped on close. */
    private final class Session {
        final SyncJournal journal;
        final byte[] journalKey;
        final byte[] dedupKey;
        final boolean rebuilt;

        Session() throws VaultCryptoException {
            journalKey = keys.deriveSubkey(PURPOSE_JOURNAL); // INVALID_STATE if locked
            byte[] dk = null;
            SyncJournal loaded;
            boolean wasRebuilt = false;
            try {
                dk = keys.deriveSubkey(PURPOSE_DEDUP);
                try {
                    loaded = SyncJournal.load(journalFile, journalKey);
                } catch (VaultCryptoException e) {
                    if (e.getReason() != VaultCryptoException.Reason.CORRUPTED) {
                        throw e;
                    }
                    // A damaged journal is rebuilt from the server and the local files; nothing is lost
                    // because uploads are idempotent and imports never overwrite.
                    loaded = new SyncJournal();
                    wasRebuilt = true;
                }
            } catch (VaultCryptoException e) {
                VaultCrypto.wipe(journalKey);
                VaultCrypto.wipe(dk);
                throw e;
            }
            journal = loaded;
            dedupKey = dk;
            rebuilt = wasRebuilt;
        }

        void save() throws VaultCryptoException {
            journal.save(journalFile, journalKey);
        }

        void close() {
            VaultCrypto.wipe(journalKey);
            VaultCrypto.wipe(dedupKey);
        }
    }

    private Session open() throws VaultCryptoException {
        return new Session();
    }

    @SuppressWarnings("unused")
    private static Set<String> setOf(List<String> list) {
        return new HashSet<>(list);
    }
}
