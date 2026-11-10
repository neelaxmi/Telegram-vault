package org.telegram.messenger.vault;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * What the Vault chat screen shows and does, without any Android code: the (filtered) list, the selection and
 * deletion. The screen calls {@link #refresh} after sync results, adds and deletes, and re-reads {@link #rows}.
 */
public final class VaultListModel {

    /** One line of the list. Text is shortened; the full item is read with {@link VaultStore#get}. */
    public static final class Row {
        public final String id;
        public final VaultItem.Type type;
        public final String title;
        public final String subtitle;
        public final long dateMillis;
        public final boolean hasMedia;
        public final boolean selected;

        Row(VaultItem item, boolean selected) {
            this.id = item.id;
            this.type = item.type;
            this.title = titleOf(item);
            this.subtitle = subtitleOf(item);
            this.dateMillis = item.originalDateMillis > 0 ? item.originalDateMillis : item.createdAtMillis;
            this.hasMedia = item.mediaId != null;
            this.selected = selected;
        }
    }

    static final int MAX_TITLE_CHARS = 120;

    private final VaultStore store;
    private String query = "";
    private List<VaultItem> shown = new ArrayList<>();
    private final Set<String> selection = new LinkedHashSet<>();
    private int corrupt;
    private int unsupported;

    public VaultListModel(VaultStore store) {
        if (store == null) {
            throw new IllegalArgumentException("store required");
        }
        this.store = store;
    }

    /** Re-reads the vault. The selection keeps only ids that still exist. */
    public synchronized void refresh() throws VaultCryptoException {
        VaultStore.Listing listing = store.list();
        corrupt = listing.corruptIds.size();
        unsupported = listing.unsupportedIds.size();
        shown = store.search(query);
        Set<String> alive = new LinkedHashSet<>();
        for (VaultItem i : listing.items) {
            alive.add(i.id);
        }
        selection.retainAll(alive);
    }

    public synchronized void setQuery(String text) throws VaultCryptoException {
        query = text == null ? "" : text;
        refresh();
    }

    public synchronized String query() {
        return query;
    }

    public synchronized List<Row> rows() {
        List<Row> rows = new ArrayList<>(shown.size());
        for (VaultItem i : shown) {
            rows.add(new Row(i, selection.contains(i.id)));
        }
        return Collections.unmodifiableList(rows);
    }

    /** Items that could not be read because they are damaged. Shown as a notice, never silently dropped. */
    public synchronized int damagedCount() {
        return corrupt;
    }

    /** Items written by a newer app version; kept untouched until the app is updated. */
    public synchronized int needsUpdateCount() {
        return unsupported;
    }

    // ---- selection

    public synchronized boolean isSelecting() {
        return !selection.isEmpty();
    }

    public synchronized int selectedCount() {
        return selection.size();
    }

    public synchronized void toggle(String id) {
        for (VaultItem i : shown) {
            if (i.id.equals(id)) {
                if (!selection.remove(id)) {
                    selection.add(id);
                }
                return;
            }
        }
    }

    public synchronized void selectAll() {
        for (VaultItem i : shown) {
            selection.add(i.id);
        }
    }

    public synchronized void clearSelection() {
        selection.clear();
    }

    /**
     * Deletes the selected items (locally now, from the server on the next sync). Items that were selected but
     * are hidden by a later search are still deleted: the user chose them.
     *
     * @return how many items were deleted
     */
    public synchronized int deleteSelected(VaultSyncEngine engine) throws VaultCryptoException {
        int n = 0;
        for (String id : new ArrayList<>(selection)) {
            if (engine.deleteItem(id)) {
                n++;
            }
            selection.remove(id);
        }
        refresh();
        return n;
    }

    // ---- text

    static String titleOf(VaultItem item) {
        String text = item.text == null ? "" : item.text.trim().replace('\n', ' ');
        if (!text.isEmpty()) {
            return text.length() > MAX_TITLE_CHARS ? text.substring(0, MAX_TITLE_CHARS) + "…" : text;
        }
        if (item.mediaName != null && !item.mediaName.isEmpty()) {
            return item.mediaName;
        }
        return item.type.name().toLowerCase(java.util.Locale.ROOT);
    }

    static String subtitleOf(VaultItem item) {
        StringBuilder sb = new StringBuilder();
        if (item.mediaId != null) {
            sb.append(formatSize(item.mediaSize));
        }
        if (item.durationSeconds > 0) {
            if (sb.length() > 0) {
                sb.append(" · ");
            }
            sb.append(item.durationSeconds / 60).append(':').append(String.format(java.util.Locale.ROOT, "%02d", item.durationSeconds % 60));
        }
        if (item.senderName != null && !item.senderName.isEmpty()) {
            if (sb.length() > 0) {
                sb.append(" · ");
            }
            sb.append(item.senderName);
        }
        return sb.toString();
    }

    static String formatSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        double v = bytes;
        String[] units = {"KB", "MB", "GB"};
        int u = -1;
        while (v >= 1024 && u < units.length - 1) {
            v /= 1024;
            u++;
        }
        return String.format(java.util.Locale.ROOT, v >= 100 ? "%.0f %s" : "%.1f %s", v, units[u]);
    }
}
