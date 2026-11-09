package org.telegram.messenger.vault;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * {@link VaultRemoteStore} on top of a private channel: one channel message per Vault object, the object
 * name in the caption ({@code "tgv1 <name>"}), the encrypted file as the document. Pure Java.
 *
 * <ul>
 *   <li>{@code seq} is the channel message id (strictly increasing), {@code ref} is its decimal string.</li>
 *   <li>The idempotency token maps to Telegram's {@code random_id} (its first 8 bytes), so a retried send after
 *       a lost reply returns the same message instead of creating a second one.</li>
 *   <li>Messages whose caption does not start with the prefix are ignored, so anything else that ends up in
 *       the channel can neither break nor impersonate Vault objects (every object is authenticated later anyway).</li>
 *   <li>{@link #list} never returns an empty page while more Vault objects exist further on.</li>
 * </ul>
 */
public final class ChannelRemoteStore implements VaultRemoteStore {

    static final String PREFIX = "tgv1 ";
    private static final int MAX_NAME_CHARS = 80;
    /** How many foreign messages in a row {@link #list} will skip before giving up on this call. */
    private static final int MAX_SCAN = 2000;
    private static final int SCAN_PAGE = 100;

    private final ChannelApi api;
    private final long maxFileBytes;

    public ChannelRemoteStore(ChannelApi api, long maxFileBytes) {
        if (api == null || maxFileBytes <= 0) {
            throw new IllegalArgumentException("api and a positive size limit are required");
        }
        this.api = api;
        this.maxFileBytes = maxFileBytes;
    }

    @Override
    public Entry upload(String name, String clientToken, File file) throws IOException {
        checkName(name);
        long randomId = randomIdFrom(clientToken);
        if (file == null || !file.isFile()) {
            throw new IOException("Nothing to upload");
        }
        if (file.length() > maxFileBytes) {
            throw new IOException("File is larger than Telegram accepts (" + file.length() + " bytes)");
        }
        ChannelApi.Message m = api.send(PREFIX + name, randomId, file);
        if (m == null || m.id <= 0) {
            throw new IOException("Telegram did not confirm the upload");
        }
        return new Entry(m.id, name, m.size > 0 ? m.size : file.length(), Long.toString(m.id));
    }

    @Override
    public List<Entry> list(long afterSeq, int limit) throws IOException {
        List<Entry> out = new ArrayList<>();
        if (limit <= 0) {
            return out;
        }
        long cursor = afterSeq;
        int scanned = 0;
        while (out.size() < limit && scanned < MAX_SCAN) {
            List<ChannelApi.Message> page = api.history(cursor, SCAN_PAGE);
            if (page == null || page.isEmpty()) {
                break;
            }
            for (ChannelApi.Message m : page) {
                if (m.id <= cursor) {
                    throw new IOException("Telegram returned messages out of order");
                }
                cursor = m.id;
                scanned++;
                String name = nameOf(m.caption);
                if (name != null && out.size() < limit) {
                    out.add(new Entry(m.id, name, m.size, Long.toString(m.id)));
                } else if (name != null) {
                    // limit reached: stop exactly after the last returned entry so nothing is skipped
                    return out;
                }
            }
        }
        return out;
    }

    @Override
    public void download(String ref, OutputStream out) throws IOException {
        api.download(parseRef(ref), out);
    }

    @Override
    public void delete(String ref) throws IOException {
        api.delete(parseRef(ref));
    }

    // ------------------------------------------------------------------ helpers

    /** The object name if the caption is ours, else null. */
    static String nameOf(String caption) {
        if (caption == null || !caption.startsWith(PREFIX)) {
            return null;
        }
        String name = caption.substring(PREFIX.length());
        if (name.length() < 3 || name.length() > MAX_NAME_CHARS || name.charAt(1) != '.') {
            return null;
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.';
            if (!ok) {
                return null;
            }
        }
        return name;
    }

    private static void checkName(String name) throws IOException {
        if (nameOf(PREFIX + name) == null) {
            throw new IOException("Invalid object name");
        }
    }

    static long parseRef(String ref) throws IOException {
        if (ref == null || ref.isEmpty() || ref.length() > 19) {
            throw new IOException("Invalid reference");
        }
        for (int i = 0; i < ref.length(); i++) {
            if (ref.charAt(i) < '0' || ref.charAt(i) > '9') {
                throw new IOException("Invalid reference");
            }
        }
        try {
            long v = Long.parseLong(ref);
            if (v <= 0) {
                throw new IOException("Invalid reference");
            }
            return v;
        } catch (NumberFormatException e) {
            throw new IOException("Invalid reference");
        }
    }

    /** First 8 bytes of the 32-hex-character token as a signed long; never 0 (0 means "no random id"). */
    static long randomIdFrom(String token) throws IOException {
        if (token == null || token.length() != 32) {
            throw new IOException("Invalid token");
        }
        long v = 0;
        for (int i = 0; i < 16; i++) {
            int d = Character.digit(token.charAt(i), 16);
            if (d < 0) {
                throw new IOException("Invalid token");
            }
            v = (v << 4) | d;
        }
        return v == 0 ? 1 : v;
    }
}
