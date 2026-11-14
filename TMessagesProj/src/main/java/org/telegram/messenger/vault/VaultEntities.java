package org.telegram.messenger.vault;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Compact, platform-independent encoding of the text formatting of a message (bold, italic, links, ...), so a saved
 * message keeps its formatting instead of being flattened to plain text.
 *
 * <p>Format: entries separated by {@code ;}, each {@code kind,offset,length} or {@code kind,offset,length,url} where
 * {@code url} is percent-encoded for {@code % ; ,}. Offsets and lengths are UTF-16 units of the stored text, exactly as
 * Telegram counts them. Custom emoji and other entity kinds this app cannot render are not stored (their text stays).
 */
public final class VaultEntities {

    public static final char BOLD = 'b';
    public static final char ITALIC = 'i';
    public static final char UNDERLINE = 'u';
    public static final char STRIKE = 's';
    public static final char CODE = 'c';
    public static final char PRE = 'p';
    public static final char QUOTE = 'q';
    public static final char SPOILER = 'x';
    /** A URL that appears as text. */
    public static final char URL = 'l';
    /** Text that links elsewhere (needs a url). */
    public static final char TEXT_URL = 'L';
    public static final char MENTION = 'm';
    public static final char HASHTAG = 'h';
    public static final char EMAIL = 'e';
    public static final char PHONE = 'n';

    private static final String KINDS = "biuscpqxlLmhen";

    public static final class Entity {
        public final char kind;
        public final int offset;
        public final int length;
        /** Only for {@link #TEXT_URL}; null otherwise. */
        public final String url;

        public Entity(char kind, int offset, int length, String url) {
            this.kind = kind;
            this.offset = offset;
            this.length = length;
            this.url = url;
        }
    }

    private VaultEntities() {
    }

    /** Encodes valid entities for a text of {@code textLength} UTF-16 units; invalid ones are dropped. */
    public static String encode(List<Entity> entities, int textLength) {
        if (entities == null || entities.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Entity e : entities) {
            if (e == null || KINDS.indexOf(e.kind) < 0 || e.offset < 0 || e.length <= 0 || e.offset + (long) e.length > textLength) {
                continue;
            }
            if (e.kind == TEXT_URL && (e.url == null || e.url.isEmpty())) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(';');
            }
            sb.append(e.kind).append(',').append(e.offset).append(',').append(e.length);
            if (e.kind == TEXT_URL) {
                sb.append(',').append(escape(e.url));
            }
        }
        return sb.toString();
    }

    /** Decodes; malformed or out-of-range entries are skipped, never thrown about (formatting is cosmetic). */
    public static List<Entity> decode(String encoded, int textLength) {
        List<Entity> out = new ArrayList<>();
        if (encoded == null || encoded.isEmpty()) {
            return out;
        }
        for (String part : encoded.split(";")) {
            String[] f = part.split(",", -1);
            if (f.length < 3 || f[0].length() != 1 || KINDS.indexOf(f[0].charAt(0)) < 0) {
                continue;
            }
            try {
                char kind = f[0].charAt(0);
                int offset = Integer.parseInt(f[1]);
                int length = Integer.parseInt(f[2]);
                if (offset < 0 || length <= 0 || offset + (long) length > textLength) {
                    continue;
                }
                String url = null;
                if (kind == TEXT_URL) {
                    if (f.length < 4 || f[3].isEmpty()) {
                        continue;
                    }
                    url = unescape(f[3]);
                }
                out.add(new Entity(kind, offset, length, url));
            } catch (NumberFormatException ignored) {
                // skip
            }
        }
        return out;
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' || c == ';' || c == ',') {
                sb.append(String.format(Locale.ROOT, "%%%02X", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String unescape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length()) {
                try {
                    sb.append((char) Integer.parseInt(s.substring(i + 1, i + 3), 16));
                    i += 2;
                    continue;
                } catch (NumberFormatException ignored) {
                    // literal %
                }
            }
            sb.append(c);
        }
        return sb.toString();
    }

    /** True if any entity is a link (used by the "Links" category). */
    public static boolean hasLink(String encoded, int textLength) {
        for (Entity e : decode(encoded, textLength)) {
            if (e.kind == URL || e.kind == TEXT_URL) {
                return true;
            }
        }
        return false;
    }
}
