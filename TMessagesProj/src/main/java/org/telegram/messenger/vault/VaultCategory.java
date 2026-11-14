package org.telegram.messenger.vault;

import java.util.regex.Pattern;

/** The filters of the Vault chat (like the Saved Messages tabs). They look at the stored kind of an item, not at labels. */
public enum VaultCategory {
    ALL("All"), PHOTOS("Photos"), VIDEOS("Videos"), FILES("Files"), LINKS("Links"), MUSIC("Music"), VOICE("Voice");

    private static final Pattern LINK = Pattern.compile("(?i)\\b(?:https?://|www\\.|t\\.me/)[^\\s]+");

    public final String label;

    VaultCategory(String label) {
        this.label = label;
    }

    public boolean matches(VaultItem item) {
        switch (this) {
            case ALL:
                return true;
            case PHOTOS:
                return item.type == VaultItem.Type.PHOTO;
            case VIDEOS:
                return item.type == VaultItem.Type.VIDEO;
            case VOICE:
                return item.isVoice();
            case MUSIC:
                return isMusic(item);
            case FILES:
                return item.type == VaultItem.Type.DOCUMENT && !item.isVoice() && !isMusic(item);
            case LINKS:
                return hasLink(item);
            default:
                return false;
        }
    }

    static boolean isMusic(VaultItem item) {
        if (item.type != VaultItem.Type.DOCUMENT || item.isVoice()) {
            return false;
        }
        return item.isMusic() || (item.mimeType != null && item.mimeType.toLowerCase(java.util.Locale.ROOT).startsWith("audio/"));
    }

    static boolean hasLink(VaultItem item) {
        if (item.text.isEmpty()) {
            return false;
        }
        return LINK.matcher(item.text).find() || VaultEntities.hasLink(item.entities, item.text.length());
    }
}
