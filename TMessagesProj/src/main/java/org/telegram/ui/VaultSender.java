package org.telegram.ui;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.FileLoader;
import org.telegram.messenger.MessageObject;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.UserObject;
import org.telegram.messenger.vault.VaultCryptoException;
import org.telegram.messenger.vault.VaultItem;
import org.telegram.messenger.vault.VaultRuntime;
import org.telegram.messenger.vault.VaultStore;
import org.telegram.tgnet.TLRPC;


import org.telegram.messenger.vault.VaultEntities;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * "Send to Vault": copies one chat message into the Protected Vault.
 *
 * The original message is never touched. Content protection is honoured: a message
 * from a chat or sender with "restrict saving content" (noforwards) is refused, and the
 * menu entry is not offered for it (see {@link #isAllowed}).
 */
public final class VaultSender {

    public interface Result {
        void done(String userMessage);
    }

    private VaultSender() {
    }

    public enum Refusal {
        NONE, PROTECTED_CONTENT, UNSUPPORTED_TYPE, EMPTY
    }

    /** Pure decision used both to show the menu entry and again just before saving. */
    public static Refusal check(int account, MessageObject mo) {
        if (mo == null || mo.messageOwner == null) {
            return Refusal.UNSUPPORTED_TYPE;
        }
        if (mo.messageOwner.noforwards || MessagesController.getInstance(account).isPeerNoForwards(mo.getDialogId())) {
            return Refusal.PROTECTED_CONTENT;
        }
        if (mo.isSponsored() || mo.isLiveLocation() || mo.isPoll() || mo.isDice() || mo.isSecretMedia()
                || mo.messageOwner.action != null || mo.type == MessageObject.TYPE_PHONE_CALL) {
            return Refusal.UNSUPPORTED_TYPE;
        }
        VaultItem.Type t = typeOf(mo);
        if (t == null) {
            return Refusal.UNSUPPORTED_TYPE;
        }
        if (t == VaultItem.Type.TEXT && (mo.messageOwner.message == null || mo.messageOwner.message.isEmpty())) {
            return Refusal.EMPTY;
        }
        return Refusal.NONE;
    }

    public static boolean isAllowed(int account, MessageObject mo) {
        return check(account, mo) == Refusal.NONE;
    }

    private static VaultItem.Type typeOf(MessageObject mo) {
        TLRPC.MessageMedia media = mo.messageOwner.media;
        if (media == null || media instanceof TLRPC.TL_messageMediaEmpty || media instanceof TLRPC.TL_messageMediaWebPage) {
            return VaultItem.Type.TEXT;
        }
        if (mo.isPhoto()) {
            return VaultItem.Type.PHOTO;
        }
        if (mo.isVideo() || mo.isRoundVideo() || mo.isGif()) {
            return VaultItem.Type.VIDEO;
        }
        if (mo.isDocument() || mo.isMusic() || mo.isVoice() || mo.isSticker()) {
            return VaultItem.Type.DOCUMENT;
        }
        return null;
    }

    /**
     * Saves the message. The caller must be on the UI thread. A locked Vault does not need to be opened:
     * the message is sealed into the write-only inbox (see VaultInbox).
     */
    public static void send(final int account, final MessageObject mo, final Result result) {
        final VaultRuntime rt = VaultRuntime.get(account);
        Refusal refusal = check(account, mo);
        if (refusal == Refusal.PROTECTED_CONTENT) {
            result.done("This chat restricts saving content, so it cannot be copied to the Vault.");
            return;
        } else if (refusal != Refusal.NONE) {
            result.done("This kind of message cannot be saved to the Vault.");
            return;
        }
        if (!rt.keys.isInitialized()) {
            result.done("Set up the Protected Vault first (menu, Protected Vault).");
            return;
        }
        // Unlocked: save straight into the Vault. Locked: seal the message into the write-only inbox (public-key
        // encryption, no password and no master key needed); it moves into the Vault at the next unlock.
        final boolean locked = !rt.keys.isUnlocked();
        if (locked && !rt.inbox.canAccept()) {
            result.done("Open the Protected Vault and unlock it once. After that you can save messages without unlocking.");
            return;
        }
        final VaultItem.Type type = typeOf(mo);
        final VaultItem.Draft draft = new VaultItem.Draft(type)
                .originalDateMillis(mo.messageOwner.date * 1000L)
                .source(mo.getDialogId(), mo.getId());
        String text = mo.messageOwner.message == null ? "" : mo.messageOwner.message;
        draft.text(text);
        draft.entities(entitiesOf(mo.messageOwner.entities, text.length()));
        draft.senderName(senderName(account, mo));
        if (mo.messageOwner.fwd_from != null) {
            String from = mo.messageOwner.fwd_from.from_name;
            draft.forwardedFrom(from, mo.messageOwner.fwd_from.date * 1000L);
        }
        File file = null;
        String mediaName = null, mediaMime = null;
        int mediaDuration = 0;
        if (type.hasMedia()) {
            file = FileLoader.getInstance(account).getPathToMessage(mo.messageOwner);
            if (file == null || !file.exists() || file.length() == 0) {
                result.done("Download the media first, then save it to the Vault.");
                return;
            }
            String name = mo.getFileName();
            String mime = mo.getMimeType();
            int flags = 0;
            if (mo.isVoice()) {
                flags |= VaultItem.FLAG_VOICE;
            } else if (mo.isMusic()) {
                flags |= VaultItem.FLAG_MUSIC;
            }
            if (mo.isRoundVideo()) {
                flags |= VaultItem.FLAG_ROUND_VIDEO;
            }
            if (mo.isGif()) {
                flags |= VaultItem.FLAG_ANIMATION;
            }
            draft.flags(flags);
            mediaName = name == null || name.isEmpty() ? "file" : name;
            mediaMime = mime == null ? "application/octet-stream" : mime;
            mediaDuration = (int) Math.max(0, mo.getDuration());
            draft.media(mediaName, mediaMime, 0, 0, mediaDuration);
        }
        final String mediaName0 = mediaName, mediaMime0 = mediaMime;
        final int mediaDuration0 = mediaDuration;
        final File mediaFile = file;
        // the locked path must never queue behind a long network sync, so it has its own thread
        (locked ? rt.inboxIo() : rt.io()).execute(() -> {
            String message;
            try {
                byte[] thumbnail = null;
                if (mediaFile != null) {
                    // preview and size are made off the UI thread
                    VaultThumbs.Info info = VaultThumbs.make(org.telegram.messenger.ApplicationLoader.applicationContext,
                            android.net.Uri.fromFile(mediaFile), type);
                    thumbnail = info.thumbnail;
                    draft.media(mediaName0, mediaMime0, info.width, info.height, mediaDuration0 > 0 ? mediaDuration0 : info.durationSeconds);
                }
                if (locked || !rt.keys.isUnlocked()) {
                    // The Vault may have locked since the check above: the sealed inbox still works.
                    long limit = VaultStore.DEFAULT_MAX_UPLOAD_BYTES;
                    if (mediaFile == null) {
                        rt.inbox.put(draft, null, limit);
                    } else {
                        try (InputStream in = new FileInputStream(mediaFile)) {
                            rt.inbox.put(draft, in, thumbnail, limit);
                        }
                    }
                    message = "Saved to the Protected Vault. It is encrypted and will appear when you open the Vault.";
                } else {
                    if (mediaFile == null) {
                        rt.engine().addItem(draft, null, null);
                    } else {
                        try (InputStream in = new FileInputStream(mediaFile)) {
                            rt.engine().addItem(draft, in, thumbnail);
                        }
                    }
                    message = "Saved to the Protected Vault.";
                    rt.coordinator().requestSync(false);
                }
            } catch (VaultCryptoException e) {
                switch (e.getReason()) {
                    case MEDIA_TOO_LARGE:
                        message = "This file is larger than the Vault can store (Telegram's file size limit).";
                        break;
                    case INVALID_STATE:
                        message = "The Vault locked. Try again.";
                        break;
                    case CORRUPTED:
                        message = "The Vault's save-while-locked key looks damaged, so nothing was saved. Unlock the Vault once to repair it.";
                        break;
                    default:
                        message = "Could not save to the Vault.";
                }
            } catch (Exception e) {
                message = "Could not read the file, nothing was saved.";
            }
            final String m = message;
            AndroidUtilities.runOnUIThread(() -> result.done(m));
        });
    }

    private static String entitiesOf(List<TLRPC.MessageEntity> in, int textLength) {
        if (in == null || in.isEmpty()) {
            return "";
        }
        List<VaultEntities.Entity> out = new ArrayList<>();
        for (TLRPC.MessageEntity e : in) {
            char k;
            String url = null;
            if (e instanceof TLRPC.TL_messageEntityBold) k = VaultEntities.BOLD;
            else if (e instanceof TLRPC.TL_messageEntityItalic) k = VaultEntities.ITALIC;
            else if (e instanceof TLRPC.TL_messageEntityUnderline) k = VaultEntities.UNDERLINE;
            else if (e instanceof TLRPC.TL_messageEntityStrike) k = VaultEntities.STRIKE;
            else if (e instanceof TLRPC.TL_messageEntityCode) k = VaultEntities.CODE;
            else if (e instanceof TLRPC.TL_messageEntityPre) k = VaultEntities.PRE;
            else if (e instanceof TLRPC.TL_messageEntityBlockquote) k = VaultEntities.QUOTE;
            else if (e instanceof TLRPC.TL_messageEntitySpoiler) k = VaultEntities.SPOILER;
            else if (e instanceof TLRPC.TL_messageEntityTextUrl) {
                k = VaultEntities.TEXT_URL;
                url = ((TLRPC.TL_messageEntityTextUrl) e).url;
            } else if (e instanceof TLRPC.TL_messageEntityUrl) k = VaultEntities.URL;
            else if (e instanceof TLRPC.TL_messageEntityMention) k = VaultEntities.MENTION;
            else if (e instanceof TLRPC.TL_messageEntityHashtag) k = VaultEntities.HASHTAG;
            else if (e instanceof TLRPC.TL_messageEntityEmail) k = VaultEntities.EMAIL;
            else if (e instanceof TLRPC.TL_messageEntityPhone) k = VaultEntities.PHONE;
            else continue; // e.g. custom emoji: not preserved
            out.add(new VaultEntities.Entity(k, e.offset, e.length, url));
        }
        return VaultEntities.encode(out, textLength);
    }

    private static String senderName(int account, MessageObject mo) {
        long from = mo.getFromChatId();
        if (from > 0) {
            TLRPC.User u = MessagesController.getInstance(account).getUser(from);
            if (u != null) {
                return UserObject.getUserName(u);
            }
        } else if (from < 0) {
            TLRPC.Chat c = MessagesController.getInstance(account).getChat(-from);
            if (c != null) {
                return c.title;
            }
        }
        return null;
    }
}
