package org.telegram.ui;

import org.telegram.messenger.MessageObject;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.SendMessagesHelper;
import org.telegram.messenger.vault.VaultChatLink;
import org.telegram.messenger.vault.VaultItem;
import org.telegram.tgnet.TLRPC;

import java.util.ArrayList;

/**
 * "Send to Vault": copies one chat message into the Vault chat.
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
     * Saves the message into the Vault chat by forwarding it there (the same thing as forwarding it to Saved
     * Messages): the original stays unchanged, text, photos, videos, documents, voice and forwarded messages keep
     * their type, media and captions. No password is needed because nothing of the Vault is opened or read; the
     * chat is simply another destination. The caller must be on the UI thread.
     */
    public static void send(final int account, final MessageObject mo, final Result result) {
        Refusal refusal = check(account, mo);
        if (refusal == Refusal.PROTECTED_CONTENT) {
            result.done("This chat restricts saving content, so it cannot be copied to the Vault.");
            return;
        } else if (refusal != Refusal.NONE) {
            result.done("This kind of message cannot be saved to the Vault.");
            return;
        }
        long chatId = VaultChatLink.find(account);
        if (chatId == 0) {
            result.done("Open Protected Vault once (menu, Protected Vault) so the Vault chat exists. After that you can save messages without unlocking.");
            return;
        }
        ArrayList<MessageObject> list = new ArrayList<>();
        list.add(mo);
        try {
            SendMessagesHelper.getInstance(account).sendMessage(list, -chatId, false, false, true, 0, 0);
            result.done("Saved to the Vault chat.");
        } catch (Exception e) {
            result.done("Could not save to the Vault chat.");
        }
    }
}
