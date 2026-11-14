package org.telegram.messenger.vault;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ChatObject;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.NotificationsController;
import org.telegram.tgnet.ConnectionsManager;
import org.telegram.tgnet.TLObject;
import org.telegram.tgnet.TLRPC;

import java.io.IOException;

/**
 * The Vault as a real Telegram chat: a private group that only this account is in, called "Telegram Vault". It is
 * opened with Telegram's own chat screen (same bubbles, media, search, attach and viewers as Saved Messages); the
 * Vault only adds the password wall in front of it.
 *
 * <p><b>Security note, by design:</b> the messages in this chat are ordinary Telegram messages stored by Telegram.
 * The password stops people who have the unlocked phone from opening the chat through the Vault, it does not
 * encrypt the messages. The chat is muted. STATUS: type-checked against the real Telegram classes, never run.
 */
public final class VaultChatLink {

    public static final String TITLE = "Telegram Vault";
    private static final String ABOUT = "Private. Opens only through the Protected Vault password screen.";

    private VaultChatLink() {
    }

    /** The positive chat id of the Vault chat among the chats already loaded, or 0. */
    public static long find(int account) {
        MessagesController controller = MessagesController.getInstance(account);
        for (TLRPC.Dialog dialog : controller.getAllDialogs()) {
            if (dialog == null || dialog.id >= 0) {
                continue;
            }
            TLRPC.Chat chat = controller.getChat(-dialog.id);
            if (isOurs(chat)) {
                return chat.id;
            }
        }
        return 0;
    }

    public static boolean isVaultChat(int account, long chatId) {
        return chatId != 0 && isOurs(MessagesController.getInstance(account).getChat(chatId));
    }

    /** True for a dialog id (negative for chats) that is the Vault chat. */
    public static boolean isVaultDialog(int account, long dialogId) {
        return dialogId < 0 && isVaultChat(account, -dialogId);
    }

    /** Creates the group. Blocks; call from a background thread, and only after {@link #find} returned 0. */
    public static long create(final int account) throws IOException {
        TLRPC.TL_channels_createChannel req = new TLRPC.TL_channels_createChannel();
        req.megagroup = true;
        req.title = TITLE;
        req.about = ABOUT;
        TLObject response = TelegramChannelApi.request(account, req, 0, ConnectionsManager.ConnectionTypeGeneric, ConnectionsManager.DEFAULT_DATACENTER_ID);
        if (!(response instanceof TLRPC.Updates)) {
            throw new IOException("Unexpected reply to createChannel");
        }
        TLRPC.Updates updates = (TLRPC.Updates) response;
        MessagesController.getInstance(account).processUpdates(updates, false);
        for (TLRPC.Chat chat : updates.chats) {
            if (chat != null && TITLE.equals(chat.title) && ChatObject.isChannel(chat) && ChatObject.isMegagroup(chat)) {
                final long dialogId = -chat.id;
                AndroidUtilities.runOnUIThread(() -> NotificationsController.getInstance(account).muteUntil(dialogId, 0, Integer.MAX_VALUE));
                return chat.id;
            }
        }
        throw new IOException("Telegram did not return the new group");
    }

    private static boolean isOurs(TLRPC.Chat chat) {
        return chat != null && TITLE.equals(chat.title) && ChatObject.isChannel(chat) && ChatObject.isMegagroup(chat) && chat.creator;
    }
}
