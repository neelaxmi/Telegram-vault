package org.telegram.messenger.vault;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.NotificationsController;
import org.telegram.messenger.ChatObject;
import org.telegram.messenger.MessagesController;
import org.telegram.tgnet.ConnectionsManager;
import org.telegram.tgnet.TLObject;
import org.telegram.tgnet.TLRPC;

import java.io.IOException;

/**
 * Finds or creates the private channel that holds the encrypted Vault data of this Telegram account (decision 1).
 * The channel has no username, so nobody can join it by search; everything in it is ciphertext. Other devices of
 * the same account find it by its title among their chats.
 *
 * <p><b>STATUS: type-checked against the real Telegram classes, never run.</b> Unverified assumptions: the
 * dialog list is loaded when {@link #find} is called (a fresh install may need a moment after login), the
 * creator flag is set on a channel the account created, and createChannel returns the channel in
 * {@code Updates.chats}. The channel appears in the user's chat list like any channel; archiving or hiding it is a
 * UI decision for a later phase.
 */
public final class TelegramVaultChannel {

    public static final String TITLE = "Protected Vault storage";
    private static final String ABOUT = "Encrypted Protected Vault data. Do not delete or edit.";

    /** What {@link TelegramChannelApi} needs to talk to the channel. */
    public static final class Ref {
        public final long channelId;
        public final long accessHash;

        public Ref(long channelId, long accessHash) {
            this.channelId = channelId;
            this.accessHash = accessHash;
        }
    }

    private TelegramVaultChannel() {
    }

    /**
     * True once the account's chat list has been loaded. Before that, {@link #find} returning null does NOT mean
     * the channel does not exist (e.g. just after login on a new phone), so nothing may be created yet.
     */
    public static boolean chatsLoaded(int account) {
        return MessagesController.getInstance(account).dialogsLoaded;
    }

    /**
     * True if {@code chatId} (the positive channel id used by chat screens) is this account's Vault storage channel.
     * The Vault must never open as an ordinary chat (it would show encrypted blobs and a "Broadcast" composer), so
     * the chat screen sends the user to the Vault screen instead.
     */
    public static boolean isVaultChannel(int account, long chatId) {
        if (chatId == 0) {
            return false;
        }
        TLRPC.Chat chat = MessagesController.getInstance(account).getChat(chatId);
        return chat != null && isOurs(chat);
    }

    /** The existing channel from the locally known chats, or null. Non-blocking. */
    public static Ref find(int account) {
        MessagesController controller = MessagesController.getInstance(account);
        for (TLRPC.Dialog dialog : controller.getAllDialogs()) {
            if (dialog == null || dialog.id >= 0) {
                continue;
            }
            TLRPC.Chat chat = controller.getChat(-dialog.id);
            if (isOurs(chat)) {
                return new Ref(chat.id, chat.access_hash);
            }
        }
        return null;
    }

    /** Creates the channel. Blocks; call from a background thread, and only after {@link #find} returned null. */
    public static Ref create(int account) throws IOException {
        TLRPC.TL_channels_createChannel req = new TLRPC.TL_channels_createChannel();
        req.broadcast = true;
        req.title = TITLE;
        req.about = ABOUT;
        TLObject response = TelegramChannelApi.request(account, req, 0, ConnectionsManager.ConnectionTypeGeneric, ConnectionsManager.DEFAULT_DATACENTER_ID);
        if (!(response instanceof TLRPC.Updates)) {
            throw new IOException("Unexpected reply to createChannel");
        }
        TLRPC.Updates updates = (TLRPC.Updates) response;
        MessagesController.getInstance(account).processUpdates(updates, false);
        for (TLRPC.Chat chat : updates.chats) {
            if (chat != null && TITLE.equals(chat.title) && ChatObject.isChannel(chat) && !ChatObject.isMegagroup(chat)) {
                // Storage objects are silent already; muting keeps the channel from ever raising a notification.
                final long dialogId = -chat.id;
                AndroidUtilities.runOnUIThread(() -> NotificationsController.getInstance(account).muteUntil(dialogId, 0, Integer.MAX_VALUE));
                return new Ref(chat.id, chat.access_hash);
            }
        }
        throw new IOException("Telegram did not return the new channel");
    }

    private static boolean isOurs(TLRPC.Chat chat) {
        return chat != null && TITLE.equals(chat.title) && ChatObject.isChannel(chat) && !ChatObject.isMegagroup(chat) && chat.creator;
    }
}
