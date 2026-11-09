package org.telegram.messenger.vault;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

/**
 * The few operations the Vault needs from ONE private Telegram channel, in Telegram's own terms (message ids,
 * captions, random ids). Pure Java so that {@link ChannelRemoteStore} can be tested without Telegram; the
 * Android implementation (a thin wrapper over Telegram's networking) cannot be tested off a device.
 *
 * <p>All methods block and throw IOException for anything transient or unexpected.
 */
public interface ChannelApi {

    final class Message {
        /** The channel message id. Increases with every new message in the channel. */
        public final long id;
        /** The message caption ("" if none). */
        public final String caption;
        /** The attached file's size in bytes, or 0 if it has none. */
        public final long size;

        public Message(long id, String caption, long size) {
            this.id = id;
            this.caption = caption == null ? "" : caption;
            this.size = size;
        }
    }

    /**
     * Sends {@code file} as a document with {@code caption}, using {@code randomId} as Telegram's {@code random_id}
     * so that repeating the call after a lost reply does not create a second message (Telegram's documented
     * behaviour for random_id; not verified here). Returns the created message (or, on a repeat, the existing one).
     */
    Message send(String caption, long randomId, File file) throws IOException;

    /** Messages with id greater than {@code afterId}, oldest first, at most {@code limit}; may include foreign messages. */
    List<Message> history(long afterId, int limit) throws IOException;

    /** Writes the document attached to the message into {@code out}. */
    void download(long messageId, OutputStream out) throws IOException;

    /** Deletes the message for everyone. A message that is already gone is not an error. */
    void delete(long messageId) throws IOException;
}
