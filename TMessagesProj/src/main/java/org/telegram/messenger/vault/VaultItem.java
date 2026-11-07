package org.telegram.messenger.vault;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * One saved Vault entry: a text message, or a photo / video / document with optional caption,
 * plus the metadata the Vault UI needs (timestamps, forward information, media preview info).
 * Immutable. Created by {@link VaultStore} from a {@link Draft}, or decoded from storage.
 *
 * <h3>Record encoding (inside the encryption)</h3>
 * A versioned binary layout: strings are {@code int32 length (-1 = null) + UTF-8 bytes}, numbers
 * are big-endian. The encoded form is prefixed with its real length and then zero-padded to a
 * multiple of 256 bytes, so the on-disk size of a record reveals only a coarse size bucket
 * instead of the exact text length.
 *
 * Note: Java strings holding unpaired surrogates cannot be represented in UTF-8 and come back
 * with a replacement character.
 *
 * {@link #toString()} deliberately omits message content so items are safe to log accidentally.
 */
public final class VaultItem {

    public enum Type {
        TEXT(0), PHOTO(1), VIDEO(2), DOCUMENT(3);

        final int code;

        Type(int code) {
            this.code = code;
        }

        public boolean hasMedia() {
            return this != TEXT;
        }

        static Type fromCode(int code) {
            for (Type t : values()) {
                if (t.code == code) {
                    return t;
                }
            }
            return null;
        }
    }

    public static final int MAX_TEXT_CHARS = 100_000;
    public static final int MAX_NAME_CHARS = 1_000;

    static final int FORMAT_VERSION = 1;
    static final int PAD_BLOCK = 256;
    private static final int MAX_STRING_BYTES = 1 << 20;

    public final String id;
    public final Type type;
    /** When the item was saved into the Vault (epoch millis). */
    public final long createdAtMillis;
    /** When the original message was sent (epoch millis), 0 if unknown. */
    public final long originalDateMillis;
    /** Message text, or the caption of a media item. Never null. */
    public final String text;
    public final String senderName;
    public final String forwardedFromName;
    /** Original date of a forwarded message (epoch millis), 0 if the message was not forwarded. */
    public final long forwardedDateMillis;
    public final long sourceDialogId;
    public final long sourceMessageId;
    public final String mediaId;
    public final String mediaName;
    public final String mimeType;
    /** Size of the decrypted media in bytes. */
    public final long mediaSize;
    public final int width;
    public final int height;
    public final int durationSeconds;
    public final String thumbnailId;

    VaultItem(String id, Type type, long createdAtMillis, long originalDateMillis, String text,
              String senderName, String forwardedFromName, long forwardedDateMillis,
              long sourceDialogId, long sourceMessageId, String mediaId, String mediaName,
              String mimeType, long mediaSize, int width, int height, int durationSeconds, String thumbnailId) {
        this.id = id;
        this.type = type;
        this.createdAtMillis = createdAtMillis;
        this.originalDateMillis = originalDateMillis;
        this.text = text == null ? "" : text;
        this.senderName = senderName;
        this.forwardedFromName = forwardedFromName;
        this.forwardedDateMillis = forwardedDateMillis;
        this.sourceDialogId = sourceDialogId;
        this.sourceMessageId = sourceMessageId;
        this.mediaId = mediaId;
        this.mediaName = mediaName;
        this.mimeType = mimeType;
        this.mediaSize = mediaSize;
        this.width = width;
        this.height = height;
        this.durationSeconds = durationSeconds;
        this.thumbnailId = thumbnailId;
    }

    public boolean isForwarded() {
        return forwardedFromName != null || forwardedDateMillis != 0;
    }

    // ------------------------------------------------------------------ Draft

    /** Caller-supplied fields of a new item. The store assigns id, creation time and media ids. */
    public static final class Draft {
        Type type;
        long originalDateMillis;
        String text = "";
        String senderName;
        String forwardedFromName;
        long forwardedDateMillis;
        long sourceDialogId;
        long sourceMessageId;
        String mediaName;
        String mimeType;
        int width;
        int height;
        int durationSeconds;

        public Draft(Type type) {
            this.type = type;
        }

        public Draft originalDateMillis(long v) {
            originalDateMillis = v;
            return this;
        }

        /** Message text, or the caption for media. */
        public Draft text(String v) {
            text = v == null ? "" : v;
            return this;
        }

        public Draft senderName(String v) {
            senderName = v;
            return this;
        }

        public Draft forwardedFrom(String name, long originalDateMillis) {
            forwardedFromName = name;
            forwardedDateMillis = originalDateMillis;
            return this;
        }

        public Draft source(long dialogId, long messageId) {
            sourceDialogId = dialogId;
            sourceMessageId = messageId;
            return this;
        }

        public Draft media(String name, String mimeType, int width, int height, int durationSeconds) {
            this.mediaName = name;
            this.mimeType = mimeType;
            this.width = width;
            this.height = height;
            this.durationSeconds = durationSeconds;
            return this;
        }

        void validate() throws VaultCryptoException {
            if (type == null) {
                throw invalid("Item type required");
            }
            if (text.length() > MAX_TEXT_CHARS) {
                throw invalid("Text too long");
            }
            if (type == Type.TEXT && text.isEmpty()) {
                throw invalid("Text message is empty");
            }
            checkName(senderName);
            checkName(forwardedFromName);
            checkName(mediaName);
            checkName(mimeType);
            if (width < 0 || height < 0 || durationSeconds < 0 || originalDateMillis < 0 || forwardedDateMillis < 0) {
                throw invalid("Negative value");
            }
        }

        private static void checkName(String s) throws VaultCryptoException {
            if (s != null && s.length() > MAX_NAME_CHARS) {
                throw invalid("Name too long");
            }
        }

        private static VaultCryptoException invalid(String message) {
            return new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, message);
        }

        VaultItem toItem(String id, long createdAtMillis, String mediaId, long mediaSize, String thumbnailId) {
            return new VaultItem(id, type, createdAtMillis, originalDateMillis, text, senderName, forwardedFromName,
                    forwardedDateMillis, sourceDialogId, sourceMessageId, mediaId, mediaName, mimeType, mediaSize,
                    width, height, durationSeconds, thumbnailId);
        }
    }

    // ------------------------------------------------------------------ encoding

    byte[] encodePadded() throws VaultCryptoException {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bos);
            out.writeByte(FORMAT_VERSION);
            writeString(out, id);
            out.writeByte(type.code);
            out.writeLong(createdAtMillis);
            out.writeLong(originalDateMillis);
            writeString(out, text);
            writeString(out, senderName);
            writeString(out, forwardedFromName);
            out.writeLong(forwardedDateMillis);
            out.writeLong(sourceDialogId);
            out.writeLong(sourceMessageId);
            writeString(out, mediaId);
            writeString(out, mediaName);
            writeString(out, mimeType);
            out.writeLong(mediaSize);
            out.writeInt(width);
            out.writeInt(height);
            out.writeInt(durationSeconds);
            writeString(out, thumbnailId);
            out.flush();
            byte[] payload = bos.toByteArray();

            int padded = ((4 + payload.length + PAD_BLOCK - 1) / PAD_BLOCK) * PAD_BLOCK;
            byte[] result = new byte[padded];
            result[0] = (byte) (payload.length >>> 24);
            result[1] = (byte) (payload.length >>> 16);
            result[2] = (byte) (payload.length >>> 8);
            result[3] = (byte) payload.length;
            System.arraycopy(payload, 0, result, 4, payload.length);
            return result;
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not encode item", e);
        }
    }

    static VaultItem decodePadded(byte[] data) throws VaultCryptoException {
        if (data == null || data.length < 4 || data.length % PAD_BLOCK != 0) {
            throw corrupted("Bad record size");
        }
        int length = ((data[0] & 0xFF) << 24) | ((data[1] & 0xFF) << 16) | ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
        if (length < 0 || length > data.length - 4) {
            throw corrupted("Bad record length");
        }
        for (int i = 4 + length; i < data.length; i++) {
            if (data[i] != 0) {
                throw corrupted("Bad record padding");
            }
        }
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(data, 4, length));
            if (in.readUnsignedByte() != FORMAT_VERSION) {
                throw corrupted("Unsupported record version");
            }
            String id = readString(in);
            Type type = Type.fromCode(in.readUnsignedByte());
            long createdAt = in.readLong();
            long originalDate = in.readLong();
            String text = readString(in);
            String senderName = readString(in);
            String forwardedFrom = readString(in);
            long forwardedDate = in.readLong();
            long sourceDialog = in.readLong();
            long sourceMessage = in.readLong();
            String mediaId = readString(in);
            String mediaName = readString(in);
            String mimeType = readString(in);
            long mediaSize = in.readLong();
            int width = in.readInt();
            int height = in.readInt();
            int duration = in.readInt();
            String thumbnailId = readString(in);
            if (in.available() != 0) {
                throw corrupted("Trailing bytes in record");
            }
            if (id == null || type == null || text == null) {
                throw corrupted("Record missing required fields");
            }
            if (type.hasMedia() != (mediaId != null) || mediaSize < 0 || width < 0 || height < 0 || duration < 0) {
                throw corrupted("Record fields inconsistent");
            }
            return new VaultItem(id, type, createdAt, originalDate, text, senderName, forwardedFrom, forwardedDate,
                    sourceDialog, sourceMessage, mediaId, mediaName, mimeType, mediaSize, width, height, duration, thumbnailId);
        } catch (IOException e) {
            throw corrupted("Record is truncated");
        }
    }

    private static void writeString(DataOutputStream out, String s) throws IOException {
        if (s == null) {
            out.writeInt(-1);
            return;
        }
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_STRING_BYTES) {
            throw new IOException("String too long");
        }
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static String readString(DataInputStream in) throws IOException, VaultCryptoException {
        int n = in.readInt();
        if (n == -1) {
            return null;
        }
        if (n < 0 || n > MAX_STRING_BYTES || n > in.available()) {
            throw corrupted("Bad string length");
        }
        byte[] bytes = new byte[n];
        in.readFully(bytes);
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw corrupted("Invalid text encoding");
        }
    }

    private static VaultCryptoException corrupted(String message) {
        return new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, message);
    }

    // ------------------------------------------------------------------ Object

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof VaultItem)) {
            return false;
        }
        VaultItem b = (VaultItem) o;
        return type == b.type && createdAtMillis == b.createdAtMillis && originalDateMillis == b.originalDateMillis
                && forwardedDateMillis == b.forwardedDateMillis && sourceDialogId == b.sourceDialogId
                && sourceMessageId == b.sourceMessageId && mediaSize == b.mediaSize && width == b.width
                && height == b.height && durationSeconds == b.durationSeconds && Objects.equals(id, b.id)
                && Objects.equals(text, b.text) && Objects.equals(senderName, b.senderName)
                && Objects.equals(forwardedFromName, b.forwardedFromName) && Objects.equals(mediaId, b.mediaId)
                && Objects.equals(mediaName, b.mediaName) && Objects.equals(mimeType, b.mimeType)
                && Objects.equals(thumbnailId, b.thumbnailId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, type, createdAtMillis, text, mediaId);
    }

    /** Content-free on purpose. */
    @Override
    public String toString() {
        return "VaultItem{" + type + ", id=" + id + "}";
    }
}
