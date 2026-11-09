package org.telegram.messenger.vault;

import org.telegram.messenger.FileUploadOperation;
import org.telegram.messenger.MessagesController;
import org.telegram.tgnet.ConnectionsManager;
import org.telegram.tgnet.NativeByteBuffer;
import org.telegram.tgnet.TLObject;
import org.telegram.tgnet.TLRPC;
import org.telegram.tgnet.tl.TL_update;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * {@link ChannelApi} over Telegram's own networking (MTProto requests through {@link ConnectionsManager}).
 *
 * <p><b>STATUS: written against the real Telegram classes in this repository and type-checked against them with
 * a partial class path (see PROJECT_STATUS.md), but NEVER RUN.</b> No device or Telegram server was available.
 * Everything that depends on server behaviour is an assumption until tested on a device: that {@code random_id}
 * deduplicates a repeated send, that {@code offset_id + add_offset = -limit} returns the messages newer than
 * {@code offset_id}, that FILE_REFERENCE_EXPIRED is the only retryable download error, flood-wait handling, and
 * the upload resume of {@link FileUploadOperation}.
 *
 * <p>All methods block; call them from a background thread only (never the UI thread).
 */
public final class TelegramChannelApi implements ChannelApi {

    private static final String MIME = "application/octet-stream";
    private static final String FILE_NAME = "vault.bin";
    private static final int DOWNLOAD_PART = 512 * 1024;
    private static final long REQUEST_TIMEOUT_SECONDS = 120;
    private static final long UPLOAD_TIMEOUT_SECONDS = 4L * 60 * 60;

    private final int account;
    private final long channelId;
    private final long accessHash;

    public TelegramChannelApi(int account, long channelId, long accessHash) {
        this.account = account;
        this.channelId = channelId;
        this.accessHash = accessHash;
    }

    // ------------------------------------------------------------------ send

    @Override
    public Message send(String caption, long randomId, File file) throws IOException {
        if (file == null || !file.isFile()) {
            throw new IOException("Nothing to upload");
        }
        TLRPC.InputFile inputFile = upload(file);

        TLRPC.TL_inputMediaUploadedDocument media = new TLRPC.TL_inputMediaUploadedDocument();
        media.file = inputFile;
        media.mime_type = MIME;
        media.force_file = true;
        TLRPC.TL_documentAttributeFilename name = new TLRPC.TL_documentAttributeFilename();
        name.file_name = FILE_NAME;
        media.attributes.add(name);

        TLRPC.TL_messages_sendMedia req = new TLRPC.TL_messages_sendMedia();
        req.peer = inputPeer();
        req.media = media;
        req.message = caption;
        req.random_id = randomId;
        req.silent = true;

        TLObject response = request(req, 0, ConnectionsManager.ConnectionTypeGeneric, ConnectionsManager.DEFAULT_DATACENTER_ID);
        if (!(response instanceof TLRPC.Updates)) {
            throw new IOException("Unexpected reply to sendMedia");
        }
        TLRPC.Updates updates = (TLRPC.Updates) response;
        MessagesController.getInstance(account).processUpdates(updates, false);
        return messageFrom(updates, randomId);
    }

    private TLRPC.InputFile upload(File file) throws IOException {
        final AtomicReference<TLRPC.InputFile> result = new AtomicReference<>();
        final CountDownLatch done = new CountDownLatch(1);
        FileUploadOperation op = new FileUploadOperation(account, file.getAbsolutePath(), false, file.length(), ConnectionsManager.FileTypeFile);
        op.setDelegate(new FileUploadOperation.FileUploadOperationDelegate() {
            @Override
            public void didFinishUploadingFile(FileUploadOperation operation, TLRPC.InputFile inputFile, TLRPC.InputEncryptedFile inputEncryptedFile, byte[] key, byte[] iv) {
                result.set(inputFile);
                done.countDown();
            }

            @Override
            public void didFailedUploadingFile(FileUploadOperation operation) {
                done.countDown();
            }

            @Override
            public void didChangedUploadProgress(FileUploadOperation operation, long uploadedSize, long totalSize) {
            }
        });
        op.start();
        try {
            if (!done.await(UPLOAD_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                op.cancel();
                throw new IOException("Upload timed out");
            }
        } catch (InterruptedException e) {
            op.cancel();
            Thread.currentThread().interrupt();
            throw new IOException("Upload interrupted");
        }
        TLRPC.InputFile inputFile = result.get();
        if (inputFile == null) {
            throw new IOException("Upload failed");
        }
        return inputFile;
    }

    /** Finds the new message in the reply by its random id; size comes from the attached document. */
    private Message messageFrom(TLRPC.Updates updates, long randomId) throws IOException {
        int id = 0;
        for (TLRPC.Update u : updates.updates) {
            if (u instanceof TL_update.TL_updateMessageID && ((TL_update.TL_updateMessageID) u).random_id == randomId) {
                id = ((TL_update.TL_updateMessageID) u).id;
            }
        }
        for (TLRPC.Update u : updates.updates) {
            if (u instanceof TL_update.TL_updateNewChannelMessage) {
                TLRPC.Message m = ((TL_update.TL_updateNewChannelMessage) u).message;
                if (m != null && (id == 0 || m.id == id)) {
                    return toMessage(m);
                }
            }
        }
        if (id != 0) {
            return new Message(id, "", 0);
        }
        throw new IOException("Telegram did not report the new message");
    }

    // ------------------------------------------------------------------ history

    @Override
    public List<Message> history(long afterId, int limit) throws IOException {
        if (afterId < 0 || afterId > Integer.MAX_VALUE || limit <= 0) {
            throw new IOException("Invalid history arguments");
        }
        TLRPC.TL_messages_getHistory req = new TLRPC.TL_messages_getHistory();
        req.peer = inputPeer();
        req.offset_id = (int) afterId;
        req.add_offset = -limit; // newer than offset_id; the server returns newest first
        req.limit = limit;
        TLObject response = request(req, 0, ConnectionsManager.ConnectionTypeGeneric, ConnectionsManager.DEFAULT_DATACENTER_ID);
        if (!(response instanceof TLRPC.messages_Messages)) {
            throw new IOException("Unexpected reply to getHistory");
        }
        List<Message> out = new ArrayList<>();
        for (TLRPC.Message m : ((TLRPC.messages_Messages) response).messages) {
            if (m instanceof TLRPC.TL_message && m.id > afterId) {
                out.add(toMessage(m));
            }
        }
        Collections.sort(out, new Comparator<Message>() {
            @Override
            public int compare(Message a, Message b) {
                return Long.compare(a.id, b.id);
            }
        });
        return out;
    }

    private static Message toMessage(TLRPC.Message m) {
        long size = 0;
        if (m.media instanceof TLRPC.TL_messageMediaDocument && ((TLRPC.TL_messageMediaDocument) m.media).document != null) {
            size = ((TLRPC.TL_messageMediaDocument) m.media).document.size;
        }
        return new Message(m.id, m.message, size);
    }

    // ------------------------------------------------------------------ download

    @Override
    public void download(long messageId, OutputStream out) throws IOException {
        TLRPC.Document doc = fetchDocument(messageId);
        long written = 0;
        boolean refreshed = false;
        while (written < doc.size) {
            TLRPC.TL_upload_getFile req = new TLRPC.TL_upload_getFile();
            TLRPC.TL_inputDocumentFileLocation location = new TLRPC.TL_inputDocumentFileLocation();
            location.id = doc.id;
            location.access_hash = doc.access_hash;
            location.file_reference = doc.file_reference;
            location.thumb_size = "";
            req.location = location;
            req.offset = written;
            req.limit = DOWNLOAD_PART;
            TLObject response;
            try {
                response = request(req, 0, ConnectionsManager.ConnectionTypeDownload, doc.dc_id);
            } catch (TelegramError e) {
                if (!refreshed && e.text != null && e.text.startsWith("FILE_REFERENCE")) {
                    refreshed = true;
                    doc = fetchDocument(messageId);
                    continue;
                }
                throw e;
            }
            if (!(response instanceof TLRPC.TL_upload_file)) {
                throw new IOException("Unexpected reply to getFile");
            }
            NativeByteBuffer buffer = ((TLRPC.TL_upload_file) response).bytes;
            int n = buffer.limit();
            if (n <= 0) {
                buffer.reuse();
                throw new IOException("Telegram returned an empty part");
            }
            byte[] bytes = new byte[n];
            buffer.readBytes(bytes, false);
            buffer.reuse();
            out.write(bytes);
            written += n;
        }
    }

    private TLRPC.Document fetchDocument(long messageId) throws IOException {
        TLRPC.TL_channels_getMessages req = new TLRPC.TL_channels_getMessages();
        req.channel = inputChannel();
        req.id.add((int) messageId);
        TLObject response = request(req, 0, ConnectionsManager.ConnectionTypeGeneric, ConnectionsManager.DEFAULT_DATACENTER_ID);
        if (!(response instanceof TLRPC.messages_Messages)) {
            throw new IOException("Unexpected reply to getMessages");
        }
        for (TLRPC.Message m : ((TLRPC.messages_Messages) response).messages) {
            if (m.id == messageId && m.media instanceof TLRPC.TL_messageMediaDocument
                    && ((TLRPC.TL_messageMediaDocument) m.media).document != null) {
                return ((TLRPC.TL_messageMediaDocument) m.media).document;
            }
        }
        throw new IOException("Message has no document (deleted?)");
    }

    // ------------------------------------------------------------------ delete

    @Override
    public void delete(long messageId) throws IOException {
        TLRPC.TL_channels_deleteMessages req = new TLRPC.TL_channels_deleteMessages();
        req.channel = inputChannel();
        req.id.add((int) messageId);
        request(req, 0, ConnectionsManager.ConnectionTypeGeneric, ConnectionsManager.DEFAULT_DATACENTER_ID);
    }

    // ------------------------------------------------------------------ plumbing

    private TLRPC.InputPeer inputPeer() {
        TLRPC.TL_inputPeerChannel peer = new TLRPC.TL_inputPeerChannel();
        peer.channel_id = channelId;
        peer.access_hash = accessHash;
        return peer;
    }

    private TLRPC.InputChannel inputChannel() {
        TLRPC.TL_inputChannel channel = new TLRPC.TL_inputChannel();
        channel.channel_id = channelId;
        channel.access_hash = accessHash;
        return channel;
    }

    /** A Telegram error reply. {@code text} is e.g. "FLOOD_WAIT_30" or "FILE_REFERENCE_EXPIRED". */
    static final class TelegramError extends IOException {
        private static final long serialVersionUID = 1L;
        final int code;
        final String text;

        TelegramError(int code, String text) {
            super("Telegram error " + code + ": " + text);
            this.code = code;
            this.text = text;
        }
    }

    /** Sends one request and waits for the reply. Never call on the network or UI thread. */
    private TLObject request(TLObject req, int flags, int connectionType, int datacenterId) throws IOException {
        return request(account, req, flags, connectionType, datacenterId);
    }

    static TLObject request(int account, TLObject req, int flags, int connectionType, int datacenterId) throws IOException {
        final AtomicReference<TLObject> response = new AtomicReference<>();
        final AtomicReference<TLRPC.TL_error> error = new AtomicReference<>();
        final CountDownLatch done = new CountDownLatch(1);
        ConnectionsManager.getInstance(account).sendRequest(req, (res, err) -> {
            response.set(res);
            error.set(err);
            done.countDown();
        }, null, null, null, flags, datacenterId, connectionType, true);
        try {
            if (!done.await(REQUEST_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new IOException("Telegram did not answer in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted");
        }
        TLRPC.TL_error err = error.get();
        if (err != null) {
            throw new TelegramError(err.code, err.text);
        }
        if (response.get() == null) {
            throw new IOException("Empty reply");
        }
        return response.get();
    }
}
