package org.telegram.messenger.vault;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** A channel as Telegram is documented to behave: increasing ids, random_id deduplication, small history pages. */
final class FakeChannelApi implements ChannelApi {

    private final List<Message> messages = new ArrayList<>();
    private final Map<Long, byte[]> files = new HashMap<>();
    private final Map<Long, Message> byRandomId = new HashMap<>();
    private long nextId = 100;
    int pageCap = 3;
    int failAtCall;
    boolean failAfterEffect;
    int calls;
    int sends;

    private boolean fail() {
        calls++;
        return failAtCall != 0 && calls == failAtCall;
    }

    @Override
    public synchronized Message send(String caption, long randomId, File file) throws IOException {
        sends++;
        boolean f = fail();
        if (f && !failAfterEffect) {
            throw new IOException("injected");
        }
        Message m = byRandomId.get(randomId);
        if (m == null || !files.containsKey(m.id)) {
            byte[] data = read(file);
            m = new Message(nextId += 1 + (nextId % 3), caption, data.length); // gaps in ids, like a real channel
            messages.add(m);
            files.put(m.id, data);
            byRandomId.put(randomId, m);
        }
        if (f) {
            throw new IOException("injected after effect");
        }
        return m;
    }

    @Override
    public synchronized List<Message> history(long afterId, int limit) throws IOException {
        if (fail()) {
            throw new IOException("injected");
        }
        List<Message> out = new ArrayList<>();
        for (Message m : messages) {
            if (m.id > afterId && out.size() < Math.min(limit, pageCap)) {
                out.add(m);
            }
        }
        return out;
    }

    @Override
    public synchronized void download(long id, OutputStream out) throws IOException {
        if (fail()) {
            throw new IOException("injected");
        }
        byte[] d = files.get(id);
        if (d == null) {
            throw new IOException("gone");
        }
        out.write(d);
    }

    @Override
    public synchronized void delete(long id) throws IOException {
        if (fail()) {
            throw new IOException("injected");
        }
        for (int i = 0; i < messages.size(); i++) {
            if (messages.get(i).id == id) {
                messages.remove(i);
                break;
            }
        }
        files.remove(id);
    }

    /** Someone else's message in the channel (no Vault caption or a fake one). */
    synchronized long post(String caption, byte[] data) {
        Message m = new Message(nextId += 1 + (nextId % 3), caption, data.length);
        messages.add(m);
        files.put(m.id, data);
        return m.id;
    }

    synchronized int messageCount() {
        return messages.size();
    }

    private static byte[] read(File f) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InputStream in = new FileInputStream(f)) {
            byte[] b = new byte[8192];
            int n;
            while ((n = in.read(b)) > 0) {
                out.write(b, 0, n);
            }
        }
        return out.toByteArray();
    }
}
