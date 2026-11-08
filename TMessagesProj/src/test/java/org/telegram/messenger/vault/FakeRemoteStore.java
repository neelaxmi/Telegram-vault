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

/**
 * In-memory stand-in for the Telegram channel with fault injection. It models only what
 * {@link VaultRemoteStore} promises; whether the real channel keeps those promises is untested here.
 */
final class FakeRemoteStore implements VaultRemoteStore {

    private final List<Entry> entries = new ArrayList<>();
    private final Map<String, byte[]> blobs = new HashMap<>();
    private final Map<String, Entry> byToken = new HashMap<>();
    private long nextSeq = 1;
    private int refCounter = 1;

    /** Operations performed so far (upload/list/download/delete each count once). */
    int ops;
    /** Fail the operation whose number equals this (1-based); 0 = never. */
    int failAtOp;
    /** If true the failing operation has its effect first (a lost acknowledgement). */
    boolean failAfterEffect;
    /** If true, list() returns nothing (models a listing that lags behind uploads). */
    boolean listBlind;
    /** Bytes the consumer accepted in the most recent download. */
    long lastDelivered;
    /** Largest number of bytes any single download delivered. */
    long maxDelivered;
    int uploadCalls;
    int deleteCalls;

    private boolean shouldFail() {
        ops++;
        return failAtOp != 0 && ops == failAtOp;
    }

    @Override
    public synchronized Entry upload(String name, String token, File file) throws IOException {
        uploadCalls++;
        boolean fail = shouldFail();
        if (fail && !failAfterEffect) {
            throw new IOException("injected failure before upload");
        }
        Entry existing = byToken.get(token);
        Entry result;
        if (existing != null && blobs.containsKey(existing.ref)) {
            result = existing;
        } else {
            byte[] data = readAll(file);
            String ref = "ref" + (refCounter++);
            result = new Entry(nextSeq++, name, data.length, ref);
            entries.add(result);
            blobs.put(ref, data);
            byToken.put(token, result);
        }
        if (fail) {
            throw new IOException("injected failure after upload (lost ack)");
        }
        return result;
    }

    @Override
    public synchronized List<Entry> list(long afterSeq, int limit) throws IOException {
        if (shouldFail()) {
            throw new IOException("injected list failure");
        }
        List<Entry> out = new ArrayList<>();
        if (listBlind) {
            return out;
        }
        for (Entry e : entries) {
            if (e.seq > afterSeq && out.size() < limit) {
                out.add(e);
            }
        }
        return out;
    }

    @Override
    public synchronized void download(String ref, OutputStream out) throws IOException {
        if (shouldFail()) {
            throw new IOException("injected download failure");
        }
        byte[] data = blobs.get(ref);
        if (data == null) {
            throw new IOException("no such object");
        }
        lastDelivered = 0;
        for (int off = 0; off < data.length; off += 65536) {
            int n = Math.min(65536, data.length - off);
            out.write(data, off, n); // a consumer that refuses more makes this throw
            lastDelivered += n;
            maxDelivered = Math.max(maxDelivered, lastDelivered);
        }
    }

    @Override
    public synchronized void delete(String ref) throws IOException {
        deleteCalls++;
        boolean fail = shouldFail();
        if (fail && !failAfterEffect) {
            throw new IOException("injected failure before delete");
        }
        removeRef(ref);
        if (fail) {
            throw new IOException("injected failure after delete");
        }
    }

    // ---- test-only manipulation

    synchronized void removeRef(String ref) {
        blobs.remove(ref);
        for (int i = 0; i < entries.size(); i++) {
            if (entries.get(i).ref.equals(ref)) {
                entries.remove(i);
                break;
            }
        }
    }

    synchronized void removeByName(String name) {
        for (Entry e : new ArrayList<>(entries)) {
            if (e.name.equals(name)) {
                removeRef(e.ref);
            }
        }
    }

    /** An entry planted by someone who does not hold the keys. */
    synchronized Entry inject(String name, byte[] data) {
        String ref = "ref" + (refCounter++);
        Entry e = new Entry(nextSeq++, name, data.length, ref);
        entries.add(e);
        blobs.put(ref, data);
        return e;
    }

    synchronized void tamper(String name) {
        for (Entry e : entries) {
            if (e.name.equals(name)) {
                byte[] d = blobs.get(e.ref);
                d[d.length - 1] ^= 1;
            }
        }
    }

    synchronized byte[] bytesOf(String name) {
        for (Entry e : entries) {
            if (e.name.equals(name)) {
                return blobs.get(e.ref).clone();
            }
        }
        return null;
    }

    synchronized List<String> names() {
        List<String> n = new ArrayList<>();
        for (Entry e : entries) {
            n.add(e.name);
        }
        return n;
    }

    synchronized int count(String name) {
        int c = 0;
        for (Entry e : entries) {
            if (e.name.equals(name)) {
                c++;
            }
        }
        return c;
    }

    void clearFaults() {
        failAtOp = 0;
    }

    private static byte[] readAll(File f) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InputStream in = new FileInputStream(f)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
        }
        return out.toByteArray();
    }
}
