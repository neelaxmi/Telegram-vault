package org.telegram.messenger.vault;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Carries the {@link DeviceLink} messages through the Vault channel as short-lived objects named
 * {@code l.<session>} (request), {@code o.<session>} (offer), {@code v.<session>} (reveal) and {@code g.<session>}
 * (grant), then deletes them. The channel is NOT trusted: everything is authenticated by the protocol, and anything
 * that does not authenticate is skipped. Blocking; run on a background thread.
 *
 * <p>The sync engine ignores these names, so linking does not disturb a running sync.
 */
public final class LinkTransport {

    /** Waiting between polls; replaced in tests. */
    public interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }

    static final long POLL_MILLIS = 2_000;
    private static final int MAX_MESSAGE = 8192;
    private static final Sleeper REAL_SLEEP = new Sleeper() {
        @Override
        public void sleep(long millis) throws InterruptedException {
            Thread.sleep(millis);
        }
    };
    private static final VaultStore.Clock REAL_CLOCK = new VaultStore.Clock() {
        @Override
        public long nowMillis() {
            return System.currentTimeMillis();
        }
    };

    private LinkTransport() {
    }

    // ------------------------------------------------------------------ shared plumbing

    private abstract static class Base {
        final VaultRemoteStore remote;
        final VaultStore.Clock clock;
        final Sleeper sleeper;
        final long pollMillis;
        final long startedAt;
        final File workDir;
        volatile boolean cancelled;
        long cursor;
        final List<String> ownRefs = new ArrayList<>();

        Base(VaultRemoteStore remote, File workDir, VaultStore.Clock clock, Sleeper sleeper, long pollMillis) {
            if (remote == null || workDir == null) {
                throw new IllegalArgumentException("arguments required");
            }
            this.remote = remote;
            this.workDir = workDir;
            this.clock = clock;
            this.sleeper = sleeper;
            this.pollMillis = pollMillis;
            this.startedAt = clock.nowMillis();
        }

        /** Ends any waiting loop. Call {@code cleanup} afterwards. */
        public void cancel() {
            cancelled = true;
        }

        void checkAlive() throws VaultCryptoException {
            if (cancelled) {
                throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "Linking was cancelled");
            }
            long now = clock.nowMillis();
            if (now < startedAt || now - startedAt > DeviceLink.TTL_MILLIS) {
                throw new VaultCryptoException(VaultCryptoException.Reason.LINK_EXPIRED, "Link session expired");
            }
        }

        void pause() throws VaultCryptoException {
            try {
                sleeper.sleep(pollMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                cancelled = true;
                throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "Linking was interrupted");
            }
        }

        void put(String name, byte[] message) throws VaultCryptoException {
            File tmp = new File(workDir, "link-" + System.nanoTime() + ".tmp");
            try {
                try (OutputStream out = new FileOutputStream(tmp)) {
                    out.write(message);
                }
                VaultRemoteStore.Entry e = remote.upload(name, token(name), tmp);
                ownRefs.add(e.ref);
            } catch (IOException e) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not send a link message", e);
            } finally {
                VaultFiles.deleteQuietly(tmp);
            }
        }

        /** New entries (after the cursor) in server order. */
        List<VaultRemoteStore.Entry> poll() throws VaultCryptoException {
            try {
                List<VaultRemoteStore.Entry> all = new ArrayList<>();
                while (true) {
                    List<VaultRemoteStore.Entry> page = remote.list(cursor, VaultSyncEngine.PAGE_SIZE);
                    if (page == null || page.isEmpty()) {
                        return all;
                    }
                    for (VaultRemoteStore.Entry e : page) {
                        if (e.seq <= cursor) {
                            throw new IOException("Server returned entries out of order");
                        }
                        cursor = e.seq;
                        all.add(e);
                    }
                }
            } catch (IOException e) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not read link messages", e);
            }
        }

        byte[] fetch(VaultRemoteStore.Entry entry) throws VaultCryptoException {
            final ByteArrayOutputStream buf = new ByteArrayOutputStream();
            try {
                remote.download(entry.ref, new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        if (buf.size() >= MAX_MESSAGE) {
                            throw new IOException("too large");
                        }
                        buf.write(b);
                    }

                    @Override
                    public void write(byte[] b, int off, int len) throws IOException {
                        if (buf.size() + len > MAX_MESSAGE) {
                            throw new IOException("too large");
                        }
                        buf.write(b, off, len);
                    }
                });
            } catch (IOException e) {
                return null; // oversized or vanished: not a message for us
            }
            return buf.toByteArray();
        }

        /** Ignores everything already in the channel: old, abandoned link attempts must not be answered. */
        void skipHistory() throws VaultCryptoException {
            poll();
        }

        /** Deletes this side's own link objects (best effort). */
        public void cleanup() {
            for (String ref : ownRefs) {
                try {
                    remote.delete(ref);
                } catch (IOException ignored) {
                    // leftovers are harmless: sessions expire and carry no secrets
                }
            }
            ownRefs.clear();
        }
    }

    private static String token(String name) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(("tg-vault/link/token/" + name).getBytes(StandardCharsets.US_ASCII));
            byte[] d = md.digest();
            StringBuilder sb = new StringBuilder(32);
            for (int i = 0; i < 16; i++) {
                sb.append(Character.forDigit((d[i] >> 4) & 15, 16)).append(Character.forDigit(d[i] & 15, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String newSession() {
        byte[] r = VaultCrypto.randomBytes(16);
        StringBuilder sb = new StringBuilder(32);
        for (byte b : r) {
            sb.append(Character.forDigit((b >> 4) & 15, 16)).append(Character.forDigit(b & 15, 16));
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ new device

    /** Runs on the NEW device. */
    public static final class Joiner extends Base {
        private final DeviceLink.Joiner link;
        private String session;
        private boolean requestSent;

        public Joiner(VaultRemoteStore remote, File workDir) {
            this(remote, workDir, new DeviceLink.Joiner(), REAL_CLOCK, REAL_SLEEP, POLL_MILLIS);
        }

        Joiner(VaultRemoteStore remote, File workDir, DeviceLink.Joiner link, VaultStore.Clock clock, Sleeper sleeper, long pollMillis) {
            super(remote, workDir, clock, sleeper, pollMillis);
            this.link = link;
        }

        /** Sends the request, waits for the other device's offer, answers it, and returns the 6-digit code to compare. */
        public String awaitCode() throws VaultCryptoException {
            if (!requestSent) {
                skipHistory();
                session = newSession();
                put("l." + session, link.request());
                requestSent = true;
            }
            while (true) {
                checkAlive();
                for (VaultRemoteStore.Entry e : poll()) {
                    if (!e.name.equals("o." + session)) {
                        continue;
                    }
                    byte[] msg = fetch(e);
                    if (msg == null) {
                        continue;
                    }
                    byte[] reveal;
                    try {
                        reveal = link.handleOffer(msg);
                    } catch (VaultCryptoException ex) {
                        if (ex.getReason() == VaultCryptoException.Reason.CORRUPTED) {
                            continue; // not a well-formed offer: keep waiting for a real one
                        }
                        throw ex;
                    }
                    put("v." + session, reveal);
                    return link.code();
                }
                pause();
            }
        }

        /** Waits for the existing device to approve; then installs the Vault on {@code keys} with the new password. */
        public void awaitGrantAndInstall(VaultKeyManager keys, char[] password, char[] confirmation, boolean replace)
                throws VaultCryptoException {
            while (true) {
                checkAlive();
                for (VaultRemoteStore.Entry e : poll()) {
                    if (!e.name.equals("g." + session)) {
                        continue;
                    }
                    byte[] msg = fetch(e);
                    if (msg == null) {
                        continue;
                    }
                    try {
                        link.handleGrant(msg);
                    } catch (VaultCryptoException ex) {
                        if (ex.getReason() == VaultCryptoException.Reason.LINK_MISMATCH
                                || ex.getReason() == VaultCryptoException.Reason.CORRUPTED) {
                            continue; // a forged grant must not stop the real one from working
                        }
                        throw ex;
                    }
                    link.install(keys, password, confirmation, replace);
                    return;
                }
                pause();
            }
        }

        @Override
        public void cancel() {
            super.cancel();
            link.cancel();
        }
    }

    // ------------------------------------------------------------------ existing device

    /** Runs on the device that already has the Vault (unlocked). */
    public static final class Approver extends Base {
        private final DeviceLink.Approver link;
        private String session;
        private boolean historySkipped;

        public Approver(VaultRemoteStore remote, VaultKeyManager keys, File workDir) {
            this(remote, workDir, new DeviceLink.Approver(keys), REAL_CLOCK, REAL_SLEEP, POLL_MILLIS);
        }

        Approver(VaultRemoteStore remote, File workDir, DeviceLink.Approver link, VaultStore.Clock clock, Sleeper sleeper, long pollMillis) {
            super(remote, workDir, clock, sleeper, pollMillis);
            this.link = link;
        }

        /**
         * Waits for a new device's request (the first well-formed one wins) and answers it. Objects that are
         * not requests are skipped.
         */
        public void awaitRequest() throws VaultCryptoException {
            if (!historySkipped) {
                skipHistory(); // so: start linking on THIS device first, then on the new one
                historySkipped = true;
            }
            while (session == null) {
                checkAlive();
                for (VaultRemoteStore.Entry e : poll()) {
                    if (!e.name.startsWith("l.") || e.name.length() != 34) {
                        continue;
                    }
                    byte[] msg = fetch(e);
                    if (msg == null) {
                        continue;
                    }
                    byte[] offer;
                    try {
                        offer = link.handleRequest(msg);
                    } catch (VaultCryptoException ex) {
                        if (ex.getReason() == VaultCryptoException.Reason.CORRUPTED
                                || ex.getReason() == VaultCryptoException.Reason.UNSUPPORTED_VERSION) {
                            continue;
                        }
                        throw ex;
                    }
                    session = e.name.substring(2);
                    put("o." + session, offer);
                    break;
                }
                if (session == null) {
                    pause();
                }
            }
        }

        /** Waits for the new device's reveal and returns the 6-digit code to show. A wrong reveal cancels the session. */
        public String awaitCode() throws VaultCryptoException {
            if (session == null) {
                throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "No request yet");
            }
            while (true) {
                checkAlive();
                for (VaultRemoteStore.Entry e : poll()) {
                    if (!e.name.equals("v." + session)) {
                        continue;
                    }
                    byte[] msg = fetch(e);
                    if (msg == null) {
                        continue;
                    }
                    try {
                        link.handleReveal(msg);
                    } catch (VaultCryptoException ex) {
                        if (ex.getReason() == VaultCryptoException.Reason.CORRUPTED) {
                            continue; // malformed: not a reveal at all
                        }
                        throw ex; // LINK_MISMATCH: the session is cancelled for good
                    }
                    return link.code();
                }
                pause();
            }
        }

        /** The user confirmed the codes match: sends the grant. */
        public void approve() throws VaultCryptoException {
            checkAlive();
            put("g." + session, link.approve());
        }

        @Override
        public void cancel() {
            super.cancel();
            link.cancel();
        }
    }
}
