package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.util.concurrent.atomic.AtomicReference;

/** The link protocol running over a (fake) channel, with each device on its own thread. */
public class LinkTransportTest {

    private static final String PW = "existing device pw";
    private static final String PW_NEW = "linked device pw 1";

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private FakeRemoteStore remote;
    private VaultKeyManager existing;
    private volatile long now = 1_000_000;
    private final VaultStore.Clock clock = () -> now;
    private final LinkTransport.Sleeper sleeper = ms -> Thread.sleep(ms);

    @Before
    public void setUp() throws Exception {
        remote = new FakeRemoteStore();
        existing = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), 1000);
        existing.createVault(PW.toCharArray(), PW.toCharArray());
    }

    private LinkTransport.Approver approver() throws Exception {
        return new LinkTransport.Approver(remote, tmp.newFolder(), new DeviceLink.Approver(existing, clock), clock, sleeper, 1);
    }

    private LinkTransport.Joiner joiner() throws Exception {
        return new LinkTransport.Joiner(remote, tmp.newFolder(), new DeviceLink.Joiner(clock), clock, sleeper, 1);
    }

    /** Runs a body on its own thread and rethrows its failure on join. */
    private static final class Task extends Thread {
        volatile Throwable failure;
        volatile String result;
        private final Body body;

        interface Body {
            String run() throws Exception;
        }

        Task(Body body) {
            this.body = body;
            setDaemon(true);
        }

        @Override
        public void run() {
            try {
                result = body.run();
            } catch (Throwable t) {
                failure = t;
            }
        }

        String finish() throws Exception {
            join(15_000);
            assertFalse("task did not finish", isAlive());
            if (failure != null) {
                if (failure instanceof Exception) {
                    throw (Exception) failure;
                }
                throw new AssertionError(failure);
            }
            return result;
        }
    }

    @Test
    public void fullLink_overTheChannel_andCleansUp() throws Exception {
        final LinkTransport.Approver a = approver();
        final LinkTransport.Joiner j = joiner();
        final VaultKeyManager fresh = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), 1000);
        final AtomicReference<String> aCode = new AtomicReference<>();

        Task approverTask = new Task(() -> {
            a.awaitRequest();
            String code = a.awaitCode();
            aCode.set(code);
            a.approve();
            return code;
        });
        approverTask.start();
        Thread.sleep(50); // the existing device is listening first (as the screens require)
        Task joinerTask = new Task(() -> {
            String code = j.awaitCode();
            j.awaitGrantAndInstall(fresh, PW_NEW.toCharArray(), PW_NEW.toCharArray(), false);
            return code;
        });
        joinerTask.start();
        String jc = joinerTask.finish();
        String ac = approverTask.finish();
        assertEquals(ac, jc);
        assertTrue(fresh.isUnlocked());
        assertArrayEquals(existing.getVaultId(), fresh.getVaultId());
        assertArrayEquals(existing.deriveSubkey("messages"), fresh.deriveSubkey("messages"));
        assertEquals(4, remote.names().size());
        a.cleanup();
        j.cleanup();
        assertEquals(0, remote.names().size());
    }

    @Test
    public void approverIgnoresOldAbandonedRequests() throws Exception {
        // an old request from a joiner that gave up
        LinkTransport.Joiner old = joiner();
        Task t = new Task(() -> {
            old.awaitCode();
            return "x";
        });
        t.start();
        for (int i = 0; i < 200 && remote.names().isEmpty(); i++) {
            Thread.sleep(5);
        }
        assertEquals(1, remote.names().size());
        old.cancel();
        try {
            t.finish();
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
        final LinkTransport.Approver a = approver();
        Task at = new Task(() -> {
            a.awaitRequest();
            return "answered";
        });
        at.start();
        Thread.sleep(100);
        assertTrue("must not answer a request from before it started listening", at.isAlive());
        a.cancel();
        try {
            at.finish();
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
    }

    @Test
    public void approverSkipsMalformedRequests_andJunkInTheChannel() throws Exception {
        final LinkTransport.Approver a = approver();
        Task at = new Task(() -> {
            a.awaitRequest();
            return a.awaitCode();
        });
        at.start();
        Thread.sleep(50);
        remote.inject("l.0123456789abcdef0123456789abcdef", new byte[40]); // garbage request
        remote.inject("l.short", new byte[10]);
        remote.inject("r.0123456789abcdef0123456789abcdef", new byte[10]);
        final LinkTransport.Joiner j = joiner();
        final VaultKeyManager fresh = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), 1000);
        Task jt = new Task(() -> {
            String c = j.awaitCode();
            j.awaitGrantAndInstall(fresh, PW_NEW.toCharArray(), PW_NEW.toCharArray(), false);
            return c;
        });
        jt.start();
        String code = at.finish();
        assertNotNull(code);
        // approve now so the joiner can finish
        a.approve();
        assertEquals(code, jt.finish());
        assertTrue(fresh.isUnlocked());
    }

    @Test
    public void forgedGrant_doesNotStopTheRealOne() throws Exception {
        final LinkTransport.Approver a = approver();
        final LinkTransport.Joiner j = joiner();
        final VaultKeyManager fresh = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), 1000);
        final AtomicReference<String> session = new AtomicReference<>();
        Task at = new Task(() -> {
            a.awaitRequest();
            return a.awaitCode();
        });
        at.start();
        Thread.sleep(50);
        Task jt = new Task(() -> {
            String c = j.awaitCode();
            j.awaitGrantAndInstall(fresh, PW_NEW.toCharArray(), PW_NEW.toCharArray(), false);
            return c;
        });
        jt.start();
        at.finish();
        String sid = null;
        for (String n : remote.names()) {
            if (n.startsWith("l.")) {
                sid = n.substring(2);
            }
        }
        // attacker posts garbage and a tampered copy before the genuine grant
        byte[] garbage = new byte[120];
        garbage[0] = 'T';
        garbage[1] = 'G';
        garbage[2] = 'V';
        garbage[3] = 'L';
        garbage[4] = 1;
        garbage[5] = 4;
        remote.inject("g." + sid, garbage);
        Thread.sleep(30);
        assertTrue(jt.isAlive());
        a.approve();
        jt.finish();
        assertTrue(fresh.isUnlocked());
    }

    @Test
    public void wrongReveal_cancelsApproverSession_andNothingIsGranted() throws Exception {
        final LinkTransport.Approver a = approver();
        Task at = new Task(() -> {
            a.awaitRequest();
            return a.awaitCode();
        });
        at.start();
        Thread.sleep(50);
        // an attacker plays the new device: commits, then reveals something else
        DeviceLink.Joiner honestCommit = new DeviceLink.Joiner(clock);
        byte[] req = honestCommit.request();
        String sid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        remote.inject("l." + sid, req);
        for (int i = 0; i < 400 && !remote.names().contains("o." + sid); i++) {
            Thread.sleep(5);
        }
        DeviceLink.Joiner other = new DeviceLink.Joiner(clock);
        other.request();
        byte[] offer = remote.bytesOf("o." + sid);
        byte[] badReveal = other.handleOffer(offer);
        remote.inject("v." + sid, badReveal);
        try {
            at.finish();
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.LINK_MISMATCH, e.getReason());
        }
        try {
            a.approve();
            fail();
        } catch (VaultCryptoException e) {
            assertTrue(e.getReason() == VaultCryptoException.Reason.INVALID_STATE);
        }
        for (String n : remote.names()) {
            assertFalse("no grant may exist", n.startsWith("g."));
        }
    }

    @Test
    public void waitingExpires_onBothSides() throws Exception {
        final LinkTransport.Joiner j = joiner();
        final LinkTransport.Approver a = approver();
        Task jt = new Task(j::awaitCode);
        jt.start();
        Thread.sleep(30);
        now += DeviceLink.TTL_MILLIS + 1;
        try {
            jt.finish();
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.LINK_EXPIRED, e.getReason());
        }
        try {
            a.awaitRequest();
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.LINK_EXPIRED, e.getReason());
        }
    }

    @Test
    public void joinerIgnoresOffersForOtherSessions() throws Exception {
        final LinkTransport.Approver a = new LinkTransport.Approver(remote, tmp.newFolder(), new DeviceLink.Approver(existing, clock), clock, sleeper, 150);
        final LinkTransport.Joiner j = joiner();
        final VaultKeyManager fresh = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), 1000);
        Task at = new Task(() -> {
            a.awaitRequest();
            String c = a.awaitCode();
            a.approve();
            return c;
        });
        at.start();
        Thread.sleep(40);
        Task jt = new Task(() -> {
            String c = j.awaitCode();
            j.awaitGrantAndInstall(fresh, PW_NEW.toCharArray(), PW_NEW.toCharArray(), false);
            return c;
        });
        jt.start();
        // an attacker answers with a perfectly valid offer, but under a different session name
        VaultKeyManager other = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), 1000);
        other.createVault("attacker password!".toCharArray(), "attacker password!".toCharArray());
        for (int i = 0; i < 400 && countPrefix("l.") == 0; i++) {
            Thread.sleep(2);
        }
        byte[] req = null;
        for (String n : remote.names()) {
            if (n.startsWith("l.")) {
                req = remote.bytesOf(n);
            }
        }
        byte[] bogus = new DeviceLink.Approver(other, clock).handleRequest(req);
        remote.inject("o.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", bogus);
        String jc = jt.finish();
        assertEquals(at.finish(), jc);
        assertTrue(fresh.isUnlocked());
        assertArrayEquals(existing.getVaultId(), fresh.getVaultId());
    }

    private int countPrefix(String prefix) {
        int n = 0;
        for (String s : remote.names()) {
            if (s.startsWith(prefix)) {
                n++;
            }
        }
        return n;
    }

    @Test
    public void networkErrors_surfaceAsIoError() throws Exception {
        final LinkTransport.Joiner j = joiner();
        remote.failAtOp = 1;
        try {
            j.awaitCode();
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.IO_ERROR, e.getReason());
        }
    }

    @Test
    public void linkObjects_doNotDisturbTheSyncEngine() throws Exception {
        File dir = tmp.newFolder("sync");
        VaultStore store = new VaultStore(new File(dir, "v"), existing, () -> now, 4096);
        VaultSyncEngine engine = new VaultSyncEngine(store, existing, remote, new File(dir, "j"), () -> now);
        engine.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("x"), null, null);
        remote.inject("l.0123456789abcdef0123456789abcdef", new byte[40]);
        remote.inject("o.0123456789abcdef0123456789abcdef", new byte[40]);
        remote.inject("v.0123456789abcdef0123456789abcdef", new byte[40]);
        remote.inject("g.0123456789abcdef0123456789abcdef", new byte[40]);
        VaultSyncEngine.SyncReport r = engine.sync();
        assertEquals(4, r.ignoredUnknown);
        assertEquals(0, r.rejectedRemote);
    }
}
