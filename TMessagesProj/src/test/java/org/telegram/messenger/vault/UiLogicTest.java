package org.telegram.messenger.vault;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;

/** The pure-Java parts behind the Phase 8 screens: setup flow, list model, sync coordinator. */
public class UiLogicTest {

    private static final String PW = "a long enough password";

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private long now = 1_000_000;

    private interface Action {
        void run() throws Exception;
    }

    private static void assertReason(VaultCryptoException.Reason r, Action a) {
        try {
            a.run();
            fail("expected " + r);
        } catch (VaultCryptoException e) {
            assertEquals(r, e.getReason());
        } catch (Exception e) {
            fail("unexpected " + e);
        }
    }

    private static VaultKeyManager newKeys() {
        return new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), 1000);
    }

    // ------------------------------------------------------------------ SetupFlow

    @Test
    public void setup_happyPath_writesNothingUntilConfirmed() throws Exception {
        InMemoryHeaderStore hs = new InMemoryHeaderStore();
        VaultKeyManager keys = new VaultKeyManager(hs, new TestDeviceKeyWrapper(), 1000);
        SetupFlow f = new SetupFlow(keys);
        assertEquals(SetupFlow.Step.PASSWORD, f.step());
        f.submitPassword(PW.toCharArray(), PW.toCharArray());
        assertEquals(SetupFlow.Step.SHOW_KEY, f.step());
        String key = f.recoveryKeyText();
        assertEquals(12, key.split(" ").length); // 12-word recovery phrase
        f.keyWrittenDown();
        assertFalse(hs.exists());
        assertFalse(keys.isUnlocked());
        byte[] bundle = f.confirm(key);
        assertEquals(SetupFlow.Step.DONE, f.step());
        assertTrue(hs.exists());
        assertTrue(keys.isUnlocked());
        assertTrue(bundle.length > 60);
        assertReason(VaultCryptoException.Reason.INVALID_STATE, f::recoveryKeyText);
    }

    @Test
    public void setup_wrongKeyTyped_staysOnConfirm_andCanRetry() throws Exception {
        VaultKeyManager keys = newKeys();
        SetupFlow f = new SetupFlow(keys);
        f.submitPassword(PW.toCharArray(), PW.toCharArray());
        String key = f.recoveryKeyText();
        f.keyWrittenDown();
        String other = RecoveryKey.generate().format();
        assertReason(VaultCryptoException.Reason.WRONG_RECOVERY_KEY, () -> f.confirm(other));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> f.confirm("not a key"));
        assertEquals(SetupFlow.Step.CONFIRM_KEY, f.step());
        assertFalse(keys.isInitialized());
        f.confirm(key.toLowerCase().replace("-", " "));
        assertTrue(keys.isUnlocked());
    }

    @Test
    public void setup_badPassword_staysOnPassword() throws Exception {
        VaultKeyManager keys = newKeys();
        SetupFlow f = new SetupFlow(keys);
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> f.submitPassword("short".toCharArray(), "short".toCharArray()));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> f.submitPassword(PW.toCharArray(), (PW + "x").toCharArray()));
        assertEquals(SetupFlow.Step.PASSWORD, f.step());
        f.submitPassword(PW.toCharArray(), PW.toCharArray());
    }

    @Test
    public void setup_stepsCannotBeSkipped() throws Exception {
        SetupFlow f = new SetupFlow(newKeys());
        assertReason(VaultCryptoException.Reason.INVALID_STATE, f::keyWrittenDown);
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> f.confirm(RecoveryKey.generate().format()));
        assertReason(VaultCryptoException.Reason.INVALID_STATE, f::recoveryKeyText);
        f.submitPassword(PW.toCharArray(), PW.toCharArray());
        // the key cannot be confirmed before it was shown and acknowledged
        String k = f.recoveryKeyText();
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> f.confirm(k));
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> f.submitPassword(PW.toCharArray(), PW.toCharArray()));
    }

    @Test
    public void setup_cancel_leavesNothing_andNewFlowGetsNewKey() throws Exception {
        InMemoryHeaderStore hs = new InMemoryHeaderStore();
        VaultKeyManager keys = new VaultKeyManager(hs, new TestDeviceKeyWrapper(), 1000);
        SetupFlow f = new SetupFlow(keys);
        f.submitPassword(PW.toCharArray(), PW.toCharArray());
        String first = f.recoveryKeyText();
        f.cancel();
        assertEquals(SetupFlow.Step.CANCELLED, f.step());
        assertFalse(hs.exists());
        assertReason(VaultCryptoException.Reason.INVALID_STATE, f::recoveryKeyText);
        SetupFlow g = new SetupFlow(keys);
        g.submitPassword(PW.toCharArray(), PW.toCharArray());
        assertNotEquals(first, g.recoveryKeyText());
    }

    @Test
    public void setup_backToKey() throws Exception {
        SetupFlow f = new SetupFlow(newKeys());
        f.submitPassword(PW.toCharArray(), PW.toCharArray());
        f.keyWrittenDown();
        f.backToKey();
        assertEquals(SetupFlow.Step.SHOW_KEY, f.step());
    }

    // ------------------------------------------------------------------ VaultListModel

    private final class Dev {
        final VaultKeyManager keys = newKeys();
        final VaultStore store;
        final VaultSyncEngine engine;
        final VaultListModel model;

        Dev(FakeRemoteStore remote) throws Exception {
            keys.createVault(PW.toCharArray(), PW.toCharArray());
            File dir = tmp.newFolder("d" + System.nanoTime());
            store = new VaultStore(new File(dir, "vault"), keys, () -> now, 4096);
            engine = new VaultSyncEngine(store, keys, remote, new File(dir, "journal"), () -> now);
            model = new VaultListModel(store);
        }

        VaultItem text(String t) throws Exception {
            now += 10;
            return engine.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text(t), null, null);
        }
    }

    @Test
    public void list_isChronologicalLikeAChat_andSearchFilters() throws Exception {
        Dev d = new Dev(new FakeRemoteStore());
        d.text("alpha note");
        d.text("Beta NOTE");
        d.text("gamma");
        d.model.refresh();
        assertEquals(3, d.model.rows().size());
        assertEquals("alpha note", d.model.rows().get(0).title);
        assertEquals("gamma", d.model.rows().get(2).title);
        d.model.setQuery("note");
        assertEquals(2, d.model.rows().size());
        d.model.setQuery("zzz");
        assertEquals(0, d.model.rows().size());
        d.model.setQuery("");
        assertEquals(3, d.model.rows().size());
    }

    @Test
    public void selection_toggleAll_andDelete() throws Exception {
        FakeRemoteStore remote = new FakeRemoteStore();
        Dev d = new Dev(remote);
        VaultItem a = d.text("one");
        VaultItem b = d.text("two");
        d.text("three");
        d.engine.sync();
        d.model.refresh();
        assertFalse(d.model.isSelecting());
        d.model.toggle(a.id);
        d.model.toggle(b.id);
        assertEquals(2, d.model.selectedCount());
        d.model.toggle(b.id);
        assertEquals(1, d.model.selectedCount());
        d.model.toggle("not an item");
        assertEquals(1, d.model.selectedCount());
        d.model.selectAll();
        assertEquals(3, d.model.selectedCount());
        d.model.toggle(a.id);
        assertEquals(2, d.model.deleteSelected(d.engine));
        assertFalse(d.model.isSelecting());
        assertEquals(1, d.model.rows().size());
        assertEquals(a.id, d.model.rows().get(0).id);
        d.engine.sync();
        assertEquals(2, countNames(remote, "x."));
    }

    private static int countNames(FakeRemoteStore r, String prefix) {
        int n = 0;
        for (String s : r.names()) {
            if (s.startsWith(prefix)) {
                n++;
            }
        }
        return n;
    }

    @Test
    public void selectedItemsHiddenBySearch_areStillDeleted() throws Exception {
        Dev d = new Dev(new FakeRemoteStore());
        VaultItem a = d.text("keep apple");
        d.text("other");
        d.model.refresh();
        d.model.toggle(a.id);
        d.model.setQuery("other");
        assertEquals(1, d.model.selectedCount());
        assertEquals(1, d.model.deleteSelected(d.engine));
        d.model.setQuery("");
        assertEquals(1, d.model.rows().size());
    }

    @Test
    public void selection_dropsItemsDeletedElsewhere() throws Exception {
        FakeRemoteStore remote = new FakeRemoteStore();
        Dev a = new Dev(remote);
        VaultItem item = a.text("x");
        a.model.refresh();
        a.model.toggle(item.id);
        a.store.delete(item.id);
        a.model.refresh();
        assertEquals(0, a.model.selectedCount());
    }

    @Test
    public void damagedAndNewerItems_areCountedNotHidden() throws Exception {
        Dev d = new Dev(new FakeRemoteStore());
        VaultItem good = d.text("good");
        VaultItem bad = d.text("bad");
        java.nio.file.Files.write(d.store.recordCipherFile(bad.id).toPath(), new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10});
        d.model.refresh();
        assertEquals(1, d.model.rows().size());
        assertEquals(1, d.model.damagedCount());
        assertEquals(0, d.model.needsUpdateCount());
        assertEquals(good.id, d.model.rows().get(0).id);
    }

    @Test
    public void rowText_isShortenedAndFormatted() throws Exception {
        Dev d = new Dev(new FakeRemoteStore());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 300; i++) {
            sb.append('x');
        }
        d.text(sb.toString());
        now += 10;
        VaultItem.Draft doc = new VaultItem.Draft(VaultItem.Type.DOCUMENT).media("report.pdf", "application/pdf", 0, 0, 0);
        d.engine.addItem(doc, new java.io.ByteArrayInputStream(new byte[3000]), null);
        d.model.refresh();
        List<VaultListModel.Row> rows = d.model.rows();
        VaultListModel.Row docRow = rows.get(1);
        assertEquals("report.pdf", docRow.title);
        assertEquals("2.9 KB", docRow.subtitle);
        assertTrue(docRow.hasMedia);
        assertEquals(VaultListModel.MAX_TITLE_CHARS + 1, rows.get(0).title.length());
        assertEquals("0 B", VaultListModel.formatSize(0));
        assertEquals("1.0 MB", VaultListModel.formatSize(1024 * 1024));
        assertEquals("150 MB", VaultListModel.formatSize(150L * 1024 * 1024));
    }

    // ------------------------------------------------------------------ SyncCoordinator

    private static final class Queue implements Executor {
        final List<Runnable> tasks = new ArrayList<>();

        @Override
        public void execute(Runnable r) {
            tasks.add(r);
        }

        void runAll() {
            List<Runnable> copy = new ArrayList<>(tasks);
            tasks.clear();
            for (Runnable r : copy) {
                r.run();
            }
        }
    }

    private SyncCoordinator coordinator(Dev d, Queue q, List<SyncCoordinator.Status> log) {
        return new SyncCoordinator(d.engine, q, s -> log.add(s), () -> now);
    }

    @Test
    public void coordinator_successfulRun_reportsIdleAndPending() throws Exception {
        Dev d = new Dev(new FakeRemoteStore());
        d.text("x");
        Queue q = new Queue();
        List<SyncCoordinator.Status> log = new ArrayList<>();
        SyncCoordinator c = coordinator(d, q, log);
        assertTrue(c.requestSync(false));
        assertEquals(SyncCoordinator.State.SYNCING, c.status().state);
        assertFalse("single flight", c.requestSync(false));
        q.runAll();
        assertEquals(SyncCoordinator.State.IDLE, c.status().state);
        assertEquals(0, c.status().pendingItems);
        assertEquals(now, c.status().lastSuccessMillis);
        assertEquals(SyncCoordinator.State.SYNCING, log.get(0).state);
        assertEquals(SyncCoordinator.State.IDLE, log.get(log.size() - 1).state);
    }

    @Test
    public void coordinator_backsOffExponentially_andForceOverrides() throws Exception {
        FakeRemoteStore remote = new FakeRemoteStore();
        Dev d = new Dev(remote);
        d.text("x");
        Queue q = new Queue();
        SyncCoordinator c = coordinator(d, q, new ArrayList<SyncCoordinator.Status>());
        long[] expected = {5_000, 10_000, 20_000, 40_000};
        for (int i = 0; i < expected.length; i++) {
            remote.ops = 0;
            remote.failAtOp = 1;
            assertTrue(c.requestSync(true));
            q.runAll();
            SyncCoordinator.Status s = c.status();
            assertEquals(SyncCoordinator.State.WAITING_RETRY, s.state);
            assertEquals(VaultCryptoException.Reason.IO_ERROR, s.error);
            assertEquals(i + 1, s.consecutiveFailures);
            assertEquals(now + expected[i], s.nextAttemptMillis);
            assertFalse("still backing off", c.requestSync(false));
        }
        now += 40_000;
        remote.failAtOp = 0;
        assertTrue(c.requestSync(false));
        q.runAll();
        assertEquals(SyncCoordinator.State.IDLE, c.status().state);
        assertEquals(0, c.status().consecutiveFailures);
    }

    @Test
    public void coordinator_backoffIsCapped() throws Exception {
        FakeRemoteStore remote = new FakeRemoteStore();
        Dev d = new Dev(remote);
        d.text("x");
        Queue q = new Queue();
        SyncCoordinator c = coordinator(d, q, new ArrayList<SyncCoordinator.Status>());
        for (int i = 0; i < 40; i++) {
            remote.ops = 0;
            remote.failAtOp = 1;
            c.requestSync(true);
            q.runAll();
        }
        assertEquals(now + SyncCoordinator.MAX_BACKOFF_MILLIS, c.status().nextAttemptMillis);
    }

    @Test
    public void floodWait_isParsedFromTheCauseChain() {
        VaultCryptoException e = new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Upload failed",
                new java.io.IOException("Telegram error 420: FLOOD_WAIT_300"));
        assertEquals(301_000, SyncCoordinator.floodWaitMillis(e));
        assertEquals(0, SyncCoordinator.floodWaitMillis(new RuntimeException("nothing")));
        assertEquals(0, SyncCoordinator.floodWaitMillis(new RuntimeException("FLOOD_WAIT_")));
        assertEquals(1000, SyncCoordinator.floodWaitMillis(new RuntimeException("FLOOD_WAIT_0")));
    }

    @Test
    public void coordinator_honoursFloodWaitLongerThanBackoff() throws Exception {
        Dev d = new Dev(new FakeRemoteStore());
        d.text("x");
        VaultSyncEngine floody = new VaultSyncEngine(d.store, d.keys, new FakeRemoteStore() {
            @Override
            public synchronized List<Entry> list(long afterSeq, int limit) throws java.io.IOException {
                throw new java.io.IOException("Telegram error 420: FLOOD_WAIT_120");
            }
        }, new File(tmp.newFolder(), "journal"), () -> now);
        Queue q = new Queue();
        SyncCoordinator c = new SyncCoordinator(floody, q, null, () -> now);
        c.requestSync(false);
        q.runAll();
        assertEquals(now + 121_000, c.status().nextAttemptMillis);
    }

    @Test
    public void coordinator_securityAndRestoreStates_areNotRetriedAutomatically() throws Exception {
        FakeRemoteStore remote = new FakeRemoteStore();
        Dev d = new Dev(remote);
        d.text("x");
        d.engine.sync();
        // a newer-epoch bundle: needs restore
        remote.inject("b.9", VaultBundle.create(VaultCrypto.randomBytes(32), d.keys.getVaultId(), 9, RecoveryKey.generate()));
        Queue q = new Queue();
        SyncCoordinator c = coordinator(d, q, new ArrayList<SyncCoordinator.Status>());
        c.requestSync(false);
        q.runAll();
        assertEquals(SyncCoordinator.State.NEEDS_RESTORE, c.status().state);
        assertFalse(c.requestSync(true));
        c.clearBlockingState();
        assertEquals(SyncCoordinator.State.IDLE, c.status().state);
        // a forged bundle: security error
        byte[] forged = d.keys.currentBundle();
        forged[forged.length - 1] ^= 1;
        remote.inject("b.12", forged);
        c.requestSync(false);
        q.runAll();
        assertEquals(SyncCoordinator.State.SECURITY_ERROR, c.status().state);
        assertEquals(VaultCryptoException.Reason.CORRUPTED, c.status().error);
        assertFalse(c.requestSync(true));
    }

    @Test
    public void coordinator_lockedVault_reportsLocked() throws Exception {
        Dev d = new Dev(new FakeRemoteStore());
        d.keys.lock();
        Queue q = new Queue();
        SyncCoordinator c = coordinator(d, q, new ArrayList<SyncCoordinator.Status>());
        c.requestSync(false);
        q.runAll();
        assertEquals(SyncCoordinator.State.LOCKED, c.status().state);
        d.keys.unlock(PW.toCharArray());
        c.clearBlockingState();
        assertTrue(c.requestSync(false));
        q.runAll();
        assertEquals(SyncCoordinator.State.IDLE, c.status().state);
    }
}
