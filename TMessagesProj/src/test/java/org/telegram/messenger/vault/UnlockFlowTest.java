package org.telegram.messenger.vault;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The password wall at the model level: what the UI can and cannot reach while the Vault is locked, unlock with the
 * right and wrong password, lock on background, restart, and the sealed inbox through the whole cycle.
 * (Blur and layout themselves are Android views and need a device; what must hold underneath is tested here.)
 */
public class UnlockFlowTest {

    private static final String PW = "abc123"; // six characters: the minimum

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private InMemoryHeaderStore headers;
    private InMemoryHeaderStore attempts;
    private TestDeviceKeyWrapper device;
    private VaultKeyManager keys;
    private VaultStore store;
    private VaultInbox inbox;
    private VaultAccess access;
    private AutoLock autoLock;
    private final AtomicInteger lockedCallbacks = new AtomicInteger();
    private long now = 1_000_000;

    @Before
    public void setUp() throws Exception {
        headers = new InMemoryHeaderStore();
        attempts = new InMemoryHeaderStore();
        device = new TestDeviceKeyWrapper();
        keys = new VaultKeyManager(headers, device, 1000);
        keys.createVault(PW.toCharArray(), PW.toCharArray());
        store = new VaultStore(new File(tmp.getRoot(), "data"), keys);
        inbox = new VaultInbox(new File(tmp.getRoot(), "inbox"), device);
        access = new VaultAccess(keys, attempts, device, VaultAccess.localWipe(keys, store, inbox), () -> now);
        autoLock = new AutoLock(keys, lockedCallbacks::incrementAndGet, () -> now);
        inbox.ensureKeyPair(keys);
        store.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("private note").originalDateMillis(1L), null, null);
    }

    private static void assertLockedError(VaultCryptoException e) {
        assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
    }

    // ------------------------------------------------------------ 1 + 2: correct and wrong password

    @Test
    public void correctPassword_unlocks_andTheItemsBecomeReadable() throws Exception {
        keys.lock();
        access.unlock(PW.toCharArray());
        assertTrue(keys.isUnlocked());
        VaultListModel model = new VaultListModel(store);
        model.refresh();
        assertEquals(1, model.rows().size());
        assertEquals("private note", model.rows().get(0).title);
    }

    @Test
    public void wrongPassword_isRejected_andNothingBecomesReadable() throws Exception {
        keys.lock();
        try {
            access.unlock("abc124".toCharArray());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.WRONG_PASSWORD, e.getReason());
        }
        assertFalse(keys.isUnlocked());
        try {
            new VaultListModel(store).refresh();
            fail("a failed unlock must not expose items");
        } catch (VaultCryptoException e) {
            assertLockedError(e);
        }
    }

    @Test
    public void shortAndEmptyPasswords_neverUnlock() throws Exception {
        keys.lock();
        for (String bad : new String[]{"", "a", "abc12"}) {
            try {
                access.unlock(bad.toCharArray());
                fail("unlocked with " + bad);
            } catch (VaultCryptoException e) {
                assertTrue(e.getReason() == VaultCryptoException.Reason.WRONG_PASSWORD
                        || e.getReason() == VaultCryptoException.Reason.INVALID_ARGUMENT);
            }
            assertFalse(keys.isUnlocked());
        }
    }

    // ------------------------------------------------------------ 9: nothing sensitive reachable while locked

    @Test
    public void whileLocked_noContentIsReachable_anywhere() throws Exception {
        String id = store.localIds().get(0);
        keys.lock();
        try {
            new VaultListModel(store).refresh();
            fail();
        } catch (VaultCryptoException e) {
            assertLockedError(e);
        }
        try {
            store.get(id);
            fail();
        } catch (VaultCryptoException e) {
            assertLockedError(e);
        }
        try {
            store.search("note");
            fail();
        } catch (VaultCryptoException e) {
            assertLockedError(e);
        }
        try {
            keys.deriveSubkey("messages");
            fail();
        } catch (VaultCryptoException e) {
            assertLockedError(e);
        }
        inbox.put(new VaultItem.Draft(VaultItem.Type.TEXT).text("pending"), null, 100);
        try {
            inbox.drain(keys, store); // opening waiting items needs the private key, which needs the VMK
            fail();
        } catch (VaultCryptoException e) {
            assertLockedError(e);
        }
    }

    // ------------------------------------------------------------ 3: background / foreground

    @Test
    public void background_locksImmediately_foregroundDoesNotUnlock_passwordNeededAgain() throws Exception {
        assertTrue(keys.isUnlocked());
        autoLock.onBackground();
        assertFalse(keys.isUnlocked());
        assertEquals("the UI is told to show the wall", 1, lockedCallbacks.get());
        autoLock.onForeground();
        assertFalse("coming back must not unlock", keys.isUnlocked());
        access.unlock(PW.toCharArray());
        autoLock.onUnlocked();
        assertTrue(keys.isUnlocked());
        VaultListModel again = new VaultListModel(store);
        again.refresh();
        assertEquals(1, again.rows().size());
    }

    @Test
    public void inactivityTimeout_locksAgain() throws Exception {
        autoLock.setLockOnBackground(false);
        autoLock.setInactivityMillis(AutoLock.MIN_INACTIVITY_MILLIS);
        autoLock.onUnlocked();
        now += AutoLock.MIN_INACTIVITY_MILLIS + 1;
        assertTrue(autoLock.tick());
        assertFalse(keys.isUnlocked());
    }

    // ------------------------------------------------------------ 4 + 5 + 6 + 7: saving while locked, viewing after

    @Test
    public void savedWhileLocked_isInvisibleUntilAuthentication_thenShown() throws Exception {
        keys.lock();
        inbox.put(new VaultItem.Draft(VaultItem.Type.TEXT).text("saved while locked").originalDateMillis(2L), null, 1 << 20);
        inbox.put(new VaultItem.Draft(VaultItem.Type.PHOTO).text("pic").media("a.jpg", "image/jpeg", 10, 10, 0),
                new ByteArrayInputStream(new byte[]{1, 2, 3, 4, 5}), 1 << 20);
        inbox.put(new VaultItem.Draft(VaultItem.Type.DOCUMENT).media("b.pdf", "application/pdf", 0, 0, 0),
                new ByteArrayInputStream(new byte[]{9, 9, 9}), 1 << 20);
        assertFalse("saving did not unlock", keys.isUnlocked());
        assertEquals(3, inbox.pendingCount());
        assertEquals("nothing in the store yet", 1, store.localIds().size());

        access.unlock(PW.toCharArray());
        assertEquals(3, inbox.drain(keys, store).moved);
        VaultListModel model = new VaultListModel(store);
        model.refresh();
        assertEquals(4, model.rows().size());
        StringBuilder titles = new StringBuilder();
        for (VaultListModel.Row r : model.rows()) {
            titles.append(r.title).append('|');
        }
        assertTrue(titles.toString().contains("saved while locked"));
        assertTrue(titles.toString().contains("pic"));
    }

    // ------------------------------------------------------------ 10: restart

    @Test
    public void afterRestart_passwordStillUnlocks_andInboxItemsArrive() throws Exception {
        keys.lock();
        inbox.put(new VaultItem.Draft(VaultItem.Type.TEXT).text("before restart"), null, 100);
        // new process: everything rebuilt from the files and the same device key
        VaultKeyManager keys2 = new VaultKeyManager(headers, device, 1000);
        VaultStore store2 = new VaultStore(new File(tmp.getRoot(), "data"), keys2);
        VaultInbox inbox2 = new VaultInbox(new File(tmp.getRoot(), "inbox"), device);
        VaultAccess access2 = new VaultAccess(keys2, attempts, device, VaultAccess.localWipe(keys2, store2, inbox2), () -> now);
        assertTrue(keys2.isInitialized());
        assertFalse(keys2.isUnlocked());
        access2.unlock(PW.toCharArray());
        inbox2.ensureKeyPair(keys2);
        assertEquals(1, inbox2.drain(keys2, store2).moved);
        VaultListModel model = new VaultListModel(store2);
        model.refresh();
        assertEquals(2, model.rows().size());
    }

    // ------------------------------------------------------------ wipe covers the inbox

    @Test
    public void fiveWrongPasswords_wipeThisDevice_includingWaitingInboxItems() throws Exception {
        access.setWipeEnabled(true);
        keys.lock();
        inbox.put(new VaultItem.Draft(VaultItem.Type.TEXT).text("waiting"), null, 100);
        VaultCryptoException last = null;
        for (int i = 0; i < AttemptTracker.WIPE_LIMIT; i++) {
            try {
                access.unlock("wrong1".toCharArray());
                fail();
            } catch (VaultCryptoException e) {
                last = e;
            }
        }
        assertEquals(VaultCryptoException.Reason.VAULT_WIPED, last.getReason());
        assertEquals(0, inbox.pendingCount());
        assertFalse(inbox.canAccept());
        assertEquals(0, store.localIds().size());
    }
}
