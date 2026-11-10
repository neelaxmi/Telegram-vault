package org.telegram.messenger.vault;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;

public class AutoLockTest {

    private static final String PW = "auto lock password";
    private VaultKeyManager keys;
    private AutoLock lock;
    private long now = 100_000;
    private int lockedCallbacks;

    @Before
    public void setUp() throws Exception {
        keys = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), 1000);
        keys.createVault(PW.toCharArray(), PW.toCharArray());
        lock = new AutoLock(keys, () -> lockedCallbacks++, () -> now);
        lock.onUnlocked();
    }

    @Test
    public void backgroundLocksImmediatelyByDefault() {
        lock.onBackground();
        assertFalse(keys.isUnlocked());
        assertEquals(1, lockedCallbacks);
    }

    @Test
    public void backgroundDoesNotLock_whenDisabled_butInactivityStillCounts() {
        lock.setLockOnBackground(false);
        lock.setInactivityMillis(60_000);
        lock.onBackground();
        assertTrue(keys.isUnlocked());
        now += 59_000;
        lock.onForeground();
        assertTrue(keys.isUnlocked());
        // away for longer than the limit
        lock.onBackground();
        now += 61_000;
        lock.onForeground();
        assertFalse(keys.isUnlocked());
    }

    @Test
    public void inactivityLocksAtTheLimit_activityPostpones() {
        lock.setInactivityMillis(30_000);
        now += 29_999;
        assertFalse(lock.tick());
        lock.userActivity();
        now += 29_999;
        assertFalse(lock.tick());
        now += 1;
        assertTrue(lock.tick());
        assertFalse(keys.isUnlocked());
    }

    @Test
    public void activityWhileBackgroundedDoesNotExtendTheTimer() {
        lock.setLockOnBackground(false);
        lock.setInactivityMillis(30_000);
        lock.onBackground();
        now += 20_000;
        lock.userActivity(); // e.g. a stray event from a background service
        now += 15_000;
        assertTrue(lock.tick());
    }

    @Test
    public void clockGoingBackwards_locks() {
        now -= 5;
        assertTrue(lock.tick());
        assertFalse(keys.isUnlocked());
    }

    @Test
    public void callbackRunsOncePerLock_notWhenAlreadyLocked() {
        lock.lockNow();
        lock.lockNow();
        lock.onBackground();
        assertEquals(1, lockedCallbacks);
    }

    @Test
    public void manualLock() {
        lock.lockNow();
        assertFalse(keys.isUnlocked());
        assertEquals(-1, lock.millisUntilLock());
    }

    @Test
    public void millisUntilLock_countsDown() {
        lock.setInactivityMillis(60_000);
        now += 10_000;
        assertEquals(50_000, lock.millisUntilLock());
        now += 100_000;
        assertEquals(0, lock.millisUntilLock());
    }

    @Test
    public void timeoutBounds_areEnforced() {
        for (long bad : new long[]{0, 9_999, AutoLock.MAX_INACTIVITY_MILLIS + 1, -1}) {
            try {
                lock.setInactivityMillis(bad);
                fail("accepted " + bad);
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        lock.setInactivityMillis(AutoLock.MIN_INACTIVITY_MILLIS);
        lock.setInactivityMillis(AutoLock.MAX_INACTIVITY_MILLIS);
    }

    @Test
    public void relockAfterUnlock_startsFreshTimer() throws Exception {
        lock.setInactivityMillis(30_000);
        now += 40_000;
        assertTrue(lock.tick());
        keys.unlock(PW.toCharArray());
        lock.onUnlocked();
        assertFalse(lock.tick());
        assertEquals(30_000, lock.millisUntilLock());
    }

    @Test
    public void keysAreDiscarded_notJustFlagged() throws Exception {
        lock.lockNow();
        try {
            keys.deriveSubkey("messages");
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
    }
}
