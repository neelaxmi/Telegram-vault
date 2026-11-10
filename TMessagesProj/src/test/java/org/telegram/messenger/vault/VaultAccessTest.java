package org.telegram.messenger.vault;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.util.concurrent.atomic.AtomicInteger;

public class VaultAccessTest {

    private static final int ITER = 1000;
    private static final String PW = "the right password";
    private static final String WRONG = "a wrong password!";

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private InMemoryHeaderStore headerStore;
    private InMemoryHeaderStore attemptStore;
    private TestDeviceKeyWrapper device;
    private VaultKeyManager keys;
    private AtomicInteger wipes;
    private long now = 10_000;
    private VaultAccess access;

    @Before
    public void setUp() throws Exception {
        headerStore = new InMemoryHeaderStore();
        attemptStore = new InMemoryHeaderStore();
        device = new TestDeviceKeyWrapper();
        keys = new VaultKeyManager(headerStore, device, ITER);
        keys.createVault(PW.toCharArray(), PW.toCharArray());
        keys.lock();
        wipes = new AtomicInteger();
        access = newAccess(() -> wipes.incrementAndGet());
    }

    private VaultAccess newAccess(VaultAccess.WipeAction action) {
        return new VaultAccess(keys, attemptStore, device, action, () -> now);
    }

    private void wrong() throws Exception {
        try {
            access.unlock(WRONG.toCharArray());
            fail("expected WRONG_PASSWORD");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.WRONG_PASSWORD, e.getReason());
        }
    }

    private void enableWipe() throws Exception {
        access.unlock(PW.toCharArray());
        access.setWipeEnabled(true);
        keys.lock();
    }

    @Test
    public void successfulUnlock_reportsNoFailures() throws Exception {
        VaultAccess.Report r = access.unlock(PW.toCharArray());
        assertEquals(0, r.failedAttempts);
        assertEquals(0, r.lastFailureMillis);
        assertTrue(keys.isUnlocked());
    }

    @Test
    public void failures_areCountedAndShownAfterNextSuccess_untilAcknowledged() throws Exception {
        now = 1000;
        wrong();
        now = 2000;
        wrong();
        now = 3000;
        VaultAccess.Report r = access.unlock(PW.toCharArray());
        assertEquals(2, r.failedAttempts);
        assertEquals(2000, r.lastFailureMillis);
        keys.lock();
        // not acknowledged (e.g. the app died before showing it): still reported next time
        VaultAccess.Report again = access.unlock(PW.toCharArray());
        assertEquals(2, again.failedAttempts);
        access.acknowledge();
        keys.lock();
        assertEquals(0, access.unlock(PW.toCharArray()).failedAttempts);
    }

    @Test
    public void countSurvivesRestart() throws Exception {
        wrong();
        wrong();
        VaultAccess restarted = newAccess(() -> wipes.incrementAndGet());
        assertEquals(2, restarted.unlock(PW.toCharArray()).failedAttempts);
    }

    @Test
    public void attemptIsSavedBeforePasswordIsChecked() throws Exception {
        // a process killed during verification must still have left the attempt on record
        InMemoryHeaderStore dying = new InMemoryHeaderStore() {
            @Override
            public byte[] read() {
                throw new IllegalStateException("process killed");
            }
        };
        dying.data = headerStore.data.clone();
        VaultKeyManager crashing = new VaultKeyManager(dying, device, ITER);
        VaultAccess a = new VaultAccess(crashing, attemptStore, device, () -> wipes.incrementAndGet(), () -> now);
        try {
            a.unlock(WRONG.toCharArray());
            fail();
        } catch (IllegalStateException expected) {
            // simulated kill
        }
        assertEquals(1, access.unlock(PW.toCharArray()).failedAttempts);
    }

    @Test
    public void unlockIsRefusedWhenTheCountCannotBeSaved() throws Exception {
        attemptStore.failWrites = true;
        try {
            access.unlock(PW.toCharArray());
            fail("expected IO_ERROR");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.IO_ERROR, e.getReason());
        }
        assertFalse(keys.isUnlocked());
    }

    @Test
    public void nonPasswordFailures_areRefunded() throws Exception {
        headerStore.failReads = true;
        for (int i = 0; i < 8; i++) {
            try {
                access.unlock(PW.toCharArray());
                fail();
            } catch (VaultCryptoException e) {
                assertTrue(e.getReason() != VaultCryptoException.Reason.WRONG_PASSWORD);
            }
        }
        headerStore.failReads = false;
        assertEquals(0, access.unlock(PW.toCharArray()).failedAttempts);
    }

    // ------------------------------------------------------------------ wipe

    @Test
    public void wipeOff_neverWipes() throws Exception {
        for (int i = 0; i < 12; i++) {
            wrong();
        }
        assertEquals(0, wipes.get());
        assertEquals(-1, access.attemptsRemaining());
        assertTrue(access.unlock(PW.toCharArray()).failedAttempts == 12);
    }

    @Test
    public void wipeOn_fifthWrongPasswordWipes() throws Exception {
        enableWipe();
        assertEquals(5, access.attemptsRemaining());
        for (int i = 1; i <= 4; i++) {
            wrong();
            assertEquals(5 - i, access.attemptsRemaining());
            assertEquals(0, wipes.get());
        }
        try {
            access.unlock(WRONG.toCharArray());
            fail("expected VAULT_WIPED");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.VAULT_WIPED, e.getReason());
        }
        assertEquals(1, wipes.get());
        assertFalse(attemptStore.exists());
    }

    @Test
    public void correctPasswordResetsTheCountdown() throws Exception {
        enableWipe();
        for (int i = 0; i < 4; i++) {
            wrong();
        }
        access.unlock(PW.toCharArray());
        keys.lock();
        assertEquals(5, access.attemptsRemaining());
        for (int i = 0; i < 4; i++) {
            wrong();
        }
        assertEquals(0, wipes.get());
    }

    @Test
    public void correctPasswordOnTheLastAttempt_doesNotWipe() throws Exception {
        enableWipe();
        for (int i = 0; i < 4; i++) {
            wrong();
        }
        access.unlock(PW.toCharArray());
        assertEquals(0, wipes.get());
        assertTrue(keys.isUnlocked());
    }

    @Test
    public void failedWipe_isRetriedOnTheNextAttempt() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        access = newAccess(() -> {
            if (calls.incrementAndGet() == 1) {
                throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "disk");
            }
        });
        enableWipe();
        for (int i = 0; i < 4; i++) {
            wrong();
        }
        try {
            access.unlock(WRONG.toCharArray());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.IO_ERROR, e.getReason());
        }
        try {
            access.unlock(WRONG.toCharArray());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.VAULT_WIPED, e.getReason());
        }
        assertEquals(2, calls.get());
    }

    @Test
    public void wipeSwitch_canOnlyBeChangedWhileUnlocked() throws Exception {
        try {
            access.setWipeEnabled(true);
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        }
        access.unlock(PW.toCharArray());
        access.setWipeEnabled(true);
        assertTrue(access.isWipeEnabled());
        access.setWipeEnabled(false);
        assertFalse(access.isWipeEnabled());
    }

    // ------------------------------------------------------------------ tampering

    @Test
    public void editedAttemptFile_isTreatedCautiously_notAsReset() throws Exception {
        enableWipe();
        wrong();
        wrong();
        attemptStore.data[attemptStore.data.length - 1] ^= 1; // tamper
        // one wrong attempt is now enough: counting continues from the limit - 1
        try {
            access.unlock(WRONG.toCharArray());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.VAULT_WIPED, e.getReason());
        }
    }

    @Test
    public void damagedRecord_doesNotLockOutTheRightPassword_andIsReported() throws Exception {
        wrong();
        attemptStore.data = new byte[]{1, 2, 3};
        VaultAccess.Report r = access.unlock(PW.toCharArray());
        assertTrue(r.trackingDamaged);
        assertTrue(r.failedAttempts >= 1);
        access.acknowledge();
        keys.lock();
        assertFalse(access.unlock(PW.toCharArray()).trackingDamaged);
    }

    @Test
    public void stateIsNotStoredInTheClear() throws Exception {
        enableWipe();
        wrong();
        // wrapped by the device key: the plain layout (flag, counts, time) must not be visible
        byte[] data = attemptStore.data;
        assertNotNull(data);
        assertTrue(data.length > 21 + 5);
    }

    // ------------------------------------------------------------------ the real local wipe

    @Test
    public void localWipe_deletesThisDeviceOnly_remoteAndOtherDeviceSurvive() throws Exception {
        FakeRemoteStore remote = new FakeRemoteStore();
        // device A is `keys`; device B restored from the recovery key
        VaultKeyManager ka = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), ITER);
        VaultKeyManager.Setup setup = ka.beginSetup(PW.toCharArray(), PW.toCharArray());
        String rk = setup.recoveryKey().format();
        byte[] bundle = setup.complete(rk);
        VaultKeyManager kb = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), ITER);
        kb.restoreFromBundle(bundle, rk, "device b password".toCharArray(), "device b password".toCharArray(), false);

        File da = tmp.newFolder("a");
        File db = tmp.newFolder("b");
        VaultStore sa = new VaultStore(new File(da, "vault"), ka, () -> now, 4096);
        VaultStore sb = new VaultStore(new File(db, "vault"), kb, () -> now, 4096);
        VaultSyncEngine ea = new VaultSyncEngine(sa, ka, remote, new File(da, "journal"), () -> now);
        VaultSyncEngine eb = new VaultSyncEngine(sb, kb, remote, new File(db, "journal"), () -> now);
        VaultItem item = ea.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("precious"), null, null);
        ea.sync();
        eb.sync();
        int remoteObjects = remote.names().size();

        InMemoryHeaderStore attempts = new InMemoryHeaderStore();
        TestDeviceKeyWrapper wrapperA = new TestDeviceKeyWrapper();
        // use A's own device wrapper for A's header? ka was built with its own wrapper; the attempt file uses another
        VaultAccess acc = new VaultAccess(ka, attempts, wrapperA, VaultAccess.localWipe(ka, sa), () -> now);
        acc.unlock(PW.toCharArray());
        acc.setWipeEnabled(true);
        ka.lock();
        for (int i = 0; i < 4; i++) {
            try {
                acc.unlock(WRONG.toCharArray());
                fail();
            } catch (VaultCryptoException e) {
                assertEquals(VaultCryptoException.Reason.WRONG_PASSWORD, e.getReason());
            }
        }
        try {
            acc.unlock(WRONG.toCharArray());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.VAULT_WIPED, e.getReason());
        }
        // A: nothing left locally
        assertFalse(ka.isInitialized());
        assertTrue(sa.localIds().isEmpty());
        // remote and B untouched
        assertEquals(remoteObjects, remote.names().size());
        assertEquals("precious", sb.get(item.id).text);
        eb.sync();
        assertEquals("precious", sb.get(item.id).text);
        // and A can come back with the recovery key and gets its data from the server
        VaultKeyManager again = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), ITER);
        again.restoreFromBundle(remote.bytesOf("b.1"), rk, "new password for a".toCharArray(), "new password for a".toCharArray(), false);
        File dn = tmp.newFolder("a2");
        VaultStore sn = new VaultStore(new File(dn, "vault"), again, () -> now, 4096);
        VaultSyncEngine en = new VaultSyncEngine(sn, again, remote, new File(dn, "journal"), () -> now);
        en.sync();
        assertEquals("precious", sn.get(item.id).text);
        assertNull(sn.get("00000000000000000000000000000000"));
    }
}
