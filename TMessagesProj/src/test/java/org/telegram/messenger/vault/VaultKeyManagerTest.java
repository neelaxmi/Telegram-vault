package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class VaultKeyManagerTest {

    private static final int TEST_ITERATIONS = 1000;
    private static final String PASSWORD = "correct horse battery staple";

    private InMemoryHeaderStore store;
    private TestDeviceKeyWrapper device;
    private VaultKeyManager manager;

    @Before
    public void setUp() {
        store = new InMemoryHeaderStore();
        device = new TestDeviceKeyWrapper();
        manager = new VaultKeyManager(store, device, TEST_ITERATIONS);
    }

    private static String rep(String s, int times) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < times; i++) {
            sb.append(s);
        }
        return sb.toString();
    }

    private static char[] pw(String s) {
        return s.toCharArray();
    }

    private void create() throws VaultCryptoException {
        manager.createVault(pw(PASSWORD), pw(PASSWORD));
    }

    private static void assertReason(VaultCryptoException.Reason expected, VaultCryptoExceptionRunnable r) {
        try {
            r.run();
            fail("Expected VaultCryptoException(" + expected + ")");
        } catch (VaultCryptoException e) {
            assertEquals(expected, e.getReason());
        }
    }

    private interface VaultCryptoExceptionRunnable {
        void run() throws VaultCryptoException;
    }

    // ------------------------------------------------------------ initial state / create

    @Test
    public void newManager_isNotInitializedAndLocked() {
        assertFalse(manager.isInitialized());
        assertFalse(manager.isUnlocked());
    }

    @Test
    public void unlockWithoutVault_isInvalidState() {
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.unlock(pw(PASSWORD)));
        assertFalse(manager.isUnlocked());
    }

    @Test
    public void create_succeeds_storesHeader_andLeavesVaultUnlocked() throws Exception {
        create();
        assertTrue(manager.isInitialized());
        assertTrue(manager.isUnlocked());
        assertNotNull(store.data);
    }

    @Test
    public void create_rejectsShortPassword() {
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> manager.createVault(pw("short"), pw("short")));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> manager.createVault(pw(""), pw("")));
        assertFalse(manager.isInitialized());
        assertFalse(manager.isUnlocked());
    }

    @Test
    public void create_lengthIsCountedInCharactersNotUtf16Units() throws Exception {
        // 11 emoji = 22 UTF-16 units but only 11 characters: must be rejected.
        String sevenEmoji = rep(new String(Character.toChars(0x1F600)), 11);
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> manager.createVault(pw(sevenEmoji), pw(sevenEmoji)));
        String eightEmoji = rep(new String(Character.toChars(0x1F600)), 12);
        manager.createVault(pw(eightEmoji), pw(eightEmoji));
        assertTrue(manager.isUnlocked());
    }

    @Test
    public void create_rejectsTooLongPassword() {
        String tooLong = rep("a", VaultKeyManager.MAX_PASSWORD_LENGTH + 1);
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> manager.createVault(pw(tooLong), pw(tooLong)));
        assertFalse(manager.isInitialized());
    }

    @Test
    public void create_acceptsPasswordOfExactlyMaximumLength() throws Exception {
        String max = rep("a", VaultKeyManager.MAX_PASSWORD_LENGTH);
        manager.createVault(pw(max), pw(max));
        manager.lock();
        manager.unlock(pw(max));
        assertTrue(manager.isUnlocked());
    }

    @Test
    public void create_rejectsMismatchedConfirmation() {
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> manager.createVault(pw(PASSWORD), pw(PASSWORD + "x")));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> manager.createVault(pw(PASSWORD), pw(PASSWORD.toUpperCase())));
        assertFalse(manager.isInitialized());
        assertFalse(manager.isUnlocked());
    }

    @Test
    public void create_rejectsNulls() {
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> manager.createVault(null, pw(PASSWORD)));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> manager.createVault(pw(PASSWORD), null));
    }

    @Test
    public void create_twice_isInvalidState_andDoesNotOverwriteExistingVault() throws Exception {
        create();
        byte[] before = store.data.clone();
        assertReason(VaultCryptoException.Reason.INVALID_STATE,
                () -> manager.createVault(pw("another password"), pw("another password")));
        assertArrayEquals(before, store.data);
    }

    @Test
    public void create_doesNotModifyCallersPasswordArrays() throws Exception {
        char[] password = pw(PASSWORD);
        char[] confirmation = pw(PASSWORD);
        manager.createVault(password, confirmation);
        assertArrayEquals(pw(PASSWORD), password);
        assertArrayEquals(pw(PASSWORD), confirmation);
    }

    @Test
    public void create_storageFailure_leavesNothingBehindAndStaysLocked() throws Exception {
        store.failWrites = true;
        assertReason(VaultCryptoException.Reason.IO_ERROR, () -> create());
        assertFalse(manager.isInitialized());
        assertFalse(manager.isUnlocked());

        store.failWrites = false;
        create(); // can retry afterwards
        assertTrue(manager.isUnlocked());
    }

    @Test
    public void create_deviceKeyFailure_leavesNothingBehind() {
        device.keyAvailable = false;
        assertReason(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> create());
        assertFalse(manager.isInitialized());
        assertFalse(manager.isUnlocked());
    }

    // ------------------------------------------------------------ nothing sensitive stored

    @Test
    public void storedHeader_hasNoPlaintextPasswordOrKeys() throws Exception {
        create();
        byte[] messagesKey = manager.deriveSubkey("messages");
        byte[] header = store.data;
        assertEquals(-1, VaultCryptoTest.indexOf(header, PASSWORD.getBytes(StandardCharsets.UTF_8)));
        assertEquals(-1, VaultCryptoTest.indexOf(header, messagesKey));
        assertEquals(-1, VaultCryptoTest.indexOf(header, "TGVH".getBytes(StandardCharsets.US_ASCII)));
        assertEquals(-1, VaultCryptoTest.indexOf(header, readDataKey(manager)));
    }

    @Test
    public void headerWithoutDeviceLayer_hasNoPlaintextPasswordOrDataKey() throws Exception {
        // Same check on the inner header, which is what an attacker with the device key would see.
        VaultKeyManager bare = new VaultKeyManager(store, new PassThroughWrapper(), TEST_ITERATIONS);
        bare.createVault(pw(PASSWORD), pw(PASSWORD));
        byte[] inner = store.data;
        assertEquals(VaultKeyManager.HEADER_VERSION, inner[4]);
        assertTrue(inner.length > VaultKeyManager.LEGACY_INNER_HEADER_LENGTH);
        assertEquals("TGVH", new String(inner, 0, 4, StandardCharsets.US_ASCII));
        assertEquals(-1, VaultCryptoTest.indexOf(inner, PASSWORD.getBytes(StandardCharsets.UTF_8)));
        assertEquals(-1, VaultCryptoTest.indexOf(inner, readDataKey(bare)));
    }

    // ------------------------------------------------------------ unlock / lock

    @Test
    public void lockThenUnlock_withCorrectPassword_works_andKeysAreStable() throws Exception {
        create();
        byte[] messagesBefore = manager.deriveSubkey("messages");
        byte[] mediaBefore = manager.deriveSubkey("media");

        manager.lock();
        assertFalse(manager.isUnlocked());
        manager.unlock(pw(PASSWORD));
        assertTrue(manager.isUnlocked());

        assertArrayEquals(messagesBefore, manager.deriveSubkey("messages"));
        assertArrayEquals(mediaBefore, manager.deriveSubkey("media"));
        assertFalse(Arrays.equals(messagesBefore, mediaBefore));
    }

    @Test
    public void unlock_afterAppRestart_usingNewManagerInstance() throws Exception {
        create();
        byte[] key = manager.deriveSubkey("messages");

        VaultKeyManager restarted = new VaultKeyManager(store, device, TEST_ITERATIONS);
        assertTrue(restarted.isInitialized());
        assertFalse(restarted.isUnlocked());
        restarted.unlock(pw(PASSWORD));
        assertArrayEquals(key, restarted.deriveSubkey("messages"));
    }

    @Test
    public void unlock_wrongPassword_isRejected_andVaultStaysLocked() throws Exception {
        create();
        manager.lock();
        assertReason(VaultCryptoException.Reason.WRONG_PASSWORD, () -> manager.unlock(pw("wrong password!")));
        assertFalse(manager.isUnlocked());
    }

    @Test
    public void unlock_isCaseSensitiveAndExact() throws Exception {
        create();
        manager.lock();
        for (String bad : new String[]{PASSWORD.toUpperCase(), PASSWORD + " ", " " + PASSWORD,
                PASSWORD.substring(1), PASSWORD.substring(0, PASSWORD.length() - 1)}) {
            assertReason(VaultCryptoException.Reason.WRONG_PASSWORD, () -> manager.unlock(pw(bad)));
        }
        assertFalse(manager.isUnlocked());
    }

    @Test
    public void unlock_emptyNullAndHugePasswords_areWrongPassword() throws Exception {
        create();
        manager.lock();
        assertReason(VaultCryptoException.Reason.WRONG_PASSWORD, () -> manager.unlock(null));
        assertReason(VaultCryptoException.Reason.WRONG_PASSWORD, () -> manager.unlock(new char[0]));
        char[] huge = new char[1_000_000];
        Arrays.fill(huge, 'a');
        assertReason(VaultCryptoException.Reason.WRONG_PASSWORD, () -> manager.unlock(huge));
        assertFalse(manager.isUnlocked());
    }

    @Test
    public void unlock_afterWrongAttempts_correctPasswordStillWorks() throws Exception {
        // This layer never locks the user out; attempt limiting is a separate component.
        create();
        manager.lock();
        for (int i = 0; i < 10; i++) {
            assertReason(VaultCryptoException.Reason.WRONG_PASSWORD, () -> manager.unlock(pw("not the password")));
        }
        manager.unlock(pw(PASSWORD));
        assertTrue(manager.isUnlocked());
    }

    @Test
    public void unlock_wrongPasswordWhileUnlocked_doesNotLockButAlsoDoesNotThrowAway() throws Exception {
        create();
        byte[] key = manager.deriveSubkey("messages");
        assertReason(VaultCryptoException.Reason.WRONG_PASSWORD, () -> manager.unlock(pw("not the password")));
        assertTrue(manager.isUnlocked());
        assertArrayEquals(key, manager.deriveSubkey("messages"));
    }

    @Test
    public void unlock_unicodePassword_andNormalisationEquivalence() throws Exception {
        String composed = "café 日本語 pass";
        String decomposed = "café 日本語 pass";
        manager.createVault(pw(composed), pw(composed));
        manager.lock();
        manager.unlock(pw(decomposed));
        assertTrue(manager.isUnlocked());
    }

    @Test
    public void unlock_doesNotModifyCallersPassword() throws Exception {
        create();
        manager.lock();
        char[] password = pw(PASSWORD);
        manager.unlock(password);
        assertArrayEquals(pw(PASSWORD), password);
    }

    @Test
    public void lock_isIdempotent() throws Exception {
        manager.lock();
        create();
        manager.lock();
        manager.lock();
        assertFalse(manager.isUnlocked());
    }

    @Test
    public void lock_zeroesTheDataKeyInMemory() throws Exception {
        create();
        byte[] internal = readDataKey(manager);
        assertFalse(isAllZero(internal));
        manager.lock();
        assertTrue("data key array must be wiped on lock", isAllZero(internal));
    }

    @Test
    public void unlockOverUnlocked_wipesPreviousKeyArray() throws Exception {
        create();
        byte[] first = readDataKey(manager);
        manager.unlock(pw(PASSWORD));
        assertTrue(isAllZero(first));
        assertFalse(isAllZero(readDataKey(manager)));
    }

    // ------------------------------------------------------------ subkeys

    @Test
    public void deriveSubkey_whileLocked_isInvalidState() throws Exception {
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.deriveSubkey("messages"));
        create();
        manager.lock();
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.deriveSubkey("messages"));
    }

    @Test
    public void deriveSubkey_returnsIndependentCopies() throws Exception {
        create();
        byte[] a = manager.deriveSubkey("messages");
        Arrays.fill(a, (byte) 0);
        assertFalse("caller wiping its copy must not affect the manager", isAllZero(manager.deriveSubkey("messages")));
    }

    @Test
    public void differentVaults_haveDifferentKeys() throws Exception {
        create();
        byte[] first = manager.deriveSubkey("messages");

        InMemoryHeaderStore otherStore = new InMemoryHeaderStore();
        VaultKeyManager other = new VaultKeyManager(otherStore, new TestDeviceKeyWrapper(), TEST_ITERATIONS);
        other.createVault(pw(PASSWORD), pw(PASSWORD)); // same password
        assertFalse(Arrays.equals(first, other.deriveSubkey("messages")));
    }

    @Test
    public void sameVaultAndPassword_headersDifferBetweenCreations() throws Exception {
        VaultKeyManager a = new VaultKeyManager(store, new PassThroughWrapper(), TEST_ITERATIONS);
        a.createVault(pw(PASSWORD), pw(PASSWORD));
        byte[] headerA = store.data.clone();

        InMemoryHeaderStore store2 = new InMemoryHeaderStore();
        VaultKeyManager b = new VaultKeyManager(store2, new PassThroughWrapper(), TEST_ITERATIONS);
        b.createVault(pw(PASSWORD), pw(PASSWORD));
        // Different random salt, so the salt portion (and everything after) must differ.
        byte[] saltA = Arrays.copyOfRange(headerA, 9, 25);
        byte[] saltB = Arrays.copyOfRange(store2.data, 9, 25);
        assertFalse(Arrays.equals(saltA, saltB));
    }

    // ------------------------------------------------------------ tampering and failures

    @Test
    public void tamperingWithAnyByteOfStoredHeader_isDetected_andNeverUnlocks() throws Exception {
        create();
        manager.lock();
        byte[] original = store.data.clone();
        for (int i = 0; i < original.length; i++) {
            byte[] tampered = original.clone();
            tampered[i] ^= 0x01;
            store.data = tampered;
            try {
                manager.unlock(pw(PASSWORD));
                fail("tampered header byte " + i + " was accepted");
            } catch (VaultCryptoException e) {
                assertEquals("byte " + i, VaultCryptoException.Reason.CORRUPTED, e.getReason());
            }
            assertFalse(manager.isUnlocked());
        }
        store.data = original;
        manager.unlock(pw(PASSWORD)); // untouched header still works
        assertTrue(manager.isUnlocked());
    }

    @Test
    public void innerHeaderTampering_withoutDeviceLayer_isStillCaughtByAeadBinding() throws Exception {
        // Simulates an attacker who can strip the device layer. Changing salt, iterations or the
        // wrapped key must still fail, because they are authenticated via the GCM tag / AAD.
        VaultKeyManager bare = new VaultKeyManager(store, new PassThroughWrapper(), TEST_ITERATIONS);
        bare.createVault(pw(PASSWORD), pw(PASSWORD));
        bare.lock();
        byte[] original = store.data.clone();

        for (int i = 0; i < original.length; i++) {
            byte[] tampered = original.clone();
            tampered[i] ^= 0x01;
            store.data = tampered;
            try {
                bare.unlock(pw(PASSWORD));
                fail("tampered inner byte " + i + " was accepted");
            } catch (VaultCryptoException e) {
                VaultCryptoException.Reason r = e.getReason();
                assertTrue("byte " + i + " gave " + r,
                        r == VaultCryptoException.Reason.CORRUPTED || r == VaultCryptoException.Reason.WRONG_PASSWORD
                                || (i == 4 && r == VaultCryptoException.Reason.UNSUPPORTED_VERSION));
            }
            assertFalse(bare.isUnlocked());
        }
    }

    @Test
    public void truncatedOrEmptyOrOversizedHeader_isCorrupted() throws Exception {
        VaultKeyManager bare = new VaultKeyManager(store, new PassThroughWrapper(), TEST_ITERATIONS);
        bare.createVault(pw(PASSWORD), pw(PASSWORD));
        bare.lock();
        byte[] original = store.data.clone();

        for (byte[] bad : new byte[][]{
                Arrays.copyOf(original, original.length - 1),
                Arrays.copyOf(original, original.length + 1),
                Arrays.copyOf(original, 10),
                new byte[0],
                new byte[original.length]}) {
            store.data = bad.length == 0 ? new byte[]{0} : bad;
            assertReason(VaultCryptoException.Reason.CORRUPTED, () -> bare.unlock(pw(PASSWORD)));
        }
    }

    @Test
    public void headerClaimingAbsurdIterationCount_isRejectedWithoutRunningKdf() throws Exception {
        VaultKeyManager bare = new VaultKeyManager(store, new PassThroughWrapper(), TEST_ITERATIONS);
        bare.createVault(pw(PASSWORD), pw(PASSWORD));
        bare.lock();
        for (int bogus : new int[]{0, 1, 999, -1, Integer.MAX_VALUE, VaultCrypto.MAX_PBKDF2_ITERATIONS + 1}) {
            byte[] h = store.data.clone();
            h[5] = (byte) (bogus >>> 24);
            h[6] = (byte) (bogus >>> 16);
            h[7] = (byte) (bogus >>> 8);
            h[8] = (byte) bogus;
            store.data = h;
            long start = System.nanoTime();
            assertReason(VaultCryptoException.Reason.CORRUPTED, () -> bare.unlock(pw(PASSWORD)));
            assertTrue("rejection must be immediate", (System.nanoTime() - start) < 2_000_000_000L);
        }
    }

    @Test
    public void unlock_lostDeviceKey_reportsDeviceKeyUnavailable() throws Exception {
        create();
        manager.lock();
        device.keyAvailable = false;
        assertReason(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> manager.unlock(pw(PASSWORD)));
        assertFalse(manager.isUnlocked());
    }

    @Test
    public void unlock_storageReadFailure_isIoError() throws Exception {
        create();
        manager.lock();
        store.failReads = true;
        assertReason(VaultCryptoException.Reason.IO_ERROR, () -> manager.unlock(pw(PASSWORD)));
        assertFalse(manager.isUnlocked());
        store.failReads = false;
        manager.unlock(pw(PASSWORD));
        assertTrue(manager.isUnlocked());
    }

    @Test
    public void headerFromAnotherDevice_cannotBeOpened() throws Exception {
        create();
        manager.lock();
        // Same files, different device key: simulates copying vault data to another phone.
        VaultKeyManager otherDevice = new VaultKeyManager(store, new TestDeviceKeyWrapper(), TEST_ITERATIONS);
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> otherDevice.unlock(pw(PASSWORD)));
        assertFalse(otherDevice.isUnlocked());
    }

    // ------------------------------------------------------------ destroy

    @Test
    public void destroy_makesVaultPermanentlyUnrecoverable() throws Exception {
        create();
        byte[] oldKey = manager.deriveSubkey("messages");
        byte[] encrypted = VaultCrypto.encrypt(oldKey, "private note".getBytes(StandardCharsets.UTF_8), null);

        manager.destroy();
        assertFalse(manager.isUnlocked());
        assertFalse(manager.isInitialized());
        assertNull(store.data);
        assertEquals(1, device.deleteCalls);
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.unlock(pw(PASSWORD)));

        // A brand-new vault with the very same password gets unrelated keys, so old data stays unreadable.
        VaultKeyManager fresh = new VaultKeyManager(store, new TestDeviceKeyWrapper(), TEST_ITERATIONS);
        fresh.createVault(pw(PASSWORD), pw(PASSWORD));
        byte[] newKey = fresh.deriveSubkey("messages");
        assertFalse(Arrays.equals(oldKey, newKey));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultCrypto.decrypt(newKey, encrypted, null));
    }

    @Test
    public void destroy_zeroesKeyInMemory_andWorksWhenAlreadyLockedOrEmpty() throws Exception {
        create();
        byte[] internal = readDataKey(manager);
        manager.destroy();
        assertTrue(isAllZero(internal));
        manager.destroy(); // nothing left: must not throw
        assertFalse(manager.isInitialized());
    }

    @Test
    public void destroy_attemptsBothDeletions_evenIfOneFails() throws Exception {
        create();
        store.failDeletes = true;
        assertReason(VaultCryptoException.Reason.IO_ERROR, () -> manager.destroy());
        assertEquals("device key must still be deleted", 1, device.deleteCalls);
        assertFalse(manager.isUnlocked());

        store.failDeletes = false;
        device.failDelete = true;
        assertReason(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> manager.destroy());
        assertFalse("header must still be deleted", store.exists());
    }

    // ------------------------------------------------------------ construction

    @Test
    public void constructor_validatesArguments() {
        try {
            new VaultKeyManager(null, device);
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
        try {
            new VaultKeyManager(store, null);
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
        try {
            new VaultKeyManager(store, device, 10);
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }

    @Test
    public void productionConstructor_usesStrongIterationCount() throws Exception {
        VaultKeyManager production = new VaultKeyManager(new InMemoryHeaderStore(), new PassThroughWrapper());
        InMemoryHeaderStore s = new InMemoryHeaderStore();
        VaultKeyManager m = new VaultKeyManager(s, new PassThroughWrapper());
        m.createVault(pw(PASSWORD), pw(PASSWORD));
        int stored = ((s.data[5] & 0xFF) << 24) | ((s.data[6] & 0xFF) << 16) | ((s.data[7] & 0xFF) << 8) | (s.data[8] & 0xFF);
        assertEquals(VaultCrypto.DEFAULT_PBKDF2_ITERATIONS, stored);
        assertNotNull(production);
    }

    // ------------------------------------------------------------ concurrency

    @Test
    public void concurrentLockUnlockAndKeyDerivation_neverCorruptsState() throws Exception {
        create();
        final byte[] expected = manager.deriveSubkey("messages");
        final java.util.concurrent.atomic.AtomicReference<Throwable> failure = new java.util.concurrent.atomic.AtomicReference<>();
        Thread[] threads = new Thread[6];
        for (int t = 0; t < threads.length; t++) {
            final boolean locker = t % 2 == 0;
            threads[t] = new Thread(() -> {
                try {
                    for (int i = 0; i < 50; i++) {
                        if (locker) {
                            manager.lock();
                        } else {
                            manager.unlock(pw(PASSWORD));
                            try {
                                byte[] k = manager.deriveSubkey("messages");
                                if (!Arrays.equals(expected, k)) {
                                    throw new AssertionError("wrong key");
                                }
                            } catch (VaultCryptoException e) {
                                // another thread locked in between: only INVALID_STATE is acceptable
                                if (e.getReason() != VaultCryptoException.Reason.INVALID_STATE) {
                                    throw e;
                                }
                            }
                        }
                    }
                } catch (Throwable e) {
                    failure.compareAndSet(null, e);
                }
            });
            threads[t].start();
        }
        for (Thread t : threads) {
            t.join(60_000);
        }
        if (failure.get() != null) {
            throw new AssertionError("concurrency failure", failure.get());
        }
    }

    // ------------------------------------------------------------ helpers

    private static void assertNull(Object o) {
        org.junit.Assert.assertNull(o);
    }

    private static boolean isAllZero(byte[] b) {
        for (byte x : b) {
            if (x != 0) {
                return false;
            }
        }
        return true;
    }

    /** Reads the manager's private data key array by reflection so tests can verify wiping. */
    private static byte[] readDataKey(VaultKeyManager m) throws Exception {
        Field f = VaultKeyManager.class.getDeclaredField("vmk");
        f.setAccessible(true);
        byte[] key = (byte[]) f.get(m);
        assertNotNull("vault must be unlocked", key);
        return key;
    }

    /** Device layer that does nothing, to inspect and attack the inner header directly. */
    private static class PassThroughWrapper implements DeviceKeyWrapper {
        @Override
        public byte[] wrap(byte[] data) {
            return data.clone();
        }

        @Override
        public byte[] unwrap(byte[] wrapped) {
            return wrapped.clone();
        }

        @Override
        public void deleteKey() {
        }
    }
}
