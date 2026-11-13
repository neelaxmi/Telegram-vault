package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Architecture v2: two-step setup with recovery key, restore, password change, migration, bundle checks. */
public class VaultKeyManagerV2Test {

    private static final int ITER = 1000;
    private static final String PASSWORD = "correct horse battery staple";
    private static final String NEW_PASSWORD = "a completely different one";

    private InMemoryHeaderStore store;
    private TestDeviceKeyWrapper device;
    private VaultKeyManager manager;

    @Before
    public void setUp() {
        store = new InMemoryHeaderStore();
        device = new TestDeviceKeyWrapper();
        manager = new VaultKeyManager(store, device, ITER);
    }

    private static char[] pw(String s) {
        return s.toCharArray();
    }

    private interface Action {
        void run() throws Exception;
    }

    private static void assertReason(VaultCryptoException.Reason reason, Action a) {
        try {
            a.run();
            fail("expected " + reason);
        } catch (VaultCryptoException e) {
            assertEquals(reason, e.getReason());
        } catch (Exception e) {
            fail("unexpected " + e);
        }
    }

    private static boolean allZero(byte[] b) {
        for (byte x : b) {
            if (x != 0) {
                return false;
            }
        }
        return true;
    }

    /** Full setup; returns {recovery key text, bundle}. */
    private Object[] setUpVault(VaultKeyManager m) throws Exception {
        VaultKeyManager.Setup setup = m.beginSetup(pw(PASSWORD), pw(PASSWORD));
        String text = setup.recoveryKey().format();
        byte[] bundle = setup.complete(text);
        return new Object[]{text, bundle};
    }

    // ------------------------------------------------------------ two-step setup

    @Test
    public void beginSetup_writesNothingAndStaysLocked() throws Exception {
        VaultKeyManager.Setup setup = manager.beginSetup(pw(PASSWORD), pw(PASSWORD));
        assertNotNull(setup.recoveryKey());
        assertFalse(manager.isInitialized());
        assertFalse(manager.isUnlocked());
        assertNull(store.data);
    }

    @Test
    public void complete_withWrongKey_writesNothing_andAllowsRetry() throws Exception {
        VaultKeyManager.Setup setup = manager.beginSetup(pw(PASSWORD), pw(PASSWORD));
        String right = setup.recoveryKey().format();
        String wrong = RecoveryKey.generate().format();
        assertReason(VaultCryptoException.Reason.WRONG_RECOVERY_KEY, () -> setup.complete(wrong));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> setup.complete("not a key"));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> setup.complete(null));
        assertFalse(manager.isInitialized());
        assertNull(store.data);
        byte[] bundle = setup.complete(right);
        assertNotNull(bundle);
        assertTrue(manager.isUnlocked());
        assertTrue(manager.isInitialized());
    }

    @Test
    public void complete_acceptsTheKeyTypedSloppily() throws Exception {
        VaultKeyManager.Setup setup = manager.beginSetup(pw(PASSWORD), pw(PASSWORD));
        String sloppy = setup.recoveryKey().format().toLowerCase().replace("-", " ");
        assertNotNull(setup.complete(sloppy));
        assertTrue(manager.isUnlocked());
    }

    @Test
    public void setup_isSingleUse() throws Exception {
        VaultKeyManager.Setup setup = manager.beginSetup(pw(PASSWORD), pw(PASSWORD));
        String text = setup.recoveryKey().format();
        setup.complete(text);
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> setup.complete(text));
    }

    @Test
    public void cancel_writesNothing_andWipesTheSecrets() throws Exception {
        VaultKeyManager.Setup setup = manager.beginSetup(pw(PASSWORD), pw(PASSWORD));
        byte[] keyBytes = setup.recoveryKey().toBytes();
        assertFalse(allZero(keyBytes));
        Field f = VaultKeyManager.Setup.class.getDeclaredField("vmk");
        f.setAccessible(true);
        byte[] internalVmk = (byte[]) f.get(setup);
        assertFalse(allZero(internalVmk));
        setup.cancel();
        assertTrue(allZero(internalVmk));
        assertTrue(allZero(setup.recoveryKey().toBytes()));
        assertNull(store.data);
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> setup.complete(setup.recoveryKey().format()));
        assertFalse(manager.isInitialized());
    }

    @Test
    public void complete_wipesTheSetupSecrets_butKeepsTheVaultOpen() throws Exception {
        VaultKeyManager.Setup setup = manager.beginSetup(pw(PASSWORD), pw(PASSWORD));
        Field f = VaultKeyManager.Setup.class.getDeclaredField("vmk");
        f.setAccessible(true);
        byte[] internalVmk = (byte[]) f.get(setup);
        setup.complete(setup.recoveryKey().format());
        assertTrue(allZero(internalVmk));
        assertEquals(32, manager.deriveSubkey("messages").length);
    }

    @Test
    public void beginSetup_enforcesSixCharactersAndConfirmation() {
        for (String shortPw : new String[]{"", "a", "short", "12345"}) {
            assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> manager.beginSetup(pw(shortPw), pw(shortPw)));
        }
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> manager.beginSetup(pw(PASSWORD), pw(PASSWORD + "x")));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> manager.beginSetup(null, pw(PASSWORD)));
        assertFalse(manager.isInitialized());
        assertEquals(6, VaultKeyManager.MIN_PASSWORD_LENGTH);
    }

    @Test
    public void twelveCharacterPassword_isAccepted() throws Exception {
        VaultKeyManager.Setup setup = manager.beginSetup(pw("twelve chars"), pw("twelve chars"));
        setup.complete(setup.recoveryKey().format());
        manager.lock();
        manager.unlock(pw("twelve chars"));
        assertTrue(manager.isUnlocked());
    }

    @Test
    public void beginSetup_onExistingVault_isInvalidState() throws Exception {
        setUpVault(manager);
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.beginSetup(pw(PASSWORD), pw(PASSWORD)));
    }

    @Test
    public void setupRacingAnotherSetup_cannotOverwriteTheFirstVault() throws Exception {
        VaultKeyManager.Setup a = manager.beginSetup(pw(PASSWORD), pw(PASSWORD));
        VaultKeyManager.Setup b = manager.beginSetup(pw(PASSWORD), pw(PASSWORD));
        a.complete(a.recoveryKey().format());
        byte[] first = store.data.clone();
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> b.complete(b.recoveryKey().format()));
        assertArrayEquals(first, store.data);
    }

    @Test
    public void storageFailure_duringComplete_leavesNothing_andCanBeRetried() throws Exception {
        VaultKeyManager.Setup setup = manager.beginSetup(pw(PASSWORD), pw(PASSWORD));
        String text = setup.recoveryKey().format();
        store.failWrites = true;
        assertReason(VaultCryptoException.Reason.IO_ERROR, () -> setup.complete(text));
        assertFalse(manager.isInitialized());
        assertFalse(manager.isUnlocked());
        store.failWrites = false;
        setup.complete(text);
        assertTrue(manager.isUnlocked());
    }

    @Test
    public void deviceKeyFailure_duringComplete_leavesNothing() throws Exception {
        VaultKeyManager.Setup setup = manager.beginSetup(pw(PASSWORD), pw(PASSWORD));
        device.keyAvailable = false;
        assertReason(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> setup.complete(setup.recoveryKey().format()));
        assertFalse(manager.isInitialized());
        assertFalse(manager.isUnlocked());
    }

    // ------------------------------------------------------------ what is stored

    @Test
    public void header_neverContainsTheRecoveryKeyVmkOrPassword() throws Exception {
        VaultKeyManager bare = new VaultKeyManager(store, new PassThroughDeviceWrapper(), ITER);
        VaultKeyManager.Setup setup = bare.beginSetup(pw(PASSWORD), pw(PASSWORD));
        RecoveryKey key = setup.recoveryKey();
        byte[] rk = key.toBytes();
        String text = key.format();
        setup.complete(text);
        byte[] inner = store.data;
        assertEquals(VaultKeyManager.HEADER_VERSION, inner[4]);
        assertEquals(-1, VaultCryptoTest.indexOf(inner, rk));
        assertEquals(-1, VaultCryptoTest.indexOf(inner, text.getBytes(StandardCharsets.US_ASCII)));
        assertEquals(-1, VaultCryptoTest.indexOf(inner, text.replace("-", "").getBytes(StandardCharsets.US_ASCII)));
        assertEquals(-1, VaultCryptoTest.indexOf(inner, PASSWORD.getBytes(StandardCharsets.UTF_8)));
        assertEquals(-1, VaultCryptoTest.indexOf(inner, readVmk(bare)));
        // The bundle (non-secret blob) sits inside the header and equals what must be uploaded.
        assertTrue(VaultCryptoTest.indexOf(inner, bare.currentBundle()) > 0);
    }

    @Test
    public void bundle_isRecoverableOnlyWithTheRecoveryKey_notWithThePassword() throws Exception {
        Object[] s = setUpVault(manager);
        byte[] bundle = (byte[]) s[1];
        assertEquals(-1, VaultCryptoTest.indexOf(bundle, PASSWORD.getBytes(StandardCharsets.UTF_8)));
        // No password slot exists: nothing in the bundle depends on the password.
        VaultKeyManager other = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), ITER);
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> other.restoreFromBundle(bundle, PASSWORD, pw(NEW_PASSWORD), pw(NEW_PASSWORD), false));
    }

    @Test
    public void accessors_requireUnlockedV2Vault() throws Exception {
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.getVaultId());
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.currentBundle());
        Object[] s = setUpVault(manager);
        assertEquals(16, manager.getVaultId().length);
        assertEquals(1, manager.getBundleVersion());
        assertArrayEquals((byte[]) s[1], manager.currentBundle());
        manager.getVaultId()[0] ^= 0x55; // copies only
        manager.lock();
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.getVaultId());
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.getBundleVersion());
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.currentBundle());
        manager.unlock(pw(PASSWORD));
        assertArrayEquals((byte[]) s[1], manager.currentBundle());
    }

    @Test
    public void vaultIdsAndBundlesDifferBetweenVaults() throws Exception {
        setUpVault(manager);
        VaultKeyManager other = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), ITER);
        setUpVault(other);
        assertFalse(Arrays.equals(manager.getVaultId(), other.getVaultId()));
        assertFalse(Arrays.equals(manager.deriveSubkey("messages"), other.deriveSubkey("messages")));
    }

    @Test
    public void unlock_afterRestart_restoresVaultIdAndBundle() throws Exception {
        Object[] s = setUpVault(manager);
        byte[] id = manager.getVaultId();
        VaultKeyManager restarted = new VaultKeyManager(store, device, ITER);
        restarted.unlock(pw(PASSWORD));
        assertArrayEquals(id, restarted.getVaultId());
        assertArrayEquals((byte[]) s[1], restarted.currentBundle());
    }

    @Test
    public void newerHeaderVersion_isUnsupportedNotCorrupted() throws Exception {
        VaultKeyManager bare = new VaultKeyManager(store, new PassThroughDeviceWrapper(), ITER);
        setUpVault(bare);
        bare.lock();
        store.data[4] = 3;
        assertReason(VaultCryptoException.Reason.UNSUPPORTED_VERSION, () -> bare.unlock(pw(PASSWORD)));
        assertFalse(bare.isUnlocked());
    }

    @Test
    public void headerBundleMismatch_isCorrupted() throws Exception {
        VaultKeyManager bare = new VaultKeyManager(store, new PassThroughDeviceWrapper(), ITER);
        setUpVault(bare);
        bare.lock();
        // A header that wraps a different VMK than its bundle was made with: swap in another vault's bundle.
        VaultKeyManager other = new VaultKeyManager(new InMemoryHeaderStore(), new PassThroughDeviceWrapper(), ITER);
        setUpVault(other);
        byte[] otherBundle = other.currentBundle();
        byte[] h = store.data;
        int bundleStart = h.length - otherBundle.length;
        System.arraycopy(otherBundle, 0, h, bundleStart, otherBundle.length);
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> bare.unlock(pw(PASSWORD)));
    }

    // ------------------------------------------------------------ restore on a new or reset device

    @Test
    public void restore_onNewDevice_givesSameKeys_andItsOwnPassword() throws Exception {
        Object[] s = setUpVault(manager);
        byte[] messages = manager.deriveSubkey("messages");
        byte[] media = manager.deriveSubkey("media");
        byte[] id = manager.getVaultId();

        InMemoryHeaderStore store2 = new InMemoryHeaderStore();
        VaultKeyManager second = new VaultKeyManager(store2, new TestDeviceKeyWrapper(), ITER);
        second.restoreFromBundle((byte[]) s[1], (String) s[0], pw(NEW_PASSWORD), pw(NEW_PASSWORD), false);
        assertTrue(second.isUnlocked());
        assertArrayEquals(messages, second.deriveSubkey("messages"));
        assertArrayEquals(media, second.deriveSubkey("media"));
        assertArrayEquals(id, second.getVaultId());
        assertArrayEquals((byte[]) s[1], second.currentBundle());

        second.lock();
        assertReason(VaultCryptoException.Reason.WRONG_PASSWORD, () -> second.unlock(pw(PASSWORD)));
        second.unlock(pw(NEW_PASSWORD));
        assertArrayEquals(messages, second.deriveSubkey("messages"));
        // The first device is unaffected and keeps its own password.
        manager.lock();
        manager.unlock(pw(PASSWORD));
    }

    @Test
    public void restore_afterKeystoreLoss_recoversWithoutTheOldDeviceKey() throws Exception {
        Object[] s = setUpVault(manager);
        byte[] messages = manager.deriveSubkey("messages");
        manager.lock();
        device.keyAvailable = false;
        assertReason(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> manager.unlock(pw(PASSWORD)));

        VaultKeyManager rebuilt = new VaultKeyManager(store, new TestDeviceKeyWrapper(), ITER);
        assertReason(VaultCryptoException.Reason.INVALID_STATE,
                () -> rebuilt.restoreFromBundle((byte[]) s[1], (String) s[0], pw(NEW_PASSWORD), pw(NEW_PASSWORD), false));
        rebuilt.restoreFromBundle((byte[]) s[1], (String) s[0], pw(NEW_PASSWORD), pw(NEW_PASSWORD), true);
        assertArrayEquals(messages, rebuilt.deriveSubkey("messages"));
        rebuilt.lock();
        rebuilt.unlock(pw(NEW_PASSWORD));
        assertTrue(rebuilt.isUnlocked());
    }

    @Test
    public void restore_failures_changeNothing() throws Exception {
        Object[] s = setUpVault(manager);
        byte[] bundle = (byte[]) s[1];
        String key = (String) s[0];
        VaultKeyManager second = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), ITER);

        assertReason(VaultCryptoException.Reason.WRONG_RECOVERY_KEY,
                () -> second.restoreFromBundle(bundle, RecoveryKey.generate().format(), pw(NEW_PASSWORD), pw(NEW_PASSWORD), false));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> second.restoreFromBundle(bundle, key.substring(5), pw(NEW_PASSWORD), pw(NEW_PASSWORD), false));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> second.restoreFromBundle(bundle, key, pw("short"), pw("short"), false));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> second.restoreFromBundle(bundle, key, pw(NEW_PASSWORD), pw(NEW_PASSWORD + "x"), false));
        byte[] tampered = bundle.clone();
        tampered[bundle.length - 1] ^= 1;
        assertReason(VaultCryptoException.Reason.CORRUPTED,
                () -> second.restoreFromBundle(tampered, key, pw(NEW_PASSWORD), pw(NEW_PASSWORD), false));
        assertReason(VaultCryptoException.Reason.CORRUPTED,
                () -> second.restoreFromBundle(new byte[10], key, pw(NEW_PASSWORD), pw(NEW_PASSWORD), false));
        assertFalse(second.isInitialized());
        assertFalse(second.isUnlocked());
    }

    @Test
    public void restore_onDeviceWithHeader_needsExplicitPermission_andKeepsHeaderOtherwise() throws Exception {
        Object[] s = setUpVault(manager);
        byte[] before = store.data.clone();
        assertReason(VaultCryptoException.Reason.INVALID_STATE,
                () -> manager.restoreFromBundle((byte[]) s[1], (String) s[0], pw(NEW_PASSWORD), pw(NEW_PASSWORD), false));
        assertArrayEquals(before, store.data);
    }

    @Test
    public void restore_storageFailure_leavesLockedAndUnchanged() throws Exception {
        Object[] s = setUpVault(manager);
        InMemoryHeaderStore store2 = new InMemoryHeaderStore();
        store2.failWrites = true;
        VaultKeyManager second = new VaultKeyManager(store2, new TestDeviceKeyWrapper(), ITER);
        assertReason(VaultCryptoException.Reason.IO_ERROR,
                () -> second.restoreFromBundle((byte[]) s[1], (String) s[0], pw(NEW_PASSWORD), pw(NEW_PASSWORD), false));
        assertFalse(second.isUnlocked());
        assertFalse(second.isInitialized());
    }

    // ------------------------------------------------------------ change password

    @Test
    public void changePassword_keepsKeysAndBundle_replacesPassword() throws Exception {
        Object[] s = setUpVault(manager);
        byte[] messages = manager.deriveSubkey("messages");
        byte[] id = manager.getVaultId();
        byte[] headerBefore = store.data.clone();

        manager.changePassword(pw(PASSWORD), pw(NEW_PASSWORD), pw(NEW_PASSWORD));
        assertTrue(manager.isUnlocked());
        assertFalse(Arrays.equals(headerBefore, store.data));
        assertArrayEquals(messages, manager.deriveSubkey("messages"));
        assertArrayEquals(id, manager.getVaultId());
        assertArrayEquals("no remote password slot, so the bundle never changes", (byte[]) s[1], manager.currentBundle());

        manager.lock();
        assertReason(VaultCryptoException.Reason.WRONG_PASSWORD, () -> manager.unlock(pw(PASSWORD)));
        manager.unlock(pw(NEW_PASSWORD));
        assertArrayEquals(messages, manager.deriveSubkey("messages"));
    }

    @Test
    public void changePassword_usesAFreshSalt() throws Exception {
        VaultKeyManager bare = new VaultKeyManager(store, new PassThroughDeviceWrapper(), ITER);
        setUpVault(bare);
        byte[] saltBefore = Arrays.copyOfRange(store.data, 9, 25);
        bare.changePassword(pw(PASSWORD), pw(PASSWORD), pw(PASSWORD)); // even the same password
        assertFalse(Arrays.equals(saltBefore, Arrays.copyOfRange(store.data, 9, 25)));
    }

    @Test
    public void changePassword_rejectsWrongOldPasswordAndBadNewOnes_andChangesNothing() throws Exception {
        setUpVault(manager);
        byte[] before = store.data.clone();
        assertReason(VaultCryptoException.Reason.WRONG_PASSWORD,
                () -> manager.changePassword(pw("not the password"), pw(NEW_PASSWORD), pw(NEW_PASSWORD)));
        assertReason(VaultCryptoException.Reason.WRONG_PASSWORD,
                () -> manager.changePassword(null, pw(NEW_PASSWORD), pw(NEW_PASSWORD)));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> manager.changePassword(pw(PASSWORD), pw("short"), pw("short")));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> manager.changePassword(pw(PASSWORD), pw(NEW_PASSWORD), pw(NEW_PASSWORD + "!")));
        assertArrayEquals(before, store.data);
        assertTrue(manager.isUnlocked());
    }

    @Test
    public void changePassword_requiresUnlocked() throws Exception {
        setUpVault(manager);
        manager.lock();
        assertReason(VaultCryptoException.Reason.INVALID_STATE,
                () -> manager.changePassword(pw(PASSWORD), pw(NEW_PASSWORD), pw(NEW_PASSWORD)));
    }

    @Test
    public void changePassword_storageFailure_keepsOldPassword() throws Exception {
        setUpVault(manager);
        store.failWrites = true;
        assertReason(VaultCryptoException.Reason.IO_ERROR,
                () -> manager.changePassword(pw(PASSWORD), pw(NEW_PASSWORD), pw(NEW_PASSWORD)));
        store.failWrites = false;
        manager.lock();
        manager.unlock(pw(PASSWORD));
        assertTrue(manager.isUnlocked());
    }

    // ------------------------------------------------------------ legacy (v1) migration

    private byte[] writeLegacy(int iterations) throws Exception {
        return LegacyHeaders.write(store, device, pw("old pass"), iterations);
    }

    @Test
    public void legacyHeader_stillUnlocks_andIsFlaggedLegacy() throws Exception {
        byte[] dataKey = writeLegacy(ITER);
        manager.unlock(pw("old pass"));
        assertTrue(manager.isUnlocked());
        assertTrue(manager.isLegacyHeader());
        assertArrayEquals(VaultCrypto.deriveSubkey(dataKey, "messages"), manager.deriveSubkey("messages"));
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.getVaultId());
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.currentBundle());
        assertReason(VaultCryptoException.Reason.INVALID_STATE,
                () -> manager.changePassword(pw("old pass"), pw(NEW_PASSWORD), pw(NEW_PASSWORD)));
        manager.lock();
        assertFalse(manager.isLegacyHeader());
    }

    @Test
    public void migration_keepsTheDataKey_assignsNewPassword_andBundleOpensWithRecoveryKey() throws Exception {
        byte[] dataKey = writeLegacy(ITER);
        manager.unlock(pw("old pass"));

        VaultKeyManager.Setup setup = manager.beginMigration(pw("old pass"), pw(NEW_PASSWORD), pw(NEW_PASSWORD));
        byte[] legacyHeader = store.data.clone();
        assertArrayEquals("nothing is written before confirmation", legacyHeader, store.data);
        assertTrue(manager.isLegacyHeader());
        String text = setup.recoveryKey().format();
        byte[] bundle = setup.complete(text);

        assertFalse(manager.isLegacyHeader());
        assertEquals(1, manager.getBundleVersion());
        assertArrayEquals(VaultCrypto.deriveSubkey(dataKey, "messages"), manager.deriveSubkey("messages"));
        assertArrayEquals(VaultCrypto.deriveSubkey(dataKey, "media"), manager.deriveSubkey("media"));
        assertArrayEquals(dataKey, VaultBundle.openWithRecoveryKey(bundle, RecoveryKey.parse(text)));

        manager.lock();
        assertReason(VaultCryptoException.Reason.WRONG_PASSWORD, () -> manager.unlock(pw("old pass")));
        manager.unlock(pw(NEW_PASSWORD));
        assertFalse(manager.isLegacyHeader());
        assertArrayEquals(VaultCrypto.deriveSubkey(dataKey, "messages"), manager.deriveSubkey("messages"));
    }

    @Test
    public void migration_rejectsWrongOldPassword_shortNewPassword_andBadState() throws Exception {
        writeLegacy(ITER);
        assertReason(VaultCryptoException.Reason.INVALID_STATE,
                () -> manager.beginMigration(pw("old pass"), pw(NEW_PASSWORD), pw(NEW_PASSWORD))); // locked
        manager.unlock(pw("old pass"));
        assertReason(VaultCryptoException.Reason.WRONG_PASSWORD,
                () -> manager.beginMigration(pw("nope nope"), pw(NEW_PASSWORD), pw(NEW_PASSWORD)));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> manager.beginMigration(pw("old pass"), pw("short"), pw("short")));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT,
                () -> manager.beginMigration(pw("old pass"), pw(NEW_PASSWORD), pw("different")));
        assertTrue(manager.isLegacyHeader());
    }

    @Test
    public void migration_ofAnAlreadyMigratedVault_isInvalidState() throws Exception {
        setUpVault(manager);
        assertReason(VaultCryptoException.Reason.INVALID_STATE,
                () -> manager.beginMigration(pw(PASSWORD), pw(NEW_PASSWORD), pw(NEW_PASSWORD)));
    }

    @Test
    public void migration_failure_keepsLegacyVaultOpenableWithOldPassword() throws Exception {
        byte[] dataKey = writeLegacy(ITER);
        manager.unlock(pw("old pass"));
        VaultKeyManager.Setup setup = manager.beginMigration(pw("old pass"), pw(NEW_PASSWORD), pw(NEW_PASSWORD));
        String text = setup.recoveryKey().format();
        byte[] legacyHeader = store.data.clone();

        store.failWrites = true;
        assertReason(VaultCryptoException.Reason.IO_ERROR, () -> setup.complete(text));
        assertArrayEquals(legacyHeader, store.data);
        assertTrue(manager.isLegacyHeader());
        manager.lock();
        manager.unlock(pw("old pass"));
        assertArrayEquals(VaultCrypto.deriveSubkey(dataKey, "messages"), manager.deriveSubkey("messages"));
    }

    @Test
    public void migration_wrongRecoveryKeyConfirmation_writesNothing() throws Exception {
        writeLegacy(ITER);
        manager.unlock(pw("old pass"));
        VaultKeyManager.Setup setup = manager.beginMigration(pw("old pass"), pw(NEW_PASSWORD), pw(NEW_PASSWORD));
        byte[] legacyHeader = store.data.clone();
        assertReason(VaultCryptoException.Reason.WRONG_RECOVERY_KEY, () -> setup.complete(RecoveryKey.generate().format()));
        assertArrayEquals(legacyHeader, store.data);
        assertTrue(manager.isLegacyHeader());
    }

    @Test
    public void migration_cancelledSetupLeavesLegacyUntouched() throws Exception {
        writeLegacy(ITER);
        manager.unlock(pw("old pass"));
        VaultKeyManager.Setup setup = manager.beginMigration(pw("old pass"), pw(NEW_PASSWORD), pw(NEW_PASSWORD));
        byte[] legacyHeader = store.data.clone();
        setup.cancel();
        assertArrayEquals(legacyHeader, store.data);
        manager.lock();
        manager.unlock(pw("old pass"));
        assertTrue(manager.isLegacyHeader());
    }

    @Test
    public void legacyHeaderTampering_isStillDetected() throws Exception {
        VaultKeyManager bare = new VaultKeyManager(store, new PassThroughDeviceWrapper(), ITER);
        LegacyHeaders.write(store, new PassThroughDeviceWrapper(), pw("old pass"), ITER);
        byte[] original = store.data.clone();
        for (int i = 0; i < original.length; i++) {
            byte[] bad = original.clone();
            bad[i] ^= 1;
            store.data = bad;
            try {
                bare.unlock(pw("old pass"));
                fail("tampered legacy byte " + i + " accepted");
            } catch (VaultCryptoException e) {
                VaultCryptoException.Reason r = e.getReason();
                assertTrue("byte " + i + " gave " + r, r == VaultCryptoException.Reason.CORRUPTED
                        || r == VaultCryptoException.Reason.WRONG_PASSWORD
                        || (i == 4 && r == VaultCryptoException.Reason.UNSUPPORTED_VERSION));
            }
            assertFalse(bare.isUnlocked());
        }
    }

    // ------------------------------------------------------------ remote bundle checks

    /** Restores a second manager from a hand-made version-2 bundle so it holds a higher version. */
    private VaultKeyManager managerAtVersion(int version, byte[] vmk, byte[] vaultId, RecoveryKey key) throws Exception {
        byte[] bundle = VaultBundle.create(vmk, vaultId, version, key);
        VaultKeyManager m = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), ITER);
        m.restoreFromBundle(bundle, key.format(), pw(PASSWORD), pw(PASSWORD), false);
        return m;
    }

    @Test
    public void checkRemoteBundle_sameBundle_isCurrent() throws Exception {
        Object[] s = setUpVault(manager);
        assertEquals(VaultKeyManager.BundleStatus.CURRENT, manager.checkRemoteBundle((byte[]) s[1]));
    }

    @Test
    public void checkRemoteBundle_olderVersion_isRollback() throws Exception {
        byte[] vmk = VaultCrypto.randomBytes(32);
        byte[] id = VaultCrypto.randomBytes(16);
        RecoveryKey key = RecoveryKey.generate();
        VaultKeyManager m = managerAtVersion(3, vmk, id, key);
        for (int older : new int[]{1, 2}) {
            byte[] old = VaultBundle.create(vmk, id, older, key);
            assertReason(VaultCryptoException.Reason.ROLLBACK_DETECTED, () -> m.checkRemoteBundle(old));
        }
        assertEquals(VaultKeyManager.BundleStatus.CURRENT, m.checkRemoteBundle(m.currentBundle()));
    }

    @Test
    public void checkRemoteBundle_newerVersion_isReportedAsNewer() throws Exception {
        byte[] vmk = VaultCrypto.randomBytes(32);
        byte[] id = VaultCrypto.randomBytes(16);
        RecoveryKey key = RecoveryKey.generate();
        VaultKeyManager m = managerAtVersion(2, vmk, id, key);
        byte[] newer = VaultBundle.create(VaultCrypto.randomBytes(32), id, 3, RecoveryKey.generate()); // rotated key epoch
        assertEquals(VaultKeyManager.BundleStatus.NEWER, m.checkRemoteBundle(newer));
    }

    @Test
    public void checkRemoteBundle_otherVault_forgeryAndGarbage_areRejected() throws Exception {
        Object[] s = setUpVault(manager);
        byte[] ours = (byte[]) s[1];
        byte[] otherVault = VaultBundle.create(VaultCrypto.randomBytes(32), VaultCrypto.randomBytes(16), 1, RecoveryKey.generate());
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.checkRemoteBundle(otherVault));

        // Same vault id and version, different content: someone who lacks the VMK cannot make a valid MAC.
        byte[] forged = ours.clone();
        forged[forged.length - 1] ^= 1;
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> manager.checkRemoteBundle(forged));
        byte[] forgedSlot = ours.clone();
        forgedSlot[40] ^= 1;
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> manager.checkRemoteBundle(forgedSlot));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> manager.checkRemoteBundle(new byte[5]));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> manager.checkRemoteBundle(null));
    }

    @Test
    public void checkRemoteBundle_sameVersionDifferentValidBundle_isCorrupted() throws Exception {
        // Same VMK, vault id and version but a different recovery key: authentic, yet not the bundle we hold.
        byte[] vmk = VaultCrypto.randomBytes(32);
        byte[] id = VaultCrypto.randomBytes(16);
        RecoveryKey key = RecoveryKey.generate();
        VaultKeyManager m = managerAtVersion(2, vmk, id, key);
        byte[] differentSlot = VaultBundle.create(vmk, id, 2, RecoveryKey.generate());
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> m.checkRemoteBundle(differentSlot));
    }

    @Test
    public void checkRemoteBundle_requiresUnlocked() throws Exception {
        Object[] s = setUpVault(manager);
        manager.lock();
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.checkRemoteBundle((byte[]) s[1]));
    }

    // ------------------------------------------------------------ lock / destroy

    @Test
    public void lock_zeroesVmkAndForgetsBundle() throws Exception {
        setUpVault(manager);
        byte[] internal = readVmk(manager);
        assertFalse(allZero(internal));
        manager.lock();
        assertTrue(allZero(internal));
    }

    @Test
    public void destroy_makesLocalVaultUnreadable_butRecoveryStillRebuildsIt() throws Exception {
        Object[] s = setUpVault(manager);
        byte[] messages = manager.deriveSubkey("messages");
        manager.destroy();
        assertFalse(manager.isInitialized());
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> manager.unlock(pw(PASSWORD)));

        // The uploaded bundle and the recovery key are outside this device, so they still work.
        VaultKeyManager fresh = new VaultKeyManager(store, new TestDeviceKeyWrapper(), ITER);
        fresh.restoreFromBundle((byte[]) s[1], (String) s[0], pw(NEW_PASSWORD), pw(NEW_PASSWORD), false);
        assertArrayEquals(messages, fresh.deriveSubkey("messages"));
    }

    @Test
    public void newSubkeyPurposes_areIndependentOfExistingOnes() throws Exception {
        setUpVault(manager);
        byte[] messages = manager.deriveSubkey("messages");
        for (String purpose : new String[]{"bundle-auth", "journal", "dedup", "object-names"}) {
            byte[] k = manager.deriveSubkey(purpose);
            assertEquals(32, k.length);
            assertFalse(Arrays.equals(messages, k));
        }
        assertNotEquals(Arrays.toString(manager.deriveSubkey("journal")), Arrays.toString(manager.deriveSubkey("dedup")));
    }

    // ------------------------------------------------------------ helpers

    private static byte[] readVmk(VaultKeyManager m) throws Exception {
        Field f = VaultKeyManager.class.getDeclaredField("vmk");
        f.setAccessible(true);
        byte[] key = (byte[]) f.get(m);
        assertNotNull(key);
        return key;
    }

    /** Device layer that does nothing, so tests can inspect the inner header. */
    static final class PassThroughDeviceWrapper implements DeviceKeyWrapper {
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
