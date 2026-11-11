package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;

/** New-phone restore and the migration step of {@link SetupFlow}. */
public class RestoreFlowTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private static VaultKeyManager newKeys() {
        return new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), 1000);
    }

    @Test
    public void newDevice_fetchesLatestBundle_restoresWithRecoveryKey_andPullsData() throws Exception {
        FakeRemoteStore remote = new FakeRemoteStore();
        VaultKeyManager ka = newKeys();
        VaultKeyManager.Setup setup = ka.beginSetup("first device pw".toCharArray(), "first device pw".toCharArray());
        String rk = setup.recoveryKey().format();
        setup.complete(rk);
        File da = tmp.newFolder("a");
        VaultStore sa = new VaultStore(new File(da, "v"), ka, System::currentTimeMillis, 4096);
        VaultSyncEngine ea = new VaultSyncEngine(sa, ka, remote, new File(da, "j"));
        VaultItem item = ea.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("from the old phone"), null, null);
        ea.sync();

        byte[] bundle = RemoteBundle.fetchLatest(remote);
        assertArrayEquals(ka.currentBundle(), bundle);
        VaultKeyManager kb = newKeys();
        try {
            kb.restoreFromBundle(bundle, RecoveryKey.generate().format(), "second device pw".toCharArray(), "second device pw".toCharArray(), false);
            fail("wrong recovery key must fail");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.WRONG_RECOVERY_KEY, e.getReason());
        }
        kb.restoreFromBundle(bundle, rk, "second device pw".toCharArray(), "second device pw".toCharArray(), false);
        File db = tmp.newFolder("b");
        VaultStore sb = new VaultStore(new File(db, "v"), kb, System::currentTimeMillis, 4096);
        VaultSyncEngine eb = new VaultSyncEngine(sb, kb, remote, new File(db, "j"));
        eb.sync();
        assertEquals("from the old phone", sb.get(item.id).text);
    }

    @Test
    public void fetchLatest_picksHighestVersion_ignoresJunk_andEmptyServer() throws Exception {
        FakeRemoteStore remote = new FakeRemoteStore();
        assertNull(RemoteBundle.fetchLatest(remote));
        VaultKeyManager k = newKeys();
        k.createVault("a long enough pw".toCharArray(), "a long enough pw".toCharArray());
        byte[] b1 = k.currentBundle();
        remote.inject("b.1", b1);
        remote.inject("b.x", new byte[10]);
        remote.inject("r.0123456789abcdef0123456789abcdef", new byte[10]);
        assertArrayEquals(b1, RemoteBundle.fetchLatest(remote));
        byte[] b3 = b1.clone();
        remote.inject("b.3", b3);
        remote.inject("b.2", b1);
        assertArrayEquals(b3, RemoteBundle.fetchLatest(remote));
    }

    @Test
    public void fetchLatest_rejectsGarbageAndOversize() throws Exception {
        FakeRemoteStore remote = new FakeRemoteStore();
        remote.inject("b.1", new byte[200]);
        try {
            RemoteBundle.fetchLatest(remote);
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.CORRUPTED, e.getReason());
        }
        FakeRemoteStore big = new FakeRemoteStore();
        big.inject("b.1", new byte[VaultBundle.MAX_BUNDLE_BYTES + 1]);
        try {
            RemoteBundle.fetchLatest(big);
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.IO_ERROR, e.getReason());
        }
    }

    @Test
    public void migrationFlow_upgradesLegacyVaultWithoutTouchingData() throws Exception {
        InMemoryHeaderStore hs = new InMemoryHeaderStore();
        TestDeviceKeyWrapper w = new TestDeviceKeyWrapper();
        LegacyHeaders.write(hs, w, "old pass".toCharArray(), 1000);
        VaultKeyManager keys = new VaultKeyManager(hs, w, 1000);
        keys.unlock("old pass".toCharArray());
        assertTrue(keys.isLegacyHeader());
        SetupFlow f = new SetupFlow(keys);
        try {
            f.submitMigration("wrong old".toCharArray(), "a brand new password".toCharArray(), "a brand new password".toCharArray());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.WRONG_PASSWORD, e.getReason());
        }
        f.submitMigration("old pass".toCharArray(), "a brand new password".toCharArray(), "a brand new password".toCharArray());
        String key = f.recoveryKeyText();
        f.keyWrittenDown();
        f.confirm(key);
        assertTrue(!keys.isLegacyHeader());
        keys.lock();
        keys.unlock("a brand new password".toCharArray());
        assertTrue(keys.isUnlocked());
    }
}
