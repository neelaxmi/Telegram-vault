package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Tests the wrapper's logic against a software key store on the JVM. They say nothing about the
 * real Android Keystore, which is exercised only by on-device checks (see TESTING.md).
 */
public class AndroidKeystoreDeviceKeyWrapperTest {

    private static final byte[] DATA = "inner vault header bytes, 85 of them or so".getBytes(StandardCharsets.UTF_8);

    private SoftwareDeviceKeyStore keyStore;
    private AndroidKeystoreDeviceKeyWrapper wrapper;

    @Before
    public void setUp() {
        keyStore = new SoftwareDeviceKeyStore();
        wrapper = new AndroidKeystoreDeviceKeyWrapper(keyStore);
    }

    private interface Action {
        void run() throws VaultCryptoException;
    }

    private static VaultCryptoException expect(VaultCryptoException.Reason reason, Action a) {
        try {
            a.run();
        } catch (VaultCryptoException e) {
            assertEquals(reason, e.getReason());
            return e;
        }
        fail("Expected " + reason);
        return null;
    }

    // ------------------------------------------------------------ happy path and format

    @Test
    public void wrapThenUnwrap_roundTrips() throws Exception {
        assertArrayEquals(DATA, wrapper.unwrap(wrapper.wrap(DATA)));
    }

    @Test
    public void roundTrip_variousSizes() throws Exception {
        for (int size : new int[]{0, 1, 85, 1000, 100_000}) {
            byte[] data = VaultCrypto.randomBytes(size);
            assertArrayEquals("size " + size, data, wrapper.unwrap(wrapper.wrap(data)));
        }
    }

    @Test
    public void blobFormat_versionIvCiphertextTag() throws Exception {
        byte[] blob = wrapper.wrap(DATA);
        assertEquals(1 + 12 + DATA.length + 16, blob.length);
        assertEquals(AndroidKeystoreDeviceKeyWrapper.FORMAT_VERSION, blob[0]);
        assertEquals(-1, VaultCryptoTest.indexOf(blob, DATA));
    }

    @Test
    public void blobIsPlainAesGcm_withTheDocumentedAad_underTheStoreKey() throws Exception {
        // Pins the on-disk format: decrypting independently with the key and the documented AAD must work,
        // and omitting the AAD must fail.
        byte[] blob = wrapper.wrap(DATA);
        byte[] withoutVersion = Arrays.copyOfRange(blob, 1, blob.length);
        byte[] aad = "tg-vault-device-wrap-v1".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(DATA, VaultCrypto.decrypt(keyStore.key.getEncoded(), withoutVersion, aad));
        expect(VaultCryptoException.Reason.CORRUPTED,
                () -> VaultCrypto.decrypt(keyStore.key.getEncoded(), withoutVersion, null));
    }

    @Test
    public void everyWrapUsesAFreshIv() throws Exception {
        Set<String> ivs = new HashSet<>();
        Set<String> blobs = new HashSet<>();
        for (int i = 0; i < 300; i++) {
            byte[] blob = wrapper.wrap(DATA);
            ivs.add(VaultCryptoTest.toHex(Arrays.copyOfRange(blob, 1, 13)));
            blobs.add(VaultCryptoTest.toHex(blob));
        }
        assertEquals(300, ivs.size());
        assertEquals(300, blobs.size());
    }

    // ------------------------------------------------------------ key creation rules

    @Test
    public void wrap_createsKeyOnlyWhenMissing_andReusesIt() throws Exception {
        assertEquals(0, keyStore.createCalls);
        wrapper.wrap(DATA);
        assertEquals(1, keyStore.createCalls);
        SecretKey first = keyStore.key;
        wrapper.wrap(DATA);
        wrapper.wrap(DATA);
        assertEquals(1, keyStore.createCalls);
        assertSame(first, keyStore.key);
    }

    @Test
    public void unwrap_neverCreatesAKey() throws Exception {
        byte[] blob = wrapper.wrap(DATA);
        keyStore.key = null; // key lost
        expect(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> wrapper.unwrap(blob));
        assertEquals("unwrap must not silently replace a lost key", 1, keyStore.createCalls);
        assertEquals(null, keyStore.key);
    }

    @Test
    public void lostKey_afterWrap_isDeviceKeyUnavailable_notCorrupted() throws Exception {
        byte[] blob = wrapper.wrap(DATA);
        keyStore.deleteKey();
        expect(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> wrapper.unwrap(blob));
    }

    @Test
    public void replacedKey_makesOldDataCorrupted_andIsNotReportedAsMissingKey() throws Exception {
        byte[] blob = wrapper.wrap(DATA);
        keyStore.deleteKey();
        wrapper.wrap(DATA); // a new key now exists
        expect(VaultCryptoException.Reason.CORRUPTED, () -> wrapper.unwrap(blob));
    }

    @Test
    public void dataFromAnotherDevice_isRejected() throws Exception {
        byte[] blob = wrapper.wrap(DATA);
        AndroidKeystoreDeviceKeyWrapper otherDevice = new AndroidKeystoreDeviceKeyWrapper(new SoftwareDeviceKeyStore());
        otherDevice.wrap(DATA); // other device has its own key
        expect(VaultCryptoException.Reason.CORRUPTED, () -> otherDevice.unwrap(blob));
    }

    // ------------------------------------------------------------ tampering

    @Test
    public void everySingleByteModification_isRejectedAsCorrupted() throws Exception {
        byte[] blob = wrapper.wrap(DATA);
        for (int i = 0; i < blob.length; i++) {
            final byte[] tampered = blob.clone();
            tampered[i] ^= 0x01;
            expect(VaultCryptoException.Reason.CORRUPTED, () -> wrapper.unwrap(tampered));
        }
        assertArrayEquals(DATA, wrapper.unwrap(blob));
    }

    @Test
    public void truncatedExtendedEmptyAndNullBlobs_areCorrupted() throws Exception {
        final byte[] blob = wrapper.wrap(DATA);
        expect(VaultCryptoException.Reason.CORRUPTED, () -> wrapper.unwrap(Arrays.copyOf(blob, blob.length - 1)));
        expect(VaultCryptoException.Reason.CORRUPTED, () -> wrapper.unwrap(Arrays.copyOf(blob, blob.length + 1)));
        expect(VaultCryptoException.Reason.CORRUPTED, () -> wrapper.unwrap(Arrays.copyOf(blob, 28)));
        expect(VaultCryptoException.Reason.CORRUPTED, () -> wrapper.unwrap(new byte[0]));
        expect(VaultCryptoException.Reason.CORRUPTED, () -> wrapper.unwrap(null));
    }

    @Test
    public void malformedBlobs_areRejectedBeforeTouchingTheKeyStore() throws Exception {
        keyStore.getFailure = new KeyStoreException("must not be called");
        expect(VaultCryptoException.Reason.CORRUPTED, () -> wrapper.unwrap(new byte[5]));
        assertEquals(0, keyStore.getCalls);
    }

    @Test
    public void unknownFormatVersion_isCorrupted() throws Exception {
        final byte[] blob = wrapper.wrap(DATA);
        blob[0] = 2;
        expect(VaultCryptoException.Reason.CORRUPTED, () -> wrapper.unwrap(blob));
        blob[0] = 0;
        expect(VaultCryptoException.Reason.CORRUPTED, () -> wrapper.unwrap(blob));
    }

    // ------------------------------------------------------------ keystore failures fail closed

    @Test
    public void getKeyThrowingSecurityExceptions_mapsToDeviceKeyUnavailable() throws Exception {
        final byte[] blob = wrapper.wrap(DATA);
        for (java.security.GeneralSecurityException failure : new java.security.GeneralSecurityException[]{
                new UnrecoverableKeyException("unrecoverable"),
                new KeyStoreException("store broken"),
                new InvalidKeyException("Key permanently invalidated"),
                new java.security.NoSuchAlgorithmException("no algo")}) {
            keyStore.getFailure = failure;
            VaultCryptoException e = expect(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> wrapper.unwrap(blob));
            assertSame(failure, e.getCause());
            expect(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> wrapper.wrap(DATA));
        }
    }

    @Test
    public void runtimeFailuresFromKeyStore_failClosed() throws Exception {
        final byte[] blob = wrapper.wrap(DATA);
        keyStore.getRuntimeFailure = new java.security.ProviderException("keystore daemon died");
        expect(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> wrapper.unwrap(blob));
        expect(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> wrapper.wrap(DATA));
        keyStore.getRuntimeFailure = new IllegalStateException("weird");
        expect(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> wrapper.unwrap(blob));
    }

    @Test
    public void keyThatCipherRefuses_simulatesInvalidatedKey_mapsToDeviceKeyUnavailable() throws Exception {
        // On Android an invalidated key throws KeyPermanentlyInvalidatedException (an InvalidKeyException)
        // from Cipher.init. A key of the wrong algorithm makes the JVM cipher throw InvalidKeyException too.
        final byte[] blob = wrapper.wrap(DATA);
        keyStore.keyOverride = new SecretKeySpec(new byte[32], "HmacSHA256");
        expect(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> wrapper.unwrap(blob));
        expect(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> wrapper.wrap(DATA));
    }

    @Test
    public void keyOfWrongSize_isNotUsed() throws Exception {
        final byte[] blob = wrapper.wrap(DATA);
        keyStore.keyOverride = new SecretKeySpec(new byte[7], "AES");
        expect(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> wrapper.unwrap(blob));
    }

    @Test
    public void createKeyFailure_onWrap_isDeviceKeyUnavailable_andNothingIsReturned() {
        keyStore.createFailure = new KeyStoreException("cannot generate");
        expect(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> wrapper.wrap(DATA));
        assertEquals(null, keyStore.key);
    }

    @Test
    public void wrapNull_isInvalidArgument() {
        expect(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> wrapper.wrap(null));
        assertEquals("must not even create a key for bad input", 0, keyStore.createCalls);
    }

    // ------------------------------------------------------------ deleteKey

    @Test
    public void deleteKey_removesKey_andIsIdempotent() throws Exception {
        wrapper.wrap(DATA);
        assertNotNull(keyStore.key);
        wrapper.deleteKey();
        assertEquals(null, keyStore.key);
        wrapper.deleteKey(); // nothing there: must not fail
        assertEquals(2, keyStore.deleteCalls);
    }

    @Test
    public void deleteKey_failures_areReported() {
        keyStore.deleteFailure = new KeyStoreException("cannot delete");
        expect(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> wrapper.deleteKey());
        keyStore.deleteFailure = null;
        keyStore.deleteRuntimeFailure = new java.security.ProviderException("daemon");
        expect(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> wrapper.deleteKey());
    }

    @Test
    public void constructor_requiresKeyStore() {
        try {
            new AndroidKeystoreDeviceKeyWrapper(null);
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }

    // ------------------------------------------------------------ integration with VaultKeyManager

    @Test
    public void vaultKeyManager_endToEnd_withThisWrapper() throws Exception {
        InMemoryHeaderStore headers = new InMemoryHeaderStore();
        VaultKeyManager manager = new VaultKeyManager(headers, wrapper, 1000);
        char[] pw = "correct horse battery".toCharArray();
        manager.createVault(pw, pw.clone());
        byte[] key = manager.deriveSubkey("messages");
        assertEquals(-1, VaultCryptoTest.indexOf(headers.data, "TGVH".getBytes(StandardCharsets.US_ASCII)));

        manager.lock();
        manager.unlock(pw);
        assertArrayEquals(key, manager.deriveSubkey("messages"));
        expect(VaultCryptoException.Reason.WRONG_PASSWORD, () -> manager.unlock("wrong password".toCharArray()));
    }

    @Test
    public void vaultKeyManager_keyLoss_isReportedAsDeviceKeyUnavailable() throws Exception {
        InMemoryHeaderStore headers = new InMemoryHeaderStore();
        VaultKeyManager manager = new VaultKeyManager(headers, wrapper, 1000);
        char[] pw = "correct horse battery".toCharArray();
        manager.createVault(pw, pw.clone());
        manager.lock();

        keyStore.key = null; // e.g. restored from backup on a new phone
        expect(VaultCryptoException.Reason.DEVICE_KEY_UNAVAILABLE, () -> manager.unlock(pw));
        assertFalse(manager.isUnlocked());
        assertTrue("header untouched so a returning key could still open it", headers.exists());
    }

    @Test
    public void vaultKeyManager_destroy_deletesTheDeviceKeyToo() throws Exception {
        InMemoryHeaderStore headers = new InMemoryHeaderStore();
        VaultKeyManager manager = new VaultKeyManager(headers, wrapper, 1000);
        char[] pw = "correct horse battery".toCharArray();
        manager.createVault(pw, pw.clone());
        manager.destroy();
        assertFalse(headers.exists());
        assertEquals(null, keyStore.key);
        assertEquals(1, keyStore.deleteCalls);
    }

    @Test
    public void concurrentWrapAndUnwrap_areConsistent() throws Exception {
        final byte[] blob = wrapper.wrap(DATA);
        final java.util.concurrent.atomic.AtomicReference<Throwable> failure = new java.util.concurrent.atomic.AtomicReference<>();
        Thread[] threads = new Thread[8];
        for (int t = 0; t < threads.length; t++) {
            threads[t] = new Thread(() -> {
                try {
                    for (int i = 0; i < 100; i++) {
                        assertArrayEquals(DATA, wrapper.unwrap(wrapper.wrap(DATA)));
                        assertArrayEquals(DATA, wrapper.unwrap(blob));
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
            throw new AssertionError(failure.get());
        }
        assertEquals("key must be created exactly once", 1, keyStore.createCalls);
    }
}
