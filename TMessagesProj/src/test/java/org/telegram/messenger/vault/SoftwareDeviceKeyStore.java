package org.telegram.messenger.vault;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * JVM stand-in for the Android Keystore: an in-memory AES key with switches to simulate the
 * failures the real Keystore can produce. It does NOT prove anything about the real Keystore.
 */
class SoftwareDeviceKeyStore implements DeviceKeyStore {

    SecretKey key;
    int getCalls;
    int createCalls;
    int deleteCalls;

    /** If set, thrown from getKey(). */
    GeneralSecurityException getFailure;
    RuntimeException getRuntimeFailure;
    GeneralSecurityException createFailure;
    GeneralSecurityException deleteFailure;
    RuntimeException deleteRuntimeFailure;
    /** If set, returned from getKey() instead of {@link #key} (e.g. an unusable key). */
    SecretKey keyOverride;

    @Override
    public SecretKey getKey() throws GeneralSecurityException {
        getCalls++;
        if (getFailure != null) {
            throw getFailure;
        }
        if (getRuntimeFailure != null) {
            throw getRuntimeFailure;
        }
        return keyOverride != null ? keyOverride : key;
    }

    @Override
    public SecretKey createKey() throws GeneralSecurityException {
        createCalls++;
        if (createFailure != null) {
            throw createFailure;
        }
        key = new SecretKeySpec(VaultCrypto.randomBytes(32), "AES");
        return key;
    }

    @Override
    public void deleteKey() throws GeneralSecurityException {
        deleteCalls++;
        if (deleteFailure != null) {
            throw deleteFailure;
        }
        if (deleteRuntimeFailure != null) {
            throw deleteRuntimeFailure;
        }
        key = null;
    }
}
