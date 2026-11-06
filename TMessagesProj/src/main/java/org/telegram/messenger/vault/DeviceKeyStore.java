package org.telegram.messenger.vault;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

/**
 * Minimal access to the one device-bound AES key used by {@link AndroidKeystoreDeviceKeyWrapper}.
 * <p>
 * Production implementation: {@code AndroidKeystoreSecretStore} (Android only). The interface
 * exists so all wrapping and error-mapping logic can be unit-tested on a plain JVM with a
 * software fake. It contains no Android types.
 */
public interface DeviceKeyStore {

    /**
     * Returns the key, or {@code null} if no key exists. Must NOT create a key.
     *
     * @throws GeneralSecurityException if the key exists but cannot be used (invalidated, unrecoverable, store broken)
     */
    SecretKey getKey() throws GeneralSecurityException;

    /** Creates and stores a new key. Only called when {@link #getKey()} returned {@code null}. */
    SecretKey createKey() throws GeneralSecurityException;

    /** Deletes the key. Must succeed silently if there is no key. */
    void deleteKey() throws GeneralSecurityException;
}
