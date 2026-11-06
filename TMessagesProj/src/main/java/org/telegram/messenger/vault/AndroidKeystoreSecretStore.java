package org.telegram.messenger.vault;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Android Keystore binding for {@link DeviceKeyStore}.
 *
 * <p><b>STATUS: NOT COMPILED AND NOT TESTED.</b> This is the only vault file that uses Android
 * APIs. The build environment it was written in has no Android SDK, so it has never been
 * compiled, and it has never run on a device or emulator. It is kept as small as possible
 * (about 50 lines of logic) so that everything around it could be unit-tested elsewhere.
 * It must be built and exercised on a real device/emulator before anyone relies on it; see
 * TESTING.md for the manual checks.
 *
 * <p>The key is an AES-256 GCM key generated inside the Keystore. Key material never enters
 * the app process (a Keystore key's {@code getEncoded()} returns null), so it cannot be exported.
 * Whether it is backed by secure hardware depends on the device. The key does not require user
 * authentication, so changing the screen lock or enrolling a fingerprint does not invalidate it.
 * It can still be lost when the app is uninstalled, data is cleared, or the phone is restored
 * from backup onto another device.
 *
 * <p>Requires API 23 (this project's minSdk).
 */
public final class AndroidKeystoreSecretStore implements DeviceKeyStore {

    private static final String PROVIDER = "AndroidKeyStore";
    public static final String DEFAULT_ALIAS = "org.telegram.messenger.vault.device_key_v1";

    private final String alias;

    public AndroidKeystoreSecretStore() {
        this(DEFAULT_ALIAS);
    }

    public AndroidKeystoreSecretStore(String alias) {
        this.alias = alias;
    }

    /** Convenience: the wrapper to hand to {@link VaultKeyManager} in production. */
    public static AndroidKeystoreDeviceKeyWrapper createWrapper() {
        return new AndroidKeystoreDeviceKeyWrapper(new AndroidKeystoreSecretStore());
    }

    @Override
    public SecretKey getKey() throws GeneralSecurityException {
        KeyStore keyStore = loadKeyStore();
        Key key = keyStore.getKey(alias, null);
        if (key == null) {
            return null;
        }
        if (!(key instanceof SecretKey)) {
            throw new KeyStoreException("Unexpected key type under vault alias");
        }
        return (SecretKey) key;
    }

    @Override
    public SecretKey createKey() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER);
        generator.init(new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false)
                .build());
        return generator.generateKey();
    }

    @Override
    public void deleteKey() throws GeneralSecurityException {
        KeyStore keyStore = loadKeyStore();
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias);
        }
    }

    private static KeyStore loadKeyStore() throws GeneralSecurityException {
        try {
            KeyStore keyStore = KeyStore.getInstance(PROVIDER);
            keyStore.load(null);
            return keyStore;
        } catch (IOException e) {
            throw new KeyStoreException("Could not load Android Keystore", e);
        }
    }
}
