package org.telegram.messenger.vault;

/**
 * Second protection layer that binds the stored vault header to this device.
 * <p>
 * Production implementation (added in a later phase) uses a non-exportable
 * Android Keystore AES-GCM key. It is deliberately an interface so the password
 * logic stays pure Java and can be unit-tested on a plain JVM.
 * <p>
 * Purpose: an attacker who copies the vault files off the phone cannot start an
 * offline password brute-force without also extracting the Keystore key. This
 * raises the bar; it does not make a weak password safe, and it gives no
 * protection against code running on the unlocked device.
 * <p>
 * Consequence to document for users: if the device key is lost (some devices
 * invalidate Keystore keys, the app is restored onto a new phone), the vault
 * cannot be opened even with the right password.
 */
public interface DeviceKeyWrapper {

    /** Encrypts {@code data} with the device-bound key. */
    byte[] wrap(byte[] data) throws VaultCryptoException;

    /**
     * Reverses {@link #wrap}. Must throw {@link VaultCryptoException.Reason#DEVICE_KEY_UNAVAILABLE}
     * if the key is gone or unusable, and {@link VaultCryptoException.Reason#CORRUPTED} if the
     * data fails authentication.
     */
    byte[] unwrap(byte[] wrapped) throws VaultCryptoException;

    /** Permanently deletes the device-bound key. Called when the vault is destroyed. Must not fail if the key is already gone. */
    void deleteKey() throws VaultCryptoException;
}
