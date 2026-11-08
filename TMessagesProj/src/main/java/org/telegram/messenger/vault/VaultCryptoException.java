package org.telegram.messenger.vault;

/**
 * Single checked exception for every Vault cryptographic or key-management failure.
 * The {@link Reason} lets callers react without parsing messages. Messages never
 * contain passwords, keys or plaintext.
 */
public class VaultCryptoException extends Exception {

    public enum Reason {
        /** The supplied password did not unlock the vault (or the key header was altered, which is indistinguishable). */
        WRONG_PASSWORD,
        /** Stored data is malformed, truncated, authentication failed, or was tampered with. */
        CORRUPTED,
        /** The device-bound key that protects the vault header is missing or unusable (e.g. new device, reset lock screen). */
        DEVICE_KEY_UNAVAILABLE,
        /** The operation is not allowed in the current state (locked, already initialised, ...). */
        INVALID_STATE,
        /** A caller-supplied argument is unacceptable (password too short, confirmation mismatch, bad key size, ...). */
        INVALID_ARGUMENT,
        /** Storage read/write failed. */
        IO_ERROR,
        /** The platform does not provide a required algorithm. */
        UNSUPPORTED_PLATFORM,
        /** Data was written by a newer version of the app. It is intact as far as we know but cannot be read yet; never treat it as damaged. */
        UNSUPPORTED_VERSION,
        /** A key bundle older than one this device has already accepted was presented (rollback attempt or stale copy). */
        ROLLBACK_DETECTED,
        /** The recovery key did not open the key bundle. */
        WRONG_RECOVERY_KEY,
        /** The media is larger than the file size Telegram accepts for an upload, so it cannot be synced. */
        MEDIA_TOO_LARGE
    }

    private static final long serialVersionUID = 1L;

    private final Reason reason;

    public VaultCryptoException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public VaultCryptoException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
