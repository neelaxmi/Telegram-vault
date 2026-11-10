package org.telegram.messenger.vault;

/**
 * The first-time setup as a small state machine for the UI (decision 3: the recovery key is mandatory and must be
 * confirmed by typing it back). Nothing is written to disk until the confirmation succeeds.
 *
 * <pre>PASSWORD -> SHOW_KEY -> CONFIRM_KEY -> DONE</pre>
 * The UI must call {@link #cancel} when the app goes to the background or the screen is left, so the key is never
 * left on screen or in memory. A new flow starts again with a NEW recovery key.
 */
public final class SetupFlow {

    public enum Step {PASSWORD, SHOW_KEY, CONFIRM_KEY, DONE, CANCELLED}

    private final VaultKeyManager keys;
    private Step step = Step.PASSWORD;
    private VaultKeyManager.Setup setup;

    public SetupFlow(VaultKeyManager keys) {
        if (keys == null) {
            throw new IllegalArgumentException("keys required");
        }
        this.keys = keys;
    }

    public synchronized Step step() {
        return step;
    }

    /** Validates and keeps the password (minimum {@value VaultKeyManager#MIN_PASSWORD_LENGTH} characters). */
    public synchronized void submitPassword(char[] password, char[] confirmation) throws VaultCryptoException {
        require(Step.PASSWORD);
        setup = keys.beginSetup(password, confirmation);
        step = Step.SHOW_KEY;
    }

    /** The key to display. Only available while it is being shown or confirmed. */
    public synchronized String recoveryKeyText() throws VaultCryptoException {
        if (step != Step.SHOW_KEY && step != Step.CONFIRM_KEY) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "No recovery key to show");
        }
        return setup.recoveryKey().format();
    }

    /** The user says they have written the key down. */
    public synchronized void keyWrittenDown() throws VaultCryptoException {
        require(Step.SHOW_KEY);
        step = Step.CONFIRM_KEY;
    }

    /** Back from the confirmation screen to the key display. */
    public synchronized void backToKey() throws VaultCryptoException {
        require(Step.CONFIRM_KEY);
        step = Step.SHOW_KEY;
    }

    /**
     * The user typed the key back. On success the vault exists and is unlocked, and the key bundle to upload is
     * returned. A wrong or malformed key throws and leaves the flow on CONFIRM_KEY.
     */
    public synchronized byte[] confirm(String typedKey) throws VaultCryptoException {
        require(Step.CONFIRM_KEY);
        byte[] bundle = setup.complete(typedKey);
        step = Step.DONE;
        setup = null;
        return bundle;
    }

    public synchronized void cancel() {
        if (setup != null) {
            setup.cancel();
            setup = null;
        }
        if (step != Step.DONE) {
            step = Step.CANCELLED;
        }
    }

    private void require(Step expected) throws VaultCryptoException {
        if (step != expected) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "Unexpected step: " + step);
        }
    }
}
