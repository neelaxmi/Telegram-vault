package org.telegram.messenger.vault;

/**
 * The only way the UI should unlock the Vault: wraps {@link VaultKeyManager#unlock} with attempt tracking and the
 * optional local wipe (decision 4: only THIS device's data and keys; remote data and other devices are never touched).
 *
 * <ul>
 *   <li><b>Count first, verify second.</b> The attempt is saved BEFORE the password is checked, so killing the app
 *       right after a wrong guess cannot hide it. If the count cannot be saved the attempt is refused (fail closed).</li>
 *   <li>Only a wrong password counts: when unlocking fails for another reason (damaged header, missing device key,
 *       IO error) the attempt is refunded.</li>
 *   <li>When the wipe is enabled, the {@link AttemptTracker#WIPE_LIMIT}th consecutive wrong password runs the wipe
 *       action and throws VAULT_WIPED. If the wipe fails, the state is kept so the next try wipes again.</li>
 *   <li>The wipe switch can be changed only while the Vault is unlocked.</li>
 * </ul>
 */
public final class VaultAccess {

    /** What the user is told after a successful unlock. */
    public static final class Report {
        /** Wrong attempts since the report was last acknowledged. */
        public final int failedAttempts;
        /** Time of the most recent of them (0 if none). */
        public final long lastFailureMillis;
        /** The attempt record was unreadable and was replaced by a cautious one. */
        public final boolean trackingDamaged;

        Report(int failedAttempts, long lastFailureMillis, boolean trackingDamaged) {
            this.failedAttempts = failedAttempts;
            this.lastFailureMillis = lastFailureMillis;
            this.trackingDamaged = trackingDamaged;
        }
    }

    /** Deletes this device's local Vault data and keys. Must not touch remote data. */
    public interface WipeAction {
        void wipe() throws VaultCryptoException;
    }

    private final VaultKeyManager keys;
    private final AttemptTracker tracker;
    private final WipeAction wipeAction;
    private final VaultStore.Clock clock;

    public VaultAccess(VaultKeyManager keys, VaultHeaderStore attemptStore, DeviceKeyWrapper device, WipeAction wipeAction) {
        this(keys, attemptStore, device, wipeAction, new VaultStore.Clock() {
            @Override
            public long nowMillis() {
                return System.currentTimeMillis();
            }
        });
    }

    VaultAccess(VaultKeyManager keys, VaultHeaderStore attemptStore, DeviceKeyWrapper device, WipeAction wipeAction, VaultStore.Clock clock) {
        if (keys == null || wipeAction == null || clock == null) {
            throw new IllegalArgumentException("arguments required");
        }
        this.keys = keys;
        this.tracker = new AttemptTracker(attemptStore, device);
        this.wipeAction = wipeAction;
        this.clock = clock;
    }

    /**
     * The normal wipe for this device: local items and media, the key header, the Keystore key and the attempt record.
     * The journal file goes with the data directory handled by {@code store}. Never contacts the network.
     */
    public static WipeAction localWipe(final VaultKeyManager keys, final VaultStore store) {
        return new WipeAction() {
            @Override
            public void wipe() throws VaultCryptoException {
                VaultCryptoException failure = null;
                try {
                    store.deleteAllData();
                } catch (VaultCryptoException e) {
                    failure = e;
                }
                try {
                    keys.destroy();
                } catch (VaultCryptoException e) {
                    if (failure == null) {
                        failure = e;
                    }
                }
                if (failure != null) {
                    throw failure;
                }
            }
        };
    }

    public synchronized Report unlock(char[] password) throws VaultCryptoException {
        AttemptTracker.State s = tracker.load();
        AttemptTracker.State before = s.copy();
        s.consecutive++;
        s.unseen++;
        s.unseenLastMillis = clock.nowMillis();
        tracker.save(s); // may throw: then no attempt is made
        try {
            keys.unlock(password);
        } catch (VaultCryptoException e) {
            if (e.getReason() != VaultCryptoException.Reason.WRONG_PASSWORD) {
                tracker.save(before); // not a guess: refund
                throw e;
            }
            if (s.wipeEnabled && s.consecutive >= AttemptTracker.WIPE_LIMIT) {
                wipeAction.wipe(); // on failure the saved state stays at the limit, so the next try wipes again
                tracker.delete();
                throw new VaultCryptoException(VaultCryptoException.Reason.VAULT_WIPED,
                        "Too many wrong passwords: this device's Vault was wiped");
            }
            throw e;
        }
        Report report = new Report(before.unseen, before.unseenLastMillis, before.damaged);
        s.consecutive = 0;
        s.unseen = before.unseen;
        s.unseenLastMillis = before.unseenLastMillis;
        s.damaged = false;
        tracker.save(s);
        return report;
    }

    /** The user has seen the report. */
    public synchronized void acknowledge() throws VaultCryptoException {
        AttemptTracker.State s = tracker.load();
        s.unseen = 0;
        s.unseenLastMillis = 0;
        s.damaged = false;
        tracker.save(s);
    }

    /** Wrong attempts left before the wipe, or -1 if the wipe is off. */
    public synchronized int attemptsRemaining() throws VaultCryptoException {
        AttemptTracker.State s = tracker.load();
        return s.wipeEnabled ? Math.max(0, AttemptTracker.WIPE_LIMIT - s.consecutive) : -1;
    }

    public synchronized boolean isWipeEnabled() throws VaultCryptoException {
        return tracker.load().wipeEnabled;
    }

    /** Turns the wipe-after-5-failures option on or off. Only while unlocked. */
    public synchronized void setWipeEnabled(boolean enabled) throws VaultCryptoException {
        if (!keys.isUnlocked()) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "Unlock the Vault to change this setting");
        }
        AttemptTracker.State s = tracker.load();
        s.wipeEnabled = enabled;
        tracker.save(s);
    }
}
