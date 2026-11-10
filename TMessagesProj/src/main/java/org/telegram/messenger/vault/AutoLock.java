package org.telegram.messenger.vault;

/**
 * Decides when the Vault locks itself: when the app goes to the background (optional), after a period without user
 * activity, or on request. Pure logic with an injectable clock; the Android side only forwards lifecycle callbacks
 * and calls {@link #tick} periodically and on resume.
 *
 * <p>The clock must be monotonic on a device (use elapsed real time, not wall time). If it ever goes backwards the
 * Vault locks, as a changed clock must never extend an unlocked period.
 */
public final class AutoLock {

    public static final long DEFAULT_INACTIVITY_MILLIS = 5 * 60 * 1000L;
    public static final long MIN_INACTIVITY_MILLIS = 10 * 1000L;
    public static final long MAX_INACTIVITY_MILLIS = 24 * 60 * 60 * 1000L;

    private final VaultKeyManager keys;
    private final VaultStore.Clock clock;
    private final Runnable onLocked;
    private boolean lockOnBackground = true;
    private long inactivityMillis = DEFAULT_INACTIVITY_MILLIS;
    private long lastActivity;
    private boolean inForeground = true;

    /** @param onLocked called (once per lock) after the keys were discarded, e.g. to close the Vault screens; may be null */
    public AutoLock(VaultKeyManager keys, Runnable onLocked) {
        this(keys, onLocked, new VaultStore.Clock() {
            @Override
            public long nowMillis() {
                return System.currentTimeMillis();
            }
        });
    }

    AutoLock(VaultKeyManager keys, Runnable onLocked, VaultStore.Clock clock) {
        if (keys == null || clock == null) {
            throw new IllegalArgumentException("arguments required");
        }
        this.keys = keys;
        this.onLocked = onLocked;
        this.clock = clock;
        this.lastActivity = clock.nowMillis();
    }

    public synchronized void setLockOnBackground(boolean value) {
        lockOnBackground = value;
    }

    public synchronized boolean isLockOnBackground() {
        return lockOnBackground;
    }

    public synchronized void setInactivityMillis(long millis) {
        if (millis < MIN_INACTIVITY_MILLIS || millis > MAX_INACTIVITY_MILLIS) {
            throw new IllegalArgumentException("Inactivity timeout must be between 10 seconds and 24 hours");
        }
        inactivityMillis = millis;
    }

    public synchronized long getInactivityMillis() {
        return inactivityMillis;
    }

    /** Call when the Vault was just unlocked. */
    public synchronized void onUnlocked() {
        lastActivity = clock.nowMillis();
        inForeground = true;
    }

    /** Call on touches, scrolls, key presses inside the Vault. Ignored while backgrounded or locked. */
    public synchronized void userActivity() {
        if (inForeground && keys.isUnlocked()) {
            long now = clock.nowMillis();
            if (now >= lastActivity) {
                lastActivity = now;
            }
        }
    }

    public synchronized void onBackground() {
        inForeground = false;
        if (lockOnBackground) {
            lockNow();
        }
    }

    /** On return to the foreground: locks first if the time away was too long, then resumes counting. */
    public synchronized void onForeground() {
        tick();
        inForeground = true;
        if (keys.isUnlocked()) {
            lastActivity = clock.nowMillis();
        }
    }

    /** Locks if the inactivity limit has passed. Returns true if the Vault is locked afterwards. */
    public synchronized boolean tick() {
        if (!keys.isUnlocked()) {
            return true;
        }
        long now = clock.nowMillis();
        if (now < lastActivity || now - lastActivity >= inactivityMillis) {
            lockNow();
            return true;
        }
        return false;
    }

    /** Milliseconds until the inactivity lock, or -1 if locked. */
    public synchronized long millisUntilLock() {
        if (!keys.isUnlocked()) {
            return -1;
        }
        long left = inactivityMillis - (clock.nowMillis() - lastActivity);
        return Math.max(0, left);
    }

    public synchronized void lockNow() {
        boolean was = keys.isUnlocked();
        keys.lock();
        if (was && onLocked != null) {
            onLocked.run();
        }
    }
}
