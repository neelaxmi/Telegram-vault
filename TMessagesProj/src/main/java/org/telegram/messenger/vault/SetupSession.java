package org.telegram.messenger.vault;

/**
 * Owns the lifetime of the first-time setup (or upgrade) so the UI can never hold a stale or missing
 * {@link SetupFlow}.
 *
 * <p>The crash this class exists for: the screen used to cancel the flow and drop its reference when the app went
 * to the background, but left the "recovery key" and "confirm" screens on display. Coming back, the buttons of
 * those old screens ran against a flow that no longer existed.
 *
 * <p>Rules:
 * <ul>
 *   <li>{@link #flow()} never returns null: without a live setup it throws INVALID_STATE, which every caller
 *       already handles by showing a message and starting again.</li>
 *   <li>Going to the background does NOT cancel the setup at once (the user may be writing the phrase down or
 *       the screen may simply have turned off). The flow is kept for {@link #graceMillis}; the UI hides the
 *       secret while away and redraws the current step on return. After the grace time the flow is cancelled
 *       (its key material wiped) and a later return reports {@link Resume#EXPIRED}; a new setup then generates
 *       a NEW recovery phrase. Nothing is on disk before the confirmation succeeds, so this loses nothing.</li>
 *   <li>The session is the only owner of the flow; the UI keeps no copy.</li>
 * </ul>
 */
public final class SetupSession {

    public enum Resume {
        /** No setup was in progress. */
        NONE,
        /** The setup is still valid: redraw {@link SetupFlow#step()}. */
        CONTINUE,
        /** The time away was too long (or the flow was cancelled): start again. */
        EXPIRED
    }

    public interface Clock {
        long nowMillis();
    }

    public static final long DEFAULT_GRACE_MILLIS = 5L * 60 * 1000;

    private final VaultKeyManager keys;
    private final Clock clock;
    private final long graceMillis;

    private SetupFlow flow;
    private boolean migration;
    private long pausedAt = -1;
    private boolean expired;

    public SetupSession(VaultKeyManager keys, Clock clock, long graceMillis) {
        if (keys == null || clock == null || graceMillis < 0) {
            throw new IllegalArgumentException("invalid arguments");
        }
        this.keys = keys;
        this.clock = clock;
        this.graceMillis = graceMillis;
    }

    /** Starts a fresh setup (new vault, or upgrade when {@code migration}); any earlier one is cancelled. */
    public synchronized SetupFlow start(boolean migration) {
        cancel();
        this.flow = new SetupFlow(keys);
        this.migration = migration;
        this.pausedAt = -1;
        this.expired = false;
        return flow;
    }

    /** The live flow. @throws VaultCryptoException INVALID_STATE if there is none or it has ended */
    public synchronized SetupFlow flow() throws VaultCryptoException {
        if (!isActive()) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "The setup is no longer in progress");
        }
        return flow;
    }

    /** True while a setup is open (password, show key or confirm step). */
    public synchronized boolean isActive() {
        if (flow == null) {
            return false;
        }
        SetupFlow.Step s = flow.step();
        return s == SetupFlow.Step.PASSWORD || s == SetupFlow.Step.SHOW_KEY || s == SetupFlow.Step.CONFIRM_KEY;
    }

    public synchronized boolean isMigration() {
        return migration;
    }

    /** The app left the screen. The caller must hide any secret that is displayed. */
    public synchronized void onPause() {
        if (isActive() && pausedAt < 0) {
            pausedAt = clock.nowMillis();
        }
    }

    /**
     * The app is back. Decides whether the setup can go on; on {@link Resume#EXPIRED} the flow is already
     * cancelled and wiped.
     */
    public synchronized Resume onResume() {
        if (expired) {
            expired = false;
            return Resume.EXPIRED;
        }
        if (!isActive()) {
            pausedAt = -1;
            return Resume.NONE;
        }
        if (pausedAt >= 0 && clock.nowMillis() - pausedAt > graceMillis) {
            cancel();
            expired = false;
            return Resume.EXPIRED;
        }
        pausedAt = -1;
        return Resume.CONTINUE;
    }

    /**
     * Called by a timer while paused: wipes the key material once the grace time has run out, even if the user
     * has not come back yet. The next {@link #onResume} then reports EXPIRED.
     *
     * @return true if the setup was cancelled now
     */
    public synchronized boolean expireIfPaused() {
        if (isActive() && pausedAt >= 0 && clock.nowMillis() - pausedAt > graceMillis) {
            cancel();
            expired = true;
            return true;
        }
        return false;
    }

    public long graceMillis() {
        return graceMillis;
    }

    /** Cancels and wipes whatever is open. Safe to call at any time and repeatedly. */
    public synchronized void cancel() {
        if (flow != null) {
            flow.cancel();
            flow = null;
        }
        pausedAt = -1;
    }
}
