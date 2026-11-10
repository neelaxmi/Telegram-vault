package org.telegram.messenger.vault;

import java.util.concurrent.Executor;

/**
 * Runs {@link VaultSyncEngine#sync} off the UI thread, one run at a time, with back-off after failures, and turns
 * the outcome into a {@link Status} for the screen. It never sleeps: after a failure it records when the next attempt
 * is allowed; the UI schedules a call to {@link #requestSync} at that time (or the user presses "sync now").
 *
 * <ul>
 *   <li>Network or server errors (including Telegram's FLOOD_WAIT) back off 5 s, 10 s, ... up to 15 minutes, and at
 *       least as long as a FLOOD_WAIT asks for.</li>
 *   <li>Security failures (bundle rollback, damaged bundle) and "this device needs the recovery key" are NOT
 *       retried automatically.</li>
 * </ul>
 */
public final class SyncCoordinator {

    public enum State {IDLE, SYNCING, WAITING_RETRY, NEEDS_RESTORE, SECURITY_ERROR, LOCKED}

    /** Immutable snapshot for the UI. */
    public static final class Status {
        public final State state;
        public final int pendingItems;
        public final long nextAttemptMillis;
        public final long lastSuccessMillis;
        public final VaultCryptoException.Reason error;
        public final int consecutiveFailures;

        Status(State state, int pendingItems, long nextAttemptMillis, long lastSuccessMillis,
               VaultCryptoException.Reason error, int consecutiveFailures) {
            this.state = state;
            this.pendingItems = pendingItems;
            this.nextAttemptMillis = nextAttemptMillis;
            this.lastSuccessMillis = lastSuccessMillis;
            this.error = error;
            this.consecutiveFailures = consecutiveFailures;
        }
    }

    public interface Listener {
        /** Called on the thread that finished the work; post to the UI thread yourself. */
        void onStatus(Status status);
    }

    static final long BASE_BACKOFF_MILLIS = 5_000;
    static final long MAX_BACKOFF_MILLIS = 15 * 60 * 1000;

    private final VaultSyncEngine engine;
    private final Executor executor;
    private final VaultStore.Clock clock;
    private final Listener listener;
    private boolean running;
    private State state = State.IDLE;
    private int failures;
    private long nextAttempt;
    private long lastSuccess;
    private int pending;
    private VaultCryptoException.Reason error;

    public SyncCoordinator(VaultSyncEngine engine, Executor executor, Listener listener) {
        this(engine, executor, listener, new VaultStore.Clock() {
            @Override
            public long nowMillis() {
                return System.currentTimeMillis();
            }
        });
    }

    SyncCoordinator(VaultSyncEngine engine, Executor executor, Listener listener, VaultStore.Clock clock) {
        if (engine == null || executor == null || clock == null) {
            throw new IllegalArgumentException("arguments required");
        }
        this.engine = engine;
        this.executor = executor;
        this.listener = listener;
        this.clock = clock;
    }

    public synchronized Status status() {
        return snapshot();
    }

    /**
     * Starts a sync unless one is running, a back-off is still in force (and {@code force} is false) or the state
     * calls for the user to act. Returns true if a run was started.
     */
    public boolean requestSync(boolean force) {
        synchronized (this) {
            if (running) {
                return false;
            }
            if (state == State.NEEDS_RESTORE || state == State.SECURITY_ERROR) {
                return false;
            }
            if (!force && state == State.WAITING_RETRY && clock.nowMillis() < nextAttempt) {
                return false;
            }
            running = true;
            state = State.SYNCING;
        }
        publish();
        executor.execute(new Runnable() {
            @Override
            public void run() {
                runOnce();
            }
        });
        return true;
    }

    /** The user fixed the cause (restored with the recovery key, updated the app): allow syncing again. */
    public synchronized void clearBlockingState() {
        if (!running && (state == State.NEEDS_RESTORE || state == State.SECURITY_ERROR || state == State.LOCKED)) {
            state = State.IDLE;
            error = null;
        }
    }

    private void runOnce() {
        State next;
        VaultCryptoException.Reason err = null;
        long wait = 0;
        int pend = 0;
        boolean ok = false;
        try {
            VaultSyncEngine.SyncReport report = engine.sync();
            if (report.needsRestore) {
                next = State.NEEDS_RESTORE;
            } else {
                next = State.IDLE;
                ok = true;
            }
            pend = engine.pendingCount();
        } catch (VaultCryptoException e) {
            err = e.getReason();
            switch (e.getReason()) {
                case IO_ERROR:
                    next = State.WAITING_RETRY;
                    wait = floodWaitMillis(e);
                    break;
                case INVALID_STATE:
                    next = State.LOCKED;
                    break;
                default:
                    next = State.SECURITY_ERROR; // rollback, corrupted bundle, unsupported version, ...
            }
            try {
                pend = engine.pendingCount();
            } catch (VaultCryptoException ignored) {
                pend = -1;
            }
        }
        synchronized (this) {
            running = false;
            state = next;
            error = err;
            pending = pend;
            if (ok) {
                failures = 0;
                lastSuccess = clock.nowMillis();
            } else if (next == State.WAITING_RETRY) {
                failures++;
                long backoff = Math.min(MAX_BACKOFF_MILLIS, BASE_BACKOFF_MILLIS << Math.min(failures - 1, 20));
                nextAttempt = clock.nowMillis() + Math.max(backoff, wait);
            }
        }
        publish();
    }

    /** Seconds asked for by a "FLOOD_WAIT_n" anywhere in the cause chain, plus one second; else 0. */
    static long floodWaitMillis(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            String m = c.getMessage();
            if (m == null) {
                continue;
            }
            int i = m.indexOf("FLOOD_WAIT_");
            if (i >= 0) {
                int j = i + "FLOOD_WAIT_".length();
                int k = j;
                while (k < m.length() && Character.isDigit(m.charAt(k)) && k - j < 7) {
                    k++;
                }
                if (k > j) {
                    return (Long.parseLong(m.substring(j, k)) + 1) * 1000L;
                }
            }
        }
        return 0;
    }

    private Status snapshot() {
        return new Status(state, pending, nextAttempt, lastSuccess, error, failures);
    }

    private void publish() {
        Status s;
        synchronized (this) {
            s = snapshot();
        }
        if (listener != null) {
            listener.onStatus(s);
        }
    }
}
