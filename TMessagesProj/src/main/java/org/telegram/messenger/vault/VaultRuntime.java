package org.telegram.messenger.vault;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.FileLog;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Wires the Vault components together for one Telegram account on Android. One instance per account; everything
 * lives under {@code <files>/vault/<account>/} and uses its own Keystore alias, so wiping or resetting one account's
 * Vault never touches another's.
 *
 * <p><b>STATUS: type-checked against the real Telegram classes only; never run on a device.</b>
 *
 * <p>Threading: Vault operations (crypto, disk, network) must run on {@link #io()}; only view updates belong on the
 * UI thread. The inactivity timer runs on the UI thread and is active only while the Vault is unlocked.
 */
public final class VaultRuntime {

    private static final VaultRuntime[] INSTANCES = new VaultRuntime[16];
    private static final long TICK_MILLIS = 5_000;

    public final int account;
    public final VaultKeyManager keys;
    public final VaultAccess access;
    public final VaultStore store;
    public final AutoLock autoLock;
    private final File dir;
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final ExecutorService linkIo = Executors.newSingleThreadExecutor();
    /** Unlock and "save while locked" get their own threads so they never wait behind a long network sync on {@link #io()}. */
    private final ExecutorService unlockIo = Executors.newSingleThreadExecutor();
    private final ExecutorService inboxIo = Executors.newSingleThreadExecutor();
    /** Write-only ingestion for messages saved while the Vault is locked (see {@link VaultInbox}). */
    public final VaultInbox inbox;
    private volatile Runnable onInboxDrained;
    private volatile VaultSyncEngine engine;
    private volatile VaultRemoteStore remote;
    private volatile SyncCoordinator.Listener uiListener;
    private volatile SyncCoordinator coordinator;
    private volatile Runnable onLockedUi;
    private boolean ticking;

    public static synchronized VaultRuntime get(int account) {
        if (account < 0 || account >= INSTANCES.length) {
            throw new IllegalArgumentException("bad account");
        }
        if (INSTANCES[account] == null) {
            INSTANCES[account] = new VaultRuntime(account);
        }
        return INSTANCES[account];
    }

    private VaultRuntime(int account) {
        this.account = account;
        this.dir = ApplicationLoader.getFilesDirFixed("vault/" + account);
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        DeviceKeyWrapper wrapper = new AndroidKeystoreDeviceKeyWrapper(
                new AndroidKeystoreSecretStore(AndroidKeystoreSecretStore.DEFAULT_ALIAS + "_" + account));
        keys = new VaultKeyManager(new FileVaultHeaderStore(new File(dir, "header.bin")), wrapper);
        store = new VaultStore(new File(dir, "data"), keys);
        inbox = new VaultInbox(new File(dir, "inbox"), wrapper);
        access = new VaultAccess(keys, new FileVaultHeaderStore(new File(dir, "attempts.bin")), wrapper,
                VaultAccess.localWipe(keys, store, inbox), new VaultStore.Clock() {
                    @Override
                    public long nowMillis() {
                        return System.currentTimeMillis();
                    }
                });
        autoLock = new AutoLock(keys, new Runnable() {
            @Override
            public void run() {
                locked();
            }
        }, new VaultStore.Clock() {
            @Override
            public long nowMillis() {
                return SystemClock.elapsedRealtime(); // monotonic: wall-clock changes cannot extend an unlocked period
            }
        });
        loadAutoLockSettings();
    }

    // The lock settings hold no secrets; they are kept so that a shorter timeout the user chose survives a restart.
    private SharedPreferences settings() {
        return ApplicationLoader.applicationContext.getSharedPreferences("vault_settings_" + account, Context.MODE_PRIVATE);
    }

    private void loadAutoLockSettings() {
        SharedPreferences p = settings();
        autoLock.setLockOnBackground(p.getBoolean("lock_on_background", true));
        try {
            autoLock.setInactivityMillis(p.getLong("inactivity_millis", AutoLock.DEFAULT_INACTIVITY_MILLIS));
        } catch (IllegalArgumentException e) {
            // an out-of-range stored value falls back to the default
        }
    }

    /** Persists the current auto-lock settings. */
    public void saveAutoLockSettings() {
        settings().edit()
                .putBoolean("lock_on_background", autoLock.isLockOnBackground())
                .putLong("inactivity_millis", autoLock.getInactivityMillis())
                .apply();
    }

    public ExecutorService unlockIo() {
        return unlockIo;
    }

    public ExecutorService inboxIo() {
        return inboxIo;
    }

    /** Called on the UI thread when items saved while locked have been moved into the open Vault. */
    public void setOnInboxDrained(Runnable r) {
        onInboxDrained = r;
    }

    public ExecutorService io() {
        return io;
    }

    /** Separate thread for device linking: it waits for the other phone for minutes and must not block syncing. */
    public ExecutorService linkIo() {
        return linkIo;
    }

    /** Where link helper files go. */
    public File workDir() {
        return dir;
    }

    /** The whole app went to the background (called by the main activity). Locks if "lock when I leave the app" is on. */
    public static void appBackground(int account) {
        VaultRuntime rt = get(account);
        if (rt.keys.isUnlocked()) {
            rt.autoLock.onBackground();
        }
    }

    /** The app came back: locks first if the time away was too long. */
    public static void appForeground(int account) {
        VaultRuntime rt = get(account);
        if (rt.keys.isUnlocked()) {
            rt.autoLock.onForeground();
        }
    }

    /** Any touch anywhere in the app: keeps the inactivity timer from locking a Vault that is in use. */
    public static void touched(int account) {
        VaultRuntime rt = get(account);
        if (rt.keys.isUnlocked()) {
            rt.autoLock.userActivity();
        }
    }

    /** Called (on the UI thread) when the Vault locks itself or is locked manually, so open screens can close. */
    public void setOnLockedUi(Runnable r) {
        onLockedUi = r;
    }

    /** The sync engine for this account, created on first use. Needs the private channel; see {@link #attachChannel}. */
    public synchronized VaultSyncEngine engine() {
        return engine;
    }

    /** The channel-backed remote store (after {@link #attachChannel}); also used to fetch the key bundle on a new device. */
    public synchronized VaultRemoteStore remote() {
        return remote;
    }

    public synchronized SyncCoordinator coordinator() {
        return coordinator;
    }

    /** Where sync status goes (the open Vault screen); may change while the engine lives on. */
    public void setSyncListener(SyncCoordinator.Listener listener) {
        uiListener = listener;
    }

    /**
     * Builds the engine on top of the Vault channel. Blocking: call on {@link #io()}.
     *
     * @param allowCreate create the channel if none exists. Never allowed before the chat list has loaded, so a new
     *                    phone cannot create a second channel just because the first one is not loaded yet.
     */
    public synchronized void attachChannel(SyncCoordinator.Listener listener, boolean allowCreate) throws IOException {
        if (listener != null) {
            uiListener = listener;
        }
        if (engine != null) {
            return;
        }
        TelegramVaultChannel.Ref ref = TelegramVaultChannel.find(account);
        if (ref == null) {
            if (!TelegramVaultChannel.chatsLoaded(account)) {
                throw new IOException("Your chats are still loading. Try again in a moment.");
            }
            if (!allowCreate) {
                throw new IOException("No Vault channel was found in your Telegram account.");
            }
            ref = TelegramVaultChannel.create(account);
        }
        remote = new ChannelRemoteStore(new TelegramChannelApi(account, ref.channelId, ref.accessHash),
                VaultStore.DEFAULT_MAX_UPLOAD_BYTES + 4096);
        engine = new VaultSyncEngine(store, keys, remote, new File(dir, "sync.journal"));
        coordinator = new SyncCoordinator(engine, io, new SyncCoordinator.Listener() {
            @Override
            public void onStatus(SyncCoordinator.Status status) {
                SyncCoordinator.Listener l = uiListener;
                if (l != null) {
                    l.onStatus(status);
                }
            }
        });
    }

    // ------------------------------------------------------------------ unlock / lock lifecycle

    /** Call on the UI thread right after a successful unlock. */
    public void unlocked() {
        try {
            // A crash in the middle of a key rotation is finished (or rolled back) before anything reads the data.
            VaultSyncEngine.recoverRotation(store, keys, new File(dir, "sync.journal"));
        } catch (VaultCryptoException e) {
            FileLog.e("Vault: could not recover an interrupted key rotation: " + e.getReason());
        }
        autoLock.onUnlocked();
        startTicking();
        // Items saved while locked wait in the sealed inbox; move them into the Vault now (off the UI thread).
        unlockIo.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    inbox.ensureKeyPair(keys); // new and upgraded vaults get their inbox key at the first unlock
                    VaultInbox.DrainReport r = inbox.drain(keys, store);
                    if (r.failed > 0) {
                        FileLog.e("Vault: " + r.failed + " inbox item(s) could not be opened and were kept aside");
                    }
                    if (r.moved > 0) {
                        FileLog.d("Vault: moved " + r.moved + " inbox item(s) into the Vault");
                        SyncCoordinator c = coordinator();
                        if (c != null) {
                            c.requestSync(false); // otherwise the next sync picks the new items up
                        }
                        final Runnable cb = onInboxDrained;
                        if (cb != null) {
                            AndroidUtilities.runOnUIThread(cb);
                        }
                    }
                } catch (VaultCryptoException e) {
                    FileLog.e("Vault: inbox step failed: " + e.getReason());
                }
            }
        });
    }

    private void startTicking() {
        if (ticking) {
            return;
        }
        ticking = true;
        AndroidUtilities.runOnUIThread(tick, TICK_MILLIS);
    }

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            if (autoLock.tick()) {
                ticking = false; // tick() locked or it was locked already; callback handled the UI
                return;
            }
            AndroidUtilities.runOnUIThread(this, TICK_MILLIS);
        }
    };

    private void locked() {
        // AutoLock calls this once per lock, from whichever thread triggered it.
        final Runnable r = onLockedUi;
        if (r != null) {
            AndroidUtilities.runOnUIThread(r);
        }
    }

    public void lockNow() {
        autoLock.lockNow();
    }
}
