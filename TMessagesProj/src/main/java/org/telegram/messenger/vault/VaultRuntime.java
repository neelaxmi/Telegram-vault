package org.telegram.messenger.vault;

import android.os.SystemClock;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;

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
        access = new VaultAccess(keys, new FileVaultHeaderStore(new File(dir, "attempts.bin")), wrapper,
                VaultAccess.localWipe(keys, store), new VaultStore.Clock() {
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
        autoLock.onUnlocked();
        startTicking();
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
