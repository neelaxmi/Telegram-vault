package org.telegram.messenger.vault;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Persistent, tamper-evident record of wrong-password attempts on THIS device, plus the "wipe after
 * {@link #WIPE_LIMIT} failures" switch. The state is wrapped with the device key (Android Keystore), so editing the
 * file is detected; it is readable while the Vault is locked because it must be updated on every attempt.
 *
 * <p>Honest limits (also for SECURITY.md): an attacker who can delete the file or restore an older copy can reset
 * the counter, and an attacker with root on a running device can do much worse. The counter defends against
 * someone guessing at the unlock screen of the app, not against someone who owns the phone's storage.
 */
final class AttemptTracker {

    static final int WIPE_LIMIT = 5;
    private static final byte[] MAGIC = {'T', 'G', 'V', 'A'};
    private static final byte VERSION = 1;

    /** Mutable snapshot; copy-in/copy-out so callers cannot corrupt the persisted copy by accident. */
    static final class State {
        boolean wipeEnabled;
        /** Wrong attempts since the last successful unlock; drives the wipe. */
        int consecutive;
        /** Wrong attempts not yet shown to the user (cleared by {@link #acknowledge}). */
        int unseen;
        long unseenLastMillis;
        /** The stored state was unreadable/tampered with and was replaced by a cautious one. */
        boolean damaged;

        State copy() {
            State s = new State();
            s.wipeEnabled = wipeEnabled;
            s.consecutive = consecutive;
            s.unseen = unseen;
            s.unseenLastMillis = unseenLastMillis;
            s.damaged = damaged;
            return s;
        }
    }

    private final VaultHeaderStore store;
    private final DeviceKeyWrapper device;

    AttemptTracker(VaultHeaderStore store, DeviceKeyWrapper device) {
        if (store == null || device == null) {
            throw new IllegalArgumentException("arguments required");
        }
        this.store = store;
        this.device = device;
    }

    /**
     * Missing file: fresh state. Present but unreadable (edited, wrong device key): one wrong attempt away from the
     * limit, so damaging the file is never better for an attacker than leaving it alone.
     */
    synchronized State load() throws VaultCryptoException {
        if (!store.exists()) {
            return new State();
        }
        try {
            byte[] wrapped = store.read();
            if (wrapped.length < MAGIC.length + 1) {
                return cautious();
            }
            for (int i = 0; i < MAGIC.length; i++) {
                if (wrapped[i] != MAGIC[i]) {
                    return cautious();
                }
            }
            if (wrapped[MAGIC.length] != VERSION) {
                return cautious();
            }
            byte[] plain = device.unwrap(Arrays.copyOfRange(wrapped, MAGIC.length + 1, wrapped.length));
            try {
                if (plain.length != 1 + 4 + 4 + 8) {
                    return cautious();
                }
                ByteBuffer b = ByteBuffer.wrap(plain);
                State s = new State();
                s.wipeEnabled = b.get() == 1;
                s.consecutive = b.getInt();
                s.unseen = b.getInt();
                s.unseenLastMillis = b.getLong();
                if (s.consecutive < 0 || s.unseen < 0 || s.consecutive > 1_000_000 || s.unseen > 1_000_000) {
                    return cautious();
                }
                return s;
            } finally {
                VaultCrypto.wipe(plain);
            }
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not read attempt state", e);
        } catch (VaultCryptoException e) {
            if (e.getReason() == VaultCryptoException.Reason.IO_ERROR) {
                throw e;
            }
            return cautious();
        }
    }

    private static State cautious() {
        State s = new State();
        s.wipeEnabled = true; // we cannot know the user's choice; being strict is the safe direction
        s.consecutive = WIPE_LIMIT - 1;
        s.unseen = 1;
        s.damaged = true;
        return s;
    }

    synchronized void save(State s) throws VaultCryptoException {
        ByteBuffer b = ByteBuffer.allocate(1 + 4 + 4 + 8);
        b.put((byte) (s.wipeEnabled ? 1 : 0));
        b.putInt(s.consecutive);
        b.putInt(s.unseen);
        b.putLong(s.unseenLastMillis);
        byte[] plain = b.array();
        try {
            byte[] wrapped = device.wrap(plain);
            byte[] out = new byte[MAGIC.length + 1 + wrapped.length];
            System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
            out[MAGIC.length] = VERSION;
            System.arraycopy(wrapped, 0, out, MAGIC.length + 1, wrapped.length);
            store.write(out);
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not save attempt state", e);
        } finally {
            VaultCrypto.wipe(plain);
        }
    }

    synchronized void delete() throws VaultCryptoException {
        try {
            store.delete();
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not delete attempt state", e);
        }
    }
}
