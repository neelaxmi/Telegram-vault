package org.telegram.messenger.vault;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

/**
 * Fetches the newest key bundle from the server for a device that has no Vault yet (new phone, lost Keystore).
 * The result is NOT trusted until {@link VaultKeyManager#restoreFromBundle} opens it with the recovery key.
 */
public final class RemoteBundle {

    private RemoteBundle() {
    }

    /**
     * @return the bundle bytes of the highest {@code b.<n>} object, or null if the server has none
     * @throws VaultCryptoException IO_ERROR on network problems; CORRUPTED if the bundle has an invalid structure
     */
    public static byte[] fetchLatest(VaultRemoteStore remote) throws VaultCryptoException {
        VaultRemoteStore.Entry best = null;
        int bestVersion = -1;
        try {
            long after = 0;
            while (true) {
                List<VaultRemoteStore.Entry> page = remote.list(after, VaultSyncEngine.PAGE_SIZE);
                if (page == null || page.isEmpty()) {
                    break;
                }
                for (VaultRemoteStore.Entry e : page) {
                    if (e.seq <= after) {
                        throw new IOException("Server returned entries out of order");
                    }
                    after = e.seq;
                    if (e.name != null && e.name.startsWith("b.")) {
                        try {
                            long v = Long.parseLong(e.name.substring(2));
                            if (v >= 1 && v <= Integer.MAX_VALUE && v > bestVersion) {
                                bestVersion = (int) v;
                                best = e;
                            }
                        } catch (NumberFormatException ignored) {
                            // not one of ours
                        }
                    }
                }
            }
            if (best == null) {
                return null;
            }
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            OutputStream bounded = new OutputStream() {
                @Override
                public void write(int b) throws IOException {
                    if (out.size() >= VaultBundle.MAX_BUNDLE_BYTES) {
                        throw new IOException("Bundle too large");
                    }
                    out.write(b);
                }

                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    if (out.size() + len > VaultBundle.MAX_BUNDLE_BYTES) {
                        throw new IOException("Bundle too large");
                    }
                    out.write(b, off, len);
                }
            };
            remote.download(best.ref, bounded);
            byte[] bytes = out.toByteArray();
            VaultBundle.peek(bytes); // structure only; authenticity is checked when the recovery key opens it
            return bytes;
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not fetch the key bundle", e);
        }
    }
}
