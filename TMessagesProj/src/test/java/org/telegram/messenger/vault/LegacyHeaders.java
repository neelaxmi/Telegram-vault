package org.telegram.messenger.vault;

import java.util.Arrays;

/** Test helper: writes a version-1 header exactly as the Phase 1/2 code did, from the format description. */
final class LegacyHeaders {
    private LegacyHeaders() {
    }

    /** Writes a v1 header (device-wrapped) into {@code store} and returns the data key it holds. */
    static byte[] write(VaultHeaderStore store, DeviceKeyWrapper device, char[] password, int iterations) throws Exception {
        byte[] dataKey = VaultCrypto.randomBytes(32);
        write(store, device, password, iterations, dataKey);
        return dataKey;
    }

    static void write(VaultHeaderStore store, DeviceKeyWrapper device, char[] password, int iterations, byte[] dataKey) throws Exception {
        byte[] salt = VaultCrypto.randomBytes(16);
        byte[] inner = new byte[25 + 60];
        inner[0] = 'T';
        inner[1] = 'G';
        inner[2] = 'V';
        inner[3] = 'H';
        inner[4] = 1;
        inner[5] = (byte) (iterations >>> 24);
        inner[6] = (byte) (iterations >>> 16);
        inner[7] = (byte) (iterations >>> 8);
        inner[8] = (byte) iterations;
        System.arraycopy(salt, 0, inner, 9, 16);
        byte[] kek = VaultCrypto.deriveKey(password, salt, iterations);
        byte[] wrapped = VaultCrypto.encrypt(kek, dataKey, Arrays.copyOf(inner, 25));
        System.arraycopy(wrapped, 0, inner, 25, wrapped.length);
        store.write(device.wrap(inner));
    }
}
