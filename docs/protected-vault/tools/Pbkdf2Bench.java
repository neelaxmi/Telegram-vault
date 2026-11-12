package org.telegram.messenger.vault;

/**
 * Times the Vault's password stretching. Run it on the PHONE (e.g. from a debug build or an instrumented test)
 * to choose an iteration count; numbers from a PC or server say little about a phone.
 * Usage: java -cp <classes> org.telegram.messenger.vault.Pbkdf2Bench
 */
public final class Pbkdf2Bench {
    public static void main(String[] args) throws Exception {
        char[] pw = "benchmark password 123".toCharArray();
        byte[] salt = new byte[VaultCrypto.SALT_BYTES];
        int[] counts = {100_000, 300_000, VaultCrypto.DEFAULT_PBKDF2_ITERATIONS, 1_000_000, 2_000_000};
        VaultCrypto.deriveKey(pw, salt, 50_000); // warm-up
        for (int n : counts) {
            long best = Long.MAX_VALUE;
            for (int i = 0; i < 3; i++) {
                long t = System.nanoTime();
                VaultCrypto.deriveKey(pw, salt, n);
                best = Math.min(best, System.nanoTime() - t);
            }
            System.out.printf("%,10d iterations: %6.0f ms (best of 3)%n", n, best / 1e6);
        }
    }
}
