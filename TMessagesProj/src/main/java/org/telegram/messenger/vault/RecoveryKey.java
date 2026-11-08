package org.telegram.messenger.vault;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * The 256-bit recovery key the user writes down at setup. It is the only secret that can rebuild the
 * Vault Master Key on a new or reset device without another device's help.
 *
 * <h3>Text form</h3>
 * 52 Crockford-base32 characters for the 256 key bits, plus 2 check characters, shown as nine groups of
 * six: {@code XXXXXX-XXXXXX-...}. The check characters catch typing mistakes (they are not a security
 * feature; the key's strength is its 256 random bits). Parsing ignores case, spaces and dashes and maps
 * the look-alikes O to 0 and I/L to 1, as Crockford base32 does.
 */
public final class RecoveryKey {

    public static final int KEY_BYTES = 32;
    /** 52 key characters + 2 check characters. */
    static final int TEXT_CHARS = 54;
    private static final int KEY_CHARS = 52;
    private static final int GROUP = 6;
    private static final String ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private static final byte[] CHECK_CONTEXT = "tg-vault/v2/recovery-check".getBytes(StandardCharsets.US_ASCII);

    private final byte[] key;

    private RecoveryKey(byte[] key) {
        this.key = key;
    }

    public static RecoveryKey generate() {
        return new RecoveryKey(VaultCrypto.randomBytes(KEY_BYTES));
    }

    /** Wraps raw key bytes (copied). */
    static RecoveryKey fromBytes(byte[] bytes) throws VaultCryptoException {
        if (bytes == null || bytes.length != KEY_BYTES) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Recovery key must be 32 bytes");
        }
        return new RecoveryKey(bytes.clone());
    }

    /**
     * Parses user-typed text.
     *
     * @throws VaultCryptoException INVALID_ARGUMENT if the length, characters or check characters are wrong
     */
    public static RecoveryKey parse(String text) throws VaultCryptoException {
        if (text == null) {
            throw bad("Recovery key is empty");
        }
        int[] values = new int[TEXT_CHARS];
        int count = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = Character.toUpperCase(text.charAt(i));
            if (c == '-' || c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                continue;
            }
            if (c == 'O') {
                c = '0';
            } else if (c == 'I' || c == 'L') {
                c = '1';
            }
            int v = ALPHABET.indexOf(c);
            if (v < 0 || count >= TEXT_CHARS) {
                throw bad("Recovery key contains an invalid character or is too long");
            }
            values[count++] = v;
        }
        if (count != TEXT_CHARS) {
            throw bad("Recovery key has the wrong length");
        }
        // Rebuild 260 bits; the last 4 bits of the 52nd character must be zero (canonical form).
        byte[] key = new byte[KEY_BYTES];
        int bitBuffer = 0;
        int bits = 0;
        int out = 0;
        for (int i = 0; i < KEY_CHARS; i++) {
            bitBuffer = (bitBuffer << 5) | values[i];
            bits += 5;
            while (bits >= 8 && out < KEY_BYTES) {
                bits -= 8;
                key[out++] = (byte) (bitBuffer >> bits);
                bitBuffer &= (1 << bits) - 1;
            }
        }
        if (out != KEY_BYTES || bitBuffer != 0) {
            VaultCrypto.wipe(key);
            throw bad("Recovery key is not in canonical form");
        }
        int[] expected = checkValues(key);
        if (expected[0] != values[KEY_CHARS] || expected[1] != values[KEY_CHARS + 1]) {
            VaultCrypto.wipe(key);
            throw bad("Recovery key check characters do not match; check for typing mistakes");
        }
        return new RecoveryKey(key);
    }

    /** The key in its displayed form. The caller must not log it. */
    public String format() {
        StringBuilder sb = new StringBuilder(TEXT_CHARS + TEXT_CHARS / GROUP);
        StringBuilder chars = new StringBuilder(TEXT_CHARS);
        int bitBuffer = 0;
        int bits = 0;
        for (byte b : key) {
            bitBuffer = (bitBuffer << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                chars.append(ALPHABET.charAt((bitBuffer >> bits) & 31));
            }
            bitBuffer &= (1 << bits) - 1;
        }
        if (bits > 0) {
            chars.append(ALPHABET.charAt((bitBuffer << (5 - bits)) & 31));
        }
        int[] check = checkValues(key);
        chars.append(ALPHABET.charAt(check[0])).append(ALPHABET.charAt(check[1]));
        for (int i = 0; i < chars.length(); i++) {
            if (i > 0 && i % GROUP == 0) {
                sb.append('-');
            }
            sb.append(chars.charAt(i));
        }
        return sb.toString();
    }

    /** A copy of the raw key bytes; the caller should wipe it. */
    public byte[] toBytes() {
        return key.clone();
    }

    public boolean sameKeyAs(RecoveryKey other) {
        return other != null && VaultCrypto.constantTimeEquals(key, other.key);
    }

    public void wipe() {
        Arrays.fill(key, (byte) 0);
    }

    @Override
    public String toString() {
        return "RecoveryKey[redacted]";
    }

    private static int[] checkValues(byte[] key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(CHECK_CONTEXT);
            byte[] d = md.digest(key);
            int ten = ((d[0] & 0xFF) << 2) | ((d[1] & 0xFF) >> 6);
            return new int[]{(ten >> 5) & 31, ten & 31};
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static VaultCryptoException bad(String message) {
        return new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, message);
    }
}
