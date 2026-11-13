package org.telegram.messenger.vault;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * The recovery secret the user writes down at setup. It is the only secret that can rebuild the
 * Vault Master Key on a new or reset device without another device's help.
 *
 * <h3>12-word recovery phrase (new vaults and new rotations)</h3>
 * 128 random bits are encoded as a standard BIP-39 mnemonic (12 words from the BIP-39 English list, the last
 * word carrying a 4-bit SHA-256 checksum that catches typing mistakes). The 256-bit secret that opens the
 * recovery slot is HKDF-SHA256 of those 128 bits, so the slot key is a full-length key and the phrase's
 * strength is its 128 random bits (the standard strength of a 12-word phrase).
 *
 * <h3>Legacy 54-character key (vaults created before the phrase; still fully supported)</h3>
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

    public static final int PHRASE_WORDS = 12;
    static final int ENTROPY_BYTES = 16;
    private static final byte[] PHRASE_INFO = "tg-vault/v3/recovery-phrase".getBytes(StandardCharsets.US_ASCII);

    private final byte[] key;
    /** The 128 bits behind a 12-word phrase; null for a legacy key. */
    private final byte[] entropy;

    private RecoveryKey(byte[] key) {
        this(key, null);
    }

    private RecoveryKey(byte[] key, byte[] entropy) {
        this.key = key;
        this.entropy = entropy;
    }

    /** A new random 12-word recovery phrase. */
    public static RecoveryKey generate() {
        byte[] entropy = VaultCrypto.randomBytes(ENTROPY_BYTES);
        try {
            return fromEntropy(entropy);
        } catch (VaultCryptoException e) {
            throw new IllegalStateException(e);
        } finally {
            VaultCrypto.wipe(entropy);
        }
    }

    /** A new random legacy 54-character key (only for tests of the legacy format). */
    static RecoveryKey generateLegacy() {
        return new RecoveryKey(VaultCrypto.randomBytes(KEY_BYTES));
    }

    /** The phrase for 16 given bytes (copied). Package-private so tests can use the BIP-39 vectors. */
    static RecoveryKey fromEntropy(byte[] entropy) throws VaultCryptoException {
        if (entropy == null || entropy.length != ENTROPY_BYTES) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Recovery phrase entropy must be 16 bytes");
        }
        byte[] key = VaultCrypto.hkdfSha256(entropy, new byte[0], PHRASE_INFO, KEY_BYTES);
        return new RecoveryKey(key, entropy.clone());
    }

    /** True if this is a 12-word phrase, false for a legacy key. */
    public boolean isPhrase() {
        return entropy != null;
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
        if (text == null || text.trim().isEmpty()) {
            throw bad("Recovery key is empty");
        }
        if (looksLikePhrase(text)) {
            return parsePhrase(text);
        }
        return parseLegacy(text);
    }

    /** Words only (no digits or dashes): anything that is not exactly 9 or 1 groups is meant as a phrase. */
    private static boolean looksLikePhrase(String text) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !Character.isWhitespace(c)) {
                return false;
            }
        }
        int words = text.trim().split("\\s+").length;
        return words == PHRASE_WORDS || (words > 1 && words != 9);
    }

    private static RecoveryKey parsePhrase(String text) throws VaultCryptoException {
        String[] words = text.trim().toLowerCase(java.util.Locale.ROOT).split("\\s+");
        if (words.length != PHRASE_WORDS) {
            throw bad("The recovery phrase must have exactly " + PHRASE_WORDS + " words");
        }
        byte[] bits = new byte[17]; // 132 bits
        for (int w = 0; w < PHRASE_WORDS; w++) {
            int index = Bip39Wordlist.indexOf(words[w]);
            if (index < 0) {
                throw bad("Word " + (w + 1) + " is not a valid recovery word; check the spelling");
            }
            for (int b = 0; b < 11; b++) {
                if (((index >> (10 - b)) & 1) != 0) {
                    int pos = w * 11 + b;
                    bits[pos / 8] |= (byte) (0x80 >> (pos % 8));
                }
            }
        }
        byte[] entropy = Arrays.copyOf(bits, ENTROPY_BYTES);
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(entropy);
            if ((hash[0] & 0xF0) != (bits[16] & 0xF0)) {
                throw bad("The recovery phrase checksum does not match; check the words and their order");
            }
            return fromEntropy(entropy);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        } finally {
            VaultCrypto.wipe(entropy);
            VaultCrypto.wipe(bits);
        }
    }

    private static RecoveryKey parseLegacy(String text) throws VaultCryptoException {
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
        if (entropy != null) {
            return formatPhrase();
        }
        return formatLegacy();
    }

    private String formatPhrase() {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(entropy);
            byte[] bits = Arrays.copyOf(entropy, 17);
            bits[16] = (byte) (hash[0] & 0xF0);
            StringBuilder sb = new StringBuilder();
            for (int w = 0; w < PHRASE_WORDS; w++) {
                int index = 0;
                for (int b = 0; b < 11; b++) {
                    int pos = w * 11 + b;
                    index = (index << 1) | ((bits[pos / 8] >> (7 - pos % 8)) & 1);
                }
                if (w > 0) {
                    sb.append(' ');
                }
                sb.append(Bip39Wordlist.WORDS[index]);
            }
            VaultCrypto.wipe(bits);
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    String formatLegacy() {
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
        if (entropy != null) {
            Arrays.fill(entropy, (byte) 0);
        }
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
