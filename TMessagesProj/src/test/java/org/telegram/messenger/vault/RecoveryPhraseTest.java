package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;

/** The 12-word BIP-39 recovery phrase, and compatibility with legacy 54-character keys. */
public class RecoveryPhraseTest {

    private static byte[] bytes(int len, int fill) {
        byte[] b = new byte[len];
        java.util.Arrays.fill(b, (byte) fill);
        return b;
    }

    @Test
    public void wordlist_isTheCanonicalBip39EnglishList() throws Exception {
        assertEquals(2048, Bip39Wordlist.WORDS.length);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (String w : Bip39Wordlist.WORDS) {
            md.update((w + "\n").getBytes("US-ASCII"));
        }
        StringBuilder hex = new StringBuilder();
        for (byte b : md.digest()) {
            hex.append(String.format("%02x", b));
        }
        assertEquals("2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda", hex.toString());
        assertEquals("abandon", Bip39Wordlist.WORDS[0]);
        assertEquals("zoo", Bip39Wordlist.WORDS[2047]);
        Set<String> unique = new HashSet<>(java.util.Arrays.asList(Bip39Wordlist.WORDS));
        assertEquals(2048, unique.size());
    }

    @Test
    public void bip39TestVectors_encodeExactly() throws Exception {
        assertEquals("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                RecoveryKey.fromEntropy(bytes(16, 0x00)).format());
        assertEquals("legal winner thank year wave sausage worth useful legal winner thank yellow",
                RecoveryKey.fromEntropy(bytes(16, 0x7f)).format());
        assertEquals("letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
                RecoveryKey.fromEntropy(bytes(16, 0x80)).format());
        assertEquals("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
                RecoveryKey.fromEntropy(bytes(16, 0xff)).format());
    }

    @Test
    public void generate_givesTwelveValidWords_andRoundTrips() throws Exception {
        for (int i = 0; i < 200; i++) {
            RecoveryKey k = RecoveryKey.generate();
            assertTrue(k.isPhrase());
            String text = k.format();
            assertEquals(12, text.split(" ").length);
            RecoveryKey back = RecoveryKey.parse(text);
            assertTrue(back.isPhrase());
            assertTrue(k.sameKeyAs(back));
            assertArrayEquals(k.toBytes(), back.toBytes());
            assertEquals(32, k.toBytes().length);
        }
    }

    @Test
    public void generate_isRandom() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            seen.add(RecoveryKey.generate().format());
        }
        assertEquals(100, seen.size());
    }

    @Test
    public void parse_ignoresCaseAndExtraWhitespace() throws Exception {
        RecoveryKey k = RecoveryKey.generate();
        String messy = "  " + k.format().toUpperCase().replace(" ", " \n  ") + " \t";
        assertTrue(k.sameKeyAs(RecoveryKey.parse(messy)));
    }

    @Test
    public void parse_rejectsWrongWordCount() {
        String eleven = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        String thirteen = eleven + " about about";
        for (String bad : new String[]{eleven, thirteen}) {
            try {
                RecoveryKey.parse(bad);
                fail("accepted " + bad);
            } catch (VaultCryptoException e) {
                assertEquals(VaultCryptoException.Reason.INVALID_ARGUMENT, e.getReason());
            }
        }
    }

    @Test
    public void parse_rejectsUnknownWord_withoutEchoingTheWords() {
        String text = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandoon";
        try {
            RecoveryKey.parse(text);
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_ARGUMENT, e.getReason());
            assertFalse(e.getMessage().contains("abandoon"));
            assertTrue(e.getMessage().contains("12"));
        }
    }

    @Test
    public void parse_rejectsBadChecksum_andSwappedWords() throws Exception {
        // last word wrong: valid words, invalid checksum
        try {
            RecoveryKey.parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon");
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_ARGUMENT, e.getReason());
        }
        // swapping two different words is a different phrase: either bad checksum or a different key, never the same key
        RecoveryKey k = RecoveryKey.generate();
        String[] w = k.format().split(" ");
        for (int i = 0; i + 1 < w.length; i++) {
            if (w[i].equals(w[i + 1])) {
                continue;
            }
            String[] s = w.clone();
            s[i] = w[i + 1];
            s[i + 1] = w[i];
            try {
                assertFalse(k.sameKeyAs(RecoveryKey.parse(String.join(" ", s))));
            } catch (VaultCryptoException expected) {
                assertEquals(VaultCryptoException.Reason.INVALID_ARGUMENT, expected.getReason());
            }
        }
    }

    @Test
    public void everySingleWordChange_isCaughtOrDifferentKey() throws Exception {
        RecoveryKey k = RecoveryKey.parse("legal winner thank year wave sausage worth useful legal winner thank yellow");
        String[] w = k.format().split(" ");
        int caught = 0;
        for (int pos = 0; pos < 12; pos++) {
            for (int idx = 0; idx < 2048; idx += 37) {
                if (Bip39Wordlist.WORDS[idx].equals(w[pos])) {
                    continue;
                }
                String[] c = w.clone();
                c[pos] = Bip39Wordlist.WORDS[idx];
                try {
                    assertFalse(k.sameKeyAs(RecoveryKey.parse(String.join(" ", c))));
                } catch (VaultCryptoException e) {
                    caught++;
                }
            }
        }
        assertTrue("checksum should catch most single-word mistakes", caught > 200);
    }

    @Test
    public void toString_isRedacted() {
        RecoveryKey k = RecoveryKey.generate();
        assertFalse(k.toString().contains(k.format().split(" ")[0] + " "));
        assertEquals("RecoveryKey[redacted]", k.toString());
    }

    // ------------------------------------------------------------ existing recovery keys keep working

    @Test
    public void legacyKey_stillParsesAndFormatsIdentically() throws Exception {
        for (int i = 0; i < 50; i++) {
            RecoveryKey legacy = RecoveryKey.generateLegacy();
            assertFalse(legacy.isPhrase());
            String text = legacy.format();
            assertEquals(54 + 8, text.length());
            RecoveryKey back = RecoveryKey.parse(text);
            assertFalse(back.isPhrase());
            assertTrue(legacy.sameKeyAs(back));
            // typed without dashes, lower case, with spaces
            assertTrue(legacy.sameKeyAs(RecoveryKey.parse(text.toLowerCase().replace('-', ' '))));
            assertTrue(legacy.sameKeyAs(RecoveryKey.parse(text.replace("-", ""))));
        }
    }

    @Test
    public void legacyKey_opensAnExistingBundle_andPhraseDoesNot() throws Exception {
        RecoveryKey legacy = RecoveryKey.generateLegacy();
        byte[] vmk = VaultCrypto.randomBytes(32);
        byte[] vaultId = VaultCrypto.randomBytes(16);
        byte[] bundle = VaultBundle.create(vmk, vaultId, 1, legacy);
        // the user types the old key text on a new phone
        assertArrayEquals(vmk, VaultBundle.openWithRecoveryKey(bundle, RecoveryKey.parse(legacy.format())));
        try {
            VaultBundle.openWithRecoveryKey(bundle, RecoveryKey.generate());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.WRONG_RECOVERY_KEY, e.getReason());
        }
    }

    @Test
    public void phrase_opensItsBundle_viaTypedWords() throws Exception {
        RecoveryKey k = RecoveryKey.generate();
        byte[] vmk = VaultCrypto.randomBytes(32);
        byte[] bundle = VaultBundle.create(vmk, VaultCrypto.randomBytes(16), 3, k);
        assertArrayEquals(vmk, VaultBundle.openWithRecoveryKey(bundle, RecoveryKey.parse(k.format())));
        assertNotEquals(k.format(), RecoveryKey.generate().format());
    }

    @Test
    public void recoveryKeyOutputLength_isFullStrengthSlotKey() throws Exception {
        // 128 bits of phrase entropy are expanded to a 256-bit slot key, different for different phrases
        byte[] a = RecoveryKey.fromEntropy(bytes(16, 1)).toBytes();
        byte[] b = RecoveryKey.fromEntropy(bytes(16, 2)).toBytes();
        assertEquals(32, a.length);
        assertFalse(java.util.Arrays.equals(a, b));
        // and not simply the entropy repeated
        assertFalse(java.util.Arrays.equals(java.util.Arrays.copyOf(a, 16), bytes(16, 1)));
    }
}
