package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

public class RecoveryKeyTest {

    /** Produced by an independent Python implementation of the format (bytes 0x40..0x5f). */
    private static final String PY_TEXT = "810M4G-T48N34-EJ2999-5MRKAE-9X852M-JKAHAN-CNTRB5-D5PQ2X-BSFGY6";
    private static final String PY_ZERO = "000000-000000-000000-000000-000000-000000-000000-000000-0000CK";
    private static final String ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    private static byte[] seq(int start) {
        byte[] b = new byte[32];
        for (int i = 0; i < 32; i++) {
            b[i] = (byte) (start + i);
        }
        return b;
    }

    private interface Action {
        void run() throws Exception;
    }

    private static void assertInvalid(Action a) {
        try {
            a.run();
            fail("expected INVALID_ARGUMENT");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_ARGUMENT, e.getReason());
        } catch (Exception e) {
            fail("unexpected " + e);
        }
    }

    @Test
    public void format_matchesIndependentPythonImplementation() throws Exception {
        assertEquals(PY_TEXT, RecoveryKey.fromBytes(seq(0x40)).format());
        assertEquals(PY_ZERO, RecoveryKey.fromBytes(new byte[32]).format());
    }

    @Test
    public void parse_readsPythonGeneratedText() throws Exception {
        assertArrayEquals(seq(0x40), RecoveryKey.parse(PY_TEXT).toBytes());
        assertArrayEquals(new byte[32], RecoveryKey.parse(PY_ZERO).toBytes());
    }

    @Test
    public void format_shapeIsNineGroupsOfSixFromTheCrockfordAlphabet() {
        String text = RecoveryKey.generate().format();
        assertEquals(54 + 8, text.length());
        String[] groups = text.split("-");
        assertEquals(9, groups.length);
        for (String g : groups) {
            assertEquals(6, g.length());
            for (char c : g.toCharArray()) {
                assertTrue("char " + c, ALPHABET.indexOf(c) >= 0);
            }
        }
    }

    @Test
    public void roundTrip_manyRandomKeys() throws Exception {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 300; i++) {
            RecoveryKey key = RecoveryKey.generate();
            String text = key.format();
            assertTrue("keys must not repeat", seen.add(text));
            RecoveryKey back = RecoveryKey.parse(text);
            assertTrue(key.sameKeyAs(back));
            assertArrayEquals(key.toBytes(), back.toBytes());
            assertEquals(text, back.format());
        }
    }

    @Test
    public void roundTrip_extremeKeys() throws Exception {
        byte[] ff = new byte[32];
        java.util.Arrays.fill(ff, (byte) 0xFF);
        for (byte[] raw : new byte[][]{new byte[32], ff, seq(0), seq(0xE0)}) {
            assertArrayEquals(raw, RecoveryKey.parse(RecoveryKey.fromBytes(raw).format()).toBytes());
        }
    }

    @Test
    public void parse_toleratesCaseSpacesDashesAndLookAlikes() throws Exception {
        assertArrayEquals(seq(0x40), RecoveryKey.parse(PY_TEXT.toLowerCase()).toBytes());
        assertArrayEquals(seq(0x40), RecoveryKey.parse(PY_TEXT.replace("-", "")).toBytes());
        assertArrayEquals(seq(0x40), RecoveryKey.parse("  " + PY_TEXT.replace("-", " ") + "\n").toBytes());
        // O reads as 0 and I/L read as 1 (the text contains '0' and '1' characters).
        assertArrayEquals(new byte[32], RecoveryKey.parse(PY_ZERO.replace('0', 'O')).toBytes());
        String withOne = RecoveryKey.fromBytes(seq(0x01)).format();
        assertTrue(withOne.indexOf('1') >= 0);
        assertArrayEquals(seq(0x01), RecoveryKey.parse(withOne.replace('1', 'l')).toBytes());
        assertArrayEquals(seq(0x01), RecoveryKey.parse(withOne.replace('1', 'I')).toBytes());
    }

    @Test
    public void parse_rejectsWrongLengthInvalidCharactersAndNull() {
        assertInvalid(() -> RecoveryKey.parse(null));
        assertInvalid(() -> RecoveryKey.parse(""));
        assertInvalid(() -> RecoveryKey.parse(PY_TEXT.substring(0, PY_TEXT.length() - 1)));
        assertInvalid(() -> RecoveryKey.parse(PY_TEXT + "0"));
        assertInvalid(() -> RecoveryKey.parse(PY_TEXT.replace('8', 'U'))); // U is not in the alphabet
        assertInvalid(() -> RecoveryKey.parse(PY_TEXT.replace('8', '!')));
        assertInvalid(() -> RecoveryKey.parse(PY_TEXT + PY_TEXT));
    }

    @Test
    public void parse_rejectsNonCanonicalTrailingBits() {
        // The 52nd character carries only 1 key bit; any other low bits make a different, non-canonical text.
        char[] chars = PY_TEXT.replace("-", "").toCharArray();
        char last = chars[51];
        int v = ALPHABET.indexOf(last);
        chars[51] = ALPHABET.charAt(v ^ 1);
        assertInvalid(() -> RecoveryKey.parse(new String(chars)));
    }

    @Test
    public void parse_typingMistakesAreCaughtByCheckCharacters() throws Exception {
        String plain = PY_TEXT.replace("-", "");
        int accepted = 0;
        int tried = 0;
        for (int pos = 0; pos < plain.length(); pos++) {
            for (int a = 0; a < 32; a++) {
                char replacement = ALPHABET.charAt(a);
                if (replacement == plain.charAt(pos)) {
                    continue;
                }
                char[] c = plain.toCharArray();
                c[pos] = replacement;
                tried++;
                try {
                    RecoveryKey.parse(new String(c));
                    accepted++;
                } catch (VaultCryptoException e) {
                    assertEquals(VaultCryptoException.Reason.INVALID_ARGUMENT, e.getReason());
                }
            }
        }
        assertEquals(54 * 31, tried);
        // A 10-bit check lets about 1 in 1024 single-character mistakes through; far fewer than 1%.
        assertTrue("accepted " + accepted + " of " + tried, accepted <= 6);
    }

    @Test
    public void parse_everyAdjacentSwapIsCaughtOrIdentical() throws Exception {
        String plain = PY_TEXT.replace("-", "");
        int accepted = 0;
        for (int pos = 0; pos + 1 < plain.length(); pos++) {
            if (plain.charAt(pos) == plain.charAt(pos + 1)) {
                continue;
            }
            char[] c = plain.toCharArray();
            char t = c[pos];
            c[pos] = c[pos + 1];
            c[pos + 1] = t;
            try {
                RecoveryKey.parse(new String(c));
                accepted++;
            } catch (VaultCryptoException e) {
                assertEquals(VaultCryptoException.Reason.INVALID_ARGUMENT, e.getReason());
            }
        }
        assertTrue("accepted swaps: " + accepted, accepted <= 1);
    }

    @Test
    public void fromBytes_validatesLength() {
        assertInvalid(() -> RecoveryKey.fromBytes(null));
        assertInvalid(() -> RecoveryKey.fromBytes(new byte[31]));
        assertInvalid(() -> RecoveryKey.fromBytes(new byte[33]));
    }

    @Test
    public void toBytes_returnsCopies_andWipeZeroesTheKey() throws Exception {
        RecoveryKey key = RecoveryKey.fromBytes(seq(5));
        byte[] copy = key.toBytes();
        java.util.Arrays.fill(copy, (byte) 0);
        assertArrayEquals(seq(5), key.toBytes());
        key.wipe();
        assertArrayEquals(new byte[32], key.toBytes());
        assertFalse(key.sameKeyAs(RecoveryKey.fromBytes(seq(5))));
    }

    @Test
    public void toString_neverShowsTheKey() throws Exception {
        RecoveryKey key = RecoveryKey.fromBytes(seq(0x40));
        assertFalse(key.toString().contains("810M4G"));
        assertEquals("RecoveryKey[redacted]", key.toString());
    }

    @Test
    public void sameKeyAs_handlesNullAndDifferentKeys() throws Exception {
        RecoveryKey a = RecoveryKey.fromBytes(seq(1));
        assertFalse(a.sameKeyAs(null));
        assertFalse(a.sameKeyAs(RecoveryKey.fromBytes(seq(2))));
        assertTrue(a.sameKeyAs(RecoveryKey.fromBytes(seq(1))));
    }
}
