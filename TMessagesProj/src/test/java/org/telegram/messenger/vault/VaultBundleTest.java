package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.Arrays;

public class VaultBundleTest {

    /** Produced by an independent Python implementation: vmk=0..31, vaultId=0x10.., recovery key=0x40.., version 7, nonce 0..11. */
    private static final String PY_BUNDLE = "5447564201101112131415161718191a1b1c1d1e1f000000070101003c000102030405060708090a0b"
            + "65d9f9e2e5fec9c0b97a12550a851fc64b51a3693857e92614b0e722e2b6ed3c5ef91597a051302a9aa15316a56bef72ba46ec98ce33e5fbbaa04406209a618a06cb14a4f8c2c4381f0d2338e2f36f20";

    private static byte[] seq(int start) {
        byte[] b = new byte[32];
        for (int i = 0; i < 32; i++) {
            b[i] = (byte) (start + i);
        }
        return b;
    }

    private static byte[] vaultId() {
        return Arrays.copyOf(seq(0x10), 16);
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private interface Action {
        void run() throws Exception;
    }

    private static void assertReason(VaultCryptoException.Reason reason, Action a) {
        try {
            a.run();
            fail("expected " + reason);
        } catch (VaultCryptoException e) {
            assertEquals(reason, e.getReason());
        } catch (Exception e) {
            fail("unexpected " + e);
        }
    }

    private static VaultCryptoException.Reason reasonOf(Action a) {
        try {
            a.run();
            return null;
        } catch (VaultCryptoException e) {
            return e.getReason();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    // ------------------------------------------------------------ format

    @Test
    public void opensBundleBuiltByIndependentPythonImplementation() throws Exception {
        RecoveryKey key = RecoveryKey.fromBytes(seq(0x40));
        byte[] vmk = VaultBundle.openWithRecoveryKey(hex(PY_BUNDLE), key);
        assertArrayEquals(seq(0), vmk);
        VaultBundle.Info info = VaultBundle.peek(hex(PY_BUNDLE));
        assertArrayEquals(vaultId(), info.vaultId);
        assertEquals(7, info.bundleVersion);
    }

    @Test
    public void javaBundleHasTheDocumentedLayout() throws Exception {
        byte[] b = VaultBundle.create(seq(0), vaultId(), 7, RecoveryKey.fromBytes(seq(0x40)));
        byte[] py = hex(PY_BUNDLE);
        assertEquals(py.length, b.length);
        assertEquals(121, b.length);
        // Header, slot type and slot length (29 bytes) are fixed; the nonce, ciphertext, tag and HMAC are not.
        assertArrayEquals(Arrays.copyOf(py, 29), Arrays.copyOf(b, 29));
        assertEquals(1, b[25]); // slot count
        assertEquals(1, b[26]); // slot type
    }

    @Test
    public void roundTrip_andPeekAndVerify() throws Exception {
        byte[] vmk = VaultCrypto.randomBytes(32);
        byte[] id = VaultCrypto.randomBytes(16);
        RecoveryKey key = RecoveryKey.generate();
        byte[] bundle = VaultBundle.create(vmk, id, 3, key);
        assertArrayEquals(vmk, VaultBundle.openWithRecoveryKey(bundle, key));
        VaultBundle.Info info = VaultBundle.peek(bundle);
        assertArrayEquals(id, info.vaultId);
        assertEquals(3, info.bundleVersion);
        VaultBundle.verify(bundle, vmk);
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultBundle.verify(bundle, VaultCrypto.randomBytes(32)));
    }

    @Test
    public void containsNeitherTheVmkNorTheRecoveryKey() throws Exception {
        byte[] vmk = VaultCrypto.randomBytes(32);
        RecoveryKey key = RecoveryKey.generate();
        byte[] bundle = VaultBundle.create(vmk, VaultCrypto.randomBytes(16), 1, key);
        assertEquals(-1, VaultCryptoTest.indexOf(bundle, vmk));
        assertEquals(-1, VaultCryptoTest.indexOf(bundle, key.toBytes()));
        assertEquals(-1, VaultCryptoTest.indexOf(bundle, key.format().getBytes("US-ASCII")));
        assertEquals(-1, VaultCryptoTest.indexOf(bundle, VaultCrypto.deriveSubkey(vmk, "bundle-auth")));
    }

    @Test
    public void twoBundlesOfTheSameVault_differ() throws Exception {
        byte[] vmk = VaultCrypto.randomBytes(32);
        byte[] id = VaultCrypto.randomBytes(16);
        RecoveryKey key = RecoveryKey.generate();
        assertFalse(Arrays.equals(VaultBundle.create(vmk, id, 1, key), VaultBundle.create(vmk, id, 1, key)));
    }

    // ------------------------------------------------------------ wrong keys

    @Test
    public void wrongRecoveryKey_isReportedAsSuch() throws Exception {
        byte[] bundle = VaultBundle.create(seq(0), vaultId(), 1, RecoveryKey.fromBytes(seq(0x40)));
        assertReason(VaultCryptoException.Reason.WRONG_RECOVERY_KEY,
                () -> VaultBundle.openWithRecoveryKey(bundle, RecoveryKey.fromBytes(seq(0x41))));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultBundle.openWithRecoveryKey(bundle, null));
    }

    @Test
    public void create_validatesArguments() {
        RecoveryKey key = RecoveryKey.generate();
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultBundle.create(null, vaultId(), 1, key));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultBundle.create(new byte[31], vaultId(), 1, key));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultBundle.create(seq(0), new byte[15], 1, key));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultBundle.create(seq(0), vaultId(), 0, key));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> VaultBundle.create(seq(0), vaultId(), 1, null));
    }

    // ------------------------------------------------------------ tampering

    @Test
    public void flippingAnyBit_ofAnyByte_isRejected() throws Exception {
        RecoveryKey key = RecoveryKey.fromBytes(seq(0x40));
        byte[] good = hex(PY_BUNDLE);
        for (int i = 0; i < good.length; i++) {
            for (int bit : new int[]{0x01, 0x80}) {
                byte[] bad = good.clone();
                bad[i] ^= bit;
                VaultCryptoException.Reason r = reasonOf(() -> VaultBundle.openWithRecoveryKey(bad, key));
                assertTrue("byte " + i + " bit " + bit + " accepted or wrong reason " + r, r != null);
                assertTrue("byte " + i + " gave " + r, r == VaultCryptoException.Reason.CORRUPTED
                        || r == VaultCryptoException.Reason.WRONG_RECOVERY_KEY
                        || r == VaultCryptoException.Reason.UNSUPPORTED_VERSION);
            }
        }
    }

    @Test
    public void tamperedMac_isCorrupted_evenWhenTheSlotOpens() throws Exception {
        RecoveryKey key = RecoveryKey.fromBytes(seq(0x40));
        byte[] bad = hex(PY_BUNDLE);
        bad[bad.length - 1] ^= 1;
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultBundle.openWithRecoveryKey(bad, key));
    }

    @Test
    public void truncation_atEveryLength_andTrailingBytes_areRejected() throws Exception {
        RecoveryKey key = RecoveryKey.fromBytes(seq(0x40));
        byte[] good = hex(PY_BUNDLE);
        for (int len = 0; len < good.length; len++) {
            byte[] bad = Arrays.copyOf(good, len);
            assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultBundle.peek(bad));
            assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultBundle.openWithRecoveryKey(bad, key));
        }
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultBundle.peek(Arrays.copyOf(good, good.length + 1)));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultBundle.peek(null));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultBundle.peek(new byte[VaultBundle.MAX_BUNDLE_BYTES + 1]));
    }

    @Test
    public void slotCannotBeMovedToAnotherVaultOrVersion() throws Exception {
        RecoveryKey key = RecoveryKey.fromBytes(seq(0x40));
        byte[] good = hex(PY_BUNDLE);
        byte[] otherVault = good.clone();
        otherVault[5] ^= 0x55; // vault id is both an HKDF salt and part of the slot AAD
        assertTrue(reasonOf(() -> VaultBundle.openWithRecoveryKey(otherVault, key)) != null);
        byte[] otherVersion = good.clone();
        otherVersion[24] = 8; // bundle version 7 -> 8
        assertTrue(reasonOf(() -> VaultBundle.openWithRecoveryKey(otherVersion, key)) != null);
    }

    @Test
    public void newerFormatVersion_isUnsupportedNotCorrupted() throws Exception {
        byte[] bad = hex(PY_BUNDLE);
        bad[4] = 2;
        assertReason(VaultCryptoException.Reason.UNSUPPORTED_VERSION, () -> VaultBundle.peek(bad));
    }

    @Test
    public void badMagicVersionZeroSlotCounts_areCorrupted() throws Exception {
        byte[] good = hex(PY_BUNDLE);
        byte[] magic = good.clone();
        magic[0] = 'X';
        byte[] versionZero = good.clone();
        versionZero[4] = 0;
        byte[] noSlots = good.clone();
        noSlots[25] = 0;
        byte[] tooManySlots = good.clone();
        tooManySlots[25] = 9;
        byte[] bundleVersionZero = good.clone();
        bundleVersionZero[21] = bundleVersionZero[22] = bundleVersionZero[23] = bundleVersionZero[24] = 0;
        for (byte[] bad : new byte[][]{magic, versionZero, noSlots, tooManySlots, bundleVersionZero}) {
            assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultBundle.peek(bad));
        }
    }

    // ------------------------------------------------------------ forward compatibility

    /** Rebuilds a bundle with extra slots and a valid MAC, to test unknown slot types. */
    private static byte[] withExtraSlot(byte[] vmk, byte[] original, int type, byte[] payload, boolean duplicateRecovery) throws Exception {
        int macStart = original.length - 32;
        byte[] body = Arrays.copyOf(original, macStart);
        byte[] slot = new byte[3 + payload.length];
        slot[0] = (byte) type;
        slot[1] = (byte) (payload.length >>> 8);
        slot[2] = (byte) payload.length;
        System.arraycopy(payload, 0, slot, 3, payload.length);
        byte[] extended = Arrays.copyOf(body, body.length + slot.length);
        System.arraycopy(slot, 0, extended, body.length, slot.length);
        extended[25] = 2;
        byte[] authKey = VaultCrypto.deriveSubkey(vmk, "bundle-auth");
        byte[] mac = VaultCrypto.hmacSha256(authKey, extended);
        byte[] out = Arrays.copyOf(extended, extended.length + 32);
        System.arraycopy(mac, 0, out, extended.length, 32);
        return out;
    }

    @Test
    public void unknownSlotTypes_areIgnoredButAuthenticated() throws Exception {
        RecoveryKey key = RecoveryKey.fromBytes(seq(0x40));
        byte[] extended = withExtraSlot(seq(0), hex(PY_BUNDLE), 9, new byte[]{1, 2, 3}, false);
        assertArrayEquals(seq(0), VaultBundle.openWithRecoveryKey(extended, key));

        byte[] flipped = extended.clone();
        flipped[extended.length - 32 - 1] ^= 1; // a byte of the unknown slot
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultBundle.openWithRecoveryKey(flipped, key));
    }

    @Test
    public void secondRecoverySlot_isRejected() throws Exception {
        byte[] original = hex(PY_BUNDLE);
        byte[] dup = withExtraSlot(seq(0), original, VaultBundle.SLOT_RECOVERY, Arrays.copyOfRange(original, 29, 89), true);
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> VaultBundle.peek(dup));
    }
}
