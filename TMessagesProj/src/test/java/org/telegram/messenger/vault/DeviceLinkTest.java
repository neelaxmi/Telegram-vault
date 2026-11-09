package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Device-linking protocol: two parties exchanging opaque messages, plus an active attacker in the middle. */
public class DeviceLinkTest {

    private static final int ITER = 1000;
    private static final String PW = "existing device pw";
    private static final String PW_NEW = "linked device pw 1";

    private VaultKeyManager existing;
    private long now = 5_000;
    private final VaultStore.Clock clock = () -> now;

    private interface Action {
        void run() throws Exception;
    }

    private static void assertReason(VaultCryptoException.Reason r, Action a) {
        try {
            a.run();
            fail("expected " + r);
        } catch (VaultCryptoException e) {
            assertEquals(r, e.getReason());
        } catch (Exception e) {
            fail("unexpected " + e);
        }
    }

    private static VaultKeyManager newManager() {
        return new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), ITER);
    }

    @Before
    public void setUp() throws Exception {
        existing = newManager();
        existing.createVault(PW.toCharArray(), PW.toCharArray());
    }

    private static byte[] hex(String h) {
        byte[] b = new byte[h.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }

    /** Runs the whole protocol and returns the joiner in GRANTED state. */
    private DeviceLink.Joiner linkUpTo(DeviceLink.Approver a, DeviceLink.Joiner j) throws Exception {
        byte[] req = j.request();
        byte[] offer = a.handleRequest(req);
        byte[] reveal = j.handleOffer(offer);
        a.handleReveal(reveal);
        return j;
    }

    // ------------------------------------------------------------------ happy path

    @Test
    public void linksNewDevice_andBothSeeTheSameCode() throws Exception {
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        linkUpTo(a, j);
        String code = a.code();
        assertEquals(code, j.code());
        assertTrue(code.matches("[0-9]{6}"));
        byte[] grant = a.approve();
        j.handleGrant(grant);

        VaultKeyManager fresh = newManager();
        j.install(fresh, PW_NEW.toCharArray(), PW_NEW.toCharArray(), false);
        assertTrue(fresh.isUnlocked());
        assertArrayEquals(existing.getVaultId(), fresh.getVaultId());
        assertEquals(existing.getBundleVersion(), fresh.getBundleVersion());
        assertArrayEquals(existing.deriveSubkey("messages"), fresh.deriveSubkey("messages"));
        assertArrayEquals(existing.currentBundle(), fresh.currentBundle());
        // and it works as a normal device afterwards: lock and unlock with its own password
        fresh.lock();
        fresh.unlock(PW_NEW.toCharArray());
        assertTrue(fresh.isUnlocked());
    }

    @Test
    public void codesDifferBetweenSessions() throws Exception {
        Set<String> codes = new HashSet<>();
        for (int i = 0; i < 12; i++) {
            DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
            DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
            linkUpTo(a, j);
            codes.add(a.code());
        }
        assertTrue(codes.size() > 8);
    }

    @Test
    public void knownAnswerVectors_matchIndependentPython() throws Exception {
        byte[] point = new byte[65];
        for (int i = 0; i < 65; i++) {
            point[i] = (byte) i;
        }
        byte[] nonce = new byte[16];
        for (int i = 0; i < 16; i++) {
            nonce[i] = (byte) i;
        }
        assertArrayEquals(hex("5f61951aae511ee9a08e7a38e74abccc97f4110af8d7fc132f398ff5698fef00"), DeviceLink.commit(point, nonce));
        byte[] t = DeviceLink.transcript(fill(32, 1), fill(65, 2), fill(16, 3), fill(65, 4), fill(16, 5));
        assertArrayEquals(hex("e6bec78afd65aa83d8d4b2bf16117ba0789562e409e2cb27f9f5384b9f78c670"), t);
        assertEquals("569248", DeviceLink.codeFrom(t));
    }

    private static byte[] fill(int n, int v) {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) v);
        return b;
    }

    // ------------------------------------------------------------------ attacks

    @Test
    public void manInTheMiddle_endsWithDifferentCodes() throws Exception {
        // N <-> Mallory <-> A: Mallory runs one session with each side using her own keys.
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner n = new DeviceLink.Joiner(clock);

        VaultKeyManager malloryKeys = newManager();
        malloryKeys.createVault("mallory password".toCharArray(), "mallory password".toCharArray());
        DeviceLink.Approver malloryAsA = new DeviceLink.Approver(malloryKeys, clock); // faces N
        DeviceLink.Joiner malloryAsN = new DeviceLink.Joiner(clock);                  // faces A

        byte[] offerToN = malloryAsA.handleRequest(n.request());
        byte[] offerFromA = a.handleRequest(malloryAsN.request());
        byte[] revealToA = malloryAsN.handleOffer(offerFromA);
        byte[] revealFromN = n.handleOffer(offerToN);
        a.handleReveal(revealToA);
        malloryAsA.handleReveal(revealFromN);

        assertEquals(a.code(), malloryAsN.code());
        assertEquals(n.code(), malloryAsA.code());
        assertNotEquals("the user would see different codes", a.code(), n.code());
    }

    @Test
    public void revealNotMatchingCommitment_cancelsSessionForGood() throws Exception {
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner honest = new DeviceLink.Joiner(clock);
        DeviceLink.Joiner attacker = new DeviceLink.Joiner(clock);
        byte[] offer = a.handleRequest(honest.request());
        byte[] attackerReveal = linkRevealOf(attacker, offer);
        assertReason(VaultCryptoException.Reason.LINK_MISMATCH, () -> a.handleReveal(attackerReveal));
        // the honest reveal arriving afterwards is too late
        byte[] honestReveal = honest.handleOffer(offer);
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> a.handleReveal(honestReveal));
        assertReason(VaultCryptoException.Reason.INVALID_STATE, a::approve);
        assertReason(VaultCryptoException.Reason.INVALID_STATE, a::code);
    }

    private static byte[] linkRevealOf(DeviceLink.Joiner j, byte[] offer) throws Exception {
        j.request();
        return j.handleOffer(offer);
    }

    @Test
    public void invalidCurvePoint_isRejected() throws Exception {
        // commit to a point that is not on the curve, then reveal it
        byte[] bad = hex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f6"); // y+1
        byte[] nonce = fill(16, 7);
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        byte[] req = message(1, DeviceLink.commit(bad, nonce));
        a.handleRequest(req);
        byte[] reveal = message(3, concat(bad, nonce));
        assertReason(VaultCryptoException.Reason.LINK_MISMATCH, () -> a.handleReveal(reveal));
        assertReason(VaultCryptoException.Reason.INVALID_STATE, a::approve);
    }

    @Test
    public void generatorPoint_decodesButOffCurveAndMalformedDoNot() throws Exception {
        byte[] g = hex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
        assertArrayEquals(g, DeviceLink.encodePoint(DeviceLink.decodePoint(g)));
        byte[] off = g.clone();
        off[64] ^= 1;
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> DeviceLink.decodePoint(off));
        byte[] compressed = g.clone();
        compressed[0] = 2;
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> DeviceLink.decodePoint(compressed));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> DeviceLink.decodePoint(new byte[65]));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> DeviceLink.decodePoint(Arrays.copyOf(g, 64)));
        byte[] big = g.clone();
        Arrays.fill(big, 1, 33, (byte) 0xFF); // x >= p
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> DeviceLink.decodePoint(big));
    }

    @Test
    public void invalidOfferPoint_cancelsJoiner() throws Exception {
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        j.request();
        byte[] offer = message(2, concat(new byte[65], fill(16, 1)));
        assertReason(VaultCryptoException.Reason.LINK_MISMATCH, () -> j.handleOffer(offer));
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> j.handleOffer(offer));
    }

    @Test
    public void forgedGrant_isRejected_andGenuineOneStillWorks() throws Exception {
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        linkUpTo(a, j);
        byte[] grant = a.approve();
        byte[] forged = grant.clone();
        forged[forged.length - 1] ^= 1;
        assertReason(VaultCryptoException.Reason.LINK_MISMATCH, () -> j.handleGrant(forged));
        byte[] random = message(4, fill(200, 9));
        assertReason(VaultCryptoException.Reason.LINK_MISMATCH, () -> j.handleGrant(random));
        j.handleGrant(grant);
        VaultKeyManager fresh = newManager();
        j.install(fresh, PW_NEW.toCharArray(), PW_NEW.toCharArray(), false);
        assertTrue(fresh.isUnlocked());
    }

    @Test
    public void grantFromAnotherSession_isRejected() throws Exception {
        DeviceLink.Approver a1 = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner j1 = new DeviceLink.Joiner(clock);
        linkUpTo(a1, j1);
        byte[] grant1 = a1.approve();
        DeviceLink.Approver a2 = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner j2 = new DeviceLink.Joiner(clock);
        linkUpTo(a2, j2);
        assertReason(VaultCryptoException.Reason.LINK_MISMATCH, () -> j2.handleGrant(grant1));
    }

    @Test
    public void grantIsNeverSentWithoutApproval() throws Exception {
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        linkUpTo(a, j);
        a.cancel();
        assertReason(VaultCryptoException.Reason.INVALID_STATE, a::approve);
    }

    @Test
    public void approveIsOneShot() throws Exception {
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        linkUpTo(a, j);
        a.approve();
        assertReason(VaultCryptoException.Reason.INVALID_STATE, a::approve);
    }

    @Test
    public void approveBeforeReveal_isRefused() throws Exception {
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        assertReason(VaultCryptoException.Reason.INVALID_STATE, a::approve);
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        a.handleRequest(j.request());
        assertReason(VaultCryptoException.Reason.INVALID_STATE, a::approve);
        assertReason(VaultCryptoException.Reason.INVALID_STATE, a::code);
    }

    @Test
    public void replayedRequest_isRefused() throws Exception {
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        byte[] req = j.request();
        a.handleRequest(req);
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> a.handleRequest(req));
    }

    // ------------------------------------------------------------------ expiry, state, parsing

    @Test
    public void expiredSession_isRefusedAtEveryStep() throws Exception {
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        byte[] req = j.request();
        byte[] offer = a.handleRequest(req);
        byte[] reveal = j.handleOffer(offer);
        now += DeviceLink.TTL_MILLIS + 1;
        assertReason(VaultCryptoException.Reason.LINK_EXPIRED, () -> a.handleReveal(reveal));
        assertReason(VaultCryptoException.Reason.LINK_EXPIRED, () -> j.handleGrant(message(4, fill(100, 1))));
    }

    @Test
    public void expiryAfterCodeShown_blocksApproval() throws Exception {
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        linkUpTo(a, j);
        now += DeviceLink.TTL_MILLIS + 1;
        assertReason(VaultCryptoException.Reason.LINK_EXPIRED, a::approve);
    }

    @Test
    public void lastSecondIsStillAccepted_andClockGoingBackwardsIsNot() throws Exception {
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        now += DeviceLink.TTL_MILLIS;
        linkUpTo(a, j);
        a.approve();
        DeviceLink.Approver b = new DeviceLink.Approver(existing, clock);
        now -= 10;
        assertReason(VaultCryptoException.Reason.LINK_EXPIRED, () -> b.handleRequest(message(1, fill(32, 1))));
    }

    @Test
    public void lockedOrLegacyApprover_refusesRequests() throws Exception {
        existing.lock();
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        byte[] req = j.request();
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> a.handleRequest(req));

        InMemoryHeaderStore hs = new InMemoryHeaderStore();
        TestDeviceKeyWrapper w = new TestDeviceKeyWrapper();
        LegacyHeaders.write(hs, w, "old pass".toCharArray(), ITER);
        VaultKeyManager legacy = new VaultKeyManager(hs, w, ITER);
        legacy.unlock("old pass".toCharArray());
        DeviceLink.Approver la = new DeviceLink.Approver(legacy, clock);
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> la.handleRequest(req));
    }

    @Test
    public void wrongStepOrder_isRefused() throws Exception {
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> j.handleOffer(message(2, fill(81, 1))));
        assertReason(VaultCryptoException.Reason.INVALID_STATE, j::code);
        j.request();
        assertReason(VaultCryptoException.Reason.INVALID_STATE, j::request);
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> j.handleGrant(message(4, fill(100, 1))));
    }

    @Test
    public void malformedMessages_areRejectedWithoutChangingState() throws Exception {
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> a.handleRequest(null));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> a.handleRequest(new byte[3]));
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> a.handleRequest(message(2, fill(32, 1)))); // wrong type
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> a.handleRequest(message(1, fill(31, 1)))); // wrong size
        byte[] wrongMagic = message(1, fill(32, 1));
        wrongMagic[0] = 'X';
        assertReason(VaultCryptoException.Reason.CORRUPTED, () -> a.handleRequest(wrongMagic));
        byte[] newer = message(1, fill(32, 1));
        newer[4] = 2;
        assertReason(VaultCryptoException.Reason.UNSUPPORTED_VERSION, () -> a.handleRequest(newer));
        // the session is still usable
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        linkUpTo(a, j);
        assertEquals(a.code(), j.code());
    }

    // ------------------------------------------------------------------ install

    @Test
    public void install_refusesWeakPasswordAndAllowsRetry() throws Exception {
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        linkUpTo(a, j);
        j.handleGrant(a.approve());
        VaultKeyManager fresh = newManager();
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> j.install(fresh, "short".toCharArray(), "short".toCharArray(), false));
        assertReason(VaultCryptoException.Reason.INVALID_ARGUMENT, () -> j.install(fresh, PW_NEW.toCharArray(), "different pw 12345".toCharArray(), false));
        assertFalse(fresh.isInitialized());
        j.install(fresh, PW_NEW.toCharArray(), PW_NEW.toCharArray(), false);
        assertTrue(fresh.isUnlocked());
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> j.install(newManager(), PW_NEW.toCharArray(), PW_NEW.toCharArray(), false));
    }

    @Test
    public void install_onDeviceWithVault_needsExplicitReplace() throws Exception {
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        linkUpTo(a, j);
        j.handleGrant(a.approve());
        VaultKeyManager other = newManager();
        other.createVault("other device pw!!".toCharArray(), "other device pw!!".toCharArray());
        assertReason(VaultCryptoException.Reason.INVALID_STATE, () -> j.install(other, PW_NEW.toCharArray(), PW_NEW.toCharArray(), false));
        j.install(other, PW_NEW.toCharArray(), PW_NEW.toCharArray(), true);
        assertArrayEquals(existing.getVaultId(), other.getVaultId());
    }

    @Test
    public void linkedDevice_canReadDataEncryptedByOriginal() throws Exception {
        VaultStore.Clock c = clock;
        java.io.File dir = java.nio.file.Files.createTempDirectory("lk").toFile();
        VaultStore sa = new VaultStore(new java.io.File(dir, "a"), existing, c, 4096);
        VaultItem item = sa.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("shared secret"), null, null);
        DeviceLink.Approver a = new DeviceLink.Approver(existing, clock);
        DeviceLink.Joiner j = new DeviceLink.Joiner(clock);
        linkUpTo(a, j);
        j.handleGrant(a.approve());
        VaultKeyManager fresh = newManager();
        j.install(fresh, PW_NEW.toCharArray(), PW_NEW.toCharArray(), false);
        // the same files, opened with the linked device's keys
        VaultStore sb = new VaultStore(new java.io.File(dir, "a"), fresh, c, 4096);
        assertEquals("shared secret", sb.get(item.id).text);
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] message(int type, byte[] body) {
        byte[] m = new byte[6 + body.length];
        m[0] = 'T';
        m[1] = 'G';
        m[2] = 'V';
        m[3] = 'L';
        m[4] = 1;
        m[5] = (byte) type;
        System.arraycopy(body, 0, m, 6, body.length);
        return m;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
