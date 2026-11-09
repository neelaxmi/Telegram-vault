package org.telegram.messenger.vault;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

/**
 * Adds a new device to an existing Vault WITHOUT the recovery key, with the user comparing a 6-digit code on
 * both screens. Pure Java; the messages are opaque byte arrays that the transport (the private channel) carries.
 *
 * <h3>Protocol (commit, offer, reveal, grant)</h3>
 * <pre>
 *   New device N                                   Existing device A (unlocked)
 *   1. generates keypair + nonce; sends REQUEST = H(pubN | nonceN)  -- N is now committed
 *                                                  2. generates keypair + nonce; sends OFFER = pubA | nonceA
 *   3. sends REVEAL = pubN | nonceN
 *                                                  4. checks H(reveal) == commitment, else cancels for good
 *   both: shared = ECDH(P-256); T = H(commitment | pubA | nonceA | pubN | nonceN); code = digits(H(T))
 *   5. the user checks that both screens show the same code, then approves on A
 *                                                  6. sends GRANT = AES-GCM(HKDF(shared, T), VMK | bundle, aad = T)
 *   7. N decrypts, checks the bundle authenticates under the VMK, installs it with a new local password
 * </pre>
 * <b>Why the code is safe to keep short.</b> A man in the middle must choose his key BEFORE he sees A's key
 * (N committed first), and A accepts only ONE reveal per session (a wrong one cancels it). So each attack
 * attempt has a 1 in 1,000,000 chance of showing the same code on both screens, and a failed attempt ends
 * the session. A session also expires after {@link #TTL_MILLIS}. Without the user's approval A never sends the grant.
 * Nothing here weakens the recovery key route; it is a convenience that needs a second, unlocked device.
 */
public final class DeviceLink {

    /** How long a link session may last. */
    public static final long TTL_MILLIS = 5 * 60 * 1000L;
    static final int CODE_DIGITS = 6;

    private static final byte[] MAGIC = {'T', 'G', 'V', 'L'};
    private static final int VERSION = 1;
    private static final int T_REQUEST = 1;
    private static final int T_OFFER = 2;
    private static final int T_REVEAL = 3;
    private static final int T_GRANT = 4;
    private static final int HEADER = 6; // magic4 | version | type
    private static final int POINT_BYTES = 65;
    private static final int NONCE_BYTES = 16;
    private static final int COMMIT_BYTES = 32;
    private static final byte[] CONTEXT = "tg-vault/link/v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] COMMIT_CONTEXT = "tg-vault/link/commit".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CODE_CONTEXT = "tg-vault/link/code".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] GRANT_INFO = "tg-vault/link/grant".getBytes(StandardCharsets.US_ASCII);

    private DeviceLink() {
    }

    // ------------------------------------------------------------------ approver (existing device)

    /** Runs on the device that already holds the Vault. One instance handles exactly one session. */
    public static final class Approver {
        private enum State {AWAIT_REQUEST, AWAIT_REVEAL, AWAIT_APPROVAL, DONE, CANCELLED}

        private final VaultKeyManager keys;
        private final VaultStore.Clock clock;
        private final long startedAt;
        private State state = State.AWAIT_REQUEST;
        private byte[] commitment;
        private KeyPair pair;
        private byte[] ownPoint;
        private byte[] ownNonce;
        private byte[] transcript;
        private byte[] grantKey;
        private String code;

        public Approver(VaultKeyManager keys) {
            this(keys, System::currentTimeMillis);
        }

        Approver(VaultKeyManager keys, final VaultStore.Clock clock) {
            if (keys == null || clock == null) {
                throw new IllegalArgumentException("arguments required");
            }
            this.keys = keys;
            this.clock = clock;
            this.startedAt = clock.nowMillis();
        }

        /** Step 2. Returns the OFFER message. */
        public synchronized byte[] handleRequest(byte[] message) throws VaultCryptoException {
            checkLive(State.AWAIT_REQUEST);
            byte[] body = parse(message, T_REQUEST, COMMIT_BYTES);
            if (!keys.isUnlocked() || keys.isLegacyHeader()) {
                throw state("The Vault must be unlocked and migrated before linking a device");
            }
            commitment = body;
            pair = generateKeyPair();
            ownPoint = encodePoint((ECPublicKey) pair.getPublic());
            ownNonce = VaultCrypto.randomBytes(NONCE_BYTES);
            state = State.AWAIT_REVEAL;
            return build(T_OFFER, concat(ownPoint, ownNonce));
        }

        /**
         * Step 4. Checks the reveal against the commitment. A mismatch cancels the session for good.
         */
        public synchronized void handleReveal(byte[] message) throws VaultCryptoException {
            checkLive(State.AWAIT_REVEAL);
            byte[] body = parse(message, T_REVEAL, POINT_BYTES + NONCE_BYTES);
            byte[] peerPoint = Arrays.copyOfRange(body, 0, POINT_BYTES);
            byte[] peerNonce = Arrays.copyOfRange(body, POINT_BYTES, POINT_BYTES + NONCE_BYTES);
            byte[] expected = commit(peerPoint, peerNonce);
            if (!VaultCrypto.constantTimeEquals(expected, commitment)) {
                cancel();
                throw new VaultCryptoException(VaultCryptoException.Reason.LINK_MISMATCH,
                        "The new device's reveal does not match its commitment; session cancelled");
            }
            byte[] shared = null;
            try {
                shared = agree(pair.getPrivate(), peerPoint);
                transcript = transcript(commitment, ownPoint, ownNonce, peerPoint, peerNonce);
                grantKey = VaultCrypto.hkdfSha256(shared, transcript, GRANT_INFO, VaultCrypto.KEY_BYTES);
                code = codeFrom(transcript);
            } catch (VaultCryptoException e) {
                cancel();
                throw new VaultCryptoException(VaultCryptoException.Reason.LINK_MISMATCH, "Invalid key from the new device", e);
            } finally {
                VaultCrypto.wipe(shared);
            }
            pair = null;
            state = State.AWAIT_APPROVAL;
        }

        /** The 6 digits to show next to the same number on the new device. Valid after {@link #handleReveal}. */
        public synchronized String code() throws VaultCryptoException {
            if (state != State.AWAIT_APPROVAL) {
                throw state("No code yet");
            }
            return code;
        }

        /** Step 6. The user has confirmed the codes match. One shot: a second call fails. */
        public synchronized byte[] approve() throws VaultCryptoException {
            checkLive(State.AWAIT_APPROVAL);
            byte[] vmk = keys.exportVmkForLink();
            try {
                byte[] bundle = keys.currentBundle();
                byte[] plain = new byte[VaultCrypto.KEY_BYTES + 2 + bundle.length];
                System.arraycopy(vmk, 0, plain, 0, VaultCrypto.KEY_BYTES);
                plain[VaultCrypto.KEY_BYTES] = (byte) (bundle.length >>> 8);
                plain[VaultCrypto.KEY_BYTES + 1] = (byte) bundle.length;
                System.arraycopy(bundle, 0, plain, VaultCrypto.KEY_BYTES + 2, bundle.length);
                byte[] blob = VaultCrypto.encrypt(grantKey, plain, transcript);
                VaultCrypto.wipe(plain);
                finish(State.DONE);
                return build(T_GRANT, blob);
            } finally {
                VaultCrypto.wipe(vmk);
            }
        }

        /** The user pressed "codes differ" / cancel. */
        public synchronized void cancel() {
            finish(State.CANCELLED);
        }

        private void finish(State next) {
            state = next;
            pair = null;
            VaultCrypto.wipe(grantKey);
            grantKey = null;
        }

        private void checkLive(State expected) throws VaultCryptoException {
            if (clock.nowMillis() - startedAt > TTL_MILLIS || clock.nowMillis() < startedAt) {
                finish(State.CANCELLED);
                throw new VaultCryptoException(VaultCryptoException.Reason.LINK_EXPIRED, "Link session expired");
            }
            if (state != expected) {
                throw state("Unexpected step for this session");
            }
        }
    }

    // ------------------------------------------------------------------ joiner (new device)

    /** Runs on the new device. One instance handles exactly one session. */
    public static final class Joiner {
        private enum State {NEW, AWAIT_OFFER, AWAIT_GRANT, GRANTED, CANCELLED, INSTALLED}

        private final VaultStore.Clock clock;
        private final long startedAt;
        private State state = State.NEW;
        private KeyPair pair;
        private byte[] ownPoint;
        private byte[] ownNonce;
        private byte[] commitment;
        private byte[] transcript;
        private byte[] grantKey;
        private String code;
        private byte[] vmk;
        private byte[] bundle;

        public Joiner() {
            this(System::currentTimeMillis);
        }

        Joiner(VaultStore.Clock clock) {
            if (clock == null) {
                throw new IllegalArgumentException("clock required");
            }
            this.clock = clock;
            this.startedAt = clock.nowMillis();
        }

        /** Step 1. Returns the REQUEST message (a commitment; it reveals nothing yet). */
        public synchronized byte[] request() throws VaultCryptoException {
            checkLive(State.NEW);
            pair = generateKeyPair();
            ownPoint = encodePoint((ECPublicKey) pair.getPublic());
            ownNonce = VaultCrypto.randomBytes(NONCE_BYTES);
            commitment = commit(ownPoint, ownNonce);
            state = State.AWAIT_OFFER;
            return build(T_REQUEST, commitment);
        }

        /** Step 3. Takes A's OFFER, returns the REVEAL. The code is available afterwards. */
        public synchronized byte[] handleOffer(byte[] message) throws VaultCryptoException {
            checkLive(State.AWAIT_OFFER);
            byte[] body = parse(message, T_OFFER, POINT_BYTES + NONCE_BYTES);
            byte[] peerPoint = Arrays.copyOfRange(body, 0, POINT_BYTES);
            byte[] peerNonce = Arrays.copyOfRange(body, POINT_BYTES, POINT_BYTES + NONCE_BYTES);
            byte[] shared = null;
            try {
                shared = agree(pair.getPrivate(), peerPoint);
                transcript = transcript(commitment, peerPoint, peerNonce, ownPoint, ownNonce);
                grantKey = VaultCrypto.hkdfSha256(shared, transcript, GRANT_INFO, VaultCrypto.KEY_BYTES);
                code = codeFrom(transcript);
            } catch (VaultCryptoException e) {
                cancel();
                throw new VaultCryptoException(VaultCryptoException.Reason.LINK_MISMATCH, "Invalid key from the other device", e);
            } finally {
                VaultCrypto.wipe(shared);
            }
            pair = null;
            state = State.AWAIT_GRANT;
            return build(T_REVEAL, concat(ownPoint, ownNonce));
        }

        /** The 6 digits to compare with the other device. Valid after {@link #handleOffer}. */
        public synchronized String code() throws VaultCryptoException {
            if (state != State.AWAIT_GRANT && state != State.GRANTED && state != State.INSTALLED) {
                throw state("No code yet");
            }
            return code;
        }

        /** Step 7a. Decrypts and checks the GRANT. The vault is not installed yet. */
        public synchronized void handleGrant(byte[] message) throws VaultCryptoException {
            checkLive(State.AWAIT_GRANT);
            byte[] blob = parse(message, T_GRANT, -1);
            byte[] plain;
            try {
                plain = VaultCrypto.decrypt(grantKey, blob, transcript);
            } catch (VaultCryptoException e) {
                // Not from the device we are talking to (or the codes were never confirmed). Keep waiting:
                // a forged message must not be able to end a genuine session.
                throw new VaultCryptoException(VaultCryptoException.Reason.LINK_MISMATCH, "Grant did not authenticate", e);
            }
            try {
                if (plain.length < VaultCrypto.KEY_BYTES + 2) {
                    throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Grant is truncated");
                }
                int len = ((plain[VaultCrypto.KEY_BYTES] & 0xFF) << 8) | (plain[VaultCrypto.KEY_BYTES + 1] & 0xFF);
                if (len != plain.length - VaultCrypto.KEY_BYTES - 2) {
                    throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Grant has a bad length");
                }
                byte[] v = Arrays.copyOfRange(plain, 0, VaultCrypto.KEY_BYTES);
                byte[] b = Arrays.copyOfRange(plain, VaultCrypto.KEY_BYTES + 2, plain.length);
                try {
                    VaultBundle.verify(b, v);
                } catch (VaultCryptoException e) {
                    VaultCrypto.wipe(v);
                    throw e;
                }
                vmk = v;
                bundle = b;
                state = State.GRANTED;
                VaultCrypto.wipe(grantKey);
                grantKey = null;
            } finally {
                VaultCrypto.wipe(plain);
            }
        }

        /** Step 7b. Installs the received Vault on this device with its own new password. */
        public synchronized void install(VaultKeyManager keys, char[] newPassword, char[] confirmation, boolean replaceExisting)
                throws VaultCryptoException {
            if (state != State.GRANTED) {
                throw state("Nothing to install");
            }
            keys.restoreFromLink(vmk, bundle, newPassword, confirmation, replaceExisting);
            VaultCrypto.wipe(vmk);
            vmk = null;
            state = State.INSTALLED;
        }

        public synchronized void cancel() {
            state = State.CANCELLED;
            pair = null;
            VaultCrypto.wipe(grantKey);
            grantKey = null;
            VaultCrypto.wipe(vmk);
            vmk = null;
        }

        private void checkLive(State expected) throws VaultCryptoException {
            if (clock.nowMillis() - startedAt > TTL_MILLIS || clock.nowMillis() < startedAt) {
                cancel();
                throw new VaultCryptoException(VaultCryptoException.Reason.LINK_EXPIRED, "Link session expired");
            }
            if (state != expected) {
                throw state("Unexpected step for this session");
            }
        }
    }

    // ------------------------------------------------------------------ shared helpers

    private static VaultCryptoException state(String message) {
        return new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, message);
    }

    private static byte[] build(int type, byte[] body) {
        byte[] out = new byte[HEADER + body.length];
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
        out[4] = VERSION;
        out[5] = (byte) type;
        System.arraycopy(body, 0, out, HEADER, body.length);
        return out;
    }

    /** @param bodyLength exact body size, or -1 for "any size up to 8 KiB" */
    private static byte[] parse(byte[] message, int type, int bodyLength) throws VaultCryptoException {
        if (message == null || message.length < HEADER || message.length > 8192) {
            throw corrupted("Not a link message");
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (message[i] != MAGIC[i]) {
                throw corrupted("Not a link message");
            }
        }
        if ((message[4] & 0xFF) > VERSION) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_VERSION, "Link message from a newer app version");
        }
        if ((message[4] & 0xFF) != VERSION || (message[5] & 0xFF) != type) {
            throw corrupted("Unexpected link message");
        }
        if (bodyLength >= 0 && message.length != HEADER + bodyLength) {
            throw corrupted("Link message has the wrong size");
        }
        return Arrays.copyOfRange(message, HEADER, message.length);
    }

    private static VaultCryptoException corrupted(String m) {
        return new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, m);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static byte[] commit(byte[] point, byte[] nonce) throws VaultCryptoException {
        return sha256(COMMIT_CONTEXT, point, nonce);
    }

    static byte[] transcript(byte[] commitment, byte[] pointA, byte[] nonceA, byte[] pointN, byte[] nonceN) throws VaultCryptoException {
        return sha256(CONTEXT, commitment, pointA, nonceA, pointN, nonceN);
    }

    static String codeFrom(byte[] transcript) throws VaultCryptoException {
        byte[] d = sha256(CODE_CONTEXT, transcript);
        long v = ((d[0] & 0xFFL) << 24) | ((d[1] & 0xFFL) << 16) | ((d[2] & 0xFFL) << 8) | (d[3] & 0xFFL);
        String s = Long.toString(v % 1_000_000L);
        StringBuilder sb = new StringBuilder(CODE_DIGITS);
        for (int i = s.length(); i < CODE_DIGITS; i++) {
            sb.append('0');
        }
        return sb.append(s).toString();
    }

    private static byte[] sha256(byte[]... parts) throws VaultCryptoException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) {
                md.update(p);
            }
            return md.digest();
        } catch (GeneralSecurityException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_PLATFORM, "SHA-256 unavailable", e);
        }
    }

    // ---- P-256

    private static KeyPair generateKeyPair() throws VaultCryptoException {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            return g.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_PLATFORM, "P-256 unavailable", e);
        }
    }

    private static ECParameterSpec curve() throws VaultCryptoException {
        try {
            AlgorithmParameters p = AlgorithmParameters.getInstance("EC");
            p.init(new ECGenParameterSpec("secp256r1"));
            return p.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_PLATFORM, "P-256 unavailable", e);
        }
    }

    /** Uncompressed X9.62 point: 0x04 | X(32) | Y(32). */
    static byte[] encodePoint(ECPublicKey key) {
        byte[] out = new byte[POINT_BYTES];
        out[0] = 4;
        copyFixed(key.getW().getAffineX(), out, 1);
        copyFixed(key.getW().getAffineY(), out, 33);
        return out;
    }

    private static void copyFixed(BigInteger v, byte[] dst, int offset) {
        byte[] b = v.toByteArray();
        int start = b.length > 32 ? b.length - 32 : 0;
        int len = b.length - start;
        System.arraycopy(b, start, dst, offset + 32 - len, len);
    }

    /** Decodes a point and rejects anything that is not on the curve (invalid-curve attacks). */
    static ECPublicKey decodePoint(byte[] point) throws VaultCryptoException {
        if (point == null || point.length != POINT_BYTES || point[0] != 4) {
            throw corrupted("Invalid public key encoding");
        }
        ECParameterSpec spec = curve();
        EllipticCurve c = spec.getCurve();
        BigInteger p = ((java.security.spec.ECFieldFp) c.getField()).getP();
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(point, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(point, 33, 65));
        if (x.compareTo(p) >= 0 || y.compareTo(p) >= 0) {
            throw corrupted("Public key coordinate out of range");
        }
        BigInteger lhs = y.multiply(y).mod(p);
        BigInteger rhs = x.pow(3).add(c.getA().multiply(x)).add(c.getB()).mod(p);
        if (!lhs.equals(rhs)) {
            throw corrupted("Public key is not on the curve");
        }
        try {
            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
        } catch (GeneralSecurityException e) {
            throw corrupted("Public key rejected");
        }
    }

    private static byte[] agree(PrivateKey own, byte[] peerPoint) throws VaultCryptoException {
        ECPublicKey peer = decodePoint(peerPoint);
        try {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(own);
            ka.doPhase(peer, true);
            return ka.generateSecret();
        } catch (GeneralSecurityException e) {
            throw corrupted("Key agreement failed");
        }
    }
}
