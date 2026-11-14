package org.telegram.messenger.vault;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.KeyAgreement;

/**
 * Write-only ingestion: lets "Send to Vault" save a message while the Vault is LOCKED, without the master key
 * (VMK) being in memory.
 *
 * <h3>Design</h3>
 * The Vault owns an EC P-256 key pair for its inbox.
 * <ul>
 *   <li>The <b>public key</b> is stored wrapped by the Android Keystore device key (the same device key that
 *       protects the key header). It is readable while the Vault is locked, so the app can encrypt TO the Vault
 *       without a password. Wrapping also means an attacker who can only write files cannot swap in their own key.</li>
 *   <li>The <b>private key</b> is stored encrypted under a subkey derived from the VMK ("inbox-private"), so it is
 *       readable only while the Vault is unlocked.</li>
 *   <li>Each saved message becomes a sealed envelope (ECIES: ephemeral ECDH P-256, HKDF-SHA256, AES-256-GCM).
 *       Media goes into its own file, encrypted in chunks with a random content key that lives inside the envelope.
 *       Nothing readable is ever written: no plaintext text, no plaintext media, no plaintext file name.</li>
 *   <li>On the next unlock {@link #drain} opens the envelopes with the private key and adds them to the normal
 *       {@link VaultStore} (re-encrypted under the VMK, then synced like any other item). Envelopes are deleted
 *       (overwritten) only after the store accepted them.</li>
 * </ul>
 *
 * <h3>What a locked device can and cannot do</h3>
 * Writing needs only the public key: a thief with the unlocked phone's file system can ADD items but cannot read
 * anything already saved, and cannot read the pending envelopes either (the private key is under the VMK). The
 * pending envelopes are protected exactly as well as the ECDH key and AES-GCM: they reveal sizes and timing.
 *
 * <h3>Limits (documented in SECURITY.md)</h3>
 * <ul>
 *   <li>The key pair is created at the first unlock after creation or upgrade; before that, saving while locked is
 *       refused with a clear message (canAccept() is false).</li>
 *   <li>A key rotation or adopting a rotation on another device replaces the VMK; the private key is then
 *       re-created ({@link #ensureKeyPair}). Items still waiting at that moment cannot be opened and are kept
 *       aside (never silently deleted); rotation first drains the inbox so this normally does not happen.</li>
 * </ul>
 */
public final class VaultInbox {

    private static final byte[] MAGIC = {'T', 'G', 'V', 'I'};
    private static final byte VERSION = 1;
    private static final byte[] KDF_INFO = "tg-vault/v1/inbox-seal".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PUB_AAD = "tg-vault/v1/inbox-pub".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PRIV_AAD = "tg-vault/v1/inbox-priv".getBytes(StandardCharsets.US_ASCII);
    private static final String SUBKEY_PURPOSE = "inbox-private";
    private static final int MAX_FIELD = 1 << 20; // sanity limit for strings inside an envelope
    private static final long ORPHAN_MEDIA_MILLIS = 60L * 60 * 1000;

    private final File dir;
    private final DeviceKeyWrapper device;

    public VaultInbox(File dir, DeviceKeyWrapper device) {
        if (dir == null || device == null) {
            throw new IllegalArgumentException("arguments required");
        }
        this.dir = dir;
        this.device = device;
    }

    /** Result of {@link #drain}. */
    public static final class DrainReport {
        public final int moved;
        public final int failed;

        DrainReport(int moved, int failed) {
            this.moved = moved;
            this.failed = failed;
        }
    }

    // ------------------------------------------------------------------ write side (works while locked)

    /** True if the public key exists and can be read, i.e. {@link #put} will work right now. */
    public synchronized boolean canAccept() {
        try {
            return readPublicKey() != null;
        } catch (VaultCryptoException e) {
            return false;
        }
    }

    /**
     * Seals one message into the inbox. Needs no password and no VMK.
     *
     * @param media    the plaintext media, or null for a text message
     * @param maxBytes largest media size accepted (MEDIA_TOO_LARGE above it); ignored without media
     * @return the id of the envelope
     * @throws VaultCryptoException INVALID_STATE if there is no inbox key yet; MEDIA_TOO_LARGE; IO_ERROR
     */
    public synchronized String put(VaultItem.Draft draft, InputStream media, long maxBytes) throws VaultCryptoException {
        if (draft == null || draft.type == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Draft required");
        }
        if (draft.type.hasMedia() != (media != null)) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_ARGUMENT, "Media does not match the item type");
        }
        PublicKey recipient = readPublicKey();
        if (recipient == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE,
                    "The Vault cannot take messages while locked until it has been unlocked once");
        }
        String id = hex(VaultCrypto.randomBytes(16));
        File mediaFile = new File(dir, id + ".media");
        File envFile = new File(dir, id + ".env");
        byte[] cek = null;
        boolean done = false;
        try {
            ensureDir();
            long mediaBytes = 0;
            if (media != null) {
                cek = VaultCrypto.randomBytes(VaultCrypto.KEY_BYTES);
                File tmp = new File(dir, id + ".media.tmp");
                try (OutputStream out = new FileOutputStream(tmp)) {
                    mediaBytes = VaultMediaCipher.encrypt(new LimitedInputStream(media, maxBytes), out, cek, id.getBytes(StandardCharsets.US_ASCII),
                            VaultMediaCipher.DEFAULT_CHUNK_SIZE);
                } catch (LimitedInputStream.TooLarge e) {
                    VaultFiles.secureDelete(tmp);
                    throw new VaultCryptoException(VaultCryptoException.Reason.MEDIA_TOO_LARGE, "The file is larger than the Vault accepts");
                }
                if (!tmp.renameTo(mediaFile)) {
                    throw new IOException("rename failed");
                }
            }
            byte[] payload = encodePayload(draft, cek, mediaBytes);
            byte[] sealed;
            try {
                sealed = seal(recipient, payload, id);
            } finally {
                VaultCrypto.wipe(payload);
            }
            File tmpEnv = new File(dir, id + ".env.tmp");
            try (FileOutputStream out = new FileOutputStream(tmpEnv)) {
                out.write(sealed);
                out.getFD().sync();
            }
            if (!tmpEnv.renameTo(envFile)) { // the envelope appears last and atomically: a reader never sees a half-written one
                throw new IOException("rename failed");
            }
            done = true;
            return id;
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not store the message", e);
        } finally {
            VaultCrypto.wipe(cek);
            if (!done) {
                quietDelete(mediaFile);
                quietDelete(new File(dir, id + ".media.tmp"));
                quietDelete(new File(dir, id + ".env.tmp"));
            }
        }
    }

    /** Number of envelopes waiting for the next unlock. */
    public synchronized int pendingCount() {
        return envelopes().length;
    }

    // ------------------------------------------------------------------ unlock side

    /**
     * Makes sure an inbox key pair exists and that its private half opens with the current VMK. Call right after
     * every unlock. Creates the pair for new and upgraded vaults; replaces it after a key rotation (the old private
     * key is under the old VMK and unreadable). Pending envelopes are never deleted here.
     */
    public synchronized void ensureKeyPair(VaultKeyManager keys) throws VaultCryptoException {
        byte[] subkey = keys.deriveSubkey(SUBKEY_PURPOSE);
        try {
            PublicKey pub = readPublicKey();
            File privFile = new File(dir, "priv.bin");
            if (pub != null && privFile.exists()) {
                try {
                    byte[] priv = VaultCrypto.decrypt(subkey, readAll(privFile), PRIV_AAD);
                    VaultCrypto.wipe(priv);
                    return; // pair is usable
                } catch (VaultCryptoException e) {
                    if (e.getReason() != VaultCryptoException.Reason.CORRUPTED && e.getReason() != VaultCryptoException.Reason.WRONG_PASSWORD) {
                        throw e;
                    }
                    // unreadable under this VMK: fall through and create a new pair
                }
            }
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair pair = gen.generateKeyPair();
            byte[] privEncoded = pair.getPrivate().getEncoded();
            try {
                ensureDir();
                // private first, then public: canAccept() turns true only when a matching private key exists
                writeAtomic(privFile, VaultCrypto.encrypt(subkey, privEncoded, PRIV_AAD));
                writeAtomic(new File(dir, "pub.bin"), device.wrap(concat(PUB_AAD, pair.getPublic().getEncoded())));
            } finally {
                VaultCrypto.wipe(privEncoded);
            }
        } catch (GeneralSecurityException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_PLATFORM, "EC P-256 is unavailable", e);
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not store the inbox key", e);
        } finally {
            VaultCrypto.wipe(subkey);
        }
    }

    /**
     * Moves every waiting envelope into the store. Requires the Vault to be unlocked. An envelope that cannot be
     * opened is renamed to {@code .bad} and counted as failed (kept, never deleted); the others are still processed.
     */
    public synchronized DrainReport drain(VaultKeyManager keys, VaultStore store) throws VaultCryptoException {
        File[] envs = envelopes();
        if (envs.length == 0) {
            removeOrphanMedia();
            return new DrainReport(0, 0);
        }
        byte[] subkey = keys.deriveSubkey(SUBKEY_PURPOSE);
        PrivateKey priv = null;
        byte[] recipientEncoded;
        PublicKey recipientKey = readPublicKey();
        if (recipientKey == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "No inbox key");
        }
        recipientEncoded = recipientKey.getEncoded();
        try {
            File privFile = new File(dir, "priv.bin");
            byte[] privBytes = VaultCrypto.decrypt(subkey, readAll(privFile), PRIV_AAD);
            try {
                priv = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(privBytes));
            } finally {
                VaultCrypto.wipe(privBytes);
            }
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Inbox key unreadable", e);
        } catch (GeneralSecurityException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Inbox key invalid", e);
        } finally {
            VaultCrypto.wipe(subkey);
        }
        int moved = 0;
        int failed = 0;
        Arrays.sort(envs);
        for (File env : envs) {
            String id = env.getName().substring(0, env.getName().length() - ".env".length());
            try {
                moveOne(id, env, priv, recipientEncoded, store);
                moved++;
            } catch (VaultCryptoException e) {
                if (e.getReason() == VaultCryptoException.Reason.INVALID_STATE) {
                    throw e; // locked again: stop, keep everything for next time
                }
                if (e.getReason() == VaultCryptoException.Reason.IO_ERROR) {
                    throw e; // transient: keep and let the caller retry later
                }
                failed++;
                //noinspection ResultOfMethodCallIgnored
                env.renameTo(new File(dir, id + ".bad"));
            }
        }
        removeOrphanMedia();
        return new DrainReport(moved, failed);
    }

    private void moveOne(String id, File envFile, PrivateKey priv, byte[] recipientEncoded, VaultStore store) throws VaultCryptoException {
        byte[] payload = null;
        try {
            payload = open(priv, recipientEncoded, readAll(envFile), id);
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not read an inbox envelope", e);
        }
        byte[] cek = null;
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload));
            VaultItem.Draft draft = readDraft(in);
            boolean hasMedia = in.readBoolean();
            long mediaBytes = in.readLong();
            if (hasMedia) {
                cek = new byte[VaultCrypto.KEY_BYTES];
                in.readFully(cek);
            }
            if (draft.type.hasMedia() != hasMedia) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Inbox envelope is inconsistent");
            }
            if (!hasMedia) {
                store.addItem(draft, null, null);
            } else {
                File mediaFile = new File(dir, id + ".media");
                addWithDecryptedMedia(store, draft, mediaFile, cek, id);
            }
            File media = new File(dir, id + ".media");
            VaultFiles.secureDelete(envFile);
            if (media.exists()) {
                VaultFiles.secureDelete(media);
            }
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Inbox envelope unreadable", e);
        } finally {
            VaultCrypto.wipe(payload);
            VaultCrypto.wipe(cek);
        }
    }

    /** Decrypts the media file through a pipe straight into {@code store.addItem}: no plaintext copy ever touches the disk. */
    private void addWithDecryptedMedia(VaultStore store, VaultItem.Draft draft, final File mediaFile, final byte[] cek, final String id)
            throws VaultCryptoException, IOException {
        final PipedInputStream pipeIn = new PipedInputStream(64 * 1024);
        final PipedOutputStream pipeOut = new PipedOutputStream(pipeIn);
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final byte[] key = cek.clone();
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try (InputStream in = new FileInputStream(mediaFile)) {
                    VaultMediaCipher.decrypt(in, pipeOut, key, id.getBytes(StandardCharsets.US_ASCII));
                } catch (Throwable e) {
                    failure.set(e);
                } finally {
                    VaultCrypto.wipe(key);
                    try {
                        pipeOut.close();
                    } catch (IOException ignored) {
                    }
                }
            }
        }, "vault-inbox-decrypt");
        t.start();
        try {
            store.addItem(draft, pipeIn, null);
        } catch (VaultCryptoException e) {
            pipeIn.close(); // unblocks the writer
            throw e;
        } finally {
            try {
                t.join(30_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        Throwable f = failure.get();
        if (f != null) {
            // the store read a truncated or altered stream; it must have refused, but never accept silently
            if (f instanceof VaultCryptoException) {
                throw (VaultCryptoException) f;
            }
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Inbox media could not be decrypted", f);
        }
    }

    /** Overwrites and deletes everything (items, media and both keys). Part of the wipe policy; needs no password. */
    public synchronized void deleteAll() throws VaultCryptoException {
        try {
            VaultFiles.secureDeleteTree(dir);
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not delete the inbox", e);
        }
    }

    // ------------------------------------------------------------------ sealing (ECIES P-256 / HKDF-SHA256 / AES-256-GCM)

    private static byte[] seal(PublicKey recipient, byte[] payload, String id) throws VaultCryptoException {
        byte[] secret = null;
        byte[] key = null;
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair eph = gen.generateKeyPair();
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(eph.getPrivate());
            ka.doPhase(recipient, true);
            secret = ka.generateSecret();
            byte[] ephPub = eph.getPublic().getEncoded();
            key = VaultCrypto.hkdfSha256(secret, concat(ephPub, recipient.getEncoded()), KDF_INFO, VaultCrypto.KEY_BYTES);
            byte[] aad = envelopeAad(ephPub, id);
            byte[] ct = VaultCrypto.encrypt(key, payload, aad);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bos);
            out.write(MAGIC);
            out.writeByte(VERSION);
            out.writeShort(ephPub.length);
            out.write(ephPub);
            out.write(ct);
            out.flush();
            return bos.toByteArray();
        } catch (GeneralSecurityException | IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_PLATFORM, "Could not seal the message", e);
        } finally {
            VaultCrypto.wipe(secret);
            VaultCrypto.wipe(key);
        }
    }

    private static byte[] open(PrivateKey priv, byte[] recipientEncoded, byte[] blob, String id) throws VaultCryptoException {
        byte[] secret = null;
        byte[] key = null;
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(blob));
            byte[] magic = new byte[4];
            in.readFully(magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Not an inbox envelope");
            }
            int version = in.readUnsignedByte();
            if (version != VERSION) {
                throw new VaultCryptoException(VaultCryptoException.Reason.UNSUPPORTED_VERSION, "Inbox envelope from a newer app");
            }
            int len = in.readUnsignedShort();
            if (len <= 0 || len > 200) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Bad inbox envelope");
            }
            byte[] ephPub = new byte[len];
            in.readFully(ephPub);
            byte[] ct = new byte[in.available()];
            in.readFully(ct);
            PublicKey eph = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(ephPub));
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(priv);
            ka.doPhase(eph, true);
            secret = ka.generateSecret();
            key = VaultCrypto.hkdfSha256(secret, concat(ephPub, recipientEncoded), KDF_INFO, VaultCrypto.KEY_BYTES);
            return VaultCrypto.decrypt(key, ct, envelopeAad(ephPub, id));
        } catch (GeneralSecurityException | IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Inbox envelope unreadable", e);
        } finally {
            VaultCrypto.wipe(secret);
            VaultCrypto.wipe(key);
        }
    }

    private static byte[] envelopeAad(byte[] ephPub, String id) {
        return concat(MAGIC, new byte[]{VERSION}, ephPub, id.getBytes(StandardCharsets.US_ASCII));
    }

    // ------------------------------------------------------------------ payload

    private static byte[] encodePayload(VaultItem.Draft d, byte[] cek, long mediaBytes) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bos);
        out.writeByte(d.type.code);
        out.writeLong(d.originalDateMillis);
        writeString(out, d.text);
        writeString(out, d.senderName);
        writeString(out, d.forwardedFromName);
        out.writeLong(d.forwardedDateMillis);
        out.writeLong(d.sourceDialogId);
        out.writeLong(d.sourceMessageId);
        writeString(out, d.mediaName);
        writeString(out, d.mimeType);
        out.writeInt(d.width);
        out.writeInt(d.height);
        out.writeInt(d.durationSeconds);
        out.writeBoolean(cek != null);
        out.writeLong(mediaBytes);
        if (cek != null) {
            out.write(cek);
        }
        out.flush();
        return bos.toByteArray();
    }

    private static VaultItem.Draft readDraft(DataInputStream in) throws IOException, VaultCryptoException {
        int code = in.readUnsignedByte();
        VaultItem.Type type = null;
        for (VaultItem.Type t : VaultItem.Type.values()) {
            if (t.code == code) {
                type = t;
            }
        }
        if (type == null) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Unknown item type in inbox");
        }
        VaultItem.Draft d = new VaultItem.Draft(type);
        d.originalDateMillis = in.readLong();
        d.text = nonNull(readString(in));
        d.senderName = readString(in);
        d.forwardedFromName = readString(in);
        d.forwardedDateMillis = in.readLong();
        d.sourceDialogId = in.readLong();
        d.sourceMessageId = in.readLong();
        d.mediaName = readString(in);
        d.mimeType = readString(in);
        d.width = in.readInt();
        d.height = in.readInt();
        d.durationSeconds = in.readInt();
        return d;
    }

    private static String nonNull(String s) {
        return s == null ? "" : s;
    }

    private static void writeString(DataOutputStream out, String s) throws IOException {
        if (s == null) {
            out.writeInt(-1);
            return;
        }
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        if (b.length > MAX_FIELD) {
            throw new IOException("field too long");
        }
        out.writeInt(b.length);
        out.write(b);
    }

    private static String readString(DataInputStream in) throws IOException {
        int n = in.readInt();
        if (n == -1) {
            return null;
        }
        if (n < 0 || n > MAX_FIELD) {
            throw new IOException("bad field length");
        }
        byte[] b = new byte[n];
        in.readFully(b);
        return new String(b, StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------ files

    private PublicKey readPublicKey() throws VaultCryptoException {
        File f = new File(dir, "pub.bin");
        if (!f.exists() || !new File(dir, "priv.bin").exists()) {
            return null;
        }
        try {
            byte[] plain = device.unwrap(readAll(f));
            if (plain.length <= PUB_AAD.length || !Arrays.equals(Arrays.copyOf(plain, PUB_AAD.length), PUB_AAD)) {
                throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Inbox public key invalid");
            }
            byte[] enc = Arrays.copyOfRange(plain, PUB_AAD.length, plain.length);
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(enc));
        } catch (IOException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, "Could not read the inbox key", e);
        } catch (GeneralSecurityException e) {
            throw new VaultCryptoException(VaultCryptoException.Reason.CORRUPTED, "Inbox public key invalid", e);
        }
    }

    private File[] envelopes() {
        File[] list = dir.listFiles();
        if (list == null) {
            return new File[0];
        }
        int n = 0;
        File[] out = new File[list.length];
        for (File f : list) {
            if (f.getName().endsWith(".env")) {
                out[n++] = f;
            }
        }
        return Arrays.copyOf(out, n);
    }

    private void removeOrphanMedia() {
        File[] list = dir.listFiles();
        if (list == null) {
            return;
        }
        long now = System.currentTimeMillis();
        for (File f : list) {
            String name = f.getName();
            if (name.endsWith(".media") || name.endsWith(".tmp")) {
                String id = name.substring(0, name.indexOf('.'));
                boolean hasEnv = new File(dir, id + ".env").exists() || new File(dir, id + ".bad").exists();
                if (!hasEnv && now - f.lastModified() > ORPHAN_MEDIA_MILLIS) {
                    try {
                        VaultFiles.secureDelete(f);
                    } catch (IOException ignored) {
                    }
                }
            }
        }
    }

    private void ensureDir() throws IOException {
        if (!dir.isDirectory() && !dir.mkdirs() && !dir.isDirectory()) {
            throw new IOException("cannot create " + dir);
        }
    }

    private static void writeAtomic(File target, byte[] data) throws IOException {
        File tmp = new File(target.getParentFile(), target.getName() + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(data);
            out.getFD().sync();
        }
        if (!tmp.renameTo(target)) {
            throw new IOException("rename failed");
        }
    }

    private static byte[] readAll(File f) throws IOException {
        try (FileInputStream in = new FileInputStream(f)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream((int) Math.min(f.length(), 1 << 20));
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
            return bos.toByteArray();
        }
    }

    private static void quietDelete(File f) {
        try {
            if (f.exists()) {
                VaultFiles.secureDelete(f);
            }
        } catch (IOException ignored) {
        }
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
        }
        return sb.toString();
    }

    /** Stops reading after {@code limit} bytes with {@link TooLarge}. */
    private static final class LimitedInputStream extends InputStream {
        static final class TooLarge extends IOException {
        }

        private final InputStream in;
        private final long limit;
        private long read;

        LimitedInputStream(InputStream in, long limit) {
            this.in = in;
            this.limit = limit;
        }

        @Override
        public int read() throws IOException {
            int b = in.read();
            if (b >= 0 && ++read > limit) {
                throw new TooLarge();
            }
            return b;
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            int n = in.read(buf, off, len);
            if (n > 0) {
                read += n;
                if (read > limit) {
                    throw new TooLarge();
                }
            }
            return n;
        }
    }
}
