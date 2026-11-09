package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class ChannelRemoteStoreTest {

    private static final String TOKEN = "00112233445566778899aabbccddeeff";
    private static final String ID1 = "0123456789abcdef0123456789abcdef";

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private FakeChannelApi api;
    private ChannelRemoteStore store;

    @Before
    public void setUp() {
        api = new FakeChannelApi();
        store = new ChannelRemoteStore(api, 1024 * 1024);
    }

    private File file(int n, int seed) throws Exception {
        File f = tmp.newFile();
        byte[] d = new byte[n];
        for (int i = 0; i < n; i++) {
            d[i] = (byte) (i + seed);
        }
        Files.write(f.toPath(), d);
        return f;
    }

    private static String token(int i) {
        return String.format("%016x%016x", 0x1000L + i, 0L);
    }

    @Test
    public void uploadListDownloadDelete_roundTrip() throws Exception {
        File f = file(500, 3);
        VaultRemoteStore.Entry e = store.upload("r." + ID1, TOKEN, f);
        assertEquals("r." + ID1, e.name);
        assertEquals(500, e.size);
        List<VaultRemoteStore.Entry> l = store.list(0, 10);
        assertEquals(1, l.size());
        assertEquals(e.seq, l.get(0).seq);
        assertEquals(e.ref, l.get(0).ref);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        store.download(e.ref, out);
        assertArrayEquals(Files.readAllBytes(f.toPath()), out.toByteArray());
        store.delete(e.ref);
        assertTrue(store.list(0, 10).isEmpty());
        store.delete(e.ref); // already gone: fine
    }

    @Test
    public void sameToken_returnsSameMessage() throws Exception {
        File f = file(100, 1);
        VaultRemoteStore.Entry a = store.upload("r." + ID1, TOKEN, f);
        VaultRemoteStore.Entry b = store.upload("r." + ID1, TOKEN, f);
        assertEquals(a.ref, b.ref);
        assertEquals(1, api.messageCount());
    }

    @Test
    public void differentTokens_makeDifferentMessages() throws Exception {
        File f = file(100, 1);
        store.upload("r." + ID1, token(1), f);
        store.upload("m." + ID1, token(2), f);
        assertEquals(2, api.messageCount());
    }

    @Test
    public void list_isOrderedAndPaged_whenServerPagesAreSmall() throws Exception {
        List<Long> seqs = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            seqs.add(store.upload("r." + String.format("%032x", i + 1), token(i), file(10, i)).seq);
        }
        List<VaultRemoteStore.Entry> all = new ArrayList<>();
        long cursor = 0;
        while (true) {
            List<VaultRemoteStore.Entry> page = store.list(cursor, 4);
            assertTrue(page.size() <= 4);
            if (page.isEmpty()) {
                break;
            }
            all.addAll(page);
            cursor = page.get(page.size() - 1).seq;
        }
        assertEquals(10, all.size());
        for (int i = 0; i < 10; i++) {
            assertEquals((long) seqs.get(i), all.get(i).seq);
        }
    }

    @Test
    public void foreignMessages_areSkipped_andNeverCauseEmptyPageEarly() throws Exception {
        store.upload("r." + ID1, token(1), file(10, 1));
        for (int i = 0; i < 20; i++) {
            api.post(i % 2 == 0 ? "hello" : "tgv1 BAD NAME!", new byte[5]);
        }
        store.upload("m." + ID1, token(2), file(10, 2));
        List<VaultRemoteStore.Entry> l = store.list(0, 100);
        assertEquals(2, l.size());
        // after the first object, the second is found even though 20 foreign messages lie between
        List<VaultRemoteStore.Entry> next = store.list(l.get(0).seq, 100);
        assertEquals(1, next.size());
        assertEquals("m." + ID1, next.get(0).name);
    }

    @Test
    public void limitIsHonoured_withoutSkippingAnything() throws Exception {
        for (int i = 0; i < 5; i++) {
            store.upload("r." + String.format("%032x", i + 1), token(i), file(10, i));
            api.post("noise", new byte[1]);
        }
        List<VaultRemoteStore.Entry> a = store.list(0, 2);
        assertEquals(2, a.size());
        List<VaultRemoteStore.Entry> b = store.list(a.get(1).seq, 10);
        assertEquals(3, b.size());
    }

    @Test
    public void nameParsing_isStrict() {
        assertEquals("r." + ID1, ChannelRemoteStore.nameOf("tgv1 r." + ID1));
        assertNull(ChannelRemoteStore.nameOf("r." + ID1));
        assertNull(ChannelRemoteStore.nameOf("tgv1 R." + ID1));
        assertNull(ChannelRemoteStore.nameOf("tgv1 r." + ID1 + "\n"));
        assertNull(ChannelRemoteStore.nameOf("tgv1 rx" + ID1));
        assertNull(ChannelRemoteStore.nameOf("tgv1 "));
        assertNull(ChannelRemoteStore.nameOf(null));
        StringBuilder sb = new StringBuilder("tgv1 r.");
        for (int i = 0; i < 100; i++) {
            sb.append('a');
        }
        assertNull(ChannelRemoteStore.nameOf(sb.toString()));
    }

    @Test
    public void invalidArguments_areRefused() throws Exception {
        File f = file(10, 1);
        expectIo(() -> store.upload("bad name", TOKEN, f));
        expectIo(() -> store.upload("r." + ID1, "short", f));
        expectIo(() -> store.upload("r." + ID1, "zz112233445566778899aabbccddeeff", f));
        expectIo(() -> store.upload("r." + ID1, TOKEN, new File(tmp.getRoot(), "missing")));
        expectIo(() -> store.download("12x", new ByteArrayOutputStream()));
        expectIo(() -> store.download("", new ByteArrayOutputStream()));
        expectIo(() -> store.delete("-5"));
        expectIo(() -> store.delete("99999999999999999999"));
        expectIo(() -> store.delete(null));
    }

    @Test
    public void oversizedFile_isRefusedBeforeSending() throws Exception {
        ChannelRemoteStore small = new ChannelRemoteStore(api, 100);
        expectIo(() -> small.upload("r." + ID1, TOKEN, file(101, 1)));
        assertEquals(0, api.sends);
        small.upload("r." + ID1, TOKEN, file(100, 1));
        assertEquals(1, api.sends);
    }

    @Test
    public void randomId_isStableAndNeverZero() throws Exception {
        assertEquals(ChannelRemoteStore.randomIdFrom(TOKEN), ChannelRemoteStore.randomIdFrom(TOKEN));
        assertEquals(0x0011223344556677L, ChannelRemoteStore.randomIdFrom(TOKEN));
        assertEquals(1, ChannelRemoteStore.randomIdFrom("00000000000000000000000000000000"));
        assertEquals(-1L, ChannelRemoteStore.randomIdFrom("ffffffffffffffff0000000000000000"));
    }

    @Test
    public void outOfOrderHistory_isAnError() throws Exception {
        ChannelApi bad = new ChannelApi() {
            @Override
            public Message send(String c, long r, File f) {
                return null;
            }

            @Override
            public List<Message> history(long after, int limit) {
                List<Message> l = new ArrayList<>();
                l.add(new Message(after, "tgv1 r." + ID1, 1)); // not greater than the cursor
                return l;
            }

            @Override
            public void download(long id, java.io.OutputStream out) {
            }

            @Override
            public void delete(long id) {
            }
        };
        expectIo(() -> new ChannelRemoteStore(bad, 10).list(5, 10));
    }

    @Test
    public void sendWithoutConfirmation_isAnError() throws Exception {
        ChannelApi none = new ChannelApi() {
            @Override
            public Message send(String c, long r, File f) {
                return new Message(0, c, 0);
            }

            @Override
            public List<Message> history(long a, int l) {
                return new ArrayList<>();
            }

            @Override
            public void download(long id, java.io.OutputStream out) {
            }

            @Override
            public void delete(long id) {
            }
        };
        expectIo(() -> new ChannelRemoteStore(none, 1000).upload("r." + ID1, TOKEN, file(5, 1)));
    }

    private interface Io {
        void run() throws Exception;
    }

    private static void expectIo(Io io) {
        try {
            io.run();
            fail("expected IOException");
        } catch (IOException e) {
            // expected
        } catch (Exception e) {
            fail("unexpected " + e);
        }
    }

    // ------------------------------------------------------------------ the sync engine on top of it

    @Test
    public void syncEngine_worksOverTheChannelAdapter_betweenTwoDevices() throws Exception {
        VaultKeyManager ka = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), 1000);
        VaultKeyManager.Setup setup = ka.beginSetup("device a password".toCharArray(), "device a password".toCharArray());
        String rk = setup.recoveryKey().format();
        byte[] bundle = setup.complete(rk);
        VaultKeyManager kb = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), 1000);
        kb.restoreFromBundle(bundle, rk, "device b password".toCharArray(), "device b password".toCharArray(), false);

        VaultSyncEngine ea = engine("a", ka, store);
        VaultSyncEngine eb = engine("b", kb, new ChannelRemoteStore(api, 1024 * 1024));
        byte[] media = new byte[30000];
        for (int i = 0; i < media.length; i++) {
            media[i] = (byte) (i * 7);
        }
        VaultItem.Draft d = new VaultItem.Draft(VaultItem.Type.PHOTO).text("c").media("p.jpg", "image/jpeg", 1, 1, 0);
        VaultItem photo = ea.addItem(d, new ByteArrayInputStream(media), new byte[]{1, 2, 3});
        VaultItem txt = ea.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("hi"), null, null);
        for (int i = 0; i < 5; i++) {
            api.post("some other post", new byte[3]);
        }
        ea.sync();
        eb.sync();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        eb.openMedia(photo.id, out);
        assertArrayEquals(media, out.toByteArray());
        ea.deleteItem(txt.id);
        ea.sync();
        VaultSyncEngine.SyncReport r = eb.sync();
        assertEquals(1, r.tombstonesApplied);
        // 5 foreign + bundle + thumbnail + media + record + tombstone
        assertEquals(10, api.messageCount());
    }

    private VaultSyncEngine engine(String name, VaultKeyManager k, VaultRemoteStore remote) throws Exception {
        File dir = tmp.newFolder(name);
        VaultStore st = new VaultStore(new File(dir, "vault"), k, System::currentTimeMillis, 4096);
        return new VaultSyncEngine(st, k, remote, new File(dir, "journal"));
    }

    @Test
    public void lostAcknowledgement_doesNotDuplicateOverTheChannel() throws Exception {
        VaultKeyManager ka = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), 1000);
        ka.createVault("device a password".toCharArray(), "device a password".toCharArray());
        VaultSyncEngine ea = engine("a", ka, store);
        ea.addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text("x"), null, null);
        api.failAtCall = 3; // list, send(bundle) ok, send(record) fails after taking effect
        api.failAfterEffect = true;
        try {
            ea.sync();
            fail("expected failure");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.IO_ERROR, e.getReason());
        }
        api.failAtCall = 0;
        ea.sync();
        assertEquals(2, api.messageCount());
    }
}
