package org.telegram.messenger.vault;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * Real media kinds in the Vault: the stored item keeps its type, kind flags, formatting and preview image, and the
 * category filters work on those stored facts. Also: records written before format version 2 still read.
 */
public class VaultMediaKindsTest {

    private static final String PW = "abc123";

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private VaultKeyManager keys;
    private VaultStore store;
    private TestDeviceKeyWrapper device;

    @Before
    public void setUp() throws Exception {
        device = new TestDeviceKeyWrapper();
        keys = new VaultKeyManager(new InMemoryHeaderStore(), device, 1000);
        keys.createVault(PW.toCharArray(), PW.toCharArray());
        store = new VaultStore(new File(tmp.getRoot(), "data"), keys);
    }

    private static byte[] random(int n, long seed) {
        byte[] b = new byte[n];
        new Random(seed).nextBytes(b);
        return b;
    }

    private VaultItem add(VaultItem.Draft d, byte[] media, byte[] thumb) throws Exception {
        return store.addItem(d, media == null ? null : new ByteArrayInputStream(media), thumb);
    }

    private byte[] media(VaultItem i) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        store.readMedia(i.id, out);
        return out.toByteArray();
    }

    // ------------------------------------------------------------ 1..6 each kind keeps its bytes, type and details

    @Test
    public void photo_keepsBytesThumbnailCaptionAndSize() throws Exception {
        byte[] photo = random(200_000, 1);
        byte[] thumb = random(3_000, 2);
        VaultItem i = add(new VaultItem.Draft(VaultItem.Type.PHOTO).text("sunset").media("p.jpg", "image/jpeg", 1280, 720, 0), photo, thumb);
        VaultItem back = store.get(i.id);
        assertEquals(VaultItem.Type.PHOTO, back.type);
        assertEquals("sunset", back.text);
        assertEquals(1280, back.width);
        assertEquals(720, back.height);
        assertEquals(200_000, back.mediaSize);
        assertArrayEquals(photo, media(back));
        assertArrayEquals(thumb, store.readThumbnail(back.id));
    }

    @Test
    public void video_keepsBytesDurationAndThumbnail() throws Exception {
        byte[] video = random(900_000, 3);
        byte[] thumb = random(4_000, 4);
        VaultItem i = add(new VaultItem.Draft(VaultItem.Type.VIDEO).text("clip").media("v.mp4", "video/mp4", 1920, 1080, 93), video, thumb);
        VaultItem back = store.get(i.id);
        assertEquals(93, back.durationSeconds);
        assertArrayEquals(video, media(back));
        assertArrayEquals(thumb, store.readThumbnail(back.id));
    }

    @Test
    public void document_keepsNameMimeSizeAndBytes() throws Exception {
        byte[] pdf = ("%PDF-1.7 " + new String(random(30_000, 5), "ISO-8859-1")).getBytes("ISO-8859-1");
        VaultItem i = add(new VaultItem.Draft(VaultItem.Type.DOCUMENT).media("Report 2026.pdf", "application/pdf", 0, 0, 0), pdf, null);
        VaultItem back = store.get(i.id);
        assertEquals("Report 2026.pdf", back.mediaName);
        assertEquals("application/pdf", back.mimeType);
        assertEquals(pdf.length, back.mediaSize);
        assertArrayEquals(pdf, media(back));
    }

    @Test
    public void voice_keepsFlagDurationAndBytes() throws Exception {
        byte[] ogg = random(20_000, 6);
        VaultItem i = add(new VaultItem.Draft(VaultItem.Type.DOCUMENT).flags(VaultItem.FLAG_VOICE)
                .media("voice.ogg", "audio/ogg", 0, 0, 17), ogg, null);
        VaultItem back = store.get(i.id);
        assertTrue(back.isVoice());
        assertFalse(back.isMusic());
        assertEquals(17, back.durationSeconds);
        assertArrayEquals(ogg, media(back));
    }

    @Test
    public void forwardedMedia_keepsOriginAndMediaTogether() throws Exception {
        byte[] photo = random(5_000, 7);
        VaultItem i = add(new VaultItem.Draft(VaultItem.Type.PHOTO).text("fwd caption").forwardedFrom("News Channel", 1_700_000_000_000L)
                .source(-100123L, 55L).media("a.jpg", "image/jpeg", 10, 10, 0), photo, random(500, 8));
        VaultItem back = store.get(i.id);
        assertTrue(back.isForwarded());
        assertEquals("News Channel", back.forwardedFromName);
        assertEquals(1_700_000_000_000L, back.forwardedDateMillis);
        assertEquals(VaultItem.Type.PHOTO, back.type);
        assertArrayEquals(photo, media(back));
    }

    @Test
    public void textFormatting_survivesAsEntities() throws Exception {
        String text = "Hello bold and link";
        List<VaultEntities.Entity> list = new ArrayList<>();
        list.add(new VaultEntities.Entity(VaultEntities.BOLD, 6, 4, null));
        list.add(new VaultEntities.Entity(VaultEntities.TEXT_URL, 15, 4, "https://example.com/a?b=1;2,3%x"));
        VaultItem i = add(new VaultItem.Draft(VaultItem.Type.TEXT).text(text).entities(VaultEntities.encode(list, text.length())), null, null);
        VaultItem back = store.get(i.id);
        List<VaultEntities.Entity> got = VaultEntities.decode(back.entities, back.text.length());
        assertEquals(2, got.size());
        assertEquals(VaultEntities.BOLD, got.get(0).kind);
        assertEquals(6, got.get(0).offset);
        assertEquals("https://example.com/a?b=1;2,3%x", got.get(1).url);
    }

    // ------------------------------------------------------------ entities encoding

    @Test
    public void entities_invalidOnesAreDropped_andDecodeNeverThrows() {
        List<VaultEntities.Entity> bad = new ArrayList<>();
        bad.add(new VaultEntities.Entity(VaultEntities.BOLD, -1, 3, null));
        bad.add(new VaultEntities.Entity(VaultEntities.BOLD, 0, 0, null));
        bad.add(new VaultEntities.Entity(VaultEntities.BOLD, 8, 5, null));
        bad.add(new VaultEntities.Entity(VaultEntities.TEXT_URL, 0, 2, null));
        bad.add(new VaultEntities.Entity('?', 0, 2, null));
        bad.add(new VaultEntities.Entity(VaultEntities.ITALIC, 0, 10, null));
        assertEquals("i,0,10", VaultEntities.encode(bad, 10));
        for (String junk : new String[]{"", null, ";;", "b", "b,x,y", "b,0,-3", "L,0,2", "zz,0,1", "b,0,99999", "b,0,2;garbage;i,1,1"}) {
            VaultEntities.decode(junk, 10); // must not throw
        }
        assertEquals(2, VaultEntities.decode("b,0,2;garbage;i,1,1", 10).size());
    }

    // ------------------------------------------------------------ categories on stored facts

    @Test
    public void categories_filterRealStoredItems() throws Exception {
        add(new VaultItem.Draft(VaultItem.Type.TEXT).text("just words"), null, null);
        add(new VaultItem.Draft(VaultItem.Type.TEXT).text("see https://example.org/page now"), null, null);
        add(new VaultItem.Draft(VaultItem.Type.TEXT).text("link text").entities("L,0,4,https%3A//x.y"), null, null);
        add(new VaultItem.Draft(VaultItem.Type.PHOTO).media("a.jpg", "image/jpeg", 1, 1, 0), random(10, 1), null);
        add(new VaultItem.Draft(VaultItem.Type.PHOTO).media("b.jpg", "image/jpeg", 1, 1, 0), random(10, 2), null);
        add(new VaultItem.Draft(VaultItem.Type.VIDEO).media("v.mp4", "video/mp4", 1, 1, 5), random(10, 3), null);
        add(new VaultItem.Draft(VaultItem.Type.DOCUMENT).media("d.pdf", "application/pdf", 0, 0, 0), random(10, 4), null);
        add(new VaultItem.Draft(VaultItem.Type.DOCUMENT).media("z.zip", "application/zip", 0, 0, 0), random(10, 5), null);
        add(new VaultItem.Draft(VaultItem.Type.DOCUMENT).flags(VaultItem.FLAG_MUSIC).media("s.mp3", "audio/mpeg", 0, 0, 200), random(10, 6), null);
        add(new VaultItem.Draft(VaultItem.Type.DOCUMENT).media("t.m4a", "audio/mp4", 0, 0, 100), random(10, 7), null); // music by mime
        add(new VaultItem.Draft(VaultItem.Type.DOCUMENT).flags(VaultItem.FLAG_VOICE).media("v.ogg", "audio/ogg", 0, 0, 4), random(10, 8), null);

        VaultListModel m = new VaultListModel(store);
        m.refresh();
        assertEquals(11, m.rows().size());
        assertEquals(11, count(m, VaultCategory.ALL));
        assertEquals(2, count(m, VaultCategory.PHOTOS));
        assertEquals(1, count(m, VaultCategory.VIDEOS));
        assertEquals(2, count(m, VaultCategory.FILES));   // pdf + zip only: no music, no voice
        assertEquals(2, count(m, VaultCategory.LINKS));   // plain URL in text + text link entity
        assertEquals(2, count(m, VaultCategory.MUSIC));   // flag and mime
        assertEquals(1, count(m, VaultCategory.VOICE));
        m.setCategory(VaultCategory.ALL);
        assertEquals(11, m.rows().size());
    }

    private static int count(VaultListModel m, VaultCategory c) throws Exception {
        m.setCategory(c);
        return m.rows().size();
    }

    @Test
    public void search_andCategory_combine() throws Exception {
        add(new VaultItem.Draft(VaultItem.Type.PHOTO).text("holiday beach").media("a.jpg", "image/jpeg", 1, 1, 0), random(10, 1), null);
        add(new VaultItem.Draft(VaultItem.Type.TEXT).text("holiday plan"), null, null);
        add(new VaultItem.Draft(VaultItem.Type.PHOTO).text("work").media("b.jpg", "image/jpeg", 1, 1, 0), random(10, 2), null);
        VaultListModel m = new VaultListModel(store);
        m.setCategory(VaultCategory.PHOTOS);
        m.setQuery("holiday");
        assertEquals(1, m.rows().size());
        assertEquals(VaultItem.Type.PHOTO, m.rows().get(0).item.type);
        m.setCategory(VaultCategory.ALL);
        assertEquals(2, m.rows().size());
    }

    // ------------------------------------------------------------ saved while locked keeps all of it

    @Test
    public void inbox_keepsKindFlagsFormattingAndThumbnail() throws Exception {
        VaultInbox inbox = new VaultInbox(new File(tmp.getRoot(), "inbox"), device);
        inbox.ensureKeyPair(keys);
        keys.lock();
        byte[] ogg = random(9_000, 11);
        byte[] thumb = random(700, 12);
        inbox.put(new VaultItem.Draft(VaultItem.Type.DOCUMENT).flags(VaultItem.FLAG_VOICE).text("note")
                .entities("b,0,4").media("v.ogg", "audio/ogg", 0, 0, 9), new ByteArrayInputStream(ogg), 1 << 20);
        inbox.put(new VaultItem.Draft(VaultItem.Type.VIDEO).media("c.mp4", "video/mp4", 640, 360, 30),
                new ByteArrayInputStream(random(4_000, 13)), thumb, 1 << 20);
        keys.unlock(PW.toCharArray());
        assertEquals(2, inbox.drain(keys, store).moved);
        VaultListModel m = new VaultListModel(store);
        m.setCategory(VaultCategory.VOICE);
        assertEquals(1, m.rows().size());
        VaultItem voice = m.rows().get(0).item;
        assertEquals("b,0,4", voice.entities);
        assertArrayEquals(ogg, media(voice));
        m.setCategory(VaultCategory.VIDEOS);
        VaultItem video = m.rows().get(0).item;
        assertArrayEquals(thumb, store.readThumbnail(video.id));
    }

    @Test
    public void inbox_thumbnailWithoutMedia_isRefused() throws Exception {
        VaultInbox inbox = new VaultInbox(new File(tmp.getRoot(), "inbox2"), device);
        inbox.ensureKeyPair(keys);
        try {
            inbox.put(new VaultItem.Draft(VaultItem.Type.TEXT).text("x"), null, new byte[]{1}, 100);
            org.junit.Assert.fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_ARGUMENT, e.getReason());
        }
    }

    // ------------------------------------------------------------ format compatibility

    /** A record exactly as written by the previous app version (format 1, no flags/entities). */
    private static byte[] version1Record(String id, String text) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bos);
        out.writeByte(1);
        writeStr(out, id);
        out.writeByte(0);            // TEXT
        out.writeLong(1_700_000_000_000L);
        out.writeLong(0);
        writeStr(out, text);
        writeStr(out, null);
        writeStr(out, null);
        out.writeLong(0);
        out.writeLong(0);
        out.writeLong(0);
        writeStr(out, null);
        writeStr(out, null);
        writeStr(out, null);
        out.writeLong(0);
        out.writeInt(0);
        out.writeInt(0);
        out.writeInt(0);
        writeStr(out, null);
        byte[] payload = bos.toByteArray();
        int padded = ((4 + payload.length + 255) / 256) * 256;
        byte[] r = new byte[padded];
        r[0] = (byte) (payload.length >>> 24);
        r[1] = (byte) (payload.length >>> 16);
        r[2] = (byte) (payload.length >>> 8);
        r[3] = (byte) payload.length;
        System.arraycopy(payload, 0, r, 4, payload.length);
        return r;
    }

    private static void writeStr(DataOutputStream out, String s) throws Exception {
        if (s == null) {
            out.writeInt(-1);
        } else {
            byte[] b = s.getBytes("UTF-8");
            out.writeInt(b.length);
            out.write(b);
        }
    }

    @Test
    public void recordsWrittenByThePreviousVersion_stillRead() throws Exception {
        VaultItem old = VaultItem.decodePadded(version1Record("abcdefabcdefabcdefabcdefabcdefab", "written before flags"));
        assertEquals("written before flags", old.text);
        assertEquals(0, old.flags);
        assertEquals("", old.entities);
        assertEquals(VaultItem.Type.TEXT, old.type);
    }

    @Test
    public void newRecords_roundTripFlagsAndEntities_andRejectBadValues() throws Exception {
        VaultItem i = new VaultItem("abcdefabcdefabcdefabcdefabcdefab", VaultItem.Type.TEXT, 5, 0, "hello", null, null, 0, 0, 0,
                null, null, null, 0, 0, 0, 0, null, 0, "b,0,5");
        VaultItem back = VaultItem.decodePadded(i.encodePadded());
        assertEquals("b,0,5", back.entities);
        VaultItem music = new VaultItem("abcdefabcdefabcdefabcdefabcdefab", VaultItem.Type.DOCUMENT, 5, 0, "", null, null, 0, 0, 0,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "s.mp3", "audio/mpeg", 10, 0, 0, 5, null, VaultItem.FLAG_MUSIC, "");
        assertTrue(VaultItem.decodePadded(music.encodePadded()).isMusic());
        try {
            new VaultItem.Draft(VaultItem.Type.TEXT).text("x").flags(-1).validate();
            org.junit.Assert.fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_ARGUMENT, e.getReason());
        }
    }
}
