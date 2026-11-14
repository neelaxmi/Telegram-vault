package org.telegram.ui;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Matrix;
import android.media.MediaMetadataRetriever;
import android.net.Uri;

import androidx.exifinterface.media.ExifInterface;

import org.telegram.messenger.vault.VaultItem;
import org.telegram.messenger.vault.VaultStore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * Preview pictures and sizes for photos and videos, made from a file or a content address without loading the whole
 * file into memory. A failure only means "no preview": the item itself is still saved.
 */
final class VaultThumbs {

    static final int MAX_EDGE = 480;

    private VaultThumbs() {
    }

    static final class Info {
        byte[] thumbnail;
        int width;
        int height;
        int durationSeconds;
    }

    static Info make(Context c, Uri uri, VaultItem.Type type) {
        Info info = new Info();
        try {
            Bitmap bmp = null;
            if (type == VaultItem.Type.PHOTO) {
                int degrees = 0;
                try (InputStream in = c.getContentResolver().openInputStream(uri)) {
                    if (in != null) {
                        degrees = degreesOf(new ExifInterface(in).getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL));
                    }
                } catch (Exception ignored) {
                    // no orientation information: draw as stored
                }
                BitmapFactory.Options o = new BitmapFactory.Options();
                o.inJustDecodeBounds = true;
                try (InputStream in = c.getContentResolver().openInputStream(uri)) {
                    BitmapFactory.decodeStream(in, null, o);
                }
                boolean swap = degrees == 90 || degrees == 270;
                info.width = Math.max(0, swap ? o.outHeight : o.outWidth);
                info.height = Math.max(0, swap ? o.outWidth : o.outHeight);
                int sample = 1;
                while (Math.max(o.outWidth, o.outHeight) / (sample * 2) >= MAX_EDGE) {
                    sample *= 2;
                }
                BitmapFactory.Options d = new BitmapFactory.Options();
                d.inSampleSize = sample;
                try (InputStream in = c.getContentResolver().openInputStream(uri)) {
                    bmp = BitmapFactory.decodeStream(in, null, d);
                }
                bmp = rotate(bmp, degrees);
            } else if (type == VaultItem.Type.VIDEO) {
                MediaMetadataRetriever r = new MediaMetadataRetriever();
                try {
                    r.setDataSource(c, uri);
                    info.width = parse(r.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH));
                    info.height = parse(r.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT));
                    int rot = parse(r.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_ROTATION));
                    if (rot == 90 || rot == 270) {
                        int t = info.width;
                        info.width = info.height;
                        info.height = t;
                    }
                    info.durationSeconds = parse(r.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)) / 1000;
                    bmp = r.getFrameAtTime(0, MediaMetadataRetriever.OPTION_CLOSEST_SYNC);
                } finally {
                    r.release();
                }
            }
            info.thumbnail = jpeg(bmp);
        } catch (Throwable t) {
            info.thumbnail = null;
        }
        return info;
    }

    /** Duration in seconds of an audio file, or 0 when unknown. */
    static int audioSeconds(Context c, Uri uri) {
        MediaMetadataRetriever r = new MediaMetadataRetriever();
        try {
            r.setDataSource(c, uri);
            return parse(r.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)) / 1000;
        } catch (Throwable t) {
            return 0;
        } finally {
            try {
                r.release();
            } catch (Throwable ignored) {
            }
        }
    }

    /** A full-size picture from decrypted bytes (kept in memory only), at most 2048 px on each side, upright. */
    static Bitmap decodeFull(byte[] bytes) {
        BitmapFactory.Options bounds = new BitmapFactory.Options();
        bounds.inJustDecodeBounds = true;
        BitmapFactory.decodeByteArray(bytes, 0, bytes.length, bounds);
        int sample = 1;
        while (bounds.outWidth / sample > 2048 || bounds.outHeight / sample > 2048) {
            sample *= 2;
        }
        BitmapFactory.Options o = new BitmapFactory.Options();
        o.inSampleSize = sample;
        Bitmap bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.length, o);
        int degrees = 0;
        try {
            degrees = degreesOf(new ExifInterface(new ByteArrayInputStream(bytes)).getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL));
        } catch (Exception ignored) {
            // draw as stored
        }
        return rotate(bmp, degrees);
    }

    /** A small preview from decrypted bytes (for photos saved before previews were stored). */
    static Bitmap decodeSmall(byte[] bytes) {
        BitmapFactory.Options bounds = new BitmapFactory.Options();
        bounds.inJustDecodeBounds = true;
        BitmapFactory.decodeByteArray(bytes, 0, bytes.length, bounds);
        int sample = 1;
        while (Math.max(bounds.outWidth, bounds.outHeight) / (sample * 2) >= MAX_EDGE) {
            sample *= 2;
        }
        BitmapFactory.Options o = new BitmapFactory.Options();
        o.inSampleSize = sample;
        Bitmap bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.length, o);
        try {
            return rotate(bmp, degreesOf(new ExifInterface(new ByteArrayInputStream(bytes)).getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)));
        } catch (Exception e) {
            return bmp;
        }
    }

    private static int degreesOf(int orientation) {
        switch (orientation) {
            case ExifInterface.ORIENTATION_ROTATE_90:
                return 90;
            case ExifInterface.ORIENTATION_ROTATE_180:
                return 180;
            case ExifInterface.ORIENTATION_ROTATE_270:
                return 270;
            default:
                return 0;
        }
    }

    private static Bitmap rotate(Bitmap b, int degrees) {
        if (b == null || degrees == 0) {
            return b;
        }
        Matrix m = new Matrix();
        m.postRotate(degrees);
        Bitmap r = Bitmap.createBitmap(b, 0, 0, b.getWidth(), b.getHeight(), m, true);
        if (r != b) {
            b.recycle();
        }
        return r;
    }

    private static byte[] jpeg(Bitmap bmp) {
        if (bmp == null) {
            return null;
        }
        int max = Math.max(bmp.getWidth(), bmp.getHeight());
        if (max > MAX_EDGE) {
            float f = (float) MAX_EDGE / max;
            Bitmap s = Bitmap.createScaledBitmap(bmp, Math.max(1, Math.round(bmp.getWidth() * f)), Math.max(1, Math.round(bmp.getHeight() * f)), true);
            if (s != bmp) {
                bmp.recycle();
            }
            bmp = s;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        bmp.compress(Bitmap.CompressFormat.JPEG, 80, out);
        bmp.recycle();
        byte[] b = out.toByteArray();
        return b.length > 0 && b.length <= VaultStore.MAX_THUMBNAIL_BYTES ? b : null;
    }

    private static int parse(String s) {
        try {
            return s == null ? 0 : Math.max(0, Integer.parseInt(s));
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
