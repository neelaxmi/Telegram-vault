package org.telegram.ui;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Matrix;
import android.net.Uri;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.ScaleGestureDetector;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.MediaController;
import android.widget.TextView;
import android.widget.VideoView;

import org.telegram.messenger.AndroidUtilities;

import java.io.File;

/**
 * Full-screen viewers for photos and videos kept in the Vault. Both windows are FLAG_SECURE, like the Vault screen
 * itself: no screenshots, and a blank picture in the app switcher.
 */
final class VaultMediaViews {

    private VaultMediaViews() {
    }

    private static Dialog fullScreen(Activity a) {
        Dialog d = new Dialog(a, android.R.style.Theme_Black_NoTitleBar_Fullscreen);
        d.requestWindowFeature(Window.FEATURE_NO_TITLE);
        d.getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        return d;
    }

    private static TextView topButton(Context c, String label, int gravity, View.OnClickListener l) {
        TextView t = new TextView(c);
        t.setText(label);
        t.setTextColor(Color.WHITE);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        t.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        t.setPadding(AndroidUtilities.dp(18), AndroidUtilities.dp(16), AndroidUtilities.dp(18), AndroidUtilities.dp(16));
        t.setBackgroundColor(0x66000000);
        t.setOnClickListener(l);
        return t;
    }

    /** A picture that can be pinched, dragged and double-tapped. */
    static final class ZoomImageView extends ImageView {
        private final Matrix matrix = new Matrix();
        private final float[] v = new float[9];
        private final ScaleGestureDetector scaler;
        private float fit = 1f;
        private float lastX, lastY;
        private long lastTap;

        ZoomImageView(Context c) {
            super(c);
            setScaleType(ScaleType.MATRIX);
            scaler = new ScaleGestureDetector(c, new ScaleGestureDetector.SimpleOnScaleGestureListener() {
                @Override
                public boolean onScale(ScaleGestureDetector d) {
                    float cur = currentScale();
                    float target = Math.max(fit, Math.min(cur * d.getScaleFactor(), fit * 6f));
                    matrix.postScale(target / cur, target / cur, d.getFocusX(), d.getFocusY());
                    clamp();
                    setImageMatrix(matrix);
                    return true;
                }
            });
        }

        private float currentScale() {
            matrix.getValues(v);
            return v[Matrix.MSCALE_X];
        }

        void show(Bitmap b) {
            setImageBitmap(b);
            post(new Runnable() {
                @Override
                public void run() {
                    reset();
                }
            });
        }

        private void reset() {
            if (getDrawable() == null || getWidth() == 0) {
                return;
            }
            float bw = getDrawable().getIntrinsicWidth();
            float bh = getDrawable().getIntrinsicHeight();
            fit = Math.min(getWidth() / bw, getHeight() / bh);
            matrix.reset();
            matrix.postScale(fit, fit);
            matrix.postTranslate((getWidth() - bw * fit) / 2f, (getHeight() - bh * fit) / 2f);
            setImageMatrix(matrix);
        }

        @Override
        protected void onSizeChanged(int w, int h, int ow, int oh) {
            super.onSizeChanged(w, h, ow, oh);
            reset();
        }

        private void clamp() {
            if (getDrawable() == null) {
                return;
            }
            matrix.getValues(v);
            float s = v[Matrix.MSCALE_X];
            float w = getDrawable().getIntrinsicWidth() * s;
            float h = getDrawable().getIntrinsicHeight() * s;
            float dx = 0, dy = 0;
            if (w <= getWidth()) {
                dx = (getWidth() - w) / 2f - v[Matrix.MTRANS_X];
            } else {
                dx = Math.max(getWidth() - w - v[Matrix.MTRANS_X], Math.min(0 - v[Matrix.MTRANS_X], 0));
            }
            if (h <= getHeight()) {
                dy = (getHeight() - h) / 2f - v[Matrix.MTRANS_Y];
            } else {
                dy = Math.max(getHeight() - h - v[Matrix.MTRANS_Y], Math.min(0 - v[Matrix.MTRANS_Y], 0));
            }
            matrix.postTranslate(dx, dy);
        }

        @Override
        public boolean onTouchEvent(MotionEvent e) {
            scaler.onTouchEvent(e);
            switch (e.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    lastX = e.getX();
                    lastY = e.getY();
                    long now = System.currentTimeMillis();
                    if (now - lastTap < 280) {
                        if (currentScale() > fit * 1.05f) {
                            reset();
                        } else {
                            matrix.postScale(2.5f, 2.5f, e.getX(), e.getY());
                            clamp();
                            setImageMatrix(matrix);
                        }
                    }
                    lastTap = now;
                    break;
                case MotionEvent.ACTION_MOVE:
                    if (!scaler.isInProgress() && e.getPointerCount() == 1 && currentScale() > fit * 1.02f) {
                        matrix.postTranslate(e.getX() - lastX, e.getY() - lastY);
                        clamp();
                        setImageMatrix(matrix);
                    }
                    lastX = e.getX();
                    lastY = e.getY();
                    break;
                default:
                    break;
            }
            return true;
        }
    }

    /** The decoded picture lives only in this dialog; closing it drops the reference. */
    static Dialog showPhoto(Activity a, final Bitmap bitmap, String caption, final Runnable onExport, final Runnable onClosed) {
        final Dialog d = fullScreen(a);
        FrameLayout root = new FrameLayout(a);
        root.setBackgroundColor(Color.BLACK);
        ZoomImageView zoom = new ZoomImageView(a);
        zoom.show(bitmap);
        root.addView(zoom, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        root.addView(topButton(a, "Close", Gravity.TOP | Gravity.START, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                d.dismiss();
            }
        }), new FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.TOP | Gravity.START));
        root.addView(topButton(a, "Export…", Gravity.TOP | Gravity.END, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onExport.run();
            }
        }), new FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.TOP | Gravity.END));
        if (caption != null && !caption.isEmpty()) {
            TextView c = new TextView(a);
            c.setText(caption);
            c.setTextColor(Color.WHITE);
            c.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
            c.setBackgroundColor(0x99000000);
            c.setPadding(AndroidUtilities.dp(16), AndroidUtilities.dp(12), AndroidUtilities.dp(16), AndroidUtilities.dp(12));
            root.addView(c, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM));
        }
        d.setContentView(root);
        d.setOnDismissListener(new android.content.DialogInterface.OnDismissListener() {
            @Override
            public void onDismiss(android.content.DialogInterface dialog) {
                onClosed.run();
            }
        });
        d.show();
        return d;
    }

    /** Plays a decrypted temporary copy with the system video player controls. */
    static Dialog showVideo(Activity a, File file, final Runnable onExport, final Runnable onClosed) {
        final Dialog d = fullScreen(a);
        FrameLayout root = new FrameLayout(a);
        root.setBackgroundColor(Color.BLACK);
        final VideoView video = new VideoView(a);
        MediaController controls = new MediaController(a);
        controls.setAnchorView(video);
        video.setMediaController(controls);
        video.setVideoURI(Uri.fromFile(file));
        video.setOnPreparedListener(new android.media.MediaPlayer.OnPreparedListener() {
            @Override
            public void onPrepared(android.media.MediaPlayer mp) {
                video.start();
            }
        });
        video.setOnErrorListener(new android.media.MediaPlayer.OnErrorListener() {
            @Override
            public boolean onError(android.media.MediaPlayer mp, int what, int extra) {
                android.widget.Toast.makeText(video.getContext(), "This video cannot be played on this device. Use Export instead.", android.widget.Toast.LENGTH_LONG).show();
                return true;
            }
        });
        FrameLayout.LayoutParams vp = new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT, Gravity.CENTER);
        root.addView(video, vp);
        root.addView(topButton(a, "Close", Gravity.TOP | Gravity.START, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                d.dismiss();
            }
        }), new FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.TOP | Gravity.START));
        root.addView(topButton(a, "Export…", Gravity.TOP | Gravity.END, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onExport.run();
            }
        }), new FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.TOP | Gravity.END));
        d.setContentView(root);
        d.setOnDismissListener(new android.content.DialogInterface.OnDismissListener() {
            @Override
            public void onDismiss(android.content.DialogInterface dialog) {
                video.stopPlayback();
                onClosed.run();
            }
        });
        d.show();
        return d;
    }
}
