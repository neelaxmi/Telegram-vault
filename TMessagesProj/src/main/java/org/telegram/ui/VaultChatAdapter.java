package org.telegram.ui;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.text.format.Formatter;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.vault.VaultItem;
import org.telegram.messenger.vault.VaultListModel;
import org.telegram.ui.ActionBar.Theme;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

/**
 * The message cells of the Vault chat: every kind of stored message is drawn the way it is stored.
 * Text keeps its formatting and links; a photo shows its preview with the caption; a video shows its preview, a
 * play mark and the length; a document is a file cell (extension, name, size); voice and music have a play button
 * and progress. Forwarded messages show where they came from. Bubbles are on the right like in Saved Messages.
 */
final class VaultChatAdapter extends BaseAdapter {

    interface Host {
        /** Puts the stored preview into {@code target} (from a memory cache, or decrypts it in the background). */
        void loadThumbnail(VaultItem item, ImageView target);

        /** 0 = not playing, 1 = playing, 2 = paused. */
        int audioState(String itemId);

        int audioPositionMs(String itemId);

        int audioLengthMs(String itemId);

        void onPlayPause(VaultItem item);
    }

    private final Context context;
    private final VaultListModel model;
    private final Host host;
    private final int maxBubble;
    private final java.util.HashMap<String, ProgressBar> audioBars = new java.util.HashMap<>();
    private final java.util.HashMap<String, TextView> audioTimes = new java.util.HashMap<>();

    VaultChatAdapter(Context context, VaultListModel model, Host host) {
        this.context = context;
        this.model = model;
        this.host = host;
        int screen = context.getResources().getDisplayMetrics().widthPixels;
        this.maxBubble = Math.min(screen - AndroidUtilities.dp(56), AndroidUtilities.dp(330));
    }

    @Override
    public void notifyDataSetChanged() {
        audioBars.clear();
        audioTimes.clear();
        super.notifyDataSetChanged();
    }

    /** Moves the progress of the playing voice/music cell without rebuilding the list. */
    void refreshAudio(String itemId, int positionMs, int lengthMs) {
        ProgressBar bar = audioBars.get(itemId);
        TextView time = audioTimes.get(itemId);
        if (bar != null) {
            bar.setMax(Math.max(1, lengthMs));
            bar.setProgress(Math.min(Math.max(1, lengthMs), Math.max(0, positionMs)));
        }
        if (time != null) {
            time.setText(duration(positionMs / 1000) + " / " + duration(lengthMs / 1000));
        }
    }

    @Override
    public int getCount() {
        return model.rows().size();
    }

    @Override
    public Object getItem(int position) {
        return model.rows().get(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public boolean areAllItemsEnabled() {
        return true;
    }

    private static boolean sameDay(long a, long b) {
        Calendar x = Calendar.getInstance();
        Calendar y = Calendar.getInstance();
        x.setTimeInMillis(a);
        y.setTimeInMillis(b);
        return x.get(Calendar.YEAR) == y.get(Calendar.YEAR) && x.get(Calendar.DAY_OF_YEAR) == y.get(Calendar.DAY_OF_YEAR);
    }

    private static String dayLabel(long t) {
        Calendar now = Calendar.getInstance();
        Calendar d = Calendar.getInstance();
        d.setTimeInMillis(t);
        String pattern = now.get(Calendar.YEAR) == d.get(Calendar.YEAR) ? "MMMM d" : "MMMM d, yyyy";
        return new SimpleDateFormat(pattern, Locale.getDefault()).format(new Date(t));
    }

    private TextView label(String s, int sp, int color, boolean bold) {
        TextView t = new TextView(context);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        if (bold) {
            t.setTypeface(Typeface.DEFAULT_BOLD);
        }
        return t;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        final java.util.List<VaultListModel.Row> rows = model.rows();
        final VaultListModel.Row row = rows.get(position);
        final VaultItem it = row.item;

        LinearLayout outer = new LinearLayout(context);
        outer.setOrientation(LinearLayout.VERTICAL);

        if (position == 0 || !sameDay(rows.get(position - 1).dateMillis, row.dateMillis)) {
            TextView day = label(dayLabel(row.dateMillis), 13, Theme.getColor(Theme.key_chat_serviceText), true);
            day.setPadding(AndroidUtilities.dp(12), AndroidUtilities.dp(4), AndroidUtilities.dp(12), AndroidUtilities.dp(4));
            GradientDrawable pill = new GradientDrawable();
            pill.setCornerRadius(AndroidUtilities.dp(14));
            pill.setColor(Theme.getColor(Theme.key_chat_serviceBackground));
            day.setBackground(pill);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.gravity = Gravity.CENTER_HORIZONTAL;
            lp.topMargin = AndroidUtilities.dp(8);
            lp.bottomMargin = AndroidUtilities.dp(4);
            outer.addView(day, lp);
        }

        FrameLayout line = new FrameLayout(context);
        line.setPadding(AndroidUtilities.dp(8), AndroidUtilities.dp(2), AndroidUtilities.dp(8), AndroidUtilities.dp(2));
        LinearLayout bubble = new LinearLayout(context);
        bubble.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadii(new float[]{AndroidUtilities.dp(16), AndroidUtilities.dp(16), AndroidUtilities.dp(16), AndroidUtilities.dp(16),
                AndroidUtilities.dp(4), AndroidUtilities.dp(4), AndroidUtilities.dp(16), AndroidUtilities.dp(16)});
        bg.setColor(Theme.getColor(Theme.key_chat_outBubble));
        if (row.selected) {
            bg.setStroke(AndroidUtilities.dp(3), Theme.getColor(Theme.key_chat_messagePanelSend));
        }
        bubble.setBackground(bg);
        int pad = AndroidUtilities.dp(8);
        bubble.setPadding(pad, pad - AndroidUtilities.dp(2), pad, AndroidUtilities.dp(4));

        final int textColor = Theme.getColor(Theme.key_chat_messageTextOut);
        final int linkColor = Theme.getColor(Theme.key_chat_messageLinkOut);
        final int timeColor = Theme.getColor(Theme.key_chat_outTimeText);

        if (it.isForwarded()) {
            String from = it.forwardedFromName == null || it.forwardedFromName.isEmpty() ? "an unknown sender" : it.forwardedFromName;
            TextView fwd = label("Forwarded from " + from, 13, Theme.getColor(Theme.key_chat_outForwardedNameText), true);
            fwd.setPadding(0, 0, 0, AndroidUtilities.dp(3));
            bubble.addView(fwd);
        }

        boolean mediaOnTop = false;
        if (it.mediaId != null) {
            if (it.type == VaultItem.Type.PHOTO || it.type == VaultItem.Type.VIDEO) {
                bubble.addView(previewBlock(it));
                mediaOnTop = true;
            } else if (it.isVoice() || org.telegram.messenger.vault.VaultCategory.isMusic(it)) {
                bubble.addView(audioBlock(it));
            } else {
                bubble.addView(fileBlock(it));
            }
        }

        if (it.text != null && !it.text.isEmpty()) {
            final TextView body = new TextView(context);
            body.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
            body.setTextColor(textColor);
            body.setLinkTextColor(linkColor);
            body.setMaxWidth(maxBubble - 2 * pad);
            body.setText(VaultSpans.format(it.text, it.entities, linkColor, textColor));
            body.setOnTouchListener(new View.OnTouchListener() {
                @Override
                public boolean onTouch(View v, MotionEvent event) {
                    return VaultSpans.handleTouch((TextView) v, event);
                }
            });
            if (mediaOnTop) {
                body.setPadding(0, AndroidUtilities.dp(6), 0, 0);
            }
            bubble.addView(body);
        }

        TextView time = label(DateFormat.getTimeInstance(DateFormat.SHORT).format(new Date(row.dateMillis)), 11, timeColor, false);
        LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        tp.gravity = Gravity.END;
        bubble.addView(time, tp);

        line.addView(bubble, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.END));
        outer.addView(line);
        return outer;
    }

    // ---------------------------------------------------------------- photo and video

    private View previewBlock(final VaultItem it) {
        int w = it.width > 0 ? it.width : 4;
        int h = it.height > 0 ? it.height : 3;
        int boxW = Math.min(maxBubble - AndroidUtilities.dp(16), AndroidUtilities.dp(260));
        int boxH = Math.max(AndroidUtilities.dp(90), Math.min(AndroidUtilities.dp(340), (int) ((long) boxW * h / w)));
        FrameLayout box = new FrameLayout(context);
        ImageView iv = new ImageView(context);
        iv.setScaleType(ImageView.ScaleType.CENTER_CROP);
        iv.setBackgroundColor(0x33000000);
        iv.setContentDescription(it.type == VaultItem.Type.PHOTO ? "Photo" : "Video");
        box.addView(iv, new FrameLayout.LayoutParams(boxW, boxH));
        host.loadThumbnail(it, iv);
        if (it.type == VaultItem.Type.VIDEO) {
            TextView play = label("▶", 22, Color.WHITE, false);
            play.setGravity(Gravity.CENTER);
            GradientDrawable circle = new GradientDrawable();
            circle.setShape(GradientDrawable.OVAL);
            circle.setColor(0x99000000);
            play.setBackground(circle);
            box.addView(play, new FrameLayout.LayoutParams(AndroidUtilities.dp(54), AndroidUtilities.dp(54), Gravity.CENTER));
            TextView dur = label(duration(it.durationSeconds), 12, Color.WHITE, false);
            dur.setPadding(AndroidUtilities.dp(6), AndroidUtilities.dp(2), AndroidUtilities.dp(6), AndroidUtilities.dp(2));
            GradientDrawable pill = new GradientDrawable();
            pill.setCornerRadius(AndroidUtilities.dp(8));
            pill.setColor(0x99000000);
            dur.setBackground(pill);
            FrameLayout.LayoutParams dp = new FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.TOP | Gravity.START);
            dp.setMargins(AndroidUtilities.dp(6), AndroidUtilities.dp(6), 0, 0);
            box.addView(dur, dp);
        }
        return box;
    }

    // ---------------------------------------------------------------- file

    private View fileBlock(VaultItem it) {
        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.addView(badge(extensionOf(it.mediaName)), new LinearLayout.LayoutParams(AndroidUtilities.dp(48), AndroidUtilities.dp(48)));
        LinearLayout col = new LinearLayout(context);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(AndroidUtilities.dp(10), 0, AndroidUtilities.dp(4), 0);
        TextView name = label(it.mediaName == null || it.mediaName.isEmpty() ? "File" : it.mediaName, 16,
                Theme.getColor(Theme.key_chat_outFileNameText), true);
        name.setSingleLine(true);
        name.setEllipsize(android.text.TextUtils.TruncateAt.MIDDLE);
        name.setMaxWidth(maxBubble - AndroidUtilities.dp(100));
        col.addView(name);
        String ext = extensionOf(it.mediaName);
        String info = Formatter.formatShortFileSize(context, it.mediaSize) + (ext.isEmpty() ? "" : " · " + ext);
        col.addView(label(info, 13, Theme.getColor(Theme.key_chat_outFileInfoText), false));
        row.addView(col);
        return row;
    }

    private View badge(String ext) {
        TextView t = label(ext.isEmpty() ? "FILE" : (ext.length() > 4 ? ext.substring(0, 4) : ext), 12, Color.WHITE, true);
        t.setGravity(Gravity.CENTER);
        GradientDrawable circle = new GradientDrawable();
        circle.setShape(GradientDrawable.OVAL);
        circle.setColor(Theme.getColor(Theme.key_chat_outFileBackground));
        t.setBackground(circle);
        return t;
    }

    // ---------------------------------------------------------------- voice and music

    private View audioBlock(final VaultItem it) {
        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        int state = host.audioState(it.id);
        TextView play = label(state == 1 ? "⏸" : "▶", 20, Color.WHITE, false);
        play.setGravity(Gravity.CENTER);
        GradientDrawable circle = new GradientDrawable();
        circle.setShape(GradientDrawable.OVAL);
        circle.setColor(Theme.getColor(Theme.key_chat_outFileBackground));
        play.setBackground(circle);
        play.setContentDescription(state == 1 ? "Pause" : "Play");
        play.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                host.onPlayPause(it);
            }
        });
        row.addView(play, new LinearLayout.LayoutParams(AndroidUtilities.dp(48), AndroidUtilities.dp(48)));

        LinearLayout col = new LinearLayout(context);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(AndroidUtilities.dp(10), 0, AndroidUtilities.dp(4), 0);
        String title = it.isVoice() ? "Voice message" : (it.mediaName == null || it.mediaName.isEmpty() ? "Audio" : it.mediaName);
        TextView name = label(title, 15, Theme.getColor(Theme.key_chat_outAudioTitleText), true);
        name.setSingleLine(true);
        name.setEllipsize(android.text.TextUtils.TruncateAt.END);
        name.setMaxWidth(maxBubble - AndroidUtilities.dp(100));
        col.addView(name);
        ProgressBar bar = new ProgressBar(context, null, android.R.attr.progressBarStyleHorizontal);
        int length = state == 0 ? it.durationSeconds * 1000 : Math.max(1, host.audioLengthMs(it.id));
        bar.setMax(Math.max(1, length));
        bar.setProgress(state == 0 ? 0 : Math.min(length, host.audioPositionMs(it.id)));
        col.addView(bar, new LinearLayout.LayoutParams(AndroidUtilities.dp(160), AndroidUtilities.dp(10)));
        String t = state == 0 ? duration(it.durationSeconds) : duration(host.audioPositionMs(it.id) / 1000) + " / " + duration(length / 1000);
        TextView info = label(state == 0 ? t + " \u00B7 " + Formatter.formatShortFileSize(context, it.mediaSize) : t, 12,
                Theme.getColor(Theme.key_chat_outFileInfoText), false);
        col.addView(info);
        audioBars.put(it.id, bar);
        audioTimes.put(it.id, info);
        row.addView(col);
        return row;
    }

    // ---------------------------------------------------------------- helpers

    static String duration(int seconds) {
        seconds = Math.max(0, seconds);
        int h = seconds / 3600;
        int m = (seconds % 3600) / 60;
        int s = seconds % 60;
        return h > 0 ? String.format(Locale.US, "%d:%02d:%02d", h, m, s) : String.format(Locale.US, "%d:%02d", m, s);
    }

    static String extensionOf(String name) {
        if (name == null) {
            return "";
        }
        int dot = name.lastIndexOf('.');
        if (dot < 0 || dot == name.length() - 1 || name.length() - dot > 8) {
            return "";
        }
        return name.substring(dot + 1).toUpperCase(Locale.ROOT);
    }
}
