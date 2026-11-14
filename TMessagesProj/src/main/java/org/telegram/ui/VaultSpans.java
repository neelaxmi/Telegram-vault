package org.telegram.ui;

import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.Uri;
import android.text.Layout;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextPaint;
import android.text.style.BackgroundColorSpan;
import android.text.style.ClickableSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.QuoteSpan;
import android.text.style.StrikethroughSpan;
import android.text.style.StyleSpan;
import android.text.style.TypefaceSpan;
import android.text.style.URLSpan;
import android.text.style.UnderlineSpan;
import android.text.util.Linkify;
import android.view.MotionEvent;
import android.view.View;
import android.widget.TextView;

import org.telegram.messenger.browser.Browser;
import org.telegram.messenger.vault.VaultEntities;

import java.util.List;

/** Turns a stored text and its stored formatting entities back into styled text, with working links. */
final class VaultSpans {

    private VaultSpans() {
    }

    /** A link the user can tap: opens a web address, an e-mail or a phone number. */
    private static final class LinkSpan extends ClickableSpan {
        final String target;
        final int color;

        LinkSpan(String target, int color) {
            this.target = target;
            this.color = color;
        }

        @Override
        public void onClick(View widget) {
            Context c = widget.getContext();
            try {
                if (target.startsWith("mailto:") || target.startsWith("tel:")) {
                    c.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(target)));
                } else {
                    Browser.openUrl(c, target);
                }
            } catch (Exception ignored) {
                // no app can open it: nothing to do
            }
        }

        @Override
        public void updateDrawState(TextPaint ds) {
            ds.setColor(color);
            ds.setUnderlineText(false);
        }
    }

    /** Hidden text that shows when tapped, like a Telegram spoiler. */
    private static final class SpoilerSpan extends ClickableSpan {
        boolean revealed;
        final int textColor;

        SpoilerSpan(int textColor) {
            this.textColor = textColor;
        }

        @Override
        public void onClick(View widget) {
            revealed = !revealed;
            widget.invalidate();
        }

        @Override
        public void updateDrawState(TextPaint ds) {
            if (revealed) {
                ds.setColor(textColor);
            } else {
                ds.setColor(0x00000000);
                ds.bgColor = 0xFF8A97A6;
            }
            ds.setUnderlineText(false);
        }
    }

    static CharSequence format(String text, String entities, int linkColor, int textColor) {
        if (text == null) {
            text = "";
        }
        SpannableStringBuilder sb = new SpannableStringBuilder(text);
        List<VaultEntities.Entity> list = VaultEntities.decode(entities, text.length());
        boolean hasUrlEntity = false;
        for (VaultEntities.Entity e : list) {
            int s = e.offset;
            int end = e.offset + e.length;
            switch (e.kind) {
                case VaultEntities.BOLD:
                    sb.setSpan(new StyleSpan(Typeface.BOLD), s, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    break;
                case VaultEntities.ITALIC:
                    sb.setSpan(new StyleSpan(Typeface.ITALIC), s, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    break;
                case VaultEntities.UNDERLINE:
                    sb.setSpan(new UnderlineSpan(), s, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    break;
                case VaultEntities.STRIKE:
                    sb.setSpan(new StrikethroughSpan(), s, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    break;
                case VaultEntities.CODE:
                case VaultEntities.PRE:
                    sb.setSpan(new TypefaceSpan("monospace"), s, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    sb.setSpan(new BackgroundColorSpan(0x22808080), s, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    break;
                case VaultEntities.QUOTE:
                    sb.setSpan(new QuoteSpan(linkColor), s, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    break;
                case VaultEntities.SPOILER:
                    sb.setSpan(new SpoilerSpan(textColor), s, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    break;
                case VaultEntities.TEXT_URL:
                    if (e.url != null) {
                        sb.setSpan(new LinkSpan(e.url, linkColor), s, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                        hasUrlEntity = true;
                    }
                    break;
                case VaultEntities.URL: {
                    String u = text.substring(s, end);
                    sb.setSpan(new LinkSpan(u.matches("(?i)^[a-z][a-z0-9+.-]*://.*") ? u : "https://" + u, linkColor), s, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    hasUrlEntity = true;
                    break;
                }
                case VaultEntities.EMAIL:
                    sb.setSpan(new LinkSpan("mailto:" + text.substring(s, end), linkColor), s, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    break;
                case VaultEntities.PHONE:
                    sb.setSpan(new LinkSpan("tel:" + text.substring(s, end), linkColor), s, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    break;
                case VaultEntities.MENTION:
                case VaultEntities.HASHTAG:
                    sb.setSpan(new ForegroundColorSpan(linkColor), s, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    break;
                default:
                    break;
            }
        }
        if (!hasUrlEntity) {
            // notes typed in the Vault have no entities: find the web addresses in the text
            Linkify.addLinks(sb, Linkify.WEB_URLS);
            URLSpan[] found = sb.getSpans(0, sb.length(), URLSpan.class);
            for (URLSpan u : found) {
                int s = sb.getSpanStart(u);
                int e = sb.getSpanEnd(u);
                String url = u.getURL();
                sb.removeSpan(u);
                sb.setSpan(new LinkSpan(url, linkColor), s, e, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
        }
        return sb;
    }

    /**
     * Touch handling for a text cell inside a list: taps on a link or spoiler are used here, every other touch
     * is left to the list (open, select, long press).
     */
    static boolean handleTouch(TextView tv, MotionEvent ev) {
        CharSequence cs = tv.getText();
        if (!(cs instanceof Spanned)) {
            return false;
        }
        int action = ev.getActionMasked();
        if (action != MotionEvent.ACTION_DOWN && action != MotionEvent.ACTION_UP) {
            return false;
        }
        Layout layout = tv.getLayout();
        if (layout == null) {
            return false;
        }
        int x = (int) ev.getX() - tv.getTotalPaddingLeft() + tv.getScrollX();
        int y = (int) ev.getY() - tv.getTotalPaddingTop() + tv.getScrollY();
        if (y < 0 || y > layout.getHeight()) {
            return false;
        }
        int line = layout.getLineForVertical(y);
        if (x < layout.getLineLeft(line) || x > layout.getLineRight(line)) {
            return false;
        }
        int off = layout.getOffsetForHorizontal(line, x);
        ClickableSpan[] spans = ((Spanned) cs).getSpans(off, off, ClickableSpan.class);
        if (spans.length == 0) {
            return false;
        }
        if (action == MotionEvent.ACTION_UP) {
            spans[0].onClick(tv);
        }
        return true;
    }
}
