package org.telegram.ui;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Typeface;
import android.net.Uri;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.UserConfig;
import org.telegram.messenger.vault.LinkTransport;
import org.telegram.messenger.vault.RemoteBundle;
import org.telegram.messenger.vault.SetupFlow;
import org.telegram.messenger.vault.SetupSession;
import org.telegram.messenger.vault.SyncCoordinator;
import org.telegram.messenger.vault.VaultAccess;
import org.telegram.messenger.vault.VaultCategory;
import org.telegram.messenger.vault.VaultCryptoException;
import org.telegram.messenger.vault.VaultTempFiles;
import org.telegram.messenger.vault.VaultItem;
import org.telegram.messenger.vault.VaultListModel;
import org.telegram.messenger.vault.VaultRuntime;
import org.telegram.messenger.vault.VaultSyncEngine;
import org.telegram.messenger.vault.VaultStore;
import org.telegram.ui.ActionBar.ActionBarMenu;
import org.telegram.ui.ActionBar.ActionBarMenuItem;
import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.DateFormat;
import java.util.Date;

/**
 * The Protected Vault screen: set-up (with a mandatory, confirmed recovery key), unlock, restore on a new phone,
 * and the Vault itself (list, search, select, delete, notes, photo viewer, export, sync status, settings).
 *
 * <p><b>STATUS: Telegram-side names type-checked only; the Android SDK calls are not even type-checked, and nothing
 * here has ever been run.</b> Texts are English literals for now (no string resources were added to Telegram's
 * files). Not implemented: in-app playback of video/audio (those items can be exported), and the "Send to Vault"
 * entry points (Phase 9).
 */
public class VaultFragment extends BaseFragment {

    private static final int REQUEST_EXPORT = 7301;
    private static final int REQUEST_ATTACH = 7302;
    private static final long MAX_INLINE_PHOTO_BYTES = 20L * 1024 * 1024;

    private VaultRuntime rt;
    private FrameLayout container;
    /** Owns the set-up flow; the UI never keeps its own reference (a stale one caused a crash after a pause). */
    private SetupSession session;
    private byte[] restoreBundle;
    private boolean restoreMode;
    private VaultListModel model;
    private VaultChatAdapter adapter;
    private TextView statusView;
    private TextView selectionView;
    private Button deleteButton;
    private String pendingExportItemId;
    private boolean destroyed;
    /** True while another app (the file picker) is on top: that must not lock the Vault. */
    private boolean launching;

    @Override
    public boolean onFragmentCreate() {
        rt = VaultRuntime.get(UserConfig.selectedAccount);
        session = new SetupSession(rt.keys, new SetupSession.Clock() {
            @Override
            public long nowMillis() {
                return android.os.SystemClock.elapsedRealtime();
            }
        }, SetupSession.DEFAULT_GRACE_MILLIS);
        temp().wipeAll(); // a crash or kill may have left a decrypted copy behind
        rt.setOnLockedUi(new Runnable() {
            @Override
            public void run() {
                if (!destroyed && container != null) {
                    leaveSecrets();
                    decide();
                }
            }
        });
        rt.setOnInboxDrained(new Runnable() {
            @Override
            public void run() {
                if (!destroyed && model != null) {
                    scrollToEnd = true;
                    reload(); // items saved while locked just arrived
                }
            }
        });
        return super.onFragmentCreate();
    }

    @Override
    public void onFragmentDestroy() {
        destroyed = true;
        session.cancel();
        if (rotationPlan != null) {
            rotationPlan.cancel();
            rotationPlan = null;
        }
        Activity act = getParentActivity();
        if (act != null) {
            act.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE); // other Telegram screens are not secured
        }
        rt.setOnLockedUi(null);
        rt.setOnInboxDrained(null);
        closeViewer();
        stopAudio();
        if (mediaPool != null) {
            mediaPool.shutdownNow();
        }
        if (openPool != null) {
            openPool.shutdownNow();
        }
        temp().wipeAll();
        thumbCache.evictAll();
        super.onFragmentDestroy();
    }

    @Override
    public android.view.View createView(Context context) {
        if (getParentActivity() != null) {
            getParentActivity().getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        }
        actionBar.setBackButtonImage(org.telegram.messenger.R.drawable.ic_ab_back);
        actionBar.setAllowOverlayTitle(true);
        actionBar.setTitle("Protected Vault");
        actionBar.setActionBarMenuOnItemClick(new org.telegram.ui.ActionBar.ActionBar.ActionBarMenuOnItemClick() {
            @Override
            public void onItemClick(int id) {
                if (id == -1) {
                    finishFragment();
                } else if (id == MENU_SYNC) {
                    syncNow(true);
                } else if (id == MENU_SELECT_ALL) {
                    if (model != null) {
                        model.selectAll();
                        renderSelection();
                    }
                } else if (id == MENU_SETTINGS) {
                    showSettings();
                } else if (id == MENU_LOCK) {
                    rt.lockNow();
                }
            }
        });
        container = new FrameLayout(context);
        container.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        container.setOnTouchListener(new View.OnTouchListener() {
            @Override
            public boolean onTouch(View v, android.view.MotionEvent event) {
                rt.autoLock.userActivity();
                return false;
            }
        });
        fragmentView = container;
        decide();
        return fragmentView;
    }

    @Override
    public void onResume() {
        super.onResume();
        Activity a = getParentActivity();
        if (a != null) {
            a.getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        }
        launching = false; // back from the file picker or another app
        rt.autoLock.onForeground(); // locks first if the time away was too long
        if (container == null) {
            return;
        }
        AndroidUtilities.cancelRunOnUIThread(expireSetup);
        switch (session.onResume()) {
            case CONTINUE:
                renderSetupStep(); // the views were removed in onPause; draw the current step again
                return;
            case EXPIRED:
                setupInterrupted();
                return;
            default:
                break;
        }
        if (!rt.keys.isUnlocked() && !restoreMode && model != null) {
            decide();
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        // FLAG_SECURE stays on while this screen exists, including while the app is in the background, so the
        // Recents thumbnail is blank. It is cleared in onFragmentDestroy.
        if (session.isActive()) {
            // Never leave the recovery phrase on screen while away. The setup itself stays valid for a short
            // time (SetupSession); onResume draws the current step again, or starts over after the grace time.
            session.onPause();
            container.removeAllViews();
            AndroidUtilities.cancelRunOnUIThread(expireSetup);
            AndroidUtilities.runOnUIThread(expireSetup, session.graceMillis() + 1000);
        }
        if (!launching) {
            rt.autoLock.onBackground();
        }
    }

    // ------------------------------------------------------------------ routing

    /** Wipes an abandoned setup once the grace time ran out, even if the user has not come back yet. */
    private final Runnable expireSetup = new Runnable() {
        @Override
        public void run() {
            if (session != null) {
                session.expireIfPaused();
            }
        }
    };

    /** Draws the step the live setup is on. Falls back to a fresh start if there is none. */
    private void renderSetupStep() {
        try {
            SetupFlow f = session.flow();
            switch (f.step()) {
                case SHOW_KEY:
                    showRecoveryKey(session.isMigration());
                    return;
                case CONFIRM_KEY:
                    showConfirmKey(session.isMigration());
                    return;
                default:
                    showSetupPassword(session.isMigration());
                    return;
            }
        } catch (VaultCryptoException e) {
            setupInterrupted();
        }
    }

    /** The setup is gone (time away, lock, or an earlier error): say so and start again with a NEW phrase. */
    private void setupInterrupted() {
        session.cancel();
        decide();
        Activity a = getParentActivity();
        if (a != null) {
            android.widget.Toast.makeText(a, "Setup was interrupted. Nothing was saved. Start again; you will get a new recovery phrase.", android.widget.Toast.LENGTH_LONG).show();
        }
    }

    private void decide() {
        if (rt.keys.isUnlocked()) {
            if (rt.keys.isLegacyHeader()) {
                showSetupPassword(true);
            } else {
                showList();
            }
        } else if (!rt.keys.isInitialized()) {
            showSetupPassword(false);
        } else {
            showUnlock(null);
        }
    }

    /** Drops anything secret from the views (called when the Vault locks). */
    private void leaveSecrets() {
        session.cancel();
        restoreBundle = null;
        if (rotationPlan != null) {
            rotationPlan.cancel();
            rotationPlan = null;
        }
        // nothing decrypted may outlive the lock: viewers, playback, temp copies, previews
        closeViewer();
        stopAudio();
        if (mediaPool != null) {
            mediaPool.shutdownNow();
            mediaPool = null;
        }
        if (openPool != null) {
            openPool.shutdownNow();
            openPool = null;
        }
        temp().wipeAll();
        thumbCache.evictAll();
        thumbLoading.clear();
        actionBar.createMenu().clearItems();
        actionBar.setSubtitle(null);
        searchQuery = "";
        model = null;
        adapter = null;
        chatList = null;
        composer = null;
        statusView = null;
        container.removeAllViews();
    }

    // ------------------------------------------------------------------ small view helpers

    private LinearLayout page(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setPadding(AndroidUtilities.dp(20), AndroidUtilities.dp(20), AndroidUtilities.dp(20), AndroidUtilities.dp(20));
        return l;
    }

    private void show(View content) {
        container.removeAllViews();
        ScrollView sv = new ScrollView(container.getContext());
        sv.addView(content);
        container.addView(sv, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
    }

    private TextView text(Context c, String s, int sp, boolean bold) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        if (bold) {
            t.setTypeface(Typeface.DEFAULT_BOLD);
        }
        t.setPadding(0, AndroidUtilities.dp(6), 0, AndroidUtilities.dp(6));
        return t;
    }

    private EditText field(Context c, String hint, boolean password) {
        EditText e = new EditText(c);
        e.setHint(hint);
        e.setSingleLine(true);
        e.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        e.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        e.setImeOptions(android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        e.setInputType(InputType.TYPE_CLASS_TEXT | (password ? InputType.TYPE_TEXT_VARIATION_PASSWORD : InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS));
        return e;
    }

    private Button button(Context c, String label, View.OnClickListener l) {
        Button b = new Button(c);
        b.setText(label);
        b.setOnClickListener(l);
        return b;
    }

    private static String messageFor(VaultCryptoException e) {
        switch (e.getReason()) {
            case WRONG_PASSWORD:
                return "Wrong password.";
            case INVALID_ARGUMENT:
                return e.getMessage();
            case WRONG_RECOVERY_KEY:
                return "That recovery key does not match.";
            case IO_ERROR:
                return "Network or storage problem. Try again.";
            case DEVICE_KEY_UNAVAILABLE:
                return "This device's secure key is unavailable. Restore the Vault with your recovery key.";
            case VAULT_WIPED:
                return "Too many wrong passwords. This device's Vault data was deleted. Your data on Telegram's server was not touched; restore it with your recovery key.";
            case LINK_EXPIRED:
                return "The linking session ran out of time. Start again on both phones.";
            case LINK_MISMATCH:
                return "Linking was stopped because a message did not match. If the codes did not match, someone may be interfering; start again.";
            case MEDIA_TOO_LARGE:
                return "That file is larger than Telegram allows.";
            default:
                return "Error: " + e.getReason();
        }
    }

    private void ui(Runnable r) {
        AndroidUtilities.runOnUIThread(new Runnable() {
            @Override
            public void run() {
                if (!destroyed) {
                    r.run();
                }
            }
        });
    }

    /** Own interface instead of java.util.function.Consumer (API 24+). */
    private interface ErrorHandler {
        void accept(VaultCryptoException e);
    }

    private interface Job {
        void run() throws Exception;
    }

    /** Runs {@code job} on the Vault thread; errors go to {@code error}, success to {@code done}, both on the UI thread. */
    private void background(final Job job, final Runnable done, final ErrorHandler error) {
        backgroundOn(rt.io(), job, done, error);
    }

    private void backgroundOn(java.util.concurrent.Executor executor, final Job job, final Runnable done, final ErrorHandler error) {
        executor.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    job.run();
                    if (done != null) {
                        ui(done);
                    }
                } catch (final VaultCryptoException e) {
                    ui(new Runnable() {
                        @Override
                        public void run() {
                            error.accept(e);
                        }
                    });
                } catch (final Exception e) {
                    ui(new Runnable() {
                        @Override
                        public void run() {
                            error.accept(new VaultCryptoException(VaultCryptoException.Reason.IO_ERROR, String.valueOf(e.getMessage()), e));
                        }
                    });
                }
            }
        });
    }

    // ------------------------------------------------------------------ set-up and migration

    private void showSetupPassword(final boolean migrate) {
        final Context c = container.getContext();
        session.start(migrate);
        LinearLayout p = page(c);
        p.addView(text(c, migrate ? "Upgrade your Vault" : "Create your Protected Vault", 22, true));
        p.addView(text(c, migrate
                ? "Your Vault will be upgraded so it can sync between your devices. Your items stay as they are. Choose a new password (at least 6 characters); you will then get a recovery key."
                : "Your Vault is encrypted on this device and stored encrypted in a private channel of your Telegram account, so you can use it on several devices. Choose a password for THIS device (at least 6 characters). Next you will get a recovery key; it is the only way back in if you lose this phone.", 15, false));
        final EditText oldPw = migrate ? field(c, "Current Vault password", true) : null;
        if (oldPw != null) {
            p.addView(oldPw);
        }
        final EditText pw = field(c, "Password (6+ characters)", true);
        final EditText pw2 = field(c, "Repeat password", true);
        final TextView err = text(c, "", 14, false);
        err.setTextColor(Theme.getColor(Theme.key_text_RedRegular));
        p.addView(pw);
        p.addView(pw2);
        p.addView(err);
        p.addView(button(c, "Continue", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    if (migrate) {
                        session.flow().submitMigration(chars(oldPw), chars(pw), chars(pw2));
                    } else {
                        session.flow().submitPassword(chars(pw), chars(pw2));
                    }
                    showRecoveryKey(migrate);
                } catch (VaultCryptoException e) {
                    if (e.getReason() == VaultCryptoException.Reason.INVALID_STATE && !session.isActive()) {
                        setupInterrupted();
                    } else {
                        err.setText(messageFor(e));
                    }
                }
            }
        }));
        if (!migrate) {
            p.addView(button(c, "I already have a Vault on another phone: link this phone", new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    showLinkJoinForm();
                }
            }));
            p.addView(button(c, "I already have a Vault: restore with recovery key", new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    startRestore();
                }
            }));
        }
        show(p);
    }

    /** "one two ..." -> "1. one  2. two ..." for a 12-word phrase; anything else unchanged. */
    private static String numbered(String key) {
        String[] w = key.split(" ");
        if (w.length != 12) {
            return key;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < w.length; i++) {
            sb.append(i + 1).append(". ").append(w[i]).append(i % 2 == 1 ? "\n" : "      ");
        }
        return sb.toString().trim();
    }

    private static char[] chars(EditText e) {
        return e.getText().toString().toCharArray();
    }

    private void showRecoveryKey(final boolean migrate) {
        final Context c = container.getContext();
        LinearLayout p = page(c);
        p.addView(text(c, "Your 12-word recovery phrase", 22, true));
        p.addView(text(c, "Write these 12 words down on paper, in order, and keep them somewhere safe. They are shown only now. Without it, a lost phone means a lost Vault. Anyone with this key and access to your Telegram account's Vault channel could open your Vault, so do not photograph it or save it in a chat.", 15, false));
        try {
            TextView key = text(c, numbered(session.flow().recoveryKeyText()), 18, true);
            key.setTypeface(Typeface.MONOSPACE);
            key.setTextIsSelectable(false);
            p.addView(key);
        } catch (VaultCryptoException e) {
            p.addView(text(c, messageFor(e), 14, false));
        }
        p.addView(button(c, "I have written it down", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    session.flow().keyWrittenDown();
                    showConfirmKey(migrate);
                } catch (VaultCryptoException e) {
                    setupInterrupted();
                }
            }
        }));
        show(p);
    }

    private void showConfirmKey(final boolean migrate) {
        final Context c = container.getContext();
        LinearLayout p = page(c);
        p.addView(text(c, "Confirm your recovery phrase", 22, true));
        p.addView(text(c, "Type the 12 words from your paper (separated by spaces) to prove you have them. The Vault is created only after this matches.", 15, false));
        final EditText key = field(c, "Recovery key", false);
        final TextView err = text(c, "", 14, false);
        err.setTextColor(Theme.getColor(Theme.key_text_RedRegular));
        p.addView(key);
        p.addView(err);
        p.addView(button(c, "Create Vault", new View.OnClickListener() {
            @Override
            public void onClick(final View v) {
                final String typed = key.getText().toString();
                try {
                    session.flow().confirm(typed);
                    session.cancel(); // finished: drop the (completed) flow
                    rt.unlocked();
                    uploadFirstBundle();
                    showList();
                } catch (VaultCryptoException e) {
                    if (e.getReason() == VaultCryptoException.Reason.INVALID_STATE) {
                        setupInterrupted(); // the setup is gone: never crash, start again
                    } else {
                        err.setText(messageFor(e));
                    }
                }
            }
        }));
        p.addView(button(c, "Back", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    session.flow().backToKey();
                    showRecoveryKey(migrate);
                } catch (VaultCryptoException e) {
                    setupInterrupted();
                }
            }
        }));
        show(p);
    }

    /** The bundle goes to the server with the first sync (the engine uploads it before any data). */
    private void uploadFirstBundle() {
        syncNow(true);
    }

    // ------------------------------------------------------------------ restore on a new phone

    private void startRestore() {
        restoreMode = true;
        final Context c = container.getContext();
        LinearLayout p = page(c);
        p.addView(text(c, "Restore your Vault", 22, true));
        final TextView status = text(c, "Looking for your Vault on Telegram…", 15, false);
        p.addView(status);
        show(p);
        background(new Job() {
            @Override
            public void run() throws Exception {
                rt.attachChannel(null, false);
                restoreBundle = RemoteBundle.fetchLatest(rt.remote());
            }
        }, new Runnable() {
            @Override
            public void run() {
                if (restoreBundle == null) {
                    status.setText("No Vault was found in your Telegram account's Vault channel.");
                    return;
                }
                showRestoreForm();
            }
        }, new ErrorHandler() {
            @Override
            public void accept(VaultCryptoException e) {
                status.setText(messageFor(e));
            }
        });
    }

    private void showRestoreForm() {
        final Context c = container.getContext();
        LinearLayout p = page(c);
        p.addView(text(c, "Restore your Vault", 22, true));
        p.addView(text(c, "Enter your recovery key and choose a password for this device (6+ characters).", 15, false));
        final EditText key = field(c, "Recovery key", false);
        final EditText pw = field(c, "New password", true);
        final EditText pw2 = field(c, "Repeat password", true);
        final TextView err = text(c, "", 14, false);
        err.setTextColor(Theme.getColor(Theme.key_text_RedRegular));
        p.addView(key);
        p.addView(pw);
        p.addView(pw2);
        p.addView(err);
        p.addView(button(c, "Restore", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    rt.keys.restoreFromBundle(restoreBundle, key.getText().toString(), chars(pw), chars(pw2), false);
                    restoreBundle = null;
                    restoreMode = false;
                    rt.unlocked();
                    syncNow(true);
                    showList();
                } catch (VaultCryptoException e) {
                    err.setText(messageFor(e));
                }
            }
        }));
        show(p);
    }

    // ------------------------------------------------------------------ unlock

    /**
     * The password wall. While locked nothing is decrypted, so there is no real chat to blur: behind the card is a
     * decoy of generic, empty bubbles (a fixed number, so it reveals nothing about how many messages exist), blurred
     * on Android 12+ and dimmed everywhere. The wall swallows every touch so nothing behind it can be used.
     */
    private void showUnlock(String message) {
        final Context c = container.getContext();
        closeViewer();
        stopAudio();
        temp().wipeAll();
        actionBar.createMenu().clearItems();
        actionBar.setSubtitle(null);
        container.removeAllViews();
        final FrameLayout wall = new FrameLayout(c);
        wall.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        wall.setClickable(true);   // swallow taps, scrolls and long presses
        wall.setFocusable(true);

        final LinearLayout decoy = new LinearLayout(c);
        decoy.setOrientation(LinearLayout.VERTICAL);
        decoy.setPadding(AndroidUtilities.dp(12), AndroidUtilities.dp(16), AndroidUtilities.dp(12), AndroidUtilities.dp(16));
        decoy.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS);
        int[] widths = {220, 140, 260, 180, 100, 240, 160, 200};
        for (int i = 0; i < widths.length; i++) {
            View bubble = new View(c);
            android.graphics.drawable.GradientDrawable d = new android.graphics.drawable.GradientDrawable();
            d.setCornerRadius(AndroidUtilities.dp(16));
            d.setColor(i % 2 == 0 ? 0xFF3A6EA5 : 0xFF4E7FB5);
            bubble.setBackground(d);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(AndroidUtilities.dp(widths[i]), AndroidUtilities.dp(i % 3 == 0 ? 64 : 44));
            lp.gravity = android.view.Gravity.END; // like Saved Messages: every bubble on the right
            lp.topMargin = AndroidUtilities.dp(10);
            decoy.addView(bubble, lp);
        }
        View ghostBar = new View(c); // where the message box is in the real chat
        android.graphics.drawable.GradientDrawable gb = new android.graphics.drawable.GradientDrawable();
        gb.setCornerRadius(AndroidUtilities.dp(22));
        gb.setColor(0xFF2B3A4C);
        ghostBar.setBackground(gb);
        LinearLayout.LayoutParams gp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, AndroidUtilities.dp(44));
        gp.topMargin = AndroidUtilities.dp(18);
        decoy.addView(ghostBar, gp);
        if (android.os.Build.VERSION.SDK_INT >= 31) {
            decoy.setRenderEffect(android.graphics.RenderEffect.createBlurEffect(28f, 28f, android.graphics.Shader.TileMode.CLAMP));
        }
        wall.addView(decoy, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        View scrim = new View(c); // dims the decoy; on older Android this is what hides it
        scrim.setBackgroundColor(android.os.Build.VERSION.SDK_INT >= 31 ? 0x88101820 : 0xEE101820);
        wall.addView(scrim, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        final LinearLayout card = new LinearLayout(c);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setGravity(android.view.Gravity.CENTER_HORIZONTAL);
        card.setPadding(AndroidUtilities.dp(22), AndroidUtilities.dp(22), AndroidUtilities.dp(22), AndroidUtilities.dp(18));
        android.graphics.drawable.GradientDrawable cardBg = new android.graphics.drawable.GradientDrawable();
        cardBg.setCornerRadius(AndroidUtilities.dp(26));
        cardBg.setColor(0xF2182433);
        cardBg.setStroke(AndroidUtilities.dp(1), 0x553C6EA8);
        card.setBackground(cardBg);

        card.addView(new LockIconView(c), new LinearLayout.LayoutParams(AndroidUtilities.dp(84), AndroidUtilities.dp(84)));
        TextView title = text(c, "Enter Password", 24, true);
        title.setTextColor(0xFFFFFFFF);
        title.setGravity(android.view.Gravity.CENTER);
        card.addView(title);
        TextView sub = text(c, "This vault is protected. Please enter your password to continue.", 15, false);
        sub.setTextColor(0xFFB9C4D2);
        sub.setGravity(android.view.Gravity.CENTER);
        sub.setPadding(0, AndroidUtilities.dp(6), 0, AndroidUtilities.dp(14));
        card.addView(sub);

        LinearLayout pwRow = new LinearLayout(c);
        pwRow.setOrientation(LinearLayout.HORIZONTAL);
        pwRow.setGravity(android.view.Gravity.CENTER_VERTICAL);
        android.graphics.drawable.GradientDrawable rowBg = new android.graphics.drawable.GradientDrawable();
        rowBg.setCornerRadius(AndroidUtilities.dp(26));
        rowBg.setColor(0x33000000);
        rowBg.setStroke(AndroidUtilities.dp(1), 0x66789AC8);
        pwRow.setBackground(rowBg);
        pwRow.setPadding(AndroidUtilities.dp(16), 0, AndroidUtilities.dp(8), 0);
        final EditText pw = new EditText(c);
        pw.setHint("Password");
        pw.setHintTextColor(0xFF7F8CA0);
        pw.setTextColor(0xFFFFFFFF);
        pw.setBackground(null);
        pw.setSingleLine(true);
        pw.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        pw.setImeOptions(android.view.inputmethod.EditorInfo.IME_ACTION_DONE | android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        pwRow.addView(pw, new LinearLayout.LayoutParams(0, AndroidUtilities.dp(52), 1f));
        final TextView toggle = text(c, "Show", 14, true);
        toggle.setTextColor(0xFF6FB1FF);
        toggle.setPadding(AndroidUtilities.dp(12), AndroidUtilities.dp(12), AndroidUtilities.dp(12), AndroidUtilities.dp(12));
        toggle.setOnClickListener(new View.OnClickListener() {
            private boolean shown;

            @Override
            public void onClick(View v) {
                shown = !shown;
                int sel = pw.getSelectionEnd();
                pw.setInputType(android.text.InputType.TYPE_CLASS_TEXT | (shown
                        ? android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                        : android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD));
                pw.setSelection(Math.max(0, sel));
                toggle.setText(shown ? "Hide" : "Show");
            }
        });
        pwRow.addView(toggle);
        card.addView(pwRow, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        final TextView err = text(c, message == null ? "" : message, 14, false);
        err.setTextColor(0xFFFF7A7A);
        err.setGravity(android.view.Gravity.CENTER);
        err.setPadding(0, AndroidUtilities.dp(8), 0, 0);
        card.addView(err);
        final TextView remaining = text(c, "", 12, false);
        remaining.setTextColor(0xFF9AA8BA);
        remaining.setGravity(android.view.Gravity.CENTER);
        card.addView(remaining);

        final TextView unlock = text(c, "Unlock  >", 17, true);
        unlock.setTextColor(0xFFFFFFFF);
        unlock.setGravity(android.view.Gravity.CENTER);
        android.graphics.drawable.GradientDrawable btnBg = new android.graphics.drawable.GradientDrawable();
        btnBg.setCornerRadius(AndroidUtilities.dp(28));
        btnBg.setColor(0xFF1E88FF);
        unlock.setBackground(btnBg);
        final android.widget.ProgressBar spinner = new android.widget.ProgressBar(c);
        spinner.setIndeterminate(true);
        spinner.setVisibility(View.GONE);
        FrameLayout btnFrame = new FrameLayout(c);
        btnFrame.addView(unlock, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, AndroidUtilities.dp(52)));
        FrameLayout.LayoutParams spLp = new FrameLayout.LayoutParams(AndroidUtilities.dp(26), AndroidUtilities.dp(26), android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.END);
        spLp.rightMargin = AndroidUtilities.dp(20);
        btnFrame.addView(spinner, spLp);
        LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        btnLp.topMargin = AndroidUtilities.dp(14);
        card.addView(btnFrame, btnLp);

        final TextView restore = text(c, "Restore with recovery phrase", 14, false);
        restore.setTextColor(0xFF6FB1FF);
        restore.setGravity(android.view.Gravity.CENTER);
        restore.setPadding(0, AndroidUtilities.dp(14), 0, AndroidUtilities.dp(4));
        restore.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startRestore();
            }
        });
        card.addView(restore);

        // One attempt at a time. The button can never be a silent no-op: it either starts an attempt (spinner, fields
        // locked) or says why not.
        final boolean[] busy = {false};
        final View.OnClickListener attempt = new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (busy[0]) {
                    return;
                }
                if (pw.getText().length() == 0) {
                    err.setText("Enter your password.");
                    return;
                }
                busy[0] = true;
                final long started = android.os.SystemClock.elapsedRealtime();
                final char[] password = chars(pw);
                err.setText("");
                unlock.setText("Unlocking…");
                spinner.setVisibility(View.VISIBLE);
                pw.setEnabled(false);
                toggle.setEnabled(false);
                restore.setEnabled(false);
                final Runnable slow = new Runnable() {
                    @Override
                    public void run() {
                        if (busy[0]) {
                            remaining.setText("Checking your password with a deliberately slow, strong key derivation. This can take a few seconds.");
                        }
                    }
                };
                AndroidUtilities.runOnUIThread(slow, 2500);
                final Runnable finish = new Runnable() {
                    @Override
                    public void run() {
                        busy[0] = false;
                        AndroidUtilities.cancelRunOnUIThread(slow);
                        unlock.setText("Unlock  >");
                        spinner.setVisibility(View.GONE);
                        pw.setEnabled(true);
                        toggle.setEnabled(true);
                        restore.setEnabled(true);
                    }
                };
                backgroundOn(rt.unlockIo(), new Job() {
                    @Override
                    public void run() throws Exception {
                        final VaultAccess.Report r = rt.access.unlock(password);
                        FileLog.d("Vault: unlock ok in " + (android.os.SystemClock.elapsedRealtime() - started) + " ms");
                        ui(new Runnable() {
                            @Override
                            public void run() {
                                finish.run();
                                pw.setText("");
                                if (destroyed) {
                                    return;
                                }
                                rt.unlocked();
                                decide();
                                showAttemptReport(r);
                            }
                        });
                    }
                }, null, new ErrorHandler() {
                    @Override
                    public void accept(VaultCryptoException e) {
                        FileLog.e("Vault: unlock failed (" + e.getReason() + ") after " + (android.os.SystemClock.elapsedRealtime() - started) + " ms");
                        finish.run();
                        pw.setText("");
                        if (e.getReason() == VaultCryptoException.Reason.VAULT_WIPED) {
                            err.setText(messageFor(e));
                            decide();
                            return;
                        }
                        err.setText(e.getReason() == VaultCryptoException.Reason.WRONG_PASSWORD ? "Wrong password. Try again." : messageFor(e));
                        refreshRemaining(remaining);
                    }
                });
            }
        };
        unlock.setOnClickListener(attempt);
        pw.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            @Override
            public boolean onEditorAction(TextView v, int actionId, android.view.KeyEvent event) {
                attempt.onClick(v);
                return true;
            }
        });

        FrameLayout.LayoutParams cardLp = new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, android.view.Gravity.CENTER);
        cardLp.leftMargin = AndroidUtilities.dp(20);
        cardLp.rightMargin = AndroidUtilities.dp(20);
        ScrollView sv = new ScrollView(c);
        sv.setFillViewport(true);
        FrameLayout holder = new FrameLayout(c);
        FrameLayout.LayoutParams maxW = new FrameLayout.LayoutParams(Math.min(AndroidUtilities.dp(380), AndroidUtilities.displaySize.x - AndroidUtilities.dp(40)),
                ViewGroup.LayoutParams.WRAP_CONTENT, android.view.Gravity.CENTER);
        holder.addView(card, maxW);
        sv.addView(holder, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        wall.addView(sv, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        container.addView(wall, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        refreshRemaining(remaining);
    }

    /** A round badge with a padlock, drawn in code (no resource needed). */
    private static final class LockIconView extends View {
        private final android.graphics.Paint paint = new android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG);

        LockIconView(Context c) {
            super(c);
        }

        @Override
        protected void onDraw(android.graphics.Canvas canvas) {
            float w = getWidth(), h = getHeight(), cx = w / 2f, cy = h / 2f, r = Math.min(w, h) / 2f;
            paint.setStyle(android.graphics.Paint.Style.FILL);
            paint.setColor(0xFF1B3A5E);
            canvas.drawCircle(cx, cy, r * 0.86f, paint);
            paint.setColor(0xFF3B8DFF);
            android.graphics.RectF body = new android.graphics.RectF(cx - r * 0.34f, cy - r * 0.04f, cx + r * 0.34f, cy + r * 0.46f);
            canvas.drawRoundRect(body, r * 0.1f, r * 0.1f, paint);
            paint.setStyle(android.graphics.Paint.Style.STROKE);
            paint.setStrokeWidth(r * 0.13f);
            android.graphics.RectF shackle = new android.graphics.RectF(cx - r * 0.22f, cy - r * 0.50f, cx + r * 0.22f, cy + r * 0.08f);
            canvas.drawArc(shackle, 180, 180, false, paint);
            canvas.drawLine(cx - r * 0.22f, cy - r * 0.21f, cx - r * 0.22f, cy - r * 0.02f, paint);
            canvas.drawLine(cx + r * 0.22f, cy - r * 0.21f, cx + r * 0.22f, cy - r * 0.02f, paint);
            paint.setStyle(android.graphics.Paint.Style.FILL);
            paint.setColor(0xFF10233B);
            canvas.drawCircle(cx, cy + r * 0.18f, r * 0.07f, paint);
        }
    }

    private void refreshRemaining(final TextView view) {
        background(new Job() {
            @Override
            public void run() throws Exception {
                final int left = rt.access.attemptsRemaining();
                ui(new Runnable() {
                    @Override
                    public void run() {
                        view.setText(left >= 0 ? left + " attempts left before this device's Vault data is deleted." : "");
                    }
                });
            }
        }, null, new ErrorHandler() {
            @Override
            public void accept(VaultCryptoException e) {
            }
        });
    }

    private void showAttemptReport(final VaultAccess.Report r) {
        if (r.failedAttempts <= 0 && !r.trackingDamaged) {
            return;
        }
        String when = r.lastFailureMillis > 0 ? DateFormat.getDateTimeInstance().format(new Date(r.lastFailureMillis)) : "unknown";
        String msg = r.trackingDamaged
                ? "The record of failed attempts on this device was damaged or changed. Someone may have tampered with it."
                : r.failedAttempts + " wrong password attempt(s) since you last looked. Most recent: " + when + ".";
        AlertDialog.Builder b = new AlertDialog.Builder(getParentActivity());
        b.setTitle("Failed unlock attempts");
        b.setMessage(msg);
        b.setPositiveButton("OK", new AlertDialog.OnButtonClickListener() {
            @Override
            public void onClick(AlertDialog d, int which) {
                background(new Job() {
                    @Override
                    public void run() throws Exception {
                        rt.access.acknowledge();
                    }
                }, null, new ErrorHandler() {
                    @Override
                    public void accept(VaultCryptoException e) {
                    }
                });
            }
        });
        showDialog(b.create());
    }

    // ------------------------------------------------------------------ the Vault: a Saved-Messages-style chat

    private static final int MENU_SEARCH = 1;
    private static final int MENU_MORE = 2;
    private static final int MENU_SYNC = 3;
    private static final int MENU_SELECT_ALL = 4;
    private static final int MENU_SETTINGS = 5;
    private static final int MENU_LOCK = 6;

    private String searchQuery = "";
    private VaultCategory category = VaultCategory.ALL;
    private boolean scrollToEnd;
    private ListView chatList;
    private TextView emptyView;
    private EditText composer;
    private final java.util.Map<VaultCategory, TextView> chips = new java.util.EnumMap<>(VaultCategory.class);
    private VaultTempFiles temp;
    private java.util.concurrent.ExecutorService mediaPool;
    private final android.util.LruCache<String, Bitmap> thumbCache = new android.util.LruCache<>(64);
    private final java.util.Set<String> thumbLoading = new java.util.HashSet<>();
    private android.media.MediaPlayer player;
    private String playingId;
    private boolean playerPaused;
    private Dialog viewer;
    private final Runnable audioTick = new Runnable() {
        @Override
        public void run() {
            if (player != null && playingId != null && adapter != null) {
                try {
                    adapter.refreshAudio(playingId, player.getCurrentPosition(), player.getDuration());
                } catch (IllegalStateException ignored) {
                    return;
                }
                AndroidUtilities.runOnUIThread(this, 400);
            }
        }
    };

    private VaultTempFiles temp() {
        if (temp == null) {
            temp = new VaultTempFiles(new java.io.File(ApplicationLoader.applicationContext.getFilesDir(), "vault-open"));
        }
        return temp;
    }

    private void buildMenu() {
        ActionBarMenu menu = actionBar.createMenu();
        menu.clearItems();
        ActionBarMenuItem search = menu.addItem(MENU_SEARCH, org.telegram.messenger.R.drawable.outline_header_search).setIsSearchField(true)
                .setActionBarMenuItemSearchListener(new ActionBarMenuItem.ActionBarMenuItemSearchListener() {
                    @Override
                    public void onSearchCollapse() {
                        searchQuery = "";
                        reload();
                    }

                    @Override
                    public void onTextChanged(EditText editText) {
                        searchQuery = editText.getText().toString();
                        reload();
                    }
                });
        search.setSearchFieldHint("Search the Vault");
        ActionBarMenuItem more = menu.addItem(MENU_MORE, org.telegram.messenger.R.drawable.ic_ab_other);
        more.addSubItem(MENU_SYNC, "Sync now");
        more.addSubItem(MENU_SELECT_ALL, "Select all");
        more.addSubItem(MENU_SETTINGS, "Settings");
        more.addSubItem(MENU_LOCK, "Lock now");
    }

    private TextView chip(Context c, final VaultCategory cat) {
        TextView t = new TextView(c);
        t.setText(cat.label);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        t.setGravity(Gravity.CENTER);
        t.setPadding(AndroidUtilities.dp(14), AndroidUtilities.dp(7), AndroidUtilities.dp(14), AndroidUtilities.dp(7));
        t.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                category = cat;
                styleChips();
                scrollToEnd = true;
                reload();
            }
        });
        chips.put(cat, t);
        return t;
    }

    private void styleChips() {
        for (java.util.Map.Entry<VaultCategory, TextView> e : chips.entrySet()) {
            boolean on = e.getKey() == category;
            android.graphics.drawable.GradientDrawable bg = new android.graphics.drawable.GradientDrawable();
            bg.setCornerRadius(AndroidUtilities.dp(18));
            bg.setColor(on ? Theme.getColor(Theme.key_chat_messagePanelSend) : Theme.getColor(Theme.key_windowBackgroundGray));
            e.getValue().setBackground(bg);
            e.getValue().setTextColor(on ? 0xFFFFFFFF : Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        }
    }

    private void showList() {
        final Context c = container.getContext();
        container.removeAllViews();
        stopAudio();
        temp().wipeAll();
        thumbCache.evictAll();
        thumbLoading.clear();
        if (mediaPool != null) {
            mediaPool.shutdownNow();
        }
        mediaPool = java.util.concurrent.Executors.newSingleThreadExecutor();
        model = new VaultListModel(rt.store);
        category = VaultCategory.ALL;
        searchQuery = "";
        scrollToEnd = true;
        chips.clear();
        buildMenu();
        adapter = new VaultChatAdapter(c, model, new VaultChatAdapter.Host() {
            @Override
            public void loadThumbnail(VaultItem item, ImageView target) {
                VaultFragment.this.loadThumbnail(item, target);
            }

            @Override
            public int audioState(String itemId) {
                return itemId.equals(playingId) ? (playerPaused ? 2 : 1) : 0;
            }

            @Override
            public int audioPositionMs(String itemId) {
                try {
                    return itemId.equals(playingId) && player != null ? player.getCurrentPosition() : 0;
                } catch (IllegalStateException e) {
                    return 0;
                }
            }

            @Override
            public int audioLengthMs(String itemId) {
                try {
                    return itemId.equals(playingId) && player != null ? player.getDuration() : 0;
                } catch (IllegalStateException e) {
                    return 0;
                }
            }

            @Override
            public void onPlayPause(VaultItem item) {
                toggleAudio(item);
            }
        });

        LinearLayout root = new LinearLayout(c);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));

        statusView = text(c, "", 13, false);
        statusView.setVisibility(View.GONE);
        statusView.setPadding(AndroidUtilities.dp(12), AndroidUtilities.dp(6), AndroidUtilities.dp(12), AndroidUtilities.dp(6));
        root.addView(statusView);

        android.widget.HorizontalScrollView chipScroll = new android.widget.HorizontalScrollView(c);
        chipScroll.setHorizontalScrollBarEnabled(false);
        chipScroll.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        LinearLayout chipRow = new LinearLayout(c);
        chipRow.setOrientation(LinearLayout.HORIZONTAL);
        chipRow.setPadding(AndroidUtilities.dp(8), AndroidUtilities.dp(6), AndroidUtilities.dp(8), AndroidUtilities.dp(6));
        for (VaultCategory cat : VaultCategory.values()) {
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.rightMargin = AndroidUtilities.dp(6);
            chipRow.addView(chip(c, cat), lp);
        }
        chipScroll.addView(chipRow);
        root.addView(chipScroll, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        styleChips();

        LinearLayout selBar = new LinearLayout(c);
        selBar.setOrientation(LinearLayout.HORIZONTAL);
        selBar.setGravity(Gravity.CENTER_VERTICAL);
        selBar.setPadding(AndroidUtilities.dp(12), 0, AndroidUtilities.dp(4), 0);
        selBar.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        selectionView = text(c, "", 14, true);
        selBar.addView(selectionView, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        selBar.addView(button(c, "Copy", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                copySelected();
            }
        }));
        deleteButton = button(c, "Delete", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                confirmDelete();
            }
        });
        selBar.addView(deleteButton);
        selBar.addView(button(c, "Cancel", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                model.clearSelection();
                renderSelection();
            }
        }));
        root.addView(selBar);

        FrameLayout listFrame = new FrameLayout(c);
        chatList = new ListView(c);
        chatList.setDivider(null);
        chatList.setDividerHeight(0);
        chatList.setSelector(new android.graphics.drawable.ColorDrawable(0));
        chatList.setCacheColorHint(0);
        chatList.setAdapter(adapter);
        chatList.setOnItemClickListener(new android.widget.AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(android.widget.AdapterView<?> parent, View view, int position, long id) {
                if (model == null || position >= model.rows().size()) {
                    return;
                }
                VaultListModel.Row row = model.rows().get(position);
                if (model.isSelecting()) {
                    model.toggle(row.id);
                    renderSelection();
                } else {
                    openItem(row.item);
                }
            }
        });
        chatList.setOnItemLongClickListener(new android.widget.AdapterView.OnItemLongClickListener() {
            @Override
            public boolean onItemLongClick(android.widget.AdapterView<?> parent, View view, int position, long id) {
                if (model == null || position >= model.rows().size()) {
                    return true;
                }
                VaultListModel.Row row = model.rows().get(position);
                if (model.isSelecting()) {
                    model.toggle(row.id);
                    renderSelection();
                } else {
                    showItemMenu(row.item);
                }
                return true;
            }
        });
        listFrame.addView(chatList, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        emptyView = text(c, "", 15, false);
        emptyView.setGravity(Gravity.CENTER);
        emptyView.setPadding(AndroidUtilities.dp(32), 0, AndroidUtilities.dp(32), 0);
        listFrame.addView(emptyView, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        root.addView(listFrame, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        // composer: attach, text, send (like Saved Messages)
        LinearLayout bar = new LinearLayout(c);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setBackgroundColor(Theme.getColor(Theme.key_chat_messagePanelBackground));
        ImageView attach = new ImageView(c);
        attach.setImageResource(org.telegram.messenger.R.drawable.input_attach);
        attach.setColorFilter(Theme.getColor(Theme.key_chat_messagePanelIcons));
        attach.setScaleType(ImageView.ScaleType.CENTER);
        attach.setContentDescription("Attach files");
        attach.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                pickFiles();
            }
        });
        bar.addView(attach, new LinearLayout.LayoutParams(AndroidUtilities.dp(48), AndroidUtilities.dp(48)));
        composer = new EditText(c);
        composer.setHint("Message");
        composer.setHintTextColor(Theme.getColor(Theme.key_chat_messagePanelHint));
        composer.setTextColor(Theme.getColor(Theme.key_chat_messagePanelText));
        composer.setBackground(null);
        composer.setMaxLines(5);
        composer.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);
        bar.addView(composer, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        ImageView send = new ImageView(c);
        send.setImageResource(org.telegram.messenger.R.drawable.ic_send);
        send.setColorFilter(Theme.getColor(Theme.key_chat_messagePanelSend));
        send.setScaleType(ImageView.ScaleType.CENTER);
        send.setContentDescription("Save to the Vault");
        send.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                sendNote();
            }
        });
        bar.addView(send, new LinearLayout.LayoutParams(AndroidUtilities.dp(48), AndroidUtilities.dp(48)));
        root.addView(bar);

        container.addView(root, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        renderSelection();
        // The engine exists only once the channel is attached; until then local items still show and can be added
        background(new Job() {
            @Override
            public void run() throws Exception {
                rt.attachChannel(new SyncCoordinator.Listener() {
                    @Override
                    public void onStatus(final SyncCoordinator.Status s) {
                        ui(new Runnable() {
                            @Override
                            public void run() {
                                renderStatus(s);
                                if (s.state == SyncCoordinator.State.IDLE) {
                                    reload();
                                } else if (s.state == SyncCoordinator.State.WAITING_RETRY) {
                                    AndroidUtilities.runOnUIThread(new Runnable() {
                                        @Override
                                        public void run() {
                                            syncNow(false);
                                        }
                                    }, Math.max(1000, s.nextAttemptMillis - System.currentTimeMillis()));
                                }
                            }
                        });
                    }
                }, true);
            }
        }, new Runnable() {
            @Override
            public void run() {
                syncNow(false);
            }
        }, new ErrorHandler() {
            @Override
            public void accept(VaultCryptoException e) {
                if (statusView != null) {
                    statusView.setVisibility(View.VISIBLE);
                    statusView.setText("Offline: " + messageFor(e));
                }
            }
        });
        reload();
    }

    private void sendNote() {
        if (composer == null) {
            return;
        }
        final String t = composer.getText().toString().trim();
        if (t.isEmpty()) {
            return;
        }
        composer.setText("");
        background(new Job() {
            @Override
            public void run() throws Exception {
                rt.engine().addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text(t), null, null);
            }
        }, new Runnable() {
            @Override
            public void run() {
                scrollToEnd = true;
                reload();
                syncNow(false);
            }
        }, new ErrorHandler() {
            @Override
            public void accept(VaultCryptoException e) {
                toast(messageFor(e));
            }
        });
    }

    private void reload() {
        if (model == null) {
            return;
        }
        final VaultListModel m = model;
        final VaultCategory cat = category;
        final String q = searchQuery;
        background(new Job() {
            @Override
            public void run() throws Exception {
                boolean catChanged = m.category() != cat;
                boolean qChanged = !m.query().equals(q);
                if (catChanged) {
                    m.setCategory(cat);
                }
                if (qChanged) {
                    m.setQuery(q);
                }
                if (!catChanged && !qChanged) {
                    m.refresh();
                }
            }
        }, new Runnable() {
            @Override
            public void run() {
                if (adapter == null || model != m) {
                    return;
                }
                adapter.notifyDataSetChanged();
                int n = m.rows().size();
                if (emptyView != null) {
                    emptyView.setVisibility(n == 0 ? View.VISIBLE : View.GONE);
                    emptyView.setText(!q.trim().isEmpty() ? "Nothing found." : cat == VaultCategory.ALL
                            ? "Your Vault is empty.\nSave messages here with \"Send to Vault\", or write a note and attach files below."
                            : "No " + cat.label.toLowerCase(java.util.Locale.ROOT) + " in the Vault yet.");
                }
                if (scrollToEnd && chatList != null && n > 0) {
                    chatList.setSelection(n - 1);
                    scrollToEnd = false;
                }
                renderSelection();
            }
        }, new ErrorHandler() {
            @Override
            public void accept(VaultCryptoException e) {
                toast(messageFor(e));
            }
        });
    }

    private void renderSelection() {
        if (model == null || selectionView == null) {
            return;
        }
        boolean sel = model.isSelecting();
        selectionView.setText(sel ? model.selectedCount() + " selected" : "");
        ((View) selectionView.getParent()).setVisibility(sel ? View.VISIBLE : View.GONE);
        if (adapter != null) {
            adapter.notifyDataSetChanged();
        }
    }

    // ------------------------------------------------------------------ previews

    private void loadThumbnail(final VaultItem item, final ImageView target) {
        Bitmap cached = thumbCache.get(item.id);
        if (cached != null) {
            target.setImageBitmap(cached);
            return;
        }
        target.setImageDrawable(null);
        final boolean canMakeFromPhoto = item.type == VaultItem.Type.PHOTO && item.mediaSize <= 8L * 1024 * 1024;
        if (item.thumbnailId == null && !canMakeFromPhoto) {
            return; // a video saved without a preview: the grey box with the play mark stays
        }
        if (!thumbLoading.add(item.id) || mediaPool == null) {
            return;
        }
        final java.util.concurrent.ExecutorService pool = mediaPool;
        pool.execute(new Runnable() {
            @Override
            public void run() {
                Bitmap bmp = null;
                try {
                    byte[] b = null;
                    if (item.thumbnailId != null) {
                        try {
                            b = rt.store.readThumbnail(item.id); // local copy
                        } catch (Exception local) {
                            VaultSyncEngine e = rt.engine();
                            b = e == null ? null : e.readThumbnail(item.id); // fetches it from the channel if needed
                        }
                    }
                    if (b != null) {
                        bmp = BitmapFactory.decodeByteArray(b, 0, b.length);
                    } else if (canMakeFromPhoto) {
                        ByteArrayOutputStream out = new ByteArrayOutputStream();
                        VaultSyncEngine e = rt.engine();
                        if (e != null) {
                            e.openMedia(item.id, out);
                            bmp = VaultThumbs.decodeSmall(out.toByteArray()); // in memory only
                        }
                    }
                } catch (Throwable ignored) {
                    // no preview: the placeholder box stays
                }
                final Bitmap result = bmp;
                ui(new Runnable() {
                    @Override
                    public void run() {
                        thumbLoading.remove(item.id);
                        if (result != null && mediaPool == pool) {
                            thumbCache.put(item.id, result);
                            if (adapter != null) {
                                adapter.notifyDataSetChanged();
                            }
                        }
                    }
                });
            }
        });
    }

    // ------------------------------------------------------------------ item menu and selection helpers

    private void showItemMenu(final VaultItem item) {
        final java.util.List<String> labels = new java.util.ArrayList<>();
        final java.util.List<Integer> ids = new java.util.ArrayList<>();
        labels.add("Select");
        ids.add(0);
        if (item.text != null && !item.text.isEmpty()) {
            labels.add("Copy text");
            ids.add(1);
        }
        if (item.mediaId != null) {
            labels.add("Open");
            ids.add(2);
            labels.add("Export…");
            ids.add(3);
        }
        labels.add("Delete");
        ids.add(4);
        AlertDialog.Builder b = new AlertDialog.Builder(getParentActivity());
        b.setItems(labels.toArray(new CharSequence[0]), new android.content.DialogInterface.OnClickListener() {
            @Override
            public void onClick(android.content.DialogInterface dialog, int which) {
                switch (ids.get(which)) {
                    case 0:
                        model.toggle(item.id);
                        renderSelection();
                        break;
                    case 1:
                        copyText(item.text);
                        break;
                    case 2:
                        openItem(item);
                        break;
                    case 3:
                        startExport(item);
                        break;
                    default:
                        model.clearSelection();
                        model.toggle(item.id);
                        renderSelection();
                        confirmDelete();
                        break;
                }
            }
        });
        showDialog(b.create());
    }

    private void copyText(String t) {
        android.content.ClipboardManager cm = (android.content.ClipboardManager) getParentActivity().getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null && t != null) {
            cm.setPrimaryClip(android.content.ClipData.newPlainText("Vault", t));
            toast("Copied");
        }
    }

    private void copySelected() {
        StringBuilder sb = new StringBuilder();
        for (VaultListModel.Row r : model.rows()) {
            if (r.selected && r.item.text != null && !r.item.text.isEmpty()) {
                if (sb.length() > 0) {
                    sb.append("\n\n");
                }
                sb.append(r.item.text);
            }
        }
        if (sb.length() == 0) {
            toast("The selected messages have no text to copy.");
            return;
        }
        copyText(sb.toString());
    }

    private void renderStatus(SyncCoordinator.Status s) {
        if (statusView == null) {
            return;
        }
        String t;
        boolean notice = true;
        switch (s.state) {
            case SYNCING:
                t = "Syncing\u2026";
                notice = false;
                break;
            case WAITING_RETRY:
                t = "Sync paused, will retry (" + s.pendingItems + " waiting)";
                break;
            case NEEDS_RESTORE:
                t = "The keys were rotated on another device. Tap here to restore with the new recovery key.";
                break;
            case SECURITY_ERROR:
                t = "Sync stopped: the server data failed a security check (" + s.error + ").";
                break;
            case LOCKED:
                t = "Locked";
                notice = false;
                break;
            default:
                t = s.pendingItems > 0 ? s.pendingItems + " waiting to sync" : "Synced";
                notice = false;
        }
        actionBar.setSubtitle(notice ? "Sync problem" : t);
        statusView.setVisibility(notice ? View.VISIBLE : View.GONE);
        statusView.setText(t);
        statusView.setOnClickListener(s.state == SyncCoordinator.State.NEEDS_RESTORE ? new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showAdoptForm();
            }
        } : null);
    }

    private void syncNow(boolean force) {
        final SyncCoordinator sc = rt.coordinator();
        if (sc != null) {
            sc.requestSync(force);
        }
    }

    private void confirmDelete() {
        final int n = model.selectedCount();
        AlertDialog.Builder b = new AlertDialog.Builder(getParentActivity());
        b.setTitle("Delete from Vault?");
        b.setMessage(n + " item(s) will be deleted from the Vault on all your devices. The original messages are not affected.");
        b.setPositiveButton("Delete", new AlertDialog.OnButtonClickListener() {
            @Override
            public void onClick(AlertDialog d, int which) {
                background(new Job() {
                    @Override
                    public void run() throws Exception {
                        model.deleteSelected(rt.engine());
                    }
                }, new Runnable() {
                    @Override
                    public void run() {
                        reload();
                        syncNow(false);
                    }
                }, new ErrorHandler() {
                    @Override
                    public void accept(VaultCryptoException e) {
                        toast(messageFor(e));
                    }
                });
            }
        });
        b.setNegativeButton("Cancel", null);
        showDialog(b.create());
    }

    private void toast(String s) {
        android.widget.Toast.makeText(getParentActivity(), s, android.widget.Toast.LENGTH_LONG).show();
    }

    // ------------------------------------------------------------------ opening items

    private interface TempReady {
        void ready(java.io.File f);
    }

    private java.util.concurrent.ExecutorService openPool;

    private java.util.concurrent.ExecutorService openPool() {
        if (openPool == null) {
            openPool = java.util.concurrent.Executors.newSingleThreadExecutor();
        }
        return openPool;
    }

    /** Decrypts a stored file into the private, short-lived temp folder (streamed, never all in memory). */
    private void decryptToTemp(final VaultItem item, final TempReady done, final Runnable failed) {
        final java.util.concurrent.ExecutorService pool = openPool();
        pool.execute(new Runnable() {
            @Override
            public void run() {
                java.io.File f = null;
                try {
                    f = temp().create(item.mediaName);
                    try (java.io.FileOutputStream o = new java.io.FileOutputStream(f)) {
                        rt.engine().openMedia(item.id, o);
                    }
                    final java.io.File ready = f;
                    ui(new Runnable() {
                        @Override
                        public void run() {
                            if (rt.keys.isUnlocked() && openPool == pool) {
                                done.ready(ready);
                            } else {
                                temp().release(ready);
                            }
                        }
                    });
                } catch (final Throwable t) {
                    temp().release(f);
                    ui(new Runnable() {
                        @Override
                        public void run() {
                            toast(t instanceof VaultCryptoException ? messageFor((VaultCryptoException) t) : "Could not open the file.");
                            if (failed != null) {
                                failed.run();
                            }
                        }
                    });
                }
            }
        });
    }

    private void openItem(final VaultItem item) {
        if (item.mediaId == null) {
            return; // text: links and spoilers are tapped in the bubble itself
        }
        if (item.type == VaultItem.Type.PHOTO && item.mediaSize <= MAX_INLINE_PHOTO_BYTES) {
            final java.util.concurrent.ExecutorService pool = openPool();
            pool.execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        ByteArrayOutputStream out = new ByteArrayOutputStream();
                        rt.engine().openMedia(item.id, out); // decrypted in memory only, never written to disk
                        final Bitmap bmp = VaultThumbs.decodeFull(out.toByteArray());
                        ui(new Runnable() {
                            @Override
                            public void run() {
                                if (bmp == null) {
                                    offerExport(item);
                                } else if (rt.keys.isUnlocked() && openPool == pool) {
                                    closeViewer();
                                    viewer = VaultMediaViews.showPhoto(getParentActivity(), bmp, item.text, new Runnable() {
                                        @Override
                                        public void run() {
                                            startExport(item);
                                        }
                                    }, new Runnable() {
                                        @Override
                                        public void run() {
                                            viewer = null;
                                        }
                                    });
                                }
                            }
                        });
                    } catch (final Throwable t) {
                        ui(new Runnable() {
                            @Override
                            public void run() {
                                toast(t instanceof VaultCryptoException ? messageFor((VaultCryptoException) t) : "Could not open the photo.");
                            }
                        });
                    }
                }
            });
        } else if (item.type == VaultItem.Type.VIDEO) {
            toast("Opening video…");
            decryptToTemp(item, new TempReady() {
                @Override
                public void ready(final java.io.File f) {
                    stopAudio();
                    closeViewer();
                    viewer = VaultMediaViews.showVideo(getParentActivity(), f, new Runnable() {
                        @Override
                        public void run() {
                            startExport(item);
                        }
                    }, new Runnable() {
                        @Override
                        public void run() {
                            viewer = null;
                            temp().release(f);
                        }
                    });
                }
            }, null);
        } else if (item.isVoice() || VaultCategory.isMusic(item)) {
            toggleAudio(item);
        } else {
            offerOpenOrExport(item);
        }
    }

    private void closeViewer() {
        Dialog d = viewer;
        viewer = null;
        if (d != null) {
            try {
                d.dismiss();
            } catch (RuntimeException ignored) {
                // already gone
            }
        }
    }

    // ------------------------------------------------------------------ voice and music

    private void toggleAudio(final VaultItem item) {
        if (item.id.equals(playingId) && player != null) {
            try {
                if (player.isPlaying()) {
                    player.pause();
                    playerPaused = true;
                    AndroidUtilities.cancelRunOnUIThread(audioTick);
                } else {
                    player.start();
                    playerPaused = false;
                    AndroidUtilities.runOnUIThread(audioTick, 400);
                }
            } catch (IllegalStateException e) {
                stopAudio();
            }
            if (adapter != null) {
                adapter.notifyDataSetChanged();
            }
            return;
        }
        stopAudio();
        playingId = item.id;
        playerPaused = false;
        if (adapter != null) {
            adapter.notifyDataSetChanged();
        }
        decryptToTemp(item, new TempReady() {
            @Override
            public void ready(final java.io.File f) {
                if (!item.id.equals(playingId)) {
                    temp().release(f);
                    return;
                }
                final android.media.MediaPlayer mp = new android.media.MediaPlayer();
                playingFile = f;
                try {
                    mp.setDataSource(f.getAbsolutePath());
                    mp.setOnCompletionListener(new android.media.MediaPlayer.OnCompletionListener() {
                        @Override
                        public void onCompletion(android.media.MediaPlayer m) {
                            stopAudio();
                        }
                    });
                    mp.setOnErrorListener(new android.media.MediaPlayer.OnErrorListener() {
                        @Override
                        public boolean onError(android.media.MediaPlayer m, int what, int extra) {
                            toast("This audio cannot be played on this device. Use Export instead.");
                            stopAudio();
                            return true;
                        }
                    });
                    mp.setOnPreparedListener(new android.media.MediaPlayer.OnPreparedListener() {
                        @Override
                        public void onPrepared(android.media.MediaPlayer m) {
                            if (m == player) {
                                m.start();
                                AndroidUtilities.runOnUIThread(audioTick, 400);
                            }
                        }
                    });
                    player = mp;
                    mp.prepareAsync();
                } catch (Exception e) {
                    mp.release();
                    player = null;
                    stopAudio();
                    toast("This audio cannot be played on this device. Use Export instead.");
                }
            }
        }, new Runnable() {
            @Override
            public void run() {
                stopAudio();
            }
        });
    }

    private java.io.File playingFile;

    private void stopAudio() {
        AndroidUtilities.cancelRunOnUIThread(audioTick);
        android.media.MediaPlayer p = player;
        player = null;
        if (p != null) {
            try {
                p.release();
            } catch (RuntimeException ignored) {
                // already released
            }
        }
        if (playingFile != null) {
            temp().release(playingFile);
            playingFile = null;
        }
        boolean was = playingId != null;
        playingId = null;
        playerPaused = false;
        if (was && adapter != null) {
            adapter.notifyDataSetChanged();
        }
    }

    // ------------------------------------------------------------------ other documents, export, attach

    private void offerOpenOrExport(final VaultItem item) {
        AlertDialog.Builder b = new AlertDialog.Builder(getParentActivity());
        b.setTitle(item.mediaName == null ? "File" : item.mediaName);
        b.setMessage(android.text.format.Formatter.formatShortFileSize(getParentActivity(), item.mediaSize)
                + "\n\nOpen decrypts a temporary copy that only the app you choose can read; it is erased when the Vault locks. "
                + "Export saves a decrypted copy where you choose, outside the Vault's protection.");
        b.setPositiveButton("Open", new AlertDialog.OnButtonClickListener() {
            @Override
            public void onClick(AlertDialog d, int which) {
                toast("Opening…");
                decryptToTemp(item, new TempReady() {
                    @Override
                    public void ready(java.io.File f) {
                        try {
                            Uri uri = androidx.core.content.FileProvider.getUriForFile(getParentActivity(),
                                    ApplicationLoader.getApplicationId() + ".provider", f);
                            Intent i = new Intent(Intent.ACTION_VIEW);
                            i.setDataAndType(uri, item.mimeType == null || item.mimeType.isEmpty() ? "application/octet-stream" : item.mimeType);
                            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                            launching = true;
                            getParentActivity().startActivity(i);
                        } catch (Exception e) {
                            launching = false;
                            temp().release(f);
                            toast("No app on this phone can open this type of file. Use Export instead.");
                        }
                    }
                }, null);
            }
        });
        b.setNeutralButton("Export…", new AlertDialog.OnButtonClickListener() {
            @Override
            public void onClick(AlertDialog d, int which) {
                startExport(item);
            }
        });
        b.setNegativeButton("Cancel", null);
        showDialog(b.create());
    }

    private void offerExport(final VaultItem item) {
        AlertDialog.Builder b = new AlertDialog.Builder(getParentActivity());
        b.setTitle(item.mediaName == null ? "File" : item.mediaName);
        b.setMessage("This file cannot be shown inside the Vault. You can export a decrypted copy to a place you choose. The copy is no longer protected by the Vault.");
        b.setPositiveButton("Export…", new AlertDialog.OnButtonClickListener() {
            @Override
            public void onClick(AlertDialog d, int which) {
                startExport(item);
            }
        });
        b.setNegativeButton("Cancel", null);
        showDialog(b.create());
    }

    private void startExport(VaultItem item) {
        pendingExportItemId = item.id;
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType(item.mimeType == null || item.mimeType.isEmpty() ? "application/octet-stream" : item.mimeType);
        i.putExtra(Intent.EXTRA_TITLE, item.mediaName == null ? "vault-file" : item.mediaName);
        launching = true;
        getParentActivity().startActivityForResult(i, REQUEST_EXPORT);
    }

    private void pickFiles() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        launching = true;
        getParentActivity().startActivityForResult(i, REQUEST_ATTACH);
    }

    @Override
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_ATTACH) {
            launching = false;
            if (resultCode != Activity.RESULT_OK || data == null || model == null) {
                return;
            }
            final java.util.List<Uri> uris = new java.util.ArrayList<>();
            if (data.getClipData() != null) {
                for (int k = 0; k < data.getClipData().getItemCount(); k++) {
                    uris.add(data.getClipData().getItemAt(k).getUri());
                }
            } else if (data.getData() != null) {
                uris.add(data.getData());
            }
            importFiles(uris);
            return;
        }
        if (requestCode == REQUEST_EXPORT) {
            launching = false;
        }
        if (requestCode != REQUEST_EXPORT || resultCode != Activity.RESULT_OK || data == null || data.getData() == null
                || pendingExportItemId == null) {
            return;
        }
        final Uri uri = data.getData();
        final String id = pendingExportItemId;
        pendingExportItemId = null;
        background(new Job() {
            @Override
            public void run() throws Exception {
                try (OutputStream out = getParentActivity().getContentResolver().openOutputStream(uri)) {
                    if (out == null) {
                        throw new IOException("Could not open the destination");
                    }
                    rt.engine().openMedia(id, out);
                }
            }
        }, new Runnable() {
            @Override
            public void run() {
                toast("Exported");
            }
        }, new ErrorHandler() {
            @Override
            public void accept(VaultCryptoException e) {
                toast(messageFor(e));
            }
        });
    }

    /** Saves the picked files as what they are (photo, video, music, document); the text box becomes the first caption. */
    private void importFiles(final java.util.List<Uri> uris) {
        if (uris.isEmpty()) {
            return;
        }
        final String caption = composer == null ? "" : composer.getText().toString().trim();
        if (composer != null) {
            composer.setText("");
        }
        final android.content.ContentResolver cr = getParentActivity().getContentResolver();
        final Context app = ApplicationLoader.applicationContext;
        final int[] saved = new int[1];
        final String[] firstError = new String[1];
        background(new Job() {
            @Override
            public void run() throws Exception {
                for (int k = 0; k < uris.size(); k++) {
                    try {
                        importOne(app, cr, uris.get(k), k == 0 ? caption : "");
                        saved[0]++;
                    } catch (VaultCryptoException e) {
                        if (firstError[0] == null) {
                            firstError[0] = messageFor(e);
                        }
                    } catch (Exception e) {
                        if (firstError[0] == null) {
                            firstError[0] = "Could not read one of the files.";
                        }
                    }
                }
            }
        }, new Runnable() {
            @Override
            public void run() {
                toast((saved[0] > 0 ? "Saved " + saved[0] + " to the Vault." : "Nothing was saved.")
                        + (firstError[0] != null ? " " + firstError[0] : ""));
                scrollToEnd = true;
                reload();
                syncNow(false);
            }
        }, new ErrorHandler() {
            @Override
            public void accept(VaultCryptoException e) {
                toast(messageFor(e));
            }
        });
    }

    private void importOne(Context app, android.content.ContentResolver cr, Uri uri, String caption) throws Exception {
        String mime = cr.getType(uri);
        if (mime == null || mime.isEmpty()) {
            mime = "application/octet-stream";
        }
        String name = null;
        try (android.database.Cursor q = cr.query(uri, null, null, null, null)) {
            if (q != null && q.moveToFirst()) {
                int ni = q.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME);
                if (ni >= 0) {
                    name = q.getString(ni);
                }
            }
        }
        if (name == null || name.isEmpty()) {
            name = "file";
        }
        VaultItem.Type type = VaultItem.Type.DOCUMENT;
        int flags = 0;
        if (mime.startsWith("image/") && !mime.equals("image/svg+xml")) {
            type = VaultItem.Type.PHOTO;
        } else if (mime.startsWith("video/")) {
            type = VaultItem.Type.VIDEO;
        } else if (mime.startsWith("audio/")) {
            flags = VaultItem.FLAG_MUSIC;
        }
        VaultThumbs.Info info = new VaultThumbs.Info();
        if (type == VaultItem.Type.PHOTO || type == VaultItem.Type.VIDEO) {
            info = VaultThumbs.make(app, uri, type);
            if (type == VaultItem.Type.PHOTO && info.width <= 0) {
                type = VaultItem.Type.DOCUMENT; // not a picture Android can read: keep it as a file
                info = new VaultThumbs.Info();
            }
        } else if (flags == VaultItem.FLAG_MUSIC) {
            info.durationSeconds = VaultThumbs.audioSeconds(app, uri);
        }
        VaultItem.Draft d = new VaultItem.Draft(type).text(caption).flags(flags)
                .media(name, mime, info.width, info.height, info.durationSeconds);
        try (InputStream in = cr.openInputStream(uri)) {
            if (in == null) {
                throw new IOException("Could not open the file");
            }
            rt.engine().addItem(d, in, info.thumbnail);
        }
    }


    // ------------------------------------------------------------------ device linking

    private LinkTransport.Approver approverRun;
    private LinkTransport.Joiner joinerRun;

    /** Existing device: waits for a new phone, shows the code, sends the key only after the user approves. */
    private void startApproving() {
        final Context c = getParentActivity();
        final TextView status = text(c, "Open the Vault on the new phone and choose \"link this phone\". Waiting for it\u2026", 15, false);
        final AlertDialog.Builder b = new AlertDialog.Builder(c);
        b.setTitle("Link a new device");
        b.setView(status);
        b.setNegativeButton("Cancel", new AlertDialog.OnButtonClickListener() {
            @Override
            public void onClick(AlertDialog d, int which) {
                if (approverRun != null) {
                    approverRun.cancel();
                }
            }
        });
        final Dialog dialog = showDialog(b.create());
        final VaultRuntime run = rt;
        approverRun = new LinkTransport.Approver(rt.remote(), rt.keys, rt.workDir());
        final LinkTransport.Approver a = approverRun;
        backgroundOn(rt.linkIo(), new Job() {
            @Override
            public void run() throws Exception {
                try {
                    a.awaitRequest();
                    final String code = a.awaitCode();
                    ui(new Runnable() {
                        @Override
                        public void run() {
                            dialog.dismiss();
                            confirmCode(code, a);
                        }
                    });
                } catch (VaultCryptoException e) {
                    a.cleanup();
                    throw e;
                }
            }
        }, null, new ErrorHandler() {
            @Override
            public void accept(VaultCryptoException e) {
                dialog.dismiss();
                if (e.getReason() != VaultCryptoException.Reason.INVALID_STATE) {
                    toast(messageFor(e));
                }
            }
        });
    }

    private void confirmCode(String code, final LinkTransport.Approver a) {
        AlertDialog.Builder b = new AlertDialog.Builder(getParentActivity());
        b.setTitle("Does the other phone show this code?");
        TextView t = text(getParentActivity(), code, 34, true);
        t.setGravity(Gravity.CENTER);
        t.setTypeface(Typeface.MONOSPACE);
        b.setView(t);
        b.setPositiveButton("Yes, the codes match", new AlertDialog.OnButtonClickListener() {
            @Override
            public void onClick(AlertDialog d, int which) {
                backgroundOn(rt.linkIo(), new Job() {
                    @Override
                    public void run() throws Exception {
                        try {
                            a.approve();
                        } finally {
                            a.cleanup();
                        }
                    }
                }, new Runnable() {
                    @Override
                    public void run() {
                        toast("The new phone is being linked.");
                    }
                }, new ErrorHandler() {
                    @Override
                    public void accept(VaultCryptoException e) {
                        toast(messageFor(e));
                    }
                });
            }
        });
        b.setNegativeButton("No, they differ", new AlertDialog.OnButtonClickListener() {
            @Override
            public void onClick(AlertDialog d, int which) {
                a.cancel();
                backgroundOn(rt.linkIo(), new Job() {
                    @Override
                    public void run() {
                        a.cleanup();
                    }
                }, null, new ErrorHandler() {
                    @Override
                    public void accept(VaultCryptoException e) {
                    }
                });
                toast("Linking cancelled. If the codes differed, do not try again on this network.");
            }
        });
        showDialog(b.create());
    }

    /** New device: choose this phone's password first, then compare the code and wait for approval. */
    private void showLinkJoinForm() {
        final Context c = container.getContext();
        LinearLayout p = page(c);
        p.addView(text(c, "Link this phone", 22, true));
        p.addView(text(c, "Choose a password for THIS phone (6+ characters). Then open the Vault on your other phone, go to Settings, and choose \"Link a new device\" first. Start here after that.", 15, false));
        final EditText pw = field(c, "Password (6+ characters)", true);
        final EditText pw2 = field(c, "Repeat password", true);
        final TextView status = text(c, "", 15, false);
        p.addView(pw);
        p.addView(pw2);
        p.addView(status);
        p.addView(button(c, "Start", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                final char[] a1 = chars(pw);
                final char[] a2 = chars(pw2);
                if (a1.length < org.telegram.messenger.vault.VaultKeyManager.MIN_PASSWORD_LENGTH || !java.util.Arrays.equals(a1, a2)) {
                    status.setText("The password needs at least 6 characters and both entries must match.");
                    return;
                }
                status.setText("Contacting your other phone\u2026");
                joinerRun = null;
                backgroundOn(rt.linkIo(), new Job() {
                    @Override
                    public void run() throws Exception {
                        rt.attachChannel(null, false);
                        final LinkTransport.Joiner j = new LinkTransport.Joiner(rt.remote(), rt.workDir());
                        joinerRun = j;
                        try {
                            final String code = j.awaitCode();
                            ui(new Runnable() {
                                @Override
                                public void run() {
                                    status.setText("Check that your other phone shows this code, then tap \"Yes, the codes match\" there:\n\n" + code);
                                }
                            });
                            j.awaitGrantAndInstall(rt.keys, a1, a2, false);
                        } finally {
                            j.cleanup();
                        }
                    }
                }, new Runnable() {
                    @Override
                    public void run() {
                        rt.unlocked();
                        showList();
                    }
                }, new ErrorHandler() {
                    @Override
                    public void accept(VaultCryptoException e) {
                        status.setText(messageFor(e));
                    }
                });
            }
        }));
        p.addView(button(c, "Cancel", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (joinerRun != null) {
                    joinerRun.cancel();
                }
                decide();
            }
        }));
        show(p);
    }

    // ------------------------------------------------------------------ key rotation

    private VaultSyncEngine.RotationPlan rotationPlan;

    /** Settings entry: explains what rotation does, asks for the password, then prepares the new keys. */
    private void startRotation() {
        final Context c = getParentActivity();
        LinearLayout p = page(c);
        p.addView(text(c, "This creates a NEW master key and a NEW recovery key. Your old recovery key stops working, and the old copy on Telegram's servers is replaced by one under the new key.", 14, false));
        p.addView(text(c, "Before you start: open the Vault on your other devices and let them finish syncing. After the rotation each of them must be restored with the NEW recovery key; anything saved on them that had not synced is lost. Keep this screen open: it needs a network connection and can take a while for a large Vault.", 14, false));
        p.addView(text(c, "Rotating cannot take back what a lost or stolen device has already read. It protects what you save from now on.", 14, false));
        final EditText pw = field(c, "Your Vault password", true);
        p.addView(pw);
        AlertDialog.Builder b = new AlertDialog.Builder(c);
        b.setTitle("Rotate keys");
        b.setView(p);
        b.setPositiveButton("Continue", new AlertDialog.OnButtonClickListener() {
            @Override
            public void onClick(AlertDialog d, int which) {
                final char[] password = chars(pw);
                toast("Preparing\u2026 this downloads anything not on this phone first.");
                backgroundOn(rt.linkIo(), new Job() {
                    @Override
                    public void run() throws Exception {
                        final VaultSyncEngine.RotationPlan plan = rt.engine().beginKeyRotation(password);
                        ui(new Runnable() {
                            @Override
                            public void run() {
                                rotationPlan = plan;
                                showRotationKey();
                            }
                        });
                    }
                }, null, new ErrorHandler() {
                    @Override
                    public void accept(VaultCryptoException e) {
                        toast(messageFor(e));
                    }
                });
            }
        });
        b.setNegativeButton("Cancel", null);
        showDialog(b.create());
    }

    private void showRotationKey() {
        final Context c = container.getContext();
        final VaultSyncEngine.RotationPlan plan = rotationPlan;
        LinearLayout p = page(c);
        p.addView(text(c, "Your NEW recovery key", 22, true));
        p.addView(text(c, "Write this down on paper and replace the old one. It is shown only now. Then type it below to prove you have it; nothing changes before that.", 15, false));
        TextView key = text(c, plan.recoveryKey().format(), 18, true);
        key.setTypeface(Typeface.MONOSPACE);
        key.setTextIsSelectable(false);
        p.addView(key);
        final EditText typed = field(c, "New recovery key", false);
        final TextView err = text(c, "", 14, false);
        err.setTextColor(Theme.getColor(Theme.key_text_RedRegular));
        p.addView(typed);
        p.addView(err);
        p.addView(button(c, "Rotate keys", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                final String t = typed.getText().toString();
                err.setText("Working\u2026 do not close the Vault.");
                backgroundOn(rt.linkIo(), new Job() {
                    @Override
                    public void run() throws Exception {
                        rt.engine().finishKeyRotation(plan, t);
                    }
                }, new Runnable() {
                    @Override
                    public void run() {
                        rotationPlan = null;
                        toast("Keys rotated. Your data is being uploaded under the new key.");
                        syncNow(true);
                        showList();
                    }
                }, new ErrorHandler() {
                    @Override
                    public void accept(VaultCryptoException e) {
                        err.setText(messageFor(e));
                        if (e.getReason() != VaultCryptoException.Reason.WRONG_RECOVERY_KEY
                                && e.getReason() != VaultCryptoException.Reason.INVALID_ARGUMENT) {
                            // anything else ended the attempt; nothing was switched, a new attempt starts from scratch
                            plan.cancel();
                            rotationPlan = null;
                        }
                    }
                });
            }
        }));
        p.addView(button(c, "Cancel", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                plan.cancel();
                rotationPlan = null;
                showList();
            }
        }));
        show(p);
    }

    /**
     * This device's keys were replaced by a rotation on another device. The recovery key (the new one) and a
     * new password for this phone restore it; the local copy is wiped first and downloaded again.
     */
    private void showAdoptForm() {
        final Context c = container.getContext();
        LinearLayout p = page(c);
        p.addView(text(c, "Restore after a key rotation", 22, true));
        p.addView(text(c, "The keys of this Vault were rotated on another device. Enter the NEW recovery key and choose a password for this phone (6+ characters). This phone's local copy is replaced by a fresh download; anything saved here that had not synced is lost.", 15, false));
        final EditText key = field(c, "New recovery key", false);
        final EditText pw = field(c, "New password", true);
        final EditText pw2 = field(c, "Repeat password", true);
        final TextView err = text(c, "", 14, false);
        err.setTextColor(Theme.getColor(Theme.key_text_RedRegular));
        p.addView(key);
        p.addView(pw);
        p.addView(pw2);
        p.addView(err);
        p.addView(button(c, "Restore", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                final String k = key.getText().toString();
                final char[] a1 = chars(pw);
                final char[] a2 = chars(pw2);
                err.setText("Working\u2026");
                backgroundOn(rt.linkIo(), new Job() {
                    @Override
                    public void run() throws Exception {
                        byte[] latest = RemoteBundle.fetchLatest(rt.remote());
                        if (latest == null) {
                            throw new VaultCryptoException(VaultCryptoException.Reason.INVALID_STATE, "No key bundle on the server");
                        }
                        rt.engine().adoptNewKeyEpoch(latest, k, a1, a2);
                    }
                }, new Runnable() {
                    @Override
                    public void run() {
                        rt.unlocked();
                        SyncCoordinator sc = rt.coordinator();
                        if (sc != null) {
                            sc.clearBlockingState();
                        }
                        syncNow(true);
                        showList();
                    }
                }, new ErrorHandler() {
                    @Override
                    public void accept(VaultCryptoException e) {
                        err.setText(messageFor(e));
                    }
                });
            }
        }));
        p.addView(button(c, "Back", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showList();
            }
        }));
        show(p);
    }

    // ------------------------------------------------------------------ settings

    private void showSettings() {
        final Context c = getParentActivity();
        LinearLayout p = page(c);
        final android.widget.CheckBox bg = new android.widget.CheckBox(c);
        bg.setText("Lock when I leave the app");
        bg.setChecked(rt.autoLock.isLockOnBackground());
        p.addView(bg);
        p.addView(text(c, "Also lock after inactivity (seconds, 10 to 86400):", 14, false));
        final EditText secs = field(c, "300", false);
        secs.setInputType(InputType.TYPE_CLASS_NUMBER);
        secs.setText(String.valueOf(rt.autoLock.getInactivityMillis() / 1000));
        p.addView(secs);
        final android.widget.CheckBox wipe = new android.widget.CheckBox(c);
        wipe.setText("Delete this device's Vault data after 5 wrong passwords");
        p.addView(wipe);
        p.addView(text(c, "Only this phone is affected: your data on Telegram's server and on your other devices stays. You can restore with your recovery key.", 12, false));
        background(new Job() {
            @Override
            public void run() throws Exception {
                final boolean on = rt.access.isWipeEnabled();
                ui(new Runnable() {
                    @Override
                    public void run() {
                        wipe.setChecked(on);
                    }
                });
            }
        }, null, new ErrorHandler() {
            @Override
            public void accept(VaultCryptoException e) {
            }
        });
        p.addView(button(c, "Link a new device\u2026", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startApproving();
            }
        }));
        p.addView(button(c, "Rotate keys\u2026", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startRotation();
            }
        }));
        AlertDialog.Builder b = new AlertDialog.Builder(c);
        b.setTitle("Vault settings");
        b.setView(p);
        b.setPositiveButton("Save", new AlertDialog.OnButtonClickListener() {
            @Override
            public void onClick(AlertDialog d, int which) {
                rt.autoLock.setLockOnBackground(bg.isChecked());
                try {
                    rt.autoLock.setInactivityMillis(Long.parseLong(secs.getText().toString().trim()) * 1000L);
                } catch (RuntimeException e) {
                    toast("Inactivity time not changed: use 10 to 86400 seconds.");
                }
                rt.saveAutoLockSettings();
                final boolean w = wipe.isChecked();
                background(new Job() {
                    @Override
                    public void run() throws Exception {
                        rt.access.setWipeEnabled(w);
                    }
                }, null, new ErrorHandler() {
                    @Override
                    public void accept(VaultCryptoException e) {
                        toast(messageFor(e));
                    }
                });
            }
        });
        b.setNegativeButton("Cancel", null);
        showDialog(b.create());
    }
}
