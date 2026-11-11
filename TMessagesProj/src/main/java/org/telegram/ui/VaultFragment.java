package org.telegram.ui;

import android.app.Activity;
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
import org.telegram.messenger.UserConfig;
import org.telegram.messenger.vault.RecoveryKey;
import org.telegram.messenger.vault.RemoteBundle;
import org.telegram.messenger.vault.SetupFlow;
import org.telegram.messenger.vault.SyncCoordinator;
import org.telegram.messenger.vault.VaultAccess;
import org.telegram.messenger.vault.VaultCryptoException;
import org.telegram.messenger.vault.VaultItem;
import org.telegram.messenger.vault.VaultListModel;
import org.telegram.messenger.vault.VaultRuntime;
import org.telegram.messenger.vault.VaultStore;
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
    private static final long MAX_INLINE_PHOTO_BYTES = 20L * 1024 * 1024;

    private VaultRuntime rt;
    private FrameLayout container;
    private SetupFlow flow;
    private byte[] restoreBundle;
    private boolean restoreMode;
    private VaultListModel model;
    private ListAdapter adapter;
    private TextView statusView;
    private TextView selectionView;
    private Button deleteButton;
    private EditText searchField;
    private String pendingExportItemId;
    private boolean destroyed;
    /** True while another app (the file picker) is on top: that must not lock the Vault. */
    private boolean launching;

    @Override
    public boolean onFragmentCreate() {
        rt = VaultRuntime.get(UserConfig.selectedAccount);
        rt.setOnLockedUi(new Runnable() {
            @Override
            public void run() {
                if (!destroyed && container != null) {
                    leaveSecrets();
                    decide();
                }
            }
        });
        return super.onFragmentCreate();
    }

    @Override
    public void onFragmentDestroy() {
        destroyed = true;
        if (flow != null) {
            flow.cancel();
        }
        rt.setOnLockedUi(null);
        super.onFragmentDestroy();
    }

    @Override
    public android.view.View createView(Context context) {
        actionBar.setBackButtonImage(org.telegram.messenger.R.drawable.ic_ab_back);
        actionBar.setAllowOverlayTitle(true);
        actionBar.setTitle("Protected Vault");
        actionBar.setActionBarMenuOnItemClick(new org.telegram.ui.ActionBar.ActionBar.ActionBarMenuOnItemClick() {
            @Override
            public void onItemClick(int id) {
                if (id == -1) {
                    finishFragment();
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
        rt.autoLock.onForeground(); // locks first if the time away was too long
        if (container != null && !rt.keys.isUnlocked() && flow == null && !restoreMode && model != null) {
            decide();
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        Activity a = getParentActivity();
        if (a != null) {
            a.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
        if (flow != null) {
            flow.cancel(); // never leave the recovery key on screen while away
            flow = null;
        }
        if (!launching) {
            rt.autoLock.onBackground();
        }
    }

    // ------------------------------------------------------------------ routing

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
        if (flow != null) {
            flow.cancel();
            flow = null;
        }
        restoreBundle = null;
        model = null;
        adapter = null;
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
        rt.io().execute(new Runnable() {
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
        flow = new SetupFlow(rt.keys);
        LinearLayout p = page(c);
        p.addView(text(c, migrate ? "Upgrade your Vault" : "Create your Protected Vault", 22, true));
        p.addView(text(c, migrate
                ? "Your Vault will be upgraded so it can sync between your devices. Your items stay as they are. Choose a new password (at least 12 characters); you will then get a recovery key."
                : "Your Vault is encrypted on this device and stored encrypted in a private channel of your Telegram account, so you can use it on several devices. Choose a password for THIS device (at least 12 characters). Next you will get a recovery key; it is the only way back in if you lose this phone.", 15, false));
        final EditText oldPw = migrate ? field(c, "Current Vault password", true) : null;
        if (oldPw != null) {
            p.addView(oldPw);
        }
        final EditText pw = field(c, "Password (12+ characters)", true);
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
                        flow.submitMigration(chars(oldPw), chars(pw), chars(pw2));
                    } else {
                        flow.submitPassword(chars(pw), chars(pw2));
                    }
                    showRecoveryKey(migrate);
                } catch (VaultCryptoException e) {
                    err.setText(messageFor(e));
                }
            }
        }));
        if (!migrate) {
            p.addView(button(c, "I already have a Vault: restore with recovery key", new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    startRestore();
                }
            }));
        }
        show(p);
    }

    private static char[] chars(EditText e) {
        return e.getText().toString().toCharArray();
    }

    private void showRecoveryKey(final boolean migrate) {
        final Context c = container.getContext();
        LinearLayout p = page(c);
        p.addView(text(c, "Your recovery key", 22, true));
        p.addView(text(c, "Write this down on paper and keep it somewhere safe. It is shown only now. Without it, a lost phone means a lost Vault. Anyone with this key and access to your Telegram account's Vault channel could open your Vault, so do not photograph it or save it in a chat.", 15, false));
        try {
            TextView key = text(c, flow.recoveryKeyText(), 18, true);
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
                    flow.keyWrittenDown();
                    showConfirmKey(migrate);
                } catch (VaultCryptoException e) {
                    decide();
                }
            }
        }));
        show(p);
    }

    private void showConfirmKey(final boolean migrate) {
        final Context c = container.getContext();
        LinearLayout p = page(c);
        p.addView(text(c, "Confirm your recovery key", 22, true));
        p.addView(text(c, "Type the recovery key from your paper to prove you have it. The Vault is created only after this matches.", 15, false));
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
                    final byte[] bundle = flow.confirm(typed);
                    flow = null;
                    rt.unlocked();
                    uploadFirstBundle();
                    showList();
                } catch (VaultCryptoException e) {
                    err.setText(messageFor(e));
                }
            }
        }));
        p.addView(button(c, "Back", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    flow.backToKey();
                    showRecoveryKey(migrate);
                } catch (VaultCryptoException e) {
                    decide();
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
        p.addView(text(c, "Enter your recovery key and choose a password for this device (12+ characters).", 15, false));
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

    private void showUnlock(String message) {
        final Context c = container.getContext();
        LinearLayout p = page(c);
        p.addView(text(c, "Protected Vault", 22, true));
        final EditText pw = field(c, "Password", true);
        final TextView err = text(c, message == null ? "" : message, 14, false);
        err.setTextColor(Theme.getColor(Theme.key_text_RedRegular));
        final TextView remaining = text(c, "", 13, false);
        p.addView(pw);
        p.addView(err);
        p.addView(remaining);
        p.addView(button(c, "Unlock", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                final char[] password = chars(pw);
                pw.setText("");
                background(new Job() {
                    @Override
                    public void run() throws Exception {
                        final VaultAccess.Report r = rt.access.unlock(password);
                        ui(new Runnable() {
                            @Override
                            public void run() {
                                rt.unlocked();
                                decide();
                                showAttemptReport(r);
                            }
                        });
                    }
                }, null, new ErrorHandler() {
                    @Override
                    public void accept(VaultCryptoException e) {
                        err.setText(messageFor(e));
                        if (e.getReason() == VaultCryptoException.Reason.VAULT_WIPED) {
                            decide();
                            return;
                        }
                        refreshRemaining(remaining);
                    }
                });
            }
        }));
        p.addView(button(c, "Restore with recovery key", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startRestore();
            }
        }));
        show(p);
        refreshRemaining(remaining);
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

    // ------------------------------------------------------------------ the Vault

    private void showList() {
        final Context c = container.getContext();
        container.removeAllViews();
        model = new VaultListModel(rt.store);
        adapter = new ListAdapter(c);

        LinearLayout root = new LinearLayout(c);
        root.setOrientation(LinearLayout.VERTICAL);

        LinearLayout bar = new LinearLayout(c);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setPadding(AndroidUtilities.dp(12), AndroidUtilities.dp(4), AndroidUtilities.dp(12), AndroidUtilities.dp(4));
        statusView = text(c, "", 13, false);
        bar.addView(statusView, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        bar.addView(button(c, "Sync", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                syncNow(true);
            }
        }));
        bar.addView(button(c, "Settings", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showSettings();
            }
        }));
        bar.addView(button(c, "Lock", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                rt.lockNow();
            }
        }));
        root.addView(bar);

        searchField = field(c, "Search", false);
        searchField.addTextChangedListener(new android.text.TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int a, int b, int d) {
            }

            @Override
            public void onTextChanged(CharSequence s, int a, int b, int d) {
                reload(s.toString());
            }

            @Override
            public void afterTextChanged(android.text.Editable s) {
            }
        });
        root.addView(searchField);

        LinearLayout selBar = new LinearLayout(c);
        selBar.setOrientation(LinearLayout.HORIZONTAL);
        selectionView = text(c, "", 14, true);
        selBar.addView(selectionView, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
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

        ListView list = new ListView(c);
        list.setAdapter(adapter);
        list.setOnItemClickListener(new android.widget.AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(android.widget.AdapterView<?> parent, View view, int position, long id) {
                VaultListModel.Row row = model.rows().get(position);
                if (model.isSelecting()) {
                    model.toggle(row.id);
                    renderSelection();
                } else {
                    openItem(row);
                }
            }
        });
        list.setOnItemLongClickListener(new android.widget.AdapterView.OnItemLongClickListener() {
            @Override
            public boolean onItemLongClick(android.widget.AdapterView<?> parent, View view, int position, long id) {
                model.toggle(model.rows().get(position).id);
                renderSelection();
                return true;
            }
        });
        root.addView(list, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        LinearLayout composer = new LinearLayout(c);
        composer.setOrientation(LinearLayout.HORIZONTAL);
        final EditText note = field(c, "Write a note to your Vault", false);
        composer.addView(note, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        composer.addView(button(c, "Add", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                final String t = note.getText().toString().trim();
                if (t.isEmpty()) {
                    return;
                }
                note.setText("");
                background(new Job() {
                    @Override
                    public void run() throws Exception {
                        rt.engine().addItem(new VaultItem.Draft(VaultItem.Type.TEXT).text(t), null, null);
                    }
                }, new Runnable() {
                    @Override
                    public void run() {
                        reload(searchField.getText().toString());
                        syncNow(false);
                    }
                }, new ErrorHandler() {
                    @Override
                    public void accept(VaultCryptoException e) {
                        toast(messageFor(e));
                    }
                });
            }
        }));
        root.addView(composer);

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
                                    reload(searchField == null ? "" : searchField.getText().toString());
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
                statusView.setText("Offline: " + messageFor(e));
            }
        });
        reload("");
    }

    private void reload(final String query) {
        if (model == null) {
            return;
        }
        final VaultListModel m = model;
        background(new Job() {
            @Override
            public void run() throws Exception {
                m.setQuery(query);
            }
        }, new Runnable() {
            @Override
            public void run() {
                if (adapter != null) {
                    adapter.notifyDataSetChanged();
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

    private void renderStatus(SyncCoordinator.Status s) {
        if (statusView == null) {
            return;
        }
        String t;
        switch (s.state) {
            case SYNCING:
                t = "Syncing…";
                break;
            case WAITING_RETRY:
                t = "Sync paused, will retry (" + s.pendingItems + " waiting)";
                break;
            case NEEDS_RESTORE:
                t = "This Vault was changed from another device. Restore with your recovery key.";
                break;
            case SECURITY_ERROR:
                t = "Sync stopped: the server data failed a security check (" + s.error + ").";
                break;
            case LOCKED:
                t = "Locked";
                break;
            default:
                t = s.pendingItems > 0 ? s.pendingItems + " waiting to sync" : "Synced";
        }
        statusView.setText(t);
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
                        reload(searchField.getText().toString());
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

    private void openItem(final VaultListModel.Row row) {
        background(new Job() {
            @Override
            public void run() throws Exception {
                final VaultItem item = rt.store.get(row.id);
                if (item == null) {
                    return;
                }
                if (item.mediaId == null) {
                    final String text = item.text == null ? "" : item.text;
                    ui(new Runnable() {
                        @Override
                        public void run() {
                            AlertDialog.Builder b = new AlertDialog.Builder(getParentActivity());
                            b.setMessage(text);
                            b.setPositiveButton("Close", null);
                            showDialog(b.create());
                        }
                    });
                } else if (item.type == VaultItem.Type.PHOTO && item.mediaSize <= MAX_INLINE_PHOTO_BYTES) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    rt.engine().openMedia(item.id, out); // decrypted in memory only, never written to disk
                    final byte[] bytes = out.toByteArray();
                    ui(new Runnable() {
                        @Override
                        public void run() {
                            showPhoto(bytes, item);
                        }
                    });
                } else {
                    ui(new Runnable() {
                        @Override
                        public void run() {
                            offerExport(item);
                        }
                    });
                }
            }
        }, null, new ErrorHandler() {
            @Override
            public void accept(VaultCryptoException e) {
                toast(messageFor(e));
            }
        });
    }

    private void showPhoto(byte[] bytes, VaultItem item) {
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
        if (bmp == null) {
            offerExport(item);
            return;
        }
        ImageView iv = new ImageView(getParentActivity());
        iv.setImageBitmap(bmp);
        iv.setAdjustViewBounds(true);
        AlertDialog.Builder b = new AlertDialog.Builder(getParentActivity());
        b.setView(iv);
        b.setPositiveButton("Close", null);
        b.setNegativeButton("Export…", new AlertDialog.OnButtonClickListener() {
            @Override
            public void onClick(AlertDialog d, int which) {
                offerExport(item);
            }
        });
        showDialog(b.create());
    }

    private void offerExport(final VaultItem item) {
        AlertDialog.Builder b = new AlertDialog.Builder(getParentActivity());
        b.setTitle(item.mediaName == null ? "File" : item.mediaName);
        b.setMessage("This file cannot be shown inside the Vault yet. You can export a decrypted copy to a place you choose. The copy is no longer protected by the Vault.");
        b.setPositiveButton("Export…", new AlertDialog.OnButtonClickListener() {
            @Override
            public void onClick(AlertDialog d, int which) {
                pendingExportItemId = item.id;
                Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                i.addCategory(Intent.CATEGORY_OPENABLE);
                i.setType(item.mimeType == null || item.mimeType.isEmpty() ? "application/octet-stream" : item.mimeType);
                i.putExtra(Intent.EXTRA_TITLE, item.mediaName == null ? "vault-file" : item.mediaName);
                launching = true;
                getParentActivity().startActivityForResult(i, REQUEST_EXPORT);
            }
        });
        b.setNegativeButton("Cancel", null);
        showDialog(b.create());
    }

    @Override
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
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

    // ------------------------------------------------------------------ list adapter

    private final class ListAdapter extends BaseAdapter {
        private final Context context;

        ListAdapter(Context context) {
            this.context = context;
        }

        @Override
        public int getCount() {
            return model == null ? 0 : model.rows().size();
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
        public View getView(int position, View convertView, ViewGroup parent) {
            VaultListModel.Row row = model.rows().get(position);
            LinearLayout l = new LinearLayout(context);
            l.setOrientation(LinearLayout.VERTICAL);
            l.setPadding(AndroidUtilities.dp(16), AndroidUtilities.dp(8), AndroidUtilities.dp(16), AndroidUtilities.dp(8));
            if (row.selected) {
                l.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
            }
            TextView title = text(context, row.title, 16, false);
            l.addView(title);
            String sub = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date(row.dateMillis));
            if (!row.subtitle.isEmpty()) {
                sub = row.subtitle + " · " + sub;
            }
            TextView subtitle = text(context, sub, 12, false);
            subtitle.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
            l.addView(subtitle);
            return l;
        }
    }
}
