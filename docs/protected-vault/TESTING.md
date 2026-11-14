# Testing

## 1. Automated tests: 475 passing (plain JVM, Java 21, JUnit 4.13.2)
Run with `docs/protected-vault/tools/run-vault-tests.sh` (see BUILD_INSTRUCTIONS.md). Last result: `OK (475 tests)`, repeated runs stable.

| Test class | Tests | Covers |
|---|---|---|
| `VaultKeyManagerV2Test` | 46 | v2 header, migration, restore, bundle checks, rollback detection |
| `VaultStoreTest` | 45 | records, media, tamper at every byte, no plaintext on disk, delete, orphans |
| `VaultKeyManagerTest` | 44 | create/unlock/lock/destroy, wrong password, restart |
| `KeyRotationTest` | 32 | rotation, crash at 4 stages, re-upload faults, other device adoption, stale objects |
| `VaultSyncEngineTest` | 31 | pull/push, tombstones, faults, tampering, lost acknowledgements, media cache |
| `AndroidKeystoreDeviceKeyWrapperTest` | 27 | wrapper logic against a software stand-in |
| `VaultCryptoTest` | 26 | RFC 7914 / 5869 / NIST vectors, GCM |
| `DeviceLinkTest` | 23 | commit/reveal, code, expiry, MITM and replay attempts |
| `VaultMediaCipherTest` | 20 | chunk format, truncation, reorder, known answers (also checked against an independent Python implementation) |
| `UiLogicTest` | 19 | setup flow, list model |
| `VaultAccessTest` | 16 | attempts saved first, damaged state, wipe, wipe switch |
| `VaultBundleTest` | 15 | bundle format and authentication |
| `RecoveryKeyTest` / `ChannelRemoteStoreTest` | 14 / 14 | key format and checks; channel adapter |
| `VaultItemTest` | 13 | record encoding, padding |
| `AutoLockTest` | 11 | background, inactivity, clock going backwards |
| `LinkTransportTest` | 9 | transport, foreign sessions, forged grant |
| `FileVaultHeaderStoreTest` / `VaultMigrationTest` / `RestoreFlowTest` | 6 / 5 / 4 | atomic file store; migration; restore |

### Mutation checks (deliberately injected bugs)
Earlier phases: all injected bugs caught (9 + 14 in phases 1-2, and the sync/link/access phases each had their own set).
Rotation: 23 mutants of the rotation code; 22 caught. The survivor ("media reader failure ignored") is equivalent: later size and read-back checks
reject the same failure. Method: change one line, run the suite, expect a failure, restore, re-verify the source is byte-identical.

### What the automated tests do NOT show
Anything involving the Android SDK, the real Keystore, real Telegram servers, real phones, the screens, or Gradle.
`AndroidKeystoreSecretStore`, `Telegram*`, `VaultRuntime`, `VaultFragment`, `VaultSender` and the `ChatActivity`/`DialogsActivity` edits
compile in the full app (CI run 43193839495) but were never executed.

## 2. Manual test plan (to be run on devices; none of it has been run)
Use at least one API 23-25 device or emulator and one recent device, and a throw-away Telegram account.

**Setup and access**
1. Menu shows "Protected Vault 🔐" directly below Saved Messages.
2. Create a Vault: password < 6 chars refused; mismatched confirmation refused; recovery key shown; wrong typed key refused; correct key creates the Vault.
3. Kill the app, reopen, unlock. Wrong password shows an error; after a successful unlock the failed-attempt count is shown once.
4. Enable "delete after 5 wrong passwords"; five wrong passwords wipe this phone only; the server and other devices keep data; restore with the recovery key works.
5. Auto-lock: leave the app (locks), wait for the inactivity time, manual lock. Restart the app: the chosen settings are still there.
6. Recents screen and screenshots show blank/black for the Vault. Settings with "lock when I leave" off: Recents still blank.
7. Uninstall/reinstall or clear data: the old Vault is reported as unreadable (device key gone), not a crash; restore from recovery key works. Add a fingerprint / change the lock screen: the Vault still opens.

**Content**
8. Add a note, a photo and a document; search; multi-select and delete; open the photo; export a file.
9. A 1.9 GB file works or is refused with the size message; a file above Telegram's limit is refused clearly; kill the app mid-upload and resume.
10. Long-press a normal chat message: "Send to Vault" appears and saves a copy; the original is unchanged.
11. In a chat with "restrict saving content": "Send to Vault" is not offered; polls, calls and service messages: not offered. Media not downloaded: asks to download first.

**Sync and devices**
12. A second phone: link with the 6-digit code (start "Link a new device" on the first phone first); codes differing means cancel. Items appear on both; deleting on one removes from the other.
13. Airplane mode: items queue; reconnect: they upload; no duplicates in the channel.
14. Restore on a fresh phone with only the recovery key.
15. Rotate keys with two devices: the second shows "restore with the new recovery key"; old recovery key is refused; all data present after restore. Kill the app during rotation at several moments, reopen, unlock: either old or new state, never lost data.
16. The storage channel exists once, is muted, and shows no notifications.
17. Backup: `adb backup` / device transfer do not contain `files/vault`.

## 3. Screenshots to capture (not possible in the authoring environment)
Menu entry; setup password; recovery key; confirm key; empty Vault; Vault with text/photo/file; search; selection; Send to Vault in the long-press menu;
refusal in a protected chat; unlock with failed-attempt report; settings; link-device code (both phones); rotate keys screens; Recents showing a blank Vault.

## 4. Demo video script (about 4 minutes)
1. Chat list: point to the menu entry below Saved Messages. 2. Create the Vault, show and confirm the recovery key. 3. Add a note and a photo. 4. Long-press a chat message: Send to Vault; show the protected-chat refusal. 5. Lock via leaving the app; Recents is blank; unlock. 6. Link a second phone: show the matching codes. 7. Delete an item on one phone and show it vanish on the other. 8. Rotate keys; show the second phone asking for the new key. 9. Five wrong passwords with the wipe switch on (this phone only). Record with the phone's screen recorder; FLAG_SECURE blocks recording of the Vault screens on some devices, so for the demo temporarily build with the flag disabled.

## Setup lifecycle fix (13 Nov 2026)
Device log showed `NullPointerException ... SetupFlow.confirm()` at `VaultFragment$10.onClick`: `onPause()` cancelled the flow and set the field to null, but the recovery/confirm screens stayed on display, so the next tap ran on null. Fix: `SetupSession` owns the flow (never null: INVALID_STATE instead), keeps it for a 5-minute grace period while the app is away, the UI hides the phrase while paused and redraws the current step on return, and an expired setup restarts with a NEW phrase (nothing is written before confirmation). Regression tests: `SetupSessionTest` (13), `RecoveryPhraseTest` (14). **Not verified on a device** until the new APK is tried: pause the app on the confirm screen, return, confirm.
