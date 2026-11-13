# Protected Vault for Telegram Android

A password-protected, end-to-end encrypted "Saved Messages"-like space added to the official Telegram Android
source (DrKLO/Telegram 13.1.1, base commit `3de37c8`).

> **Status, stated plainly.** The cryptography, storage, sync, device-linking, key-rotation and access-control
> logic is plain Java and is covered by 447 automated JVM tests, all passing. **The full Android app now compiles:
> GitHub Actions built a debug APK (`.github/workflows/android-build.yml`, arm64-v8a only). It has never been installed or run, and
> nothing has been tested against real Telegram servers.** The Android screens and the Telegram glue are therefore compiled but unexercised. Treat everything on the Android side
> as unverified until the manual checks in [TESTING.md](TESTING.md) have been done on a device.

## What it does
- **Menu entry** "Protected Vault 🔐" directly below Saved Messages (`DialogsActivity`).
- **"🔐 Send to Vault"** in a message's long-press menu (`ChatActivity`, `VaultSender`). It copies; the original is never
  changed. Messages from chats or senders with content protection (noforwards) are refused, as are polls, dice, live
  locations, secret media, service messages and calls. Media must already be downloaded; files above Telegram's size limit are refused
  with a clear message.
- **Vault screen** like Saved Messages: write notes, add files and photos, search, multi-select and delete, open
  photos, export files.
- **Password** (6+ characters, typed twice) and a **mandatory 12-word recovery phrase** (BIP-39, 128 bits; legacy 256-bit keys of older vaults still work; was 54 characters + 2 check
  characters) that must be typed back before the Vault exists.
- **Failed attempts** are counted (saved *before* the password is checked) and shown after the next successful unlock.
  An optional switch deletes **this device's** Vault data after 5 wrong passwords; it never touches the server or other devices.
- **Auto-lock**: when you leave the app, after an inactivity time (10 s to 24 h) and manually. Uses a monotonic clock.
- **Sync across your devices** through a private Telegram channel "Protected Vault storage" in your own account.
  Everything stored there is encrypted; Telegram sees only opaque blobs, their sizes and times.
- **Link a new phone** with a 6-digit code compared on both screens; **restore** with the recovery key;
  **rotate keys** (new master key and recovery key, data re-encrypted, old server copies deleted).

## Documents
| File | Contents |
|---|---|
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | Architecture, formats, protocols, every touched Telegram file |
| [BUILD_INSTRUCTIONS.md](BUILD_INSTRUCTIONS.md) | Building the app, applying the patch, running the JVM tests |
| [SECURITY.md](SECURITY.md) | Threat model, guarantees, and what is NOT protected |
| [TESTING.md](TESTING.md) | Automated test inventory, mutation checks, manual device test plan, screenshot and demo-video instructions |
| `../../PROJECT_STATUS.md` copy in the submission folder | Phase-by-phase history with the actual results |

## Repository map
- `TMessagesProj/src/main/java/org/telegram/messenger/vault/`: the Vault (pure Java except `AndroidKeystoreSecretStore`, `Telegram*`, `VaultRuntime`).
- `TMessagesProj/src/main/java/org/telegram/ui/VaultFragment.java`, `VaultSender.java`: screens and Send-to-Vault.
- `TMessagesProj/src/test/java/org/telegram/messenger/vault/`: JUnit tests.
- `TMessagesProj/src/main/res/xml/vault_*.xml`: backup exclusion rules.
- `docs/protected-vault/`: these documents and `tools/`.

## Not implemented (decided, not forgotten)
- In-app video/audio playback (files can be exported and opened elsewhere).
- A separate "device list / revoke" screen. Revoking a lost device is done with **Rotate keys**; a list of devices would
  only be informational because every device uses the same Telegram account.
- Localization: strings are English literals in the Vault screens.
- Seeking in encrypted media (decryption is sequential).
