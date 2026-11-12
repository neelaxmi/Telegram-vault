# Implementation

Everything lives in `TMessagesProj/src/main/java/org/telegram/messenger/vault/` unless noted. "JVM-tested" means a
unit test runs the code on a plain JVM; "type-checked" means it was compiled against the real Telegram classes but
never run.

## Layers (bottom to top)
| Layer | Classes | Verification |
|---|---|---|
| Crypto primitives | `VaultCrypto` (PBKDF2, HKDF, AES-GCM, wipe), `VaultMediaCipher` (chunked streaming AES-GCM), `RecoveryKey`, `VaultBundle` | JVM-tested, known-answer vectors |
| Keys | `VaultKeyManager` (setup, unlock, migration, restore, link install, rotation), `DeviceKeyWrapper` + `AndroidKeystoreDeviceKeyWrapper`, `VaultHeaderStore`/`FileVaultHeaderStore` | JVM-tested with a software wrapper; `AndroidKeystoreSecretStore` (the real Keystore) type-checked only |
| Local storage | `VaultItem`, `VaultStore` (records, media, thumbnails, search, delete, orphan cleanup, rotation staging), `VaultFiles` | JVM-tested |
| Access control | `AttemptTracker`, `VaultAccess` (unlock, wipe), `AutoLock` | JVM-tested |
| Sync | `VaultRemoteStore` (interface), `SyncJournal`, `VaultSyncEngine`, `SyncCoordinator`, `RemoteBundle` | JVM-tested against `FakeRemoteStore` with fault injection |
| Channel | `ChannelApi`, `ChannelRemoteStore` | JVM-tested against `FakeChannelApi` |
| Telegram glue | `TelegramChannelApi`, `TelegramVaultChannel`, `VaultRuntime` | type-checked only |
| Linking | `DeviceLink` (protocol), `LinkTransport` (over the channel) | JVM-tested |
| UI logic | `SetupFlow`, `VaultListModel` | JVM-tested |
| Screens | `ui/VaultFragment`, `ui/VaultSender` | type-checked only |

## Key hierarchy (v2)
VMK (32 random bytes, per account) is the root. The password goes through PBKDF2-HMAC-SHA256 (600,000 iterations,
per-device random salt) into a KEK that wraps the VMK; that is wrapped again by the Android Keystore. Subkeys by HKDF:
`messages`, `media`, `bundle-auth`, `journal`, `dedup`, `object-names`. The recovery key (256 bits) seals the VMK in
the **key bundle**, which is the only way a new device gets the VMK without another device.

Existing test Vaults (decision 8) are migrated in place: the old data key becomes the VMK, so no record is re-encrypted.

## Local layout (`<app files>/vault/<account>/`)
`header.bin` (device-wrapped key header), `attempts.bin` (device-wrapped attempt state), `sync.journal` (encrypted sync
state), `data/items/<id>.vrec`, `data/media/<id>.vmed`, `data/rotation/` (only during a key rotation).
File names are random ids. Lock settings are in the app's private preferences `vault_settings_<account>` (no secrets).

## Sync
Each object is one channel message with caption `tgv1 <name>`: `r.<id>` record, `m.<mediaId>` media, `t.<thumbId>`
thumbnail, `x.<id>` tombstone, `b.<n>` key bundle (n = version). A sync is **pull → reconcile → push**.
Upload order per item: thumbnail, media, then the record last, so a record on the server always has its media.
The encrypted journal stores the history cursor, object references and per-item state, which makes every step
resumable. A deterministic token (HMAC of the object name under the `dedup` subkey) becomes Telegram's `random_id`, so
a retry after a lost acknowledgement does not create a duplicate. Backoff 5 s doubling to 15 min, honouring FLOOD_WAIT.
Objects that do not authenticate are ignored/counted, never imported. Records from a newer format are kept untouched.

## Telegram integration
- Channel: private broadcast channel "Protected Vault storage", created once (never before the chat list has loaded; restore never creates one), silent sends, muted.
- `TelegramChannelApi`: upload via `FileUploadOperation`, `messages.sendMedia`, `messages.getHistory` (`add_offset = -limit`), `upload.getFile` in 512 KB parts, `channels.deleteMessages`.
- Menu: `DialogsActivity` adds "Protected Vault 🔐" after Saved Messages.
- Send to Vault: `ChatActivity` adds `OPTION_SEND_TO_VAULT`; `VaultSender` decides (noforwards and type checks), copies text/caption/sender/forward info/source ids and the already-downloaded media stream, and starts a sync.

## Device linking
New phone commits `H(pubN‖nonceN)` first; existing phone answers `pubA‖nonceA`; new phone reveals; existing phone checks
the commitment (mismatch cancels for good). Both derive a 6-digit code from the transcript hash; the user confirms on the
existing phone, which then sends the VMK and bundle encrypted under the ECDH session key. The new phone sets its own
password. Transport objects `l./o./v./g.<session>`; the existing phone must start listening **before** the new phone
starts, because it skips channel history; stale or foreign sessions are ignored; everything is deleted afterwards.

## Key rotation
1. `beginKeyRotation(password)`: syncs, refuses if another device already rotated, if newer-format items exist, if anything is damaged, downloads missing media, verifies the password, creates the new VMK and recovery key. Writes nothing.
2. The user writes the new recovery key down and types it back.
3. `finishKeyRotation`: syncs again, re-encrypts everything into `data/rotation/` (media streamed, each staged file authenticated on read-back), writes a journal for the new key in which every item is "pending upload" and every old server reference is "retired", writes a marker, writes the new header (point of no return), swaps the directories and the journal in.
4. Next sync: uploads the new bundle first, then all items; **only when everything is on the server** are the retired objects (old bundle included) deleted.
5. Crash handling (`VaultSyncEngine.recoverRotation`, run right after unlock): no marker → discard staging; marker but header still old → discard staging; marker and header new → finish the swap.
6. Another device sees the newer bundle, shows "restore with the new recovery key", verifies key and password before deleting anything, wipes its local copy and downloads again.

## Decisions implemented (from the 2026-11-08 directive)
1 private channel storage · 2 no remote password slot · 3 mandatory recovery key with confirmation · 4 wipe affects this device only · 5 PBKDF2 kept (benchmark tool provided, phone numbers not measured) · 6 oversized media refused with a clear error · 7 minimum password 12 · 8 test Vaults migrated in place · 9 key rotation implemented.
