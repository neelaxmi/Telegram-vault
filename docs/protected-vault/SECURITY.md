# Security notes

Status: designed and unit-tested on a JVM; **not reviewed by an independent cryptographer, the full app compiles in CI but has not been run on a device,
not tested against Telegram's servers.** Do not rely on it for anything that matters before that has happened.

## What it is meant to protect against
1. **Someone who gets the unlocked-app-less phone or its files** (lost phone, file copy, forensic image of app data):
   all Vault data is ciphertext; the master key is wrapped by a key from the password (PBKDF2) **and** by a
   hardware-backed Android Keystore key, so a copy of the files alone is useless and brute-forcing the password
   offline is impossible without the phone's Keystore.
2. **Someone with access to the storage channel or Telegram's servers**: they hold ciphertext only, authenticated so
   that tampering, swapping, truncation and replays of old key bundles are rejected.
3. **Casual snooping**: Recents thumbnail and screenshots (FLAG_SECURE), keyboard learning, notifications, backups.

## Not protected against
- Malware or a debugger running while the Vault is unlocked, a rooted/compromised OS, or a keylogger: the keys are in memory while unlocked.
- Someone who knows the password **and** has the unlocked phone. The password is the only per-use secret.
- **Anyone holding the recovery key plus access to your Telegram account's storage channel** can open the Vault. Keep it on paper only.
- What Telegram and anyone with channel access can still see: that a Vault channel exists, how many objects, their approximate sizes
  and upload times (record sizes are padded to 256-byte buckets; media sizes are not padded).
- Metadata on the phone: number of items, file times, rough media sizes.
- Rotation cannot take back what a lost device has already decrypted or downloaded. It protects data saved afterwards and
  deletes the old server copies.
- Deleted data is overwritten with zeros before unlinking, but flash storage and journaling file systems may keep old blocks.
- Export and "open file" necessarily create plaintext copies outside the Vault.
- Java strings cannot be wiped; a copy of the password or text may stay in memory until garbage collection.
- A forgotten password **and** a lost recovery key means the data is gone. If the Keystore key is lost (reset, new secure hardware) the local copy is gone and only the recovery key restores it.

## Cryptographic design
- **Master key (VMK)**: 32 random bytes per account. HKDF-SHA256 derives separate subkeys: `messages`, `media`, `bundle-auth`, `journal`, `dedup`, `object-names`.
- **Password**: NFKC-normalised, 6+ characters (the user asked for 6; a short password is weaker against guessing, mitigated by the Keystore-wrapped header, PBKDF2 600k and the five-failure wipe; no password-derived slot exists on the server). PBKDF2-HMAC-SHA256, 600,000 iterations (own implementation for API 23), random 16-byte salt per device. Result = KEK.
- **Per-device header ("TGVH" v2)**: VMK wrapped under the KEK, then wrapped again by the non-exportable Android Keystore key. No password hash exists; a wrong password is a failed AES-GCM unwrap.
- **Records and media**: AES-256-GCM. Records are padded and bound to their id; media uses 64 KiB chunks with a per-file key, chunk counter + final flag in the nonce (reordering, truncation and extension are detected) and the media id as associated data.
- **Key bundle ("TGVB")**: VMK sealed under a key derived from the 256-bit recovery key, HMAC-authenticated, versioned. A device that sees an older bundle than it has treats it as a rollback and stops.
- **Recovery phrase**: 12 BIP-39 words = 128 random bits (4-bit checksum), expanded with HKDF-SHA256 to the 256-bit slot key; must be typed back at creation. Legacy 256-bit Crockford keys (54 chars) are still accepted for existing vaults.
- **Device linking**: ECDH (P-256) with commit-then-reveal so neither side can pick its key after seeing the other's; both screens show a 6-digit code derived from the whole transcript; the user must confirm they match. Session lasts 5 minutes; a mismatch cancels it for good. The grant (VMK + bundle) is encrypted under the session key.
- **Sync objects** are one Telegram channel message each, caption `tgv1 <name>`; data is only ever accepted if it authenticates under the VMK. Server content is never trusted; foreign messages are ignored.
- **Access control**: the attempt counter is stored (device-wrapped) *before* the password is verified so killing the app cannot reset it; a damaged counter becomes a cautious state (limit minus one). The wipe switch can be changed only while unlocked, is off by default, and deletes only local data. Auto-lock uses `elapsedRealtime`; a clock that goes backwards locks.
- **Key rotation** (decision 9): new VMK and recovery key (typed back to confirm), all local data re-encrypted into a staging directory and verified, atomic switch with a crash-recovery marker, new bundle uploaded first, all items re-uploaded under the new key, old objects (including the old bundle) deleted last. Other devices must be restored with the new recovery key; their unsynced items are lost.

## Known weaknesses and open risks
1. Never audited. The PBKDF2 and HKDF code is custom (to support API 23) and checked against RFC vectors and an independent Python implementation, but not reviewed externally.
2. A stale device that has not noticed a rotation can still push objects encrypted under the old key; they are ignored and counted, never imported, but they stay on the server.
3. Behaviour against real Telegram (dedupe by `random_id`, history paging, upload resume, FLOOD_WAIT, channel discovery on a fresh install) is assumed, not tested.
4. PBKDF2 is not memory-hard; a determined attacker who has both the files **and** can use the phone's Keystore for guesses is limited only by the iteration count and the optional 5-attempt wipe.
5. Media sizes on the server are visible; the 2000 MB upload limit is enforced locally.
6. Rotation downloads every item first and needs time and network proportional to the Vault size; interrupting is safe (rolled back or completed on next unlock) but unverified on real hardware.
7. The Recents/screenshot protection, backup exclusion and Keystore behaviour depend on Android behaviour that was not exercised.

## Saving while locked: the sealed inbox (14 Nov 2026)
"Send to Vault" works with the Vault locked and needs neither the password nor the master key (VMK) in memory.
- The Vault has an EC P-256 inbox key pair. The **public** key is stored wrapped by the Android Keystore device key (readable while locked; a file-only attacker cannot substitute their own). The **private** key is stored encrypted under an HKDF subkey of the VMK (`inbox-private`), so it exists in clear only while unlocked.
- A message saved while locked is sealed with ECIES: ephemeral ECDH P-256, HKDF-SHA256 (salt = ephemeral and recipient keys), AES-256-GCM, AAD = magic, version, ephemeral key and the envelope id. Media is encrypted in 64 KiB AEAD chunks with a random content key kept inside the envelope. No plaintext text, file name, MIME type or media is written.
- At the next unlock the envelopes are opened, added to the normal encrypted store (and synced), and overwritten/deleted only after the store accepted them. Media is decrypted through a pipe straight into the store: no plaintext copy touches the disk.
- Limits: (1) the key pair is created at the first unlock after creating or upgrading a vault, so a vault that has never been unlocked since this change cannot take messages while locked (the user is told); (2) pending envelopes reveal their size and time; (3) after a key rotation adopted from another device the private key is re-created, and envelopes sealed to the old key cannot be opened (they are kept as `.bad`, never deleted); (4) the five-failure wipe deletes the inbox too.
- Not changed: PBKDF2 600k, header, recovery phrase, bundle, rotation.

## Vault storage channel
The cloud copy of the Vault is a private Telegram channel holding only encrypted blobs; local storage is the encrypted VaultStore. The channel cannot be opened as an ordinary chat inside this app any more (ChatActivity redirects to the Vault screen); it still exists on the server and is visible, muted, in the chat list and on other Telegram clients as a channel of opaque files.

## Media in the Vault chat (format version 2)

* Every item keeps its real type (photo, video, document) plus kind flags (voice, music, round video, animation), formatting entities and a preview image. Media bytes and previews are encrypted (chunked AES-GCM under keys derived from the vault key) before they are stored; nothing is converted to text.
* Locked: nothing is decrypted and no preview is drawn; the wall shows a decoy, not real content. Items saved while locked go through the sealed write-only inbox, which now also carries flags, formatting and the preview.
* Unlocked: previews are decrypted into a small in-memory cache that is cleared on lock. Photos open from memory only. Video, audio and "open document" need a file on disk for Android's players and other apps: the decrypted copy is written to a private folder (`files/vault-open/`, one random sub-folder per copy), overwritten with zeros and deleted when the viewer closes, when the Vault locks, when the screen is destroyed and at the next start. While such a copy exists it is readable by the app and, for "Open", by the app you chose. This is a deliberate, documented limit; Export is the other explicit way out.
* The photo and video viewers are FLAG_SECURE windows, like the Vault screen.
* Not preserved: custom emoji; old app versions show version-2 items as "needs update".
