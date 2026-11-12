# Build instructions

## 0. What has and has not been done
The Android build was **not** run for this work (the authoring environment has no Android SDK/NDK and no access to
Maven Central). The steps below follow Telegram's own instructions; whether the full app compiles with the Vault is
**unverified**. The pure-Java parts compile and pass 420 tests (section 4).

## 1. Get the source
Either clone the branch that contains the work:
```
git clone https://github.com/neelaxmi/Telegram-vault.git
cd Telegram-vault
git checkout protected-vault-phase1
```
or apply the patch to a clean checkout of upstream commit `3de37c8`:
```
git clone https://github.com/DrKLO/Telegram.git
cd Telegram && git checkout 3de37c8
git apply --check protected-vault-cumulative.patch   # verify first
git apply protected-vault-cumulative.patch
```

## 2. Build the app (as for any Telegram fork)
1. Android Studio (current stable), Android SDK platform 36, build-tools, NDK as required by `TMessagesProj/jni`
   (Telegram's `README.md` lists the exact versions; follow it).
2. Get your own `api_id` / `api_hash` from https://my.telegram.org and put them in
   `TMessagesProj/src/main/java/org/telegram/messenger/BuildVars.java` (`APP_ID`, `APP_HASH`). The official keys must not be reused by a fork.
3. Create a signing config and your own Firebase `google-services.json` if you need push (the Vault itself does not).
4. `./gradlew :TMessagesProj_App:assembleAfatDebug` (or open the project and run the `afat` / `debug` variant).
5. If it fails to compile, the likeliest places are the Android-only files:
   `AndroidKeystoreSecretStore.java`, `VaultRuntime.java`, `Telegram*.java`, `ui/VaultFragment.java`, `ui/VaultSender.java`,
   and the two small edits in `ChatActivity.java` / `DialogsActivity.java`. These were type-checked only against Telegram classes, never the full Android SDK.

Minimum Android version: API 23 (unchanged). The Vault code avoids APIs newer than API 23 (verified with `javac --release 8` and a source scan).

## 3. Files outside the Vault package that were changed
| File | Change |
|---|---|
| `TMessagesProj/build.gradle` | `testImplementation 'junit:junit:4.13.2'` |
| `TMessagesProj/src/main/AndroidManifest.xml` | `fullBackupContent` and `dataExtractionRules` attributes (exclude `files/vault`) |
| `TMessagesProj/src/main/res/xml/vault_backup_rules.xml`, `vault_data_extraction_rules.xml` | new |
| `ui/DialogsActivity.java` | menu item below Saved Messages |
| `ui/ChatActivity.java` | "Send to Vault" entry and handler (`OPTION_SEND_TO_VAULT`) |

## 4. Run the automated tests (no Android needed)
Java 8 or newer, plus two jars from Maven Central (`junit-4.13.2.jar`, `hamcrest-core-1.3.jar`) in a folder:
```
JUNIT_DIR=/path/to/jars docs/protected-vault/tools/run-vault-tests.sh
```
Expected last line: `OK (420 tests)`. The run takes well under a minute. Through Gradle the same tests are in
`TMessagesProj/src/test`, but `./gradlew :TMessagesProj:testDebugUnitTest` has **not** been run.

## 5. Measure PBKDF2 on a phone (decision 5)
`docs/protected-vault/tools/Pbkdf2Bench.java` times key stretching at several iteration counts. Run it on the target
phone (for example from a temporary debug entry point) before changing the 600,000 default.
