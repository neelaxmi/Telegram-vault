# Build instructions

## 0. What has and has not been done
The authoring environment has no Android SDK, so the build is done by **GitHub Actions** (`.github/workflows/android-build.yml`):
it runs the 420 JVM tests and builds `:TMessagesProj_App:assembleAfatDebug` (default ABI arm64-v8a; the manual run accepts other ABIs).
On 2026-11-12 run 43193839495 compiled the whole app including the Vault and produced a 67.5 MB debug APK (artifact `telegram-vault-debug-apk`,
path in the job `TMessagesProj_App/build/intermediates/apk/afat/debug/app.apk`). The APK was never installed or run.
Optional repository secrets `TELEGRAM_API_ID` / `TELEGRAM_API_HASH` replace the values in `BuildVars.java` at build time (masked in logs). The pure-Java parts compile and pass 420 tests (section 4).

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
5. If it fails to compile after your own changes, the Android-only files are the place to look:
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
