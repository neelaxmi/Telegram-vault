#!/bin/bash
# Compiles the pure-Java part of the Protected Vault and runs its JUnit tests on a plain JVM (Java 8 or newer).
# No Android SDK is needed. Excluded because they need Android/Telegram classes: AndroidKeystoreSecretStore,
# Telegram*.java, VaultRuntime.java (and everything under ui/).
#
# Usage:  JUNIT_DIR=/path/with/jars docs/protected-vault/tools/run-vault-tests.sh
# JUNIT_DIR must contain junit-4.13.2.jar and hamcrest-core-1.3.jar (both from Maven Central).
set -e
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SRC="$ROOT/TMessagesProj/src"
JUNIT_DIR="${JUNIT_DIR:?set JUNIT_DIR to the folder holding junit-4.13.2.jar and hamcrest-core-1.3.jar}"
OUT="${OUT:-$(mktemp -d)}"
mkdir -p "$OUT/main" "$OUT/test"
find "$SRC/main/java/org/telegram/messenger/vault" -name '*.java' ! -name AndroidKeystoreSecretStore.java ! -name 'Telegram*.java' ! -name VaultRuntime.java > "$OUT/main.txt"
find "$SRC/test/java/org/telegram/messenger/vault" -name '*.java' > "$OUT/test.txt"
javac -Xlint:all -d "$OUT/main" @"$OUT/main.txt"
CP="$OUT/main:$JUNIT_DIR/junit-4.13.2.jar:$JUNIT_DIR/hamcrest-core-1.3.jar"
javac -d "$OUT/test" -cp "$CP" @"$OUT/test.txt"
CLASSES=$(cd "$SRC/test/java" && grep -l "@Test" $(sed "s#$SRC/test/java/##" "$OUT/test.txt") | sed 's#/#.#g;s#\.java$##' | tr '\n' ' ')
java -cp "$OUT/test:$CP" org.junit.runner.JUnitCore $CLASSES
