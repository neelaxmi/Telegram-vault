package org.telegram.messenger.vault;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;

/**
 * Regression tests for the crash "NullPointerException: SetupFlow.confirm() on a null object reference"
 * (VaultFragment$10.onClick, 13 Nov 2026): the screen dropped its flow when the app went to the background
 * but kept the confirm screen, so the next tap ran on null.
 */
public class SetupSessionTest {

    private static final String PW = "six666";
    private long now;
    private InMemoryHeaderStore headers;
    private VaultKeyManager keys;
    private SetupSession session;

    private final SetupSession.Clock clock = new SetupSession.Clock() {
        @Override
        public long nowMillis() {
            return now;
        }
    };

    @Before
    public void setUp() {
        now = 1_000;
        headers = new InMemoryHeaderStore();
        keys = new VaultKeyManager(headers, new TestDeviceKeyWrapper(), 1000);
        session = new SetupSession(keys, clock, 60_000);
    }

    private SetupFlow toConfirmStep() throws Exception {
        SetupFlow f = session.start(false);
        f.submitPassword(PW.toCharArray(), PW.toCharArray());
        f.keyWrittenDown();
        assertEquals(SetupFlow.Step.CONFIRM_KEY, f.step());
        return f;
    }

    private static void assertInvalidState(Callable c) {
        try {
            c.call();
            fail("expected INVALID_STATE");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_STATE, e.getReason());
        } catch (Exception e) {
            fail("unexpected " + e);
        }
    }

    private interface Callable {
        void call() throws Exception;
    }

    // ------------------------------------------------------------ the exact crash scenario

    @Test
    public void crashScenario_pauseThenConfirm_withinGrace_succeeds() throws Exception {
        SetupFlow f = session.start(false);
        f.submitPassword(PW.toCharArray(), PW.toCharArray());
        String phrase = f.recoveryKeyText();
        f.keyWrittenDown();
        // user switches away for 23 seconds, as in the log
        session.onPause();
        now += 23_000;
        assertEquals(SetupSession.Resume.CONTINUE, session.onResume());
        assertEquals(SetupFlow.Step.CONFIRM_KEY, session.flow().step());
        byte[] bundle = session.flow().confirm(phrase);
        assertNotNull(bundle);
        assertTrue(keys.isUnlocked());
        assertTrue(headers.exists());
    }

    @Test
    public void crashScenario_pauseLongerThanGrace_confirmThrowsInvalidState_notNpe() throws Exception {
        toConfirmStep();
        session.onPause();
        now += 61_000;
        assertEquals(SetupSession.Resume.EXPIRED, session.onResume());
        assertFalse(session.isActive());
        assertInvalidState(new Callable() {
            @Override
            public void call() throws Exception {
                session.flow().confirm("anything");
            }
        });
        assertFalse("nothing written for an abandoned setup", headers.exists());
        assertFalse(keys.isUnlocked());
    }

    @Test
    public void expiryTimer_wipesWhileStillAway_andResumeReportsExpired() throws Exception {
        SetupFlow f = toConfirmStep();
        session.onPause();
        now += 30_000;
        assertFalse(session.expireIfPaused());
        assertTrue(session.isActive());
        now += 31_000;
        assertTrue(session.expireIfPaused());
        assertEquals("the old flow was cancelled and wiped", SetupFlow.Step.CANCELLED, f.step());
        assertEquals(SetupSession.Resume.EXPIRED, session.onResume());
        assertEquals("reported once", SetupSession.Resume.NONE, session.onResume());
    }

    @Test
    public void everyStep_afterCancel_throwsInvalidState_neverNull() throws Exception {
        session.start(false);
        session.cancel();
        assertInvalidState(new Callable() {
            @Override
            public void call() throws Exception {
                session.flow();
            }
        });
        // the old flow object itself also refuses, with the same reason
        final SetupFlow old = session.start(false);
        old.submitPassword(PW.toCharArray(), PW.toCharArray());
        session.cancel();
        assertInvalidState(new Callable() {
            @Override
            public void call() throws Exception {
                old.recoveryKeyText();
            }
        });
        assertInvalidState(new Callable() {
            @Override
            public void call() throws Exception {
                old.keyWrittenDown();
            }
        });
        assertInvalidState(new Callable() {
            @Override
            public void call() throws Exception {
                old.backToKey();
            }
        });
        assertInvalidState(new Callable() {
            @Override
            public void call() throws Exception {
                old.confirm("x");
            }
        });
    }

    @Test
    public void flowBeforeStart_throwsInvalidState() {
        assertFalse(session.isActive());
        assertInvalidState(new Callable() {
            @Override
            public void call() throws Exception {
                session.flow();
            }
        });
    }

    // ------------------------------------------------------------ lifecycle details

    @Test
    public void resumeWithoutSetup_isNone() {
        session.onPause();
        assertEquals(SetupSession.Resume.NONE, session.onResume());
    }

    @Test
    public void repeatedPauseResume_keepsTheSameFlowAndPhrase() throws Exception {
        SetupFlow f = session.start(false);
        f.submitPassword(PW.toCharArray(), PW.toCharArray());
        String phrase = f.recoveryKeyText();
        for (int i = 0; i < 5; i++) {
            session.onPause();
            now += 10_000;
            assertEquals(SetupSession.Resume.CONTINUE, session.onResume());
            assertEquals(phrase, session.flow().recoveryKeyText());
        }
    }

    @Test
    public void gracePeriod_countsFromTheFirstPause_notFromEachPause() throws Exception {
        toConfirmStep();
        session.onPause();
        now += 40_000;
        session.onPause(); // a second pause callback must not extend the grace time
        now += 30_000;
        assertEquals(SetupSession.Resume.EXPIRED, session.onResume());
    }

    @Test
    public void startingAgain_cancelsTheOldFlow_andGivesANewPhrase() throws Exception {
        SetupFlow first = session.start(false);
        first.submitPassword(PW.toCharArray(), PW.toCharArray());
        String phrase1 = first.recoveryKeyText();
        SetupFlow second = session.start(false);
        assertEquals(SetupFlow.Step.CANCELLED, first.step());
        second.submitPassword(PW.toCharArray(), PW.toCharArray());
        assertNotEquals(phrase1, second.recoveryKeyText());
    }

    @Test
    public void afterSuccessfulConfirm_sessionIsNotActive_andFlowRefuses() throws Exception {
        SetupFlow f = session.start(false);
        f.submitPassword(PW.toCharArray(), PW.toCharArray());
        String phrase = f.recoveryKeyText();
        f.keyWrittenDown();
        session.flow().confirm(phrase);
        assertFalse(session.isActive());
        assertInvalidState(new Callable() {
            @Override
            public void call() throws Exception {
                session.flow();
            }
        });
        // a second tap on a stale button cannot create a second vault or crash
        assertInvalidState(new Callable() {
            @Override
            public void call() throws Exception {
                f.confirm(phrase);
            }
        });
    }

    @Test
    public void migrationFlag_isKept() {
        session.start(true);
        assertTrue(session.isMigration());
        session.start(false);
        assertFalse(session.isMigration());
    }

    // ------------------------------------------------------------ complete flow with the 12-word phrase

    @Test
    public void completeFlow_phrase_wrongThenRightThenUnlockWithPassword() throws Exception {
        SetupFlow f = session.start(false);
        try {
            f.submitPassword("12345".toCharArray(), "12345".toCharArray());
            fail("5 characters must be rejected");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_ARGUMENT, e.getReason());
        }
        try {
            f.submitPassword(PW.toCharArray(), "different".toCharArray());
            fail("mismatch must be rejected");
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.INVALID_ARGUMENT, e.getReason());
        }
        f.submitPassword(PW.toCharArray(), PW.toCharArray()); // exactly 6 characters accepted
        String phrase = f.recoveryKeyText();
        assertEquals(12, phrase.split(" ").length);
        assertFalse("nothing is stored before confirmation", headers.exists());
        f.keyWrittenDown();
        try {
            f.confirm(RecoveryKey.generate().format());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.WRONG_RECOVERY_KEY, e.getReason());
        }
        assertEquals(SetupFlow.Step.CONFIRM_KEY, f.step());
        assertFalse(headers.exists());
        byte[] bundle = f.confirm(phrase.toUpperCase());
        assertTrue(headers.exists());
        keys.lock();
        keys.unlock(PW.toCharArray());
        assertTrue(keys.isUnlocked());

        // another phone: restore with the typed phrase and a new password
        VaultKeyManager other = new VaultKeyManager(new InMemoryHeaderStore(), new TestDeviceKeyWrapper(), 1000);
        other.restoreFromBundle(bundle, phrase, "another1".toCharArray(), "another1".toCharArray(), false);
        assertTrue(other.isUnlocked());
    }

    @Test
    public void confirmAcceptsTheLegacyFormatNever_forNewSetups() throws Exception {
        // a new setup shows words; typing a (valid but different) legacy-format key must not complete it
        SetupFlow f = session.start(false);
        f.submitPassword(PW.toCharArray(), PW.toCharArray());
        f.keyWrittenDown();
        try {
            f.confirm(RecoveryKey.generateLegacy().format());
            fail();
        } catch (VaultCryptoException e) {
            assertEquals(VaultCryptoException.Reason.WRONG_RECOVERY_KEY, e.getReason());
        }
        assertFalse(headers.exists());
    }
}
