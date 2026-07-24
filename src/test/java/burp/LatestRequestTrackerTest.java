package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LatestRequestTrackerTest {
    @Test
    void onlyMostRecentlySentRequestCanUpdateARule() {
        LatestRequestTracker tracker = new LatestRequestTracker();
        long first = tracker.register("alice.token");
        long second = tracker.register("alice.token");

        assertFalse(tracker.isLatest("alice.token", first));
        assertTrue(tracker.isLatest("alice.token", second));
    }

    @Test
    void sequencesAreIndependentAcrossRules() {
        LatestRequestTracker tracker = new LatestRequestTracker();
        long alice = tracker.register("alice.token");
        long bob = tracker.register("bob.token");

        assertTrue(tracker.isLatest("alice.token", alice));
        assertTrue(tracker.isLatest("bob.token", bob));
    }
}
