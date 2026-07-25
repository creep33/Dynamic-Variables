package burp;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class AutomationPolicyTest {
    @Test
    void onlyGetHeadAndOptionsReplayWithoutAdditionalPermission() {
        VariableExtractionRule rule = new VariableExtractionRule();

        assertTrue(AutomationPolicy.isReplayAuthorized("GET", List.of(rule)));
        assertTrue(AutomationPolicy.isReplayAuthorized("HEAD", List.of(rule)));
        assertTrue(AutomationPolicy.isReplayAuthorized("OPTIONS", List.of(rule)));
        assertFalse(AutomationPolicy.isReplayAuthorized("POST", List.of(rule)));
        assertFalse(AutomationPolicy.isReplayAuthorized("PUT", List.of(rule)));
        assertFalse(AutomationPolicy.isReplayAuthorized("PATCH", List.of(rule)));
        assertFalse(AutomationPolicy.isReplayAuthorized("DELETE", List.of(rule)));
    }

    @Test
    void unsafeReplayRequiresPermissionOnEveryRefreshedVariable() {
        VariableExtractionRule alice = new VariableExtractionRule();
        VariableExtractionRule token = new VariableExtractionRule();
        alice.setAllowNonIdempotentReplay(true);
        token.setAllowNonIdempotentReplay(true);
        assertTrue(AutomationPolicy.isReplayAuthorized("POST", List.of(alice, token)));

        token.setAllowNonIdempotentReplay(false);
        assertFalse(AutomationPolicy.isReplayAuthorized("POST", List.of(alice, token)));
    }

    @Test
    void multipleRulesAreAllowedOnlyInsideOneContext() {
        assertTrue(AutomationPolicy.isSingleContext(List.of("alice", "alice")));
        assertFalse(AutomationPolicy.isSingleContext(List.of("alice", "bob")));
    }

    @Test
    void recoveryRequiresEveryGlobalAndRequestGate() {
        assertTrue(AutomationPolicy.canAttemptRecovery(true, true, true, true, true));
        assertFalse(AutomationPolicy.canAttemptRecovery(false, true, true, true, true));
        assertFalse(AutomationPolicy.canAttemptRecovery(true, false, true, true, true));
        assertFalse(AutomationPolicy.canAttemptRecovery(true, true, false, true, true));
        assertFalse(AutomationPolicy.canAttemptRecovery(true, true, true, false, true));
        assertFalse(AutomationPolicy.canAttemptRecovery(true, true, true, true, false));
    }

    @Test
    void unambiguousAuthCodesAreEnoughOnTheirOwn() {
        assertTrue(AutomationPolicy.isExpirySignalUsable(signal(Set.of(401), "", "")));
        assertTrue(AutomationPolicy.isExpirySignalUsable(signal(Set.of(401, 403), "", "")));
    }

    @Test
    void ambiguousCodesNeedAContentFilterBeforeTheyCanTriggerAReplay() {
        assertFalse(AutomationPolicy.isExpirySignalUsable(signal(Set.of(302), "", "")));
        assertFalse(AutomationPolicy.isExpirySignalUsable(signal(Set.of(401, 302), "", "")));
        assertTrue(AutomationPolicy.isExpirySignalUsable(
                signal(Set.of(302), "(?m)^Location:\\s*/login", "")));
        assertTrue(AutomationPolicy.isExpirySignalUsable(signal(Set.of(), "", "invalid_token")));
    }

    @Test
    void aSignalWithoutAnyFilterDecidesNothing() {
        assertFalse(AutomationPolicy.isExpirySignalUsable(signal(Set.of(), "", "")));
        assertFalse(AutomationPolicy.isExpirySignalUsable(null));
    }

    private static VariableExtractionRule.ExpirySignal signal(Set<Integer> codes, String headerRegex,
                                                              String bodyRegex) {
        return new VariableExtractionRule.ExpirySignal(codes, headerRegex,
                VariableExtractionRule.PatternMode.REGEX, bodyRegex,
                VariableExtractionRule.PatternMode.REGEX, false);
    }

    @Test
    void refreshCandidateRequiresExplicitVariablePermissionAndSavedRequest() {
        VariableExtractionRule rule = new VariableExtractionRule();
        rule.setSavedRequestBase64("cmVxdWVzdA==");
        assertFalse(AutomationPolicy.isRefreshCandidate(rule));

        rule.setAutomaticRefreshEnabled(true);
        assertTrue(AutomationPolicy.isRefreshCandidate(rule));

        rule.setSavedRequestBase64("");
        assertFalse(AutomationPolicy.isRefreshCandidate(rule));
    }
}
