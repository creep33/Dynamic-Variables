package burp;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class VariableExtractionRuleTest {
    @Test
    void v3RoundTripPreservesAutomationAndExplicitMatching() {
        VariableExtractionRule rule = new VariableExtractionRule();
        rule.setEnabled(true);
        rule.setAutomaticRefreshEnabled(true);
        rule.setAllowNonIdempotentReplay(true);
        rule.setSource("request_headers");
        rule.setRegex("Authorization: Bearer (.+)");
        rule.setSavedRequestBase64("cmVxdWVzdA==");
        rule.setSavedHost("example.test");
        rule.setSavedPort(443);
        rule.setSavedSecure(true);
        rule.configureExplicitMatch(
                "POST", "example.test", 443, true, "/login",
                VariableExtractionRule.PatternMode.LITERAL, "tenant=alice",
                VariableExtractionRule.PatternMode.REGEX,
                VariableExtractionRule.DiscriminatorSource.REQUEST_BODY,
                "\"username\":\"alice\"");

        VariableExtractionRule decoded = VariableExtractionRule.deserialize(rule.serialize());

        assertTrue(decoded.isEnabled());
        assertTrue(decoded.isAutomaticRefreshEnabled());
        assertTrue(decoded.isAllowNonIdempotentReplay());
        assertEquals(VariableExtractionRule.MatchStrategy.EXPLICIT, decoded.getMatchStrategy());
        assertEquals("POST", decoded.getMatchMethod());
        assertEquals("/login", decoded.getMatchPath());
        assertEquals("tenant=alice", decoded.getMatchQuery());
        assertEquals(VariableExtractionRule.DiscriminatorSource.REQUEST_BODY,
                decoded.getDiscriminatorSource());
        assertEquals(VariableExtractionRule.ExtractionSource.REQUEST_HEADERS,
                decoded.getExtractionSource());
    }

    @Test
    void legacyRuleWithSavedRequestMigratesToExactAndLeavesRecoveryDisabled() {
        String legacy = "%2Flogin|body|true|token%3D%28.%2B%29|cmVxdWVzdA==|example.test|443|true";

        VariableExtractionRule decoded = VariableExtractionRule.deserialize(legacy);

        assertTrue(decoded.isEnabled());
        assertFalse(decoded.isAutomaticRefreshEnabled());
        assertFalse(decoded.isAllowNonIdempotentReplay());
        assertEquals(VariableExtractionRule.MatchStrategy.LEGACY_EXACT, decoded.getMatchStrategy());
    }

    @Test
    void newRulesDisableEveryAutomationByDefault() {
        VariableExtractionRule rule = new VariableExtractionRule();

        assertFalse(rule.isEnabled());
        assertFalse(rule.isAutomaticRefreshEnabled());
        assertFalse(rule.isAllowNonIdempotentReplay());
    }

    @Test
    void v5RoundTripPreservesNamedTargetsAndFinalValueTemplate() {
        VariableExtractionRule rule = new VariableExtractionRule();
        rule.setTargets(List.of(
                new VariableExtractionRule.ExtractionTarget(
                        "valor1",
                        VariableExtractionRule.ExtractionSource.RESPONSE_HEADERS,
                        "Set-Cookie: (_interaction=[^;]+)"),
                new VariableExtractionRule.ExtractionTarget(
                        "valor2",
                        VariableExtractionRule.ExtractionSource.RESPONSE_HEADERS,
                        "Set-Cookie: (_session\\.legacy=[^;]+)")
        ));
        rule.setValueTemplate("Cookie: {{valor1}}; {{valor2}}");

        VariableExtractionRule decoded = VariableExtractionRule.deserialize(rule.serialize());

        assertEquals(rule.getTargets(), decoded.getTargets());
        assertEquals("Cookie: {{valor1}}; {{valor2}}", decoded.getValueTemplate());
    }

    @Test
    void v6RoundTripPreservesTheExpirySignal() {
        VariableExtractionRule rule = new VariableExtractionRule();
        rule.setExpirySignal(new VariableExtractionRule.ExpirySignal(
                Set.of(301, 302), "(?m)^Location:\\s*/login",
                VariableExtractionRule.PatternMode.REGEX, "logged out",
                VariableExtractionRule.PatternMode.LITERAL, true));

        VariableExtractionRule decoded = VariableExtractionRule.deserialize(rule.serialize());

        VariableExtractionRule.ExpirySignal signal = decoded.getExpirySignal();
        assertNotNull(signal);
        assertEquals(Set.of(301, 302), signal.statusCodes());
        assertEquals("(?m)^Location:\\s*/login", signal.headerRegex());
        assertEquals(VariableExtractionRule.PatternMode.REGEX, signal.headerMode());
        assertEquals("logged out", signal.bodyRegex());
        assertEquals(VariableExtractionRule.PatternMode.LITERAL, signal.bodyMode());
        assertTrue(signal.negate());
    }

    @Test
    void aRuleWithoutSignalStaysWithoutSignalAcrossARoundTrip() {
        VariableExtractionRule rule = new VariableExtractionRule();
        rule.setEnabled(true);

        assertNull(VariableExtractionRule.deserialize(rule.serialize()).getExpirySignal());
    }

    @Test
    void v5RulesMigrateWithoutASignalSoTheyKeepUsingTheGlobalStatusCodes() {
        // Pinned on purpose: generating it from serialize() would hide a field reordering.
        String v5 = "v5||body|true|token%3D%28.*%29|R0VU|example.test|443|true|true|false"
                + "|EXPLICIT|POST|example.test|443|true|%2Flogin|LITERAL||LITERAL"
                + "|REQUEST_BODY|alice|%3B+|value1%3Abody%3Atoken%253D%2528.*%2529"
                + "|%7B%7Bvalue1%7D%7D";

        VariableExtractionRule decoded = VariableExtractionRule.deserialize(v5);

        assertNull(decoded.getExpirySignal());
        assertEquals(VariableExtractionRule.MatchStrategy.EXPLICIT, decoded.getMatchStrategy());
        assertEquals("POST", decoded.getMatchMethod());
        assertEquals("/login", decoded.getMatchPath());
        assertEquals(VariableExtractionRule.DiscriminatorSource.REQUEST_BODY,
                decoded.getDiscriminatorSource());
        assertEquals("alice", decoded.getDiscriminatorRegex());
        assertEquals("{{value1}}", decoded.getValueTemplate());
        assertEquals(1, decoded.getTargets().size());
        assertEquals("value1", decoded.getTargets().get(0).name());
        assertEquals("token=(.*)", decoded.getTargets().get(0).regex());
        assertTrue(decoded.isAutomaticRefreshEnabled());
        assertFalse(decoded.isAllowNonIdempotentReplay());
    }

    @Test
    void corruptedStatusCodesAreSkippedInsteadOfDiscardingTheSignal() {
        assertEquals(Set.of(302), VariableExtractionRule.parseStatusCodes("abc, 302"));
        assertEquals(Set.of(), VariableExtractionRule.parseStatusCodes(""));
        assertEquals(Set.of(), VariableExtractionRule.parseStatusCodes(null));
    }

    @Test
    void aSignalWithoutAnyFilterIsNormalisedToNoSignal() {
        VariableExtractionRule rule = new VariableExtractionRule();

        rule.setExpirySignal(new VariableExtractionRule.ExpirySignal(
                Set.of(), "", VariableExtractionRule.PatternMode.REGEX, "",
                VariableExtractionRule.PatternMode.REGEX, true));

        assertNull(rule.getExpirySignal());
    }

    @Test
    void removingTargetsKeepsTheLegacyPrimaryAccessorsInSync() {
        VariableExtractionRule rule = new VariableExtractionRule();
        rule.setTargets(List.of(
                new VariableExtractionRule.ExtractionTarget(
                        VariableExtractionRule.ExtractionSource.RESPONSE_BODY, "(first)"),
                new VariableExtractionRule.ExtractionTarget(
                        VariableExtractionRule.ExtractionSource.RESPONSE_HEADERS, "(second)")
        ));

        rule.removeTarget(0);

        assertEquals("headers", rule.getSource());
        assertEquals("(second)", rule.getRegex());
        assertThrows(IllegalStateException.class, () -> rule.removeTarget(0));
    }
}
