package burp;

import org.junit.jupiter.api.Test;

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
}
