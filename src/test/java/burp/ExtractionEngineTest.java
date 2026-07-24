package burp;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ExtractionEngineTest {
    private static ExtractionEngine.RequestSnapshot request() {
        return new ExtractionEngine.RequestSnapshot(
                "POST", "example.test", 443, true, "/login?tenant=alice",
                List.of("Content-Type: application/json", "X-User: alice"),
                "{\"username\":\"alice\",\"requestToken\":\"rq-123\"}");
    }

    private static ExtractionEngine.ResponseSnapshot response() {
        return new ExtractionEngine.ResponseSnapshot(
                List.of("Set-Cookie: session=cookie-123; Path=/"),
                "{\"accessToken\":\"body-123\"}");
    }

    private static VariableExtractionRule explicitRule() {
        VariableExtractionRule rule = new VariableExtractionRule();
        rule.setEnabled(true);
        rule.configureExplicitMatch(
                "POST", "example.test", 443, true, "/login",
                VariableExtractionRule.PatternMode.LITERAL, "",
                VariableExtractionRule.PatternMode.LITERAL,
                VariableExtractionRule.DiscriminatorSource.NONE, "");
        return rule;
    }

    @Test
    void explicitRouteMatchesServiceMethodAndPathWithoutRequiringQuery() {
        assertNull(ExtractionEngine.matchesExplicitRequest(explicitRule(), request()));
    }

    @Test
    void queryAndRequestDiscriminatorAreIndependentFilters() {
        VariableExtractionRule rule = explicitRule();
        rule.configureExplicitMatch(
                "POST", "example.test", 443, true, "/login",
                VariableExtractionRule.PatternMode.LITERAL, "tenant=(alice|bob)",
                VariableExtractionRule.PatternMode.REGEX,
                VariableExtractionRule.DiscriminatorSource.REQUEST_BODY,
                "\"username\":\"alice\"");

        assertNull(ExtractionEngine.matchesExplicitRequest(rule, request()));

        rule.configureExplicitMatch(
                "POST", "example.test", 443, true, "/login",
                VariableExtractionRule.PatternMode.LITERAL, "tenant=bob",
                VariableExtractionRule.PatternMode.LITERAL,
                VariableExtractionRule.DiscriminatorSource.REQUEST_BODY,
                "\"username\":\"alice\"");
        assertEquals(ExtractionOutcome.QUERY_MISMATCH,
                ExtractionEngine.matchesExplicitRequest(rule, request()));
    }

    @Test
    void extractsFromAllFourSources() {
        VariableExtractionRule rule = explicitRule();

        rule.setSource("body");
        rule.setRegex("\"accessToken\":\"([^\"]+)\"");
        assertEquals("body-123", ExtractionEngine.extract(rule, request(), response()).value());

        rule.setSource("headers");
        rule.setRegex("session=([^;]+)");
        assertEquals("cookie-123", ExtractionEngine.extract(rule, request(), response()).value());

        rule.setSource("request_body");
        rule.setRegex("\"requestToken\":\"([^\"]+)\"");
        assertEquals("rq-123", ExtractionEngine.extract(rule, request(), response()).value());

        rule.setSource("request_headers");
        rule.setRegex("X-User: ([^\\r\\n]+)");
        assertEquals("alice", ExtractionEngine.extract(rule, request(), response()).value());
    }

    @Test
    void reportsInvalidMissingGroupAndNoMatchWithoutUpdating() {
        VariableExtractionRule rule = explicitRule();
        rule.setRegex("[");
        assertEquals(ExtractionOutcome.INVALID_REGEX,
                ExtractionEngine.extract(rule, request(), response()).outcome());

        rule.setRegex("accessToken");
        assertEquals(ExtractionOutcome.MISSING_CAPTURE_GROUP,
                ExtractionEngine.extract(rule, request(), response()).outcome());

        rule.setRegex("\"missing\":\"([^\"]+)\"");
        assertEquals(ExtractionOutcome.REGEX_NO_MATCH,
                ExtractionEngine.extract(rule, request(), response()).outcome());
    }
}
