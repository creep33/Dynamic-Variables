package burp;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ExtractionEngineTest {
    private static ExtractionEngine.RequestSnapshot request() {
        return new ExtractionEngine.RequestSnapshot(
                "POST", "example.test", 443, true, "/login?tenant=alice",
                List.of("Content-Type: application/json", "X-User: alice"),
                "{\"username\":\"alice\",\"requestToken\":\"rq-123\"}");
    }

    private static ExtractionEngine.ResponseSnapshot response() {
        return new ExtractionEngine.ResponseSnapshot(200,
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

    @Test
    void extractsAndConcatenatesMultipleTargets() {
        VariableExtractionRule rule = explicitRule();
        rule.setTargets(List.of(
                new VariableExtractionRule.ExtractionTarget(
                        VariableExtractionRule.ExtractionSource.RESPONSE_HEADERS, "session=([^;]+)"),
                new VariableExtractionRule.ExtractionTarget(
                        VariableExtractionRule.ExtractionSource.RESPONSE_BODY, "\"accessToken\":\"([^\"]+)\"")
        ));
        rule.setJoinDelimiter("; ");

        ExtractionEngine.Evaluation eval = ExtractionEngine.extract(rule, request(), response());
        assertEquals(ExtractionOutcome.UPDATED, eval.outcome());
        assertEquals("cookie-123; body-123", eval.value());
    }

    @Test
    void buildsOneParentValueFromMultipleSetCookieHeadersInOrder() {
        VariableExtractionRule rule = explicitRule();
        rule.setTargets(List.of(
                cookieTarget("_interaction"),
                cookieTarget("_interaction_resume"),
                cookieTarget("_session"),
                cookieTarget("_session\\.legacy")
        ));

        ExtractionEngine.ResponseSnapshot cookieResponse = new ExtractionEngine.ResponseSnapshot(200,
                List.of(
                        "Set-Cookie: _interaction=gyiw7WCiu3Tr5bHsAi5UR; path=/interaction",
                        "Set-Cookie: _interaction_resume=gyiw7WCiu3Tr5bHsAi5UR; path=/auth",
                        "Set-Cookie: _session=dhsmjttC7q4nRxrYMJrD9; path=/",
                        "Set-Cookie: _session.legacy=dhsmjttC7q4nRxrYMJrD9; path=/"
                ), "");

        ExtractionEngine.Evaluation eval = ExtractionEngine.extract(rule, request(), cookieResponse);

        assertEquals(ExtractionOutcome.UPDATED, eval.outcome());
        assertEquals("_interaction=gyiw7WCiu3Tr5bHsAi5UR"
                        + "; _interaction_resume=gyiw7WCiu3Tr5bHsAi5UR"
                        + "; _session=dhsmjttC7q4nRxrYMJrD9"
                        + "; _session.legacy=dhsmjttC7q4nRxrYMJrD9",
                eval.value());
    }

    @Test
    void composesNamedCapturesUsingTheEditableFinalTemplate() {
        VariableExtractionRule rule = explicitRule();
        rule.setTargets(List.of(
                new VariableExtractionRule.ExtractionTarget(
                        "valor1", VariableExtractionRule.ExtractionSource.RESPONSE_HEADERS,
                        "_interaction=([^;]+)"),
                new VariableExtractionRule.ExtractionTarget(
                        "valor2", VariableExtractionRule.ExtractionSource.RESPONSE_HEADERS,
                        "_session=([^;]+)")
        ));
        rule.setValueTemplate("_interaction={{valor1}}; _session={{valor2}}");
        ExtractionEngine.ResponseSnapshot cookieResponse = new ExtractionEngine.ResponseSnapshot(200,
                List.of(
                        "Set-Cookie: _interaction=abc123; path=/interaction",
                        "Set-Cookie: _session=xyz789; path=/"
                ), "");

        ExtractionEngine.Evaluation eval = ExtractionEngine.extract(rule, request(), cookieResponse);

        assertEquals(ExtractionOutcome.UPDATED, eval.outcome());
        assertEquals("_interaction=abc123; _session=xyz789", eval.value());
    }

    @Test
    void rejectsAParentTemplateThatOmitsOrReferencesUnknownValues() {
        VariableExtractionRule rule = explicitRule();
        rule.setTargets(List.of(
                new VariableExtractionRule.ExtractionTarget(
                        "valor1", VariableExtractionRule.ExtractionSource.RESPONSE_HEADERS,
                        "session=([^;]+)"),
                new VariableExtractionRule.ExtractionTarget(
                        "valor2", VariableExtractionRule.ExtractionSource.RESPONSE_BODY,
                        "\"accessToken\":\"([^\"]+)\"")
        ));
        rule.setValueTemplate("{{valor1}}; {{desconocido}}");

        ExtractionEngine.Evaluation eval = ExtractionEngine.extract(rule, request(), response());

        assertEquals(ExtractionOutcome.INVALID_TEMPLATE, eval.outcome());
        assertNull(eval.value());
    }

    @Test
    void doesNotPartiallyUpdateTheParentWhenOneZoneDoesNotMatch() {
        VariableExtractionRule rule = explicitRule();
        rule.setTargets(List.of(
                cookieTarget("_interaction"),
                cookieTarget("_missing")
        ));
        ExtractionEngine.ResponseSnapshot cookieResponse = new ExtractionEngine.ResponseSnapshot(200,
                List.of("Set-Cookie: _interaction=value; path=/"), "");

        ExtractionEngine.Evaluation eval = ExtractionEngine.extract(rule, request(), cookieResponse);

        assertEquals(ExtractionOutcome.REGEX_NO_MATCH, eval.outcome());
        assertNull(eval.value());
    }

    @Test
    void loginRedirectIsRecognisedAsAnExpiredSession() {
        assertNull(ExtractionEngine.matchesExpirySignal(
                headerSignal(Set.of(301, 302), "(?m)^Location:\\s*/login"),
                redirectResponse(302, "/login")));
    }

    @Test
    void aRedirectToAnotherLocationIsNotAnExpiredSession() {
        assertEquals(ExtractionOutcome.EXPIRY_SIGNAL_MISMATCH,
                ExtractionEngine.matchesExpirySignal(
                        headerSignal(Set.of(301, 302), "(?m)^Location:\\s*/login"),
                        redirectResponse(302, "/dashboard")));
    }

    @Test
    void everyPopulatedFilterMustMatchSoTheStatusCodeStillApplies() {
        assertEquals(ExtractionOutcome.EXPIRY_SIGNAL_MISMATCH,
                ExtractionEngine.matchesExpirySignal(
                        headerSignal(Set.of(301, 302), "(?m)^Location:\\s*/login"),
                        redirectResponse(200, "/login")));
    }

    @Test
    void anEmptyStatusCodeSetFiltersOnContentAlone() {
        VariableExtractionRule.ExpirySignal signal = new VariableExtractionRule.ExpirySignal(
                Set.of(), "", VariableExtractionRule.PatternMode.REGEX,
                "\"error\"\\s*:\\s*\"invalid_token\"", VariableExtractionRule.PatternMode.REGEX, false);

        assertNull(ExtractionEngine.matchesExpirySignal(signal,
                new ExtractionEngine.ResponseSnapshot(200, List.of("Content-Type: application/json"),
                        "{\"error\":\"invalid_token\"}")));
        assertEquals(ExtractionOutcome.EXPIRY_SIGNAL_MISMATCH,
                ExtractionEngine.matchesExpirySignal(signal,
                        new ExtractionEngine.ResponseSnapshot(200, List.of("Content-Type: application/json"),
                                "{\"user\":\"alice\"}")));
    }

    @Test
    void negationInvertsTheVerdictOfTheWholeSignal() {
        VariableExtractionRule.ExpirySignal signal = new VariableExtractionRule.ExpirySignal(
                Set.of(), "", VariableExtractionRule.PatternMode.REGEX,
                "\"username\"", VariableExtractionRule.PatternMode.REGEX, true);

        // The marker disappeared, so the session is considered expired.
        assertNull(ExtractionEngine.matchesExpirySignal(signal,
                new ExtractionEngine.ResponseSnapshot(200, List.of(), "{\"error\":\"nope\"}")));
        assertEquals(ExtractionOutcome.EXPIRY_SIGNAL_MISMATCH,
                ExtractionEngine.matchesExpirySignal(signal,
                        new ExtractionEngine.ResponseSnapshot(200, List.of(), "{\"username\":\"alice\"}")));
    }

    @Test
    void aMalformedPatternIsReportedAsAnErrorEvenWhenNegated() {
        VariableExtractionRule.ExpirySignal signal = new VariableExtractionRule.ExpirySignal(
                Set.of(), "", VariableExtractionRule.PatternMode.REGEX,
                "([unclosed", VariableExtractionRule.PatternMode.REGEX, true);

        assertEquals(ExtractionOutcome.INVALID_REGEX,
                ExtractionEngine.matchesExpirySignal(signal,
                        new ExtractionEngine.ResponseSnapshot(200, List.of(), "body")));
    }

    @Test
    void aMissingSignalOrBodyNeverThrows() {
        assertEquals(ExtractionOutcome.EXPIRY_SIGNAL_MISMATCH,
                ExtractionEngine.matchesExpirySignal(null, response()));
        assertEquals(ExtractionOutcome.EXPIRY_SIGNAL_MISMATCH,
                ExtractionEngine.matchesExpirySignal(
                        new VariableExtractionRule.ExpirySignal(
                                Set.of(), "", VariableExtractionRule.PatternMode.REGEX,
                                "token", VariableExtractionRule.PatternMode.REGEX, false),
                        new ExtractionEngine.ResponseSnapshot(200, List.of(), null)));
    }

    @Test
    void literalHeaderFilterSearchesInsideTheBlockInsteadOfComparingItWhole() {
        VariableExtractionRule.ExpirySignal signal = new VariableExtractionRule.ExpirySignal(
                Set.of(), "Location: /login", VariableExtractionRule.PatternMode.LITERAL,
                "", VariableExtractionRule.PatternMode.REGEX, false);
        // The volatile Date header must not prevent the match.
        ExtractionEngine.ResponseSnapshot response = new ExtractionEngine.ResponseSnapshot(302,
                List.of("Date: Mon, 01 Jan 2026 10:00:00 GMT", "Location: /login",
                        "Content-Length: 0"), "");

        assertNull(ExtractionEngine.matchesExpirySignal(signal, response));
        assertEquals(ExtractionOutcome.EXPIRY_SIGNAL_MISMATCH,
                ExtractionEngine.matchesExpirySignal(signal, redirectResponse(302, "/dashboard")));
    }

    @Test
    void literalBodyFilterSearchesInsideTheBodyInsteadOfComparingItWhole() {
        VariableExtractionRule.ExpirySignal signal = new VariableExtractionRule.ExpirySignal(
                Set.of(), "", VariableExtractionRule.PatternMode.REGEX,
                "Your session has expired", VariableExtractionRule.PatternMode.LITERAL, false);

        assertNull(ExtractionEngine.matchesExpirySignal(signal,
                new ExtractionEngine.ResponseSnapshot(200, List.of(),
                        "<html><body><p>Your session has expired</p></body></html>")));
        assertEquals(ExtractionOutcome.EXPIRY_SIGNAL_MISMATCH,
                ExtractionEngine.matchesExpirySignal(signal,
                        new ExtractionEngine.ResponseSnapshot(200, List.of(),
                                "<html><body><p>Welcome back</p></body></html>")));
    }

    @Test
    void literalFiltersAreCaseSensitiveAndNeedNoEscaping() {
        VariableExtractionRule.ExpirySignal signal = new VariableExtractionRule.ExpirySignal(
                Set.of(), "", VariableExtractionRule.PatternMode.REGEX,
                "{\"error\":\"invalid_token\"}", VariableExtractionRule.PatternMode.LITERAL, false);

        // Regex metacharacters are taken verbatim in LITERAL mode.
        assertNull(ExtractionEngine.matchesExpirySignal(signal,
                new ExtractionEngine.ResponseSnapshot(200, List.of(),
                        "{\"error\":\"invalid_token\"}")));
        assertEquals(ExtractionOutcome.EXPIRY_SIGNAL_MISMATCH,
                ExtractionEngine.matchesExpirySignal(signal,
                        new ExtractionEngine.ResponseSnapshot(200, List.of(),
                                "{\"ERROR\":\"INVALID_TOKEN\"}")));
    }

    @Test
    void aBodyRegexSpansLinesBecauseItIsCompiledWithDotall() {
        VariableExtractionRule.ExpirySignal signal = new VariableExtractionRule.ExpirySignal(
                Set.of(), "", VariableExtractionRule.PatternMode.REGEX,
                "<form.*id=\"login\"", VariableExtractionRule.PatternMode.REGEX, false);

        assertNull(ExtractionEngine.matchesExpirySignal(signal,
                new ExtractionEngine.ResponseSnapshot(200, List.of(),
                        "<html>\n  <form\n     method=\"post\"\n     id=\"login\">\n</html>")));
    }

    @Test
    void aHeaderRegexAnchorsAtEveryLineWithoutTheInlineMultilineFlag() {
        VariableExtractionRule.ExpirySignal signal = new VariableExtractionRule.ExpirySignal(
                Set.of(), "^Location:\\s*/login", VariableExtractionRule.PatternMode.REGEX,
                "", VariableExtractionRule.PatternMode.REGEX, false);
        ExtractionEngine.ResponseSnapshot response = new ExtractionEngine.ResponseSnapshot(302,
                List.of("Date: Mon, 01 Jan 2026 10:00:00 GMT", "Location: /login"), "");

        assertNull(ExtractionEngine.matchesExpirySignal(signal, response));
        // Anchoring still means anchoring: a prefixed header name must not match.
        assertEquals(ExtractionOutcome.EXPIRY_SIGNAL_MISMATCH,
                ExtractionEngine.matchesExpirySignal(signal,
                        new ExtractionEngine.ResponseSnapshot(302,
                                List.of("X-Original-Location: /login"), "")));
    }

    @Test
    void aLiteralFilterNeverReportsAnInvalidRegex() {
        VariableExtractionRule.ExpirySignal signal = new VariableExtractionRule.ExpirySignal(
                Set.of(), "", VariableExtractionRule.PatternMode.REGEX,
                "([unclosed", VariableExtractionRule.PatternMode.LITERAL, false);

        assertEquals(ExtractionOutcome.EXPIRY_SIGNAL_MISMATCH,
                ExtractionEngine.matchesExpirySignal(signal,
                        new ExtractionEngine.ResponseSnapshot(200, List.of(), "body")));
        assertNull(ExtractionEngine.matchesExpirySignal(signal,
                new ExtractionEngine.ResponseSnapshot(200, List.of(), "x ([unclosed y")));
    }

    private static ExtractionEngine.ResponseSnapshot redirectResponse(int statusCode, String location) {
        return new ExtractionEngine.ResponseSnapshot(statusCode,
                List.of("Content-Length: 0", "Location: " + location), "");
    }

    private static VariableExtractionRule.ExpirySignal headerSignal(Set<Integer> codes, String headerRegex) {
        return new VariableExtractionRule.ExpirySignal(codes, headerRegex,
                VariableExtractionRule.PatternMode.REGEX, "",
                VariableExtractionRule.PatternMode.REGEX, false);
    }

    private static VariableExtractionRule.ExtractionTarget cookieTarget(String cookieNameRegex) {
        return new VariableExtractionRule.ExtractionTarget(
                VariableExtractionRule.ExtractionSource.RESPONSE_HEADERS,
                "Set-Cookie: (" + cookieNameRegex + "=[^;]+)");
    }
}
