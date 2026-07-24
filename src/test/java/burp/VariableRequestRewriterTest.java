package burp;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VariableRequestRewriterTest {
    private static final VariableNames.PlaceholderStyle TAGGED =
            new VariableNames.PlaceholderStyle(true, "dv", VariableNames.PlaceholderSyntax.CURLY_BRACES);

    @Test
    void rewritesPathHeadersAndBodyAndReportsVariablesOnce() {
        VariableRequestRewriter.RequestParts request = request(
                "/accounts/{{dv:alice.id}}?token={{dv:token}}",
                List.of(
                        new VariableRequestRewriter.HeaderValue("Authorization", "Bearer {{dv:token}}"),
                        new VariableRequestRewriter.HeaderValue("X-Account", "{{dv:alice.id}}")),
                "{\"account\":\"{{dv:alice.id}}\",\"token\":\"{{dv:token}}\"}");

        VariableRequestRewriter.RewriteResult result = VariableRequestRewriter.rewrite(request, Map.of(
                "alice.id", "42",
                "token", "secret"), TAGGED);

        assertEquals("/accounts/42?token=secret", result.request().path());
        assertEquals("Bearer secret", result.request().headers().get(0).value());
        assertEquals("42", result.request().headers().get(1).value());
        assertEquals("{\"account\":\"42\",\"token\":\"secret\"}", result.request().body());
        assertEquals(List.of("alice.id", "token"), result.variablesUsed());
        assertTrue(result.changed());
    }

    @Test
    void taggedModePreservesUntaggedOtherTaggedAndSstiPayloads() {
        VariableRequestRewriter.RequestParts request = request(
                "/?active={{dv:token}}&legacy={{token}}&other={{qa:token}}&ssti={{7*7}}",
                List.of(new VariableRequestRewriter.HeaderValue("X-Test", "{{token}}")),
                "{{config.items[0]}}");

        VariableRequestRewriter.RewriteResult result = VariableRequestRewriter.rewrite(
                request, Map.of("token", "secret"), TAGGED);

        assertEquals("/?active=secret&legacy={{token}}&other={{qa:token}}&ssti={{7*7}}",
                result.request().path());
        assertEquals("{{token}}", result.request().headers().get(0).value());
        assertEquals("{{config.items[0]}}", result.request().body());
        assertEquals(List.of("token"), result.variablesUsed());
    }

    @Test
    void leavesRequestUntouchedWhenNoKnownActivePlaceholderExists() {
        VariableRequestRewriter.RequestParts request = request(
                "/{{dv:missing}}", List.of(new VariableRequestRewriter.HeaderValue("X-Test", "{{token}}")), null);

        VariableRequestRewriter.RewriteResult result = VariableRequestRewriter.rewrite(
                request, Map.of("token", "secret"), TAGGED);

        assertEquals(request, result.request());
        assertTrue(result.variablesUsed().isEmpty());
        assertFalse(result.changed());
    }

    @Test
    void replacementValuesAreNotProcessedRecursively() {
        VariableRequestRewriter.RequestParts request = request(
                "/{{dv:first}}", List.of(), "{{dv:second}}");

        VariableRequestRewriter.RewriteResult result = VariableRequestRewriter.rewrite(request, Map.of(
                "first", "{{dv:second}}",
                "second", "final"), TAGGED);

        assertEquals("/{{dv:second}}", result.request().path());
        assertEquals("final", result.request().body());
        assertEquals(List.of("first", "second"), result.variablesUsed());
    }

    @Test
    void emptyValuesStillCountAsUsedVariables() {
        VariableRequestRewriter.RequestParts request = request(
                "/items?filter={{dv:empty}}", List.of(), "");

        VariableRequestRewriter.RewriteResult result = VariableRequestRewriter.rewrite(
                request, Map.of("empty", ""), TAGGED);

        assertEquals("/items?filter=", result.request().path());
        assertEquals(List.of("empty"), result.variablesUsed());
        assertTrue(result.changed());
    }

    @Test
    void capturedStyleCanBeReusedAfterAConfigurationChange() {
        VariableRequestRewriter.RequestParts request = request(
                "/{{dv:token}}/{{qa:token}}", List.of(), "");
        VariableNames.PlaceholderStyle capturedStyle = new VariableNames.PlaceholderStyle(true, "dv", VariableNames.PlaceholderSyntax.CURLY_BRACES);
        VariableNames.PlaceholderStyle currentStyle = new VariableNames.PlaceholderStyle(true, "qa", VariableNames.PlaceholderSyntax.CURLY_BRACES);

        VariableRequestRewriter.RewriteResult retry = VariableRequestRewriter.rewrite(
                request, Map.of("token", "secret"), capturedStyle);
        VariableRequestRewriter.RewriteResult newRequest = VariableRequestRewriter.rewrite(
                request, Map.of("token", "secret"), currentStyle);

        assertEquals("/secret/{{qa:token}}", retry.request().path());
        assertEquals("/{{dv:token}}/secret", newRequest.request().path());
    }

    private static VariableRequestRewriter.RequestParts request(
            String path, List<VariableRequestRewriter.HeaderValue> headers, String body) {
        return new VariableRequestRewriter.RequestParts(path, headers, body);
    }
}
