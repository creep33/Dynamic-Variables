package burp;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class VariableNamesTest {
    @Test
    void qualifiesFolderVariablesAndLeavesRootVariablesUnchanged() {
        assertEquals("token", VariableNames.qualify("", "token"));
        assertEquals("token", VariableNames.qualify(null, "token"));
        assertEquals("alice.token", VariableNames.qualify("alice", "token"));
        assertNotEquals(VariableNames.qualify("alice", "token"), VariableNames.qualify("bob", "token"));
    }

    @Test
    void validatesNewFolderAndVariableComponents() {
        assertTrue(VariableNames.isValidComponent("alice"));
        assertTrue(VariableNames.isValidComponent("session_token"));
        assertTrue(VariableNames.isValidComponent("A_1"));
        assertTrue(VariableNames.isValidComponent("  padded  "));
        assertFalse(VariableNames.isValidComponent(null));
        assertFalse(VariableNames.isValidComponent("  "));
        assertFalse(VariableNames.isValidComponent("alice.token"));
    }

    @Test
    void rejectsNamesOutsideTheAlphanumericAndUnderscoreCharset() {
        assertFalse(VariableNames.isValidComponent("mi variable"));
        assertFalse(VariableNames.isValidComponent("token-1"));
        assertFalse(VariableNames.isValidComponent("contraseña"));
        assertFalse(VariableNames.isValidComponent("token!"));
        assertFalse(VariableNames.isValidComponent("{{token}}"));
    }

    @Test
    void validatesPlaceholderTags() {
        assertTrue(VariableNames.isValidTag("dv"));
        assertTrue(VariableNames.isValidTag("pentest_2"));
        assertTrue(VariableNames.isValidTag("team-blue"));
        assertFalse(VariableNames.isValidTag(null));
        assertFalse(VariableNames.isValidTag(""));
        assertFalse(VariableNames.isValidTag("2dv"));
        assertFalse(VariableNames.isValidTag("dv:prod"));
        assertFalse(VariableNames.isValidTag("dv.prod"));
        assertFalse(VariableNames.isValidTag("dv prod"));
        assertFalse(VariableNames.isValidTag("{{dv}}"));
    }

    @Test
    void formatsTaggedAndUntaggedPlaceholders() {
        assertEquals("{{token}}", VariableNames.placeholder(
                "token", VariableNames.PlaceholderStyle.untagged()));
        assertEquals("{{dv:alice.token}}", VariableNames.placeholder(
                "alice.token", new VariableNames.PlaceholderStyle(true, "dv", VariableNames.PlaceholderSyntax.CURLY_BRACES)));
    }

    @Test
    void taggedModeOnlyReplacesTheExactConfiguredTag() {
        VariableNames.PlaceholderStyle style = new VariableNames.PlaceholderStyle(true, "dv", VariableNames.PlaceholderSyntax.CURLY_BRACES);
        String request = "active={{dv:token}} untagged={{token}} other={{other:token}} ssti={{7*7}}";

        assertEquals("active=secret untagged={{token}} other={{other:token}} ssti={{7*7}}",
                VariableNames.replacePlaceholders(request, Map.of("token", "secret"), style));
    }

    @Test
    void disabledTaggingKeepsLegacyReplacementBehavior() {
        VariableNames.PlaceholderStyle style = new VariableNames.PlaceholderStyle(false, "dv", VariableNames.PlaceholderSyntax.CURLY_BRACES);
        String request = "legacy={{token}} tagged={{dv:token}}";

        assertEquals("legacy=secret tagged={{dv:token}}",
                VariableNames.replacePlaceholders(request, Map.of("token", "secret"), style));
    }

    @Test
    void customTagsAreCaseSensitive() {
        VariableNames.PlaceholderStyle style = new VariableNames.PlaceholderStyle(true, "Pentest", VariableNames.PlaceholderSyntax.CURLY_BRACES);
        String request = "a={{Pentest:id}}&b={{pentest:id}}";

        assertEquals("a=42&b={{pentest:id}}",
                VariableNames.replacePlaceholders(request, Map.of("id", "42"), style));
    }

    @Test
    void placeholderStyleTrimsTagsAndRejectsInvalidEnabledTags() {
        VariableNames.PlaceholderStyle trimmed = new VariableNames.PlaceholderStyle(true, "  dv  ", VariableNames.PlaceholderSyntax.CURLY_BRACES);

        assertEquals("dv", trimmed.tag());
        assertThrows(IllegalArgumentException.class,
                () -> new VariableNames.PlaceholderStyle(true, "bad:tag", VariableNames.PlaceholderSyntax.CURLY_BRACES));
        assertThrows(IllegalArgumentException.class,
                () -> new VariableNames.PlaceholderStyle(true, "", VariableNames.PlaceholderSyntax.CURLY_BRACES));
    }

    @Test
    void taggedMaterializationOnlyReportsUnknownVariablesUsingTheActiveTag() {
        VariableNames.PlaceholderStyle style = new VariableNames.PlaceholderStyle(true, "dv", VariableNames.PlaceholderSyntax.CURLY_BRACES);

        VariableNames.MaterializationResult result = VariableNames.materializePlaceholders(
                "{{dv:known}} {{dv:missing}} {{missing}} {{qa:missing}}",
                Map.of("known", "value"), style);

        assertEquals("value {{dv:missing}} {{missing}} {{qa:missing}}", result.text());
        assertEquals(List.of("known"), result.replacedVariables());
        assertEquals(List.of("missing"), result.unresolvedVariables());
    }

    @Test
    void replacesSameLocalNameIndependentlyAcrossFolders() {
        String request = "Alice={{alice.token}}&Bob={{bob.token}}&Global={{api_url}}";
        assertEquals("Alice=alice-secret&Bob=bob-secret&Global=https://example.test",
                VariableNames.replacePlaceholders(request, Map.of(
                        "alice.token", "alice-secret",
                        "bob.token", "bob-secret",
                        "api_url", "https://example.test")));
    }

    @Test
    void materializesGlobalAndFolderVariablesAndReportsThemOnce() {
        String request = "/accounts/{{alice.id}}?token={{token}}\n"
                + "Authorization: Bearer {{token}}\n"
                + "{\"owner\":\"{{alice.id}}\"}";

        VariableNames.MaterializationResult result = VariableNames.materializePlaceholders(request, Map.of(
                "alice.id", "42",
                "token", "secret"));

        assertEquals("/accounts/42?token=secret\nAuthorization: Bearer secret\n{\"owner\":\"42\"}", result.text());
        assertEquals(java.util.List.of("alice.id", "token"), result.replacedVariables());
        assertEquals(java.util.List.of(), result.unresolvedVariables());
        assertTrue(result.changed());
        assertTrue(result.hasPlaceholders());
    }

    @Test
    void materializationIsExactAndPreservesSpecialCharactersAndEmptyValues() {
        String request = "a={{id}}&long={{accountId}}&special={{special}}&empty={{empty}}";

        VariableNames.MaterializationResult result = VariableNames.materializePlaceholders(request, Map.of(
                "id", "7",
                "accountId", "123",
                "special", "$1\\path\n{{literal}}",
                "empty", ""));

        assertEquals("a=7&long=123&special=$1\\path\n{{literal}}&empty=", result.text());
        assertEquals(java.util.List.of("id", "accountId", "special", "empty"), result.replacedVariables());
    }

    @Test
    void preservesAndReportsUnknownPlaceholders() {
        VariableNames.MaterializationResult result = VariableNames.materializePlaceholders(
                "known={{known}}&missing={{missing}}&again={{missing}}", Map.of("known", "value"));

        assertEquals("known=value&missing={{missing}}&again={{missing}}", result.text());
        assertEquals(java.util.List.of("known"), result.replacedVariables());
        assertEquals(java.util.List.of("missing"), result.unresolvedVariables());
        assertTrue(result.changed());
    }

    @Test
    void distinguishesPlainTextFromRequestsWithOnlyUnknownPlaceholders() {
        VariableNames.MaterializationResult plain = VariableNames.materializePlaceholders("ordinary text", Map.of());
        VariableNames.MaterializationResult unknown = VariableNames.materializePlaceholders("{{unknown}}", Map.of());

        assertFalse(plain.changed());
        assertFalse(plain.hasPlaceholders());
        assertFalse(unknown.changed());
        assertTrue(unknown.hasPlaceholders());
        assertEquals(java.util.List.of("unknown"), unknown.unresolvedVariables());
    }

    @Test
    void detectsQualifiedPlaceholderFoldersInFirstSeenOrder() {
        assertEquals(java.util.List.of("user1", "other"),
                VariableNames.detectPlaceholderFolders("{{user1.jwe}} {{global}} {{other.id}} {{user1.accountId}}"));
    }

    @Test
    void remapsMatchingVariablesAndReportsUnmatchedOnes() {
        String requestPart = "/accounts/{{user1.accountId}}?token={{user1.jwe}}&missing={{user1.onlyHere}}";

        VariableNames.FolderRemapResult result = VariableNames.remapFolderPlaceholders(
                requestPart, "user1", "user2", Set.of("jwe", "accountId"));

        assertEquals("/accounts/{{user2.accountId}}?token={{user2.jwe}}&missing={{user1.onlyHere}}", result.text());
        assertEquals(java.util.List.of("accountId", "jwe"), result.replacedVariables());
        assertEquals(java.util.List.of("onlyHere"), result.unmatchedVariables());
        assertTrue(result.changed());
    }

    @Test
    void remapsPlaceholdersAcrossPathHeadersAndBodyText() {
        String requestSections = "/users/{{user1.accountId}}\n"
                + "Authorization: Bearer {{user1.jwe}}\n"
                + "{\"owner\":\"{{user1.accountId}}\"}";

        VariableNames.FolderRemapResult result = VariableNames.remapFolderPlaceholders(
                requestSections, "user1", "user2", Set.of("jwe", "accountId"));

        assertEquals("/users/{{user2.accountId}}\n"
                + "Authorization: Bearer {{user2.jwe}}\n"
                + "{\"owner\":\"{{user2.accountId}}\"}", result.text());
    }

    @Test
    void remappingIsExactAndPreservesOtherKindsOfVariables() {
        String text = "id={{user1.id}} account={{user1.accountId}} global={{id}} other={{user3.id}}";

        VariableNames.FolderRemapResult result = VariableNames.remapFolderPlaceholders(
                text, "user1", "user2", Set.of("id"));

        assertEquals("id={{user2.id}} account={{user1.accountId}} global={{id}} other={{user3.id}}", result.text());
        assertEquals(java.util.List.of("id"), result.replacedVariables());
        assertEquals(java.util.List.of("accountId"), result.unmatchedVariables());
    }

    @Test
    void leavesPlainTextAndUnusableRemapsUnchanged() {
        assertFalse(VariableNames.remapFolderPlaceholders(
                "ordinary user1.id text", "user1", "user2", Set.of("id")).changed());
        assertFalse(VariableNames.remapFolderPlaceholders(
                "{{user1.id}}", "user1", "user1", Set.of("id")).changed());
        assertFalse(VariableNames.remapFolderPlaceholders(
                "{{user1.id}}", "user1", "user2", Set.of("accountId")).changed());
    }

    @Test
    void detectsAndRemapsFoldersUsingTaggedSyntaxOnly() {
        VariableNames.PlaceholderStyle style = new VariableNames.PlaceholderStyle(true, "dv", VariableNames.PlaceholderSyntax.CURLY_BRACES);
        String text = "{{dv:user1.id}} {{user1.id}} {{other:user1.id}}";

        assertEquals(java.util.List.of("user1"), VariableNames.detectPlaceholderFolders(text, style));
        VariableNames.FolderRemapResult result = VariableNames.remapFolderPlaceholders(
                text, "user1", "user2", Set.of("id"), style);

        assertEquals("{{dv:user2.id}} {{user1.id}} {{other:user1.id}}", result.text());
        assertEquals(java.util.List.of("id"), result.replacedVariables());
    }
}
