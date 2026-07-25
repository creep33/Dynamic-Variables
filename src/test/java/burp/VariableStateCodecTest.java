package burp;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class VariableStateCodecTest {
    @Test
    void roundTripsFoldersVariablesValuesRulesAndOrder() {
        VariableFolder alice = new VariableFolder("folder-id", "alice", 1, false);
        VariableExtractionRule rule = new VariableExtractionRule(true, "/login", "body", "token=([^&]+)",
                "cmVxdWVzdA==", "example.test", 443, true);
        VariableDefinition token = new VariableDefinition("variable-id", "token", alice.getId(),
                "a value with tabs\tand unicode ñ", rule, 3);

        VariableStateCodec.State decoded = VariableStateCodec.decode(
                VariableStateCodec.encode(List.of(alice), List.of(token)));

        assertEquals(1, decoded.folders().size());
        assertEquals("folder-id", decoded.folders().get(0).getId());
        assertEquals("alice", decoded.folders().get(0).getName());
        assertFalse(decoded.folders().get(0).isExpanded());
        assertEquals(1, decoded.variables().size());
        VariableDefinition restored = decoded.variables().get(0);
        assertEquals("variable-id", restored.getId());
        assertEquals("token", restored.getName());
        assertEquals("folder-id", restored.getFolderId());
        assertEquals("a value with tabs\tand unicode ñ", restored.getValue());
        assertEquals("/login", restored.getRule().getMatchUrl());
        assertTrue(restored.getRule().isEnabled());
    }

    @Test
    void rejectsUnknownStateVersions() {
        assertThrows(IllegalArgumentException.class, () -> VariableStateCodec.decode("99\n"));
    }

    @Test
    void readsVersionTwoStateAndWritesCurrentVersion() {
        VariableDefinition variable = new VariableDefinition(
                "id", "token", null, "value",
                new VariableExtractionRule(true, "/token", "body", "token=(.+)"), 0);
        String versionThree = VariableStateCodec.encode(List.of(), List.of(variable));
        String versionTwo = "2" + versionThree.substring(versionThree.indexOf('\n'));

        VariableStateCodec.State decoded = VariableStateCodec.decode(versionTwo);

        assertEquals("6", VariableStateCodec.VERSION);
        assertEquals("token", decoded.variables().get(0).getName());
        assertEquals(VariableExtractionRule.MatchStrategy.LEGACY_PATH,
                decoded.variables().get(0).getRule().getMatchStrategy());
    }

    @Test
    void roundTripsTheTwoFactorConfiguration() {
        VariableDefinition otp = new VariableDefinition("otp-id", "otp", null, "123456",
                new VariableExtractionRule(), 0);
        otp.setTotpConfig(new TotpGenerator.TotpConfig("GEZDGNBVGY3TQOJQ", 8, 60, "SHA256"));

        VariableDefinition restored = VariableStateCodec.decode(
                VariableStateCodec.encode(List.of(), List.of(otp))).variables().get(0);

        assertTrue(restored.isTotpVariable());
        assertEquals("GEZDGNBVGY3TQOJQ", restored.getTotpConfig().secret());
        assertEquals(8, restored.getTotpConfig().digits());
        assertEquals(60, restored.getTotpConfig().periodSeconds());
        assertEquals("SHA256", restored.getTotpConfig().algorithm());
    }

    @Test
    void readsVersionFiveVariablesWithoutATwoFactorColumn() {
        VariableDefinition token = new VariableDefinition("id", "token", null, "value",
                new VariableExtractionRule(), 0);
        String versionSix = VariableStateCodec.encode(List.of(), List.of(token));

        StringBuilder versionFive = new StringBuilder("5");
        for (String line : versionSix.split("\n", -1)) {
            if (line.isEmpty()) continue;
            versionFive.append('\n').append(line.startsWith("V\t")
                    ? line.substring(0, line.lastIndexOf('\t'))
                    : line);
        }

        VariableDefinition restored = VariableStateCodec.decode(
                versionFive.toString()).variables().get(0);

        assertEquals("token", restored.getName());
        assertEquals("value", restored.getValue());
        assertFalse(restored.isTotpVariable());
    }

    @Test
    void migratesLegacyVariablesToUngroupedWithoutChangingNamesValuesRulesOrOrder() {
        VariableExtractionRule tokenRule = new VariableExtractionRule(true, "/token", "body", "token=(.+)");
        VariableStateCodec.State migrated = VariableStateCodec.migrateLegacy(
                List.of("api_url", "legacy.name"),
                Map.of("api_url", "https://example.test", "legacy.name", "secret"),
                Map.of("legacy.name", tokenRule));

        assertTrue(migrated.folders().isEmpty());
        assertEquals(List.of("api_url", "legacy.name"),
                migrated.variables().stream().map(VariableDefinition::getName).toList());
        assertTrue(migrated.variables().stream().allMatch(variable -> variable.getFolderId() == null));
        assertEquals("secret", migrated.variables().get(1).getValue());
        assertSame(tokenRule, migrated.variables().get(1).getRule());
        assertEquals(1, migrated.variables().get(1).getPosition());
    }
}
