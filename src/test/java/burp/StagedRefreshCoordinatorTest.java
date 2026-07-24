package burp;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class StagedRefreshCoordinatorTest {
    @Test
    void stagesAllValuesAndMakesEarlierResultsAvailableToDependencies() {
        Map<String, VariableExtractionRule> rules = new LinkedHashMap<>();
        rules.put("alice.csrf", new VariableExtractionRule());
        rules.put("alice.token", new VariableExtractionRule());

        StagedRefreshCoordinator.Result result = StagedRefreshCoordinator.stage(
                rules, Map.of("credential", "password"),
                (name, rule, values) -> name.endsWith("csrf")
                        ? "csrf-new" : values.get("alice.csrf") + "-token");

        assertTrue(result.successful());
        assertEquals(Map.of(
                "alice.csrf", "csrf-new",
                "alice.token", "csrf-new-token"), result.values());
    }

    @Test
    void discardsEveryStagedValueWhenOneRefreshFails() {
        Map<String, VariableExtractionRule> rules = new LinkedHashMap<>();
        rules.put("alice.csrf", new VariableExtractionRule());
        rules.put("alice.token", new VariableExtractionRule());

        StagedRefreshCoordinator.Result result = StagedRefreshCoordinator.stage(
                rules, Map.of(),
                (name, rule, values) -> {
                    if (name.endsWith("token")) throw new Exception("Bearer top-secret");
                    return "csrf-new";
                });

        assertFalse(result.successful());
        assertTrue(result.values().isEmpty());
        assertNotNull(result.error());
    }
}
