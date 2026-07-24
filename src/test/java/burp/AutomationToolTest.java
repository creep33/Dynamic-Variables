package burp;

import org.junit.jupiter.api.Test;

import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AutomationToolTest {
    @Test
    void persistsExplicitScopesAndIgnoresUnknownFutureTools() {
        String encoded = AutomationTool.serialize(
                EnumSet.of(AutomationTool.REPEATER, AutomationTool.SCANNER));

        assertEquals(EnumSet.of(AutomationTool.REPEATER, AutomationTool.SCANNER),
                AutomationTool.deserialize(encoded + ",UNKNOWN"));
    }
}
