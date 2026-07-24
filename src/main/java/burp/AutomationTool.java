package burp;

import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;

import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

enum AutomationTool {
    REPEATER(ToolType.REPEATER),
    PROXY(ToolType.PROXY),
    INTRUDER(ToolType.INTRUDER),
    SCANNER(ToolType.SCANNER);

    private final ToolType toolType;

    AutomationTool(ToolType toolType) {
        this.toolType = toolType;
    }

    boolean matches(ToolSource source) {
        return source != null && source.isFromTool(toolType);
    }

    static AutomationTool from(ToolSource source) {
        for (AutomationTool tool : values()) {
            if (tool.matches(source)) return tool;
        }
        return null;
    }

    static String serialize(Set<AutomationTool> tools) {
        return tools.stream().map(Enum::name).sorted().collect(Collectors.joining(","));
    }

    static EnumSet<AutomationTool> deserialize(String value) {
        EnumSet<AutomationTool> result = EnumSet.noneOf(AutomationTool.class);
        if (value == null || value.isBlank()) return result;
        for (String part : value.split(",")) {
            try {
                result.add(valueOf(part.trim().toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException ignored) {
                // Unknown future tools remain disabled (fail closed).
            }
        }
        return result;
    }
}
