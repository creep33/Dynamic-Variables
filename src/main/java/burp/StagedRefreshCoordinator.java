package burp;

import java.util.LinkedHashMap;
import java.util.Map;

final class StagedRefreshCoordinator {
    @FunctionalInterface
    interface Refresher {
        String refresh(String variable, VariableExtractionRule rule,
                       Map<String, String> currentValues) throws Exception;
    }

    record Result(boolean successful, Map<String, String> values, Exception error) {}

    private StagedRefreshCoordinator() {}

    static Result stage(Map<String, VariableExtractionRule> rules,
                        Map<String, String> initialValues, Refresher refresher) {
        Map<String, String> inputs = new LinkedHashMap<>(initialValues);
        Map<String, String> staged = new LinkedHashMap<>();
        try {
            for (Map.Entry<String, VariableExtractionRule> entry : rules.entrySet()) {
                String value = refresher.refresh(entry.getKey(), entry.getValue(), Map.copyOf(inputs));
                if (value == null) throw new IllegalStateException("Refresh returned no value");
                staged.put(entry.getKey(), value);
                inputs.put(entry.getKey(), value);
            }
            return new Result(true, Map.copyOf(staged), null);
        } catch (Exception error) {
            return new Result(false, Map.of(), error);
        }
    }
}
