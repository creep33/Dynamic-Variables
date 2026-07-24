package burp;

import java.util.Collection;
import java.util.Set;

final class AutomationPolicy {
    private static final Set<String> SAFE_REPLAY_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    private AutomationPolicy() {}

    static boolean isReplayAuthorized(String method, Collection<VariableExtractionRule> refreshRules) {
        if (method != null && SAFE_REPLAY_METHODS.contains(method.toUpperCase())) return true;
        return refreshRules != null && !refreshRules.isEmpty()
                && refreshRules.stream().allMatch(VariableExtractionRule::isAllowNonIdempotentReplay);
    }

    static boolean isSingleContext(Collection<String> contexts) {
        return contexts != null && contexts.stream().distinct().limit(2).count() <= 1;
    }

    static boolean canAttemptRecovery(boolean globalEnabled, boolean toolEnabled,
                                      boolean configuredStatus, boolean hasOriginalTemplate,
                                      boolean hasVariables) {
        return globalEnabled && toolEnabled && configuredStatus && hasOriginalTemplate && hasVariables;
    }

    static boolean isRefreshCandidate(VariableExtractionRule rule) {
        return rule != null && rule.isAutomaticRefreshEnabled()
                && rule.getSavedRequestBase64() != null
                && !rule.getSavedRequestBase64().isEmpty();
    }
}
