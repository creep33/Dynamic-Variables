package burp;

import java.util.Collection;
import java.util.Set;

final class AutomationPolicy {
    private static final Set<String> SAFE_REPLAY_METHODS = Set.of("GET", "HEAD", "OPTIONS");
    private static final Set<Integer> UNAMBIGUOUS_AUTH_CODES = Set.of(401, 403);

    private AutomationPolicy() {}

    /**
     * A 401 or a 403 is unambiguous evidence of an expired session; a 302 is not. Without this
     * guard, a signal such as "any 302" combined with non-idempotent replay would resend POSTs
     * on every ordinary redirect of the application. Anything outside 401/403 must therefore
     * narrow the match with a header or body filter.
     */
    static boolean isExpirySignalUsable(VariableExtractionRule.ExpirySignal signal) {
        if (signal == null) return false;
        if (!signal.headerRegex().isEmpty() || !signal.bodyRegex().isEmpty()) return true;
        return !signal.statusCodes().isEmpty()
                && UNAMBIGUOUS_AUTH_CODES.containsAll(signal.statusCodes());
    }

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
