package burp;

import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

final class ExtractionEngine {
    record RequestSnapshot(String method, String host, int port, boolean secure, String path,
                           List<String> headers, String body) {
        String pathWithoutQuery() {
            int separator = path == null ? -1 : path.indexOf('?');
            return separator < 0 ? nullToEmpty(path) : path.substring(0, separator);
        }

        String query() {
            int separator = path == null ? -1 : path.indexOf('?');
            return separator < 0 ? "" : path.substring(separator + 1);
        }

        String headersText() {
            return String.join("\r\n", headers) + (headers.isEmpty() ? "" : "\r\n");
        }
    }

    record ResponseSnapshot(List<String> headers, String body) {
        String headersText() {
            return String.join("\r\n", headers) + (headers.isEmpty() ? "" : "\r\n");
        }
    }

    record Evaluation(ExtractionOutcome outcome, String value) {
        static Evaluation result(ExtractionOutcome outcome) {
            return new Evaluation(outcome, null);
        }
    }

    private ExtractionEngine() {}

    static ExtractionOutcome matchesExplicitRequest(VariableExtractionRule rule, RequestSnapshot request) {
        if (!equalsIgnoreCase(rule.getMatchMethod(), request.method())) {
            return ExtractionOutcome.METHOD_MISMATCH;
        }
        if (!equalsIgnoreCase(rule.getMatchHost(), request.host())
                || rule.getMatchPort() != request.port()
                || rule.isMatchSecure() != request.secure()) {
            return ExtractionOutcome.SERVICE_MISMATCH;
        }

        ExtractionOutcome pathResult = matchesPattern(
                rule.getMatchPath(), request.pathWithoutQuery(), rule.getPathMatchMode(),
                ExtractionOutcome.PATH_MISMATCH);
        if (pathResult != null) return pathResult;

        if (!rule.getMatchQuery().isEmpty()) {
            ExtractionOutcome queryResult = matchesPattern(
                    rule.getMatchQuery(), request.query(), rule.getQueryMatchMode(),
                    ExtractionOutcome.QUERY_MISMATCH);
            if (queryResult != null) return queryResult;
        }

        if (rule.getDiscriminatorSource() != VariableExtractionRule.DiscriminatorSource.NONE
                && !rule.getDiscriminatorRegex().isEmpty()) {
            String discriminatorContent = rule.getDiscriminatorSource()
                    == VariableExtractionRule.DiscriminatorSource.REQUEST_HEADERS
                    ? request.headersText() : nullToEmpty(request.body());
            try {
                if (!Pattern.compile(rule.getDiscriminatorRegex(), Pattern.DOTALL)
                        .matcher(discriminatorContent).find()) {
                    return ExtractionOutcome.DISCRIMINATOR_MISMATCH;
                }
            } catch (PatternSyntaxException error) {
                return ExtractionOutcome.INVALID_REGEX;
            }
        }
        return null;
    }

    static Evaluation extract(VariableExtractionRule rule, RequestSnapshot request, ResponseSnapshot response) {
        List<VariableExtractionRule.ExtractionTarget> targets = rule.getTargets();
        if (targets.isEmpty()) {
            return Evaluation.result(ExtractionOutcome.EMPTY_REGEX);
        }
        List<String> extractedValues = new java.util.ArrayList<>();
        for (VariableExtractionRule.ExtractionTarget target : targets) {
            if (target.regex() == null || target.regex().isEmpty()) {
                return Evaluation.result(ExtractionOutcome.EMPTY_REGEX);
            }
            String content = switch (target.source()) {
                case RESPONSE_HEADERS -> response.headersText();
                case REQUEST_BODY -> nullToEmpty(request.body());
                case REQUEST_HEADERS -> request.headersText();
                case RESPONSE_BODY -> nullToEmpty(response.body());
            };
            if (content.isEmpty()) return Evaluation.result(ExtractionOutcome.EMPTY_SOURCE);
            try {
                Matcher matcher = Pattern.compile(target.regex(), Pattern.DOTALL).matcher(content);
                if (!matcher.find()) return Evaluation.result(ExtractionOutcome.REGEX_NO_MATCH);
                if (matcher.groupCount() < 1) return Evaluation.result(ExtractionOutcome.MISSING_CAPTURE_GROUP);
                extractedValues.add(matcher.group(1));
            } catch (PatternSyntaxException error) {
                return Evaluation.result(ExtractionOutcome.INVALID_REGEX);
            }
        }
        if (!isValidValueTemplate(rule.getValueTemplate(), targets)) {
            return Evaluation.result(ExtractionOutcome.INVALID_TEMPLATE);
        }
        String composed = composeValue(targets, extractedValues, rule.getValueTemplate());
        if (composed == null) return Evaluation.result(ExtractionOutcome.INVALID_TEMPLATE);
        return new Evaluation(ExtractionOutcome.UPDATED, composed);
    }

    static String composeValue(List<VariableExtractionRule.ExtractionTarget> targets,
                               List<String> extractedValues, String template) {
        if (targets == null || extractedValues == null || targets.size() != extractedValues.size()) {
            return null;
        }
        Map<String, String> valuesByName = new LinkedHashMap<>();
        for (int index = 0; index < targets.size(); index++) {
            String name = targets.get(index).name();
            String extractedValue = extractedValues.get(index);
            if (name == null || name.isBlank() || extractedValue == null
                    || valuesByName.containsKey(name)) {
                return null;
            }
            valuesByName.put(name, extractedValue);
        }
        String effectiveTemplate = template == null ? "" : template;
        Matcher placeholderMatcher = Pattern.compile("\\{\\{([^{}]+)}}").matcher(effectiveTemplate);
        StringBuffer result = new StringBuffer();
        while (placeholderMatcher.find()) {
            String replacement = valuesByName.get(placeholderMatcher.group(1));
            if (replacement == null) return null;
            placeholderMatcher.appendReplacement(result, Matcher.quoteReplacement(replacement));
        }
        placeholderMatcher.appendTail(result);
        return result.toString();
    }

    static boolean isValidValueTemplate(String template,
                                        List<VariableExtractionRule.ExtractionTarget> targets) {
        if (template == null || template.isEmpty() || targets == null || targets.isEmpty()) return false;
        Set<String> names = new HashSet<>();
        for (VariableExtractionRule.ExtractionTarget target : targets) {
            if (target.name() == null || target.name().isBlank() || !names.add(target.name())) return false;
        }
        Matcher matcher = Pattern.compile("\\{\\{([^{}]+)}}").matcher(template);
        Set<String> referenced = new HashSet<>();
        while (matcher.find()) {
            if (!names.contains(matcher.group(1))) return false;
            referenced.add(matcher.group(1));
        }
        return referenced.containsAll(names);
    }

    static boolean isValidRegex(String regex) {
        if (regex == null || regex.isEmpty()) return false;
        try {
            Pattern.compile(regex, Pattern.DOTALL);
            return true;
        } catch (PatternSyntaxException error) {
            return false;
        }
    }

    static boolean hasCaptureGroup(String regex) {
        if (!isValidRegex(regex)) return false;
        return Pattern.compile(regex, Pattern.DOTALL).matcher("").groupCount() >= 1;
    }

    private static ExtractionOutcome matchesPattern(String configured, String actual,
                                                    VariableExtractionRule.PatternMode mode,
                                                    ExtractionOutcome mismatch) {
        if (configured == null || configured.isEmpty()) return mismatch;
        if (mode == VariableExtractionRule.PatternMode.LITERAL) {
            return configured.equals(actual) ? null : mismatch;
        }
        try {
            return Pattern.compile(configured).matcher(nullToEmpty(actual)).find() ? null : mismatch;
        } catch (PatternSyntaxException error) {
            return ExtractionOutcome.INVALID_REGEX;
        }
    }

    private static boolean equalsIgnoreCase(String expected, String actual) {
        return expected != null && actual != null && expected.equalsIgnoreCase(actual);
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
