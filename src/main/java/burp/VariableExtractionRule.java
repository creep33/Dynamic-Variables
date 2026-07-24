package burp;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

public class VariableExtractionRule {
    public enum MatchStrategy { EXPLICIT, LEGACY_EXACT, LEGACY_PATH }
    public enum PatternMode { LITERAL, REGEX }
    public enum DiscriminatorSource { NONE, REQUEST_BODY, REQUEST_HEADERS }
    public enum ExtractionSource {
        RESPONSE_BODY("body"),
        RESPONSE_HEADERS("headers"),
        REQUEST_BODY("request_body"),
        REQUEST_HEADERS("request_headers");

        private final String storedValue;

        ExtractionSource(String storedValue) {
            this.storedValue = storedValue;
        }

        String storedValue() {
            return storedValue;
        }

        static ExtractionSource fromStored(String value) {
            for (ExtractionSource source : values()) {
                if (source.storedValue.equalsIgnoreCase(value)) return source;
            }
            return RESPONSE_BODY;
        }
    }

    public record ExtractionTarget(String name, ExtractionSource source, String regex) {
        public ExtractionTarget(ExtractionSource source, String regex) {
            this("", source, regex);
        }

        public ExtractionTarget {
            name = name == null ? "" : name.trim();
            source = source == null ? ExtractionSource.RESPONSE_BODY : source;
            regex = regex == null ? "" : regex;
        }
    }

    private boolean enabled;
    private boolean automaticRefreshEnabled;
    private boolean allowNonIdempotentReplay;
    private String matchUrl;
    private String source;
    private String regex;
    private String savedRequestBase64 = "";
    private String savedHost = "";
    private int savedPort;
    private boolean savedSecure;

    private List<ExtractionTarget> targets = new ArrayList<>();
    private String joinDelimiter = "; ";
    private String valueTemplate = "";

    private MatchStrategy matchStrategy = MatchStrategy.EXPLICIT;
    private String matchMethod = "";
    private String matchHost = "";
    private int matchPort;
    private boolean matchSecure;
    private String matchPath = "";
    private PatternMode pathMatchMode = PatternMode.LITERAL;
    private String matchQuery = "";
    private PatternMode queryMatchMode = PatternMode.LITERAL;
    private DiscriminatorSource discriminatorSource = DiscriminatorSource.NONE;
    private String discriminatorRegex = "";

    public VariableExtractionRule() {
        enabled = false;
        matchUrl = "";
        source = "body";
        regex = "";
    }

    public VariableExtractionRule(boolean enabled, String matchUrl, String source, String regex) {
        this();
        this.enabled = enabled;
        this.matchUrl = safe(matchUrl);
        this.source = safeDefault(source, "body");
        this.regex = safe(regex);
        this.matchStrategy = MatchStrategy.LEGACY_PATH;
        syncPrimaryTarget();
    }

    public VariableExtractionRule(boolean enabled, String matchUrl, String source, String regex,
                                  String savedRequestBase64, String savedHost, int savedPort, boolean savedSecure) {
        this(enabled, matchUrl, source, regex);
        this.savedRequestBase64 = safe(savedRequestBase64);
        this.savedHost = safe(savedHost);
        this.savedPort = savedPort;
        this.savedSecure = savedSecure;
        this.matchStrategy = this.savedRequestBase64.isEmpty()
                ? MatchStrategy.LEGACY_PATH : MatchStrategy.LEGACY_EXACT;
    }

    public VariableExtractionRule copy() {
        return deserialize(serialize());
    }

    private void syncPrimaryTarget() {
        if (targets.isEmpty()) {
            targets.add(new ExtractionTarget("value1", ExtractionSource.fromStored(this.source), this.regex));
        } else {
            ExtractionTarget primary = targets.get(0);
            this.source = primary.source().storedValue();
            this.regex = primary.regex();
        }
    }

    public void configureExplicitMatch(String method, String host, int port, boolean secure,
                                       String path, PatternMode pathMode, String query,
                                       PatternMode queryMode, DiscriminatorSource discriminatorSource,
                                       String discriminatorRegex) {
        this.matchStrategy = MatchStrategy.EXPLICIT;
        this.matchMethod = safe(method);
        this.matchHost = safe(host);
        this.matchPort = port;
        this.matchSecure = secure;
        this.matchPath = safe(path);
        this.pathMatchMode = pathMode == null ? PatternMode.LITERAL : pathMode;
        this.matchQuery = safe(query);
        this.queryMatchMode = queryMode == null ? PatternMode.LITERAL : queryMode;
        this.discriminatorSource = discriminatorSource == null ? DiscriminatorSource.NONE : discriminatorSource;
        this.discriminatorRegex = safe(discriminatorRegex);
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public boolean isAutomaticRefreshEnabled() { return automaticRefreshEnabled; }
    public void setAutomaticRefreshEnabled(boolean value) { automaticRefreshEnabled = value; }
    public boolean isAllowNonIdempotentReplay() { return allowNonIdempotentReplay; }
    public void setAllowNonIdempotentReplay(boolean value) { allowNonIdempotentReplay = value; }
    public String getMatchUrl() { return matchUrl; }
    public void setMatchUrl(String matchUrl) { this.matchUrl = safe(matchUrl); }
    public String getSource() {
        return targets.isEmpty() ? source : targets.get(0).source().storedValue();
    }
    public void setSource(String source) {
        this.source = safeDefault(source, "body");
        if (targets.isEmpty()) {
            targets.add(new ExtractionTarget("value1", ExtractionSource.fromStored(this.source), this.regex));
        } else {
            ExtractionTarget primary = targets.get(0);
            targets.set(0, new ExtractionTarget(
                    primary.name(), ExtractionSource.fromStored(this.source), primary.regex()));
        }
    }
    public ExtractionSource getExtractionSource() { return ExtractionSource.fromStored(getSource()); }
    public String getRegex() {
        return targets.isEmpty() ? regex : targets.get(0).regex();
    }
    public void setRegex(String regex) {
        this.regex = safe(regex);
        if (targets.isEmpty()) {
            targets.add(new ExtractionTarget("value1", ExtractionSource.fromStored(this.source), this.regex));
        } else {
            ExtractionTarget primary = targets.get(0);
            targets.set(0, new ExtractionTarget(primary.name(), primary.source(), this.regex));
        }
    }
    public List<ExtractionTarget> getTargets() {
        if (targets.isEmpty()) {
            syncPrimaryTarget();
        }
        return Collections.unmodifiableList(targets);
    }
    public void setTargets(List<ExtractionTarget> newTargets) {
        this.targets = new ArrayList<>(newTargets == null ? List.of() : newTargets);
        if (this.targets.isEmpty()) syncPrimaryTarget();
        for (int index = 0; index < this.targets.size(); index++) {
            ExtractionTarget target = this.targets.get(index);
            if (target.name().isEmpty()) {
                this.targets.set(index, new ExtractionTarget(
                        "value" + (index + 1), target.source(), target.regex()));
            }
        }
        this.source = this.targets.get(0).source().storedValue();
        this.regex = this.targets.get(0).regex();
    }
    public void addTarget(ExtractionSource targetSource, String targetRegex) {
        if (targets.isEmpty()) syncPrimaryTarget();
        targets.add(new ExtractionTarget(
                "value" + (targets.size() + 1), targetSource, targetRegex));
    }
    public void replaceTarget(int index, ExtractionSource targetSource, String targetRegex) {
        replaceTarget(index, getTargets().get(index).name(), targetSource, targetRegex);
    }
    public void replaceTarget(int index, String targetName,
                              ExtractionSource targetSource, String targetRegex) {
        if (targets.isEmpty()) syncPrimaryTarget();
        if (index < 0 || index >= targets.size()) {
            throw new IndexOutOfBoundsException("Extraction target index: " + index);
        }
        targets.set(index, new ExtractionTarget(targetName, targetSource, targetRegex));
        if (index == 0) {
            source = targets.get(0).source().storedValue();
            regex = targets.get(0).regex();
        }
    }
    public void removeTarget(int index) {
        if (targets.isEmpty()) syncPrimaryTarget();
        if (targets.size() == 1) {
            throw new IllegalStateException("An extraction rule must keep at least one target");
        }
        targets.remove(index);
        source = targets.get(0).source().storedValue();
        regex = targets.get(0).regex();
    }
    public String getJoinDelimiter() { return joinDelimiter == null ? "; " : joinDelimiter; }
    public void setJoinDelimiter(String delimiter) { this.joinDelimiter = safeDefault(delimiter, "; "); }
    public String getValueTemplate() {
        if (valueTemplate != null && !valueTemplate.isEmpty()) return valueTemplate;
        return getTargets().stream()
                .map(target -> "{{" + target.name() + "}}")
                .collect(java.util.stream.Collectors.joining(getJoinDelimiter()));
    }
    public void setValueTemplate(String template) { valueTemplate = safe(template); }
    public void resetValueTemplate() { valueTemplate = ""; }

    public String getSavedRequestBase64() { return savedRequestBase64; }
    public void setSavedRequestBase64(String value) { savedRequestBase64 = safe(value); }
    public String getSavedHost() { return savedHost; }
    public void setSavedHost(String value) { savedHost = safe(value); }
    public int getSavedPort() { return savedPort; }
    public void setSavedPort(int value) { savedPort = value; }
    public boolean isSavedSecure() { return savedSecure; }
    public void setSavedSecure(boolean value) { savedSecure = value; }
    public MatchStrategy getMatchStrategy() { return matchStrategy; }
    public String getMatchMethod() { return matchMethod; }
    public String getMatchHost() { return matchHost; }
    public int getMatchPort() { return matchPort; }
    public boolean isMatchSecure() { return matchSecure; }
    public String getMatchPath() { return matchPath; }
    public PatternMode getPathMatchMode() { return pathMatchMode; }
    public String getMatchQuery() { return matchQuery; }
    public PatternMode getQueryMatchMode() { return queryMatchMode; }
    public DiscriminatorSource getDiscriminatorSource() { return discriminatorSource; }
    public String getDiscriminatorRegex() { return discriminatorRegex; }

    public String serialize() {
        List<ExtractionTarget> currentTargets = getTargets();
        List<String> encodedTargets = new ArrayList<>();
        for (ExtractionTarget target : currentTargets) {
            encodedTargets.add(enc(target.name()) + ":" + enc(target.source().storedValue())
                    + ":" + enc(target.regex()));
        }
        String targetsStr = String.join(";", encodedTargets);

        return String.join("|",
                "v5",
                enc(matchUrl), enc(getSource()), Boolean.toString(enabled), enc(getRegex()),
                savedRequestBase64, enc(savedHost), Integer.toString(savedPort), Boolean.toString(savedSecure),
                Boolean.toString(automaticRefreshEnabled), Boolean.toString(allowNonIdempotentReplay),
                matchStrategy.name(), enc(matchMethod), enc(matchHost), Integer.toString(matchPort),
                Boolean.toString(matchSecure), enc(matchPath), pathMatchMode.name(), enc(matchQuery),
                queryMatchMode.name(), discriminatorSource.name(), enc(discriminatorRegex),
                enc(getJoinDelimiter()), enc(targetsStr), enc(valueTemplate));
    }

    public static VariableExtractionRule deserialize(String data) {
        if (data == null || data.isEmpty()) return new VariableExtractionRule();
        try {
            String[] parts = data.split("\\|", -1);
            if (parts.length >= 25 && "v5".equals(parts[0])) {
                VariableExtractionRule rule = loadV4Fields(parts);
                rule.joinDelimiter = dec(parts[22]);
                rule.valueTemplate = dec(parts[24]);

                String targetsStr = dec(parts[23]);
                if (!targetsStr.isEmpty()) {
                    List<ExtractionTarget> loadedTargets = new ArrayList<>();
                    String[] targetParts = targetsStr.split(";");
                    for (String targetPart : targetParts) {
                        int firstColon = targetPart.indexOf(':');
                        int secondColon = targetPart.indexOf(':', firstColon + 1);
                        if (firstColon > 0 && secondColon > firstColon) {
                            loadedTargets.add(new ExtractionTarget(
                                    dec(targetPart.substring(0, firstColon)),
                                    ExtractionSource.fromStored(dec(
                                            targetPart.substring(firstColon + 1, secondColon))),
                                    dec(targetPart.substring(secondColon + 1))));
                        }
                    }
                    if (!loadedTargets.isEmpty()) rule.setTargets(loadedTargets);
                }
                return rule;
            }
            if (parts.length >= 24 && "v4".equals(parts[0])) {
                VariableExtractionRule rule = loadV4Fields(parts);
                rule.joinDelimiter = dec(parts[22]);

                String targetsStr = dec(parts[23]);
                if (!targetsStr.isEmpty()) {
                    List<ExtractionTarget> loadedTargets = new ArrayList<>();
                    String[] targetParts = targetsStr.split(";");
                    for (String tp : targetParts) {
                        int colon = tp.indexOf(':');
                        if (colon > 0) {
                            String src = dec(tp.substring(0, colon));
                            String rgz = dec(tp.substring(colon + 1));
                            loadedTargets.add(new ExtractionTarget(
                                    "value" + (loadedTargets.size() + 1),
                                    ExtractionSource.fromStored(src), rgz));
                        }
                    }
                    if (!loadedTargets.isEmpty()) {
                        rule.setTargets(loadedTargets);
                    }
                }
                return rule;
            }
            if (parts.length >= 22 && "v3".equals(parts[0])) {
                VariableExtractionRule rule = new VariableExtractionRule(
                        Boolean.parseBoolean(parts[3]), dec(parts[1]), dec(parts[2]), dec(parts[4]),
                        parts[5], dec(parts[6]), Integer.parseInt(parts[7]), Boolean.parseBoolean(parts[8]));
                rule.automaticRefreshEnabled = Boolean.parseBoolean(parts[9]);
                rule.allowNonIdempotentReplay = Boolean.parseBoolean(parts[10]);
                rule.matchStrategy = enumValue(MatchStrategy.class, parts[11], MatchStrategy.LEGACY_PATH);
                rule.matchMethod = dec(parts[12]);
                rule.matchHost = dec(parts[13]);
                rule.matchPort = Integer.parseInt(parts[14]);
                rule.matchSecure = Boolean.parseBoolean(parts[15]);
                rule.matchPath = dec(parts[16]);
                rule.pathMatchMode = enumValue(PatternMode.class, parts[17], PatternMode.LITERAL);
                rule.matchQuery = dec(parts[18]);
                rule.queryMatchMode = enumValue(PatternMode.class, parts[19], PatternMode.LITERAL);
                rule.discriminatorSource = enumValue(
                        DiscriminatorSource.class, parts[20], DiscriminatorSource.NONE);
                rule.discriminatorRegex = dec(parts[21]);
                return rule;
            }
            if (parts.length >= 8) {
                return new VariableExtractionRule(
                        Boolean.parseBoolean(parts[2]), dec(parts[0]), dec(parts[1]), dec(parts[3]),
                        parts[4], dec(parts[5]), Integer.parseInt(parts[6]), Boolean.parseBoolean(parts[7]));
            }
            if (parts.length >= 4) {
                return new VariableExtractionRule(
                        Boolean.parseBoolean(parts[2]), dec(parts[0]), dec(parts[1]), dec(parts[3]));
            }
        } catch (Exception ignored) {
            // Invalid persisted rules are disabled rather than guessed.
        }
        return new VariableExtractionRule();
    }

    private static VariableExtractionRule loadV4Fields(String[] parts) {
        VariableExtractionRule rule = new VariableExtractionRule(
                Boolean.parseBoolean(parts[3]), dec(parts[1]), dec(parts[2]), dec(parts[4]),
                parts[5], dec(parts[6]), Integer.parseInt(parts[7]), Boolean.parseBoolean(parts[8]));
        rule.automaticRefreshEnabled = Boolean.parseBoolean(parts[9]);
        rule.allowNonIdempotentReplay = Boolean.parseBoolean(parts[10]);
        rule.matchStrategy = enumValue(MatchStrategy.class, parts[11], MatchStrategy.LEGACY_PATH);
        rule.matchMethod = dec(parts[12]);
        rule.matchHost = dec(parts[13]);
        rule.matchPort = Integer.parseInt(parts[14]);
        rule.matchSecure = Boolean.parseBoolean(parts[15]);
        rule.matchPath = dec(parts[16]);
        rule.pathMatchMode = enumValue(PatternMode.class, parts[17], PatternMode.LITERAL);
        rule.matchQuery = dec(parts[18]);
        rule.queryMatchMode = enumValue(PatternMode.class, parts[19], PatternMode.LITERAL);
        rule.discriminatorSource = enumValue(
                DiscriminatorSource.class, parts[20], DiscriminatorSource.NONE);
        rule.discriminatorRegex = dec(parts[21]);
        return rule;
    }

    private static <T extends Enum<T>> T enumValue(Class<T> type, String value, T fallback) {
        try {
            return Enum.valueOf(type, value.toUpperCase(Locale.ROOT));
        } catch (Exception ignored) {
            return fallback;
        }
    }

    private static String enc(String value) {
        return URLEncoder.encode(safe(value), StandardCharsets.UTF_8);
    }

    private static String dec(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static String safeDefault(String value, String fallback) {
        return value == null ? fallback : value;
    }
}
