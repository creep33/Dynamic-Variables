package burp;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class VariableNames {
    private static final Pattern TAG = Pattern.compile("[A-Za-z][A-Za-z0-9_-]*");
    private static final Pattern COMPONENT = Pattern.compile("[A-Za-z0-9_]+");
    private static final Map<PlaceholderStyle, Pattern> PLACEHOLDER_PATTERNS = new ConcurrentHashMap<>();

    enum PlaceholderSyntax {
        CURLY_BRACES,
        PARENTHESES
    }

    record PlaceholderStyle(boolean tagEnabled, String tag, PlaceholderSyntax syntax) {
        PlaceholderStyle {
            tag = tag == null ? "" : tag.trim();
            if (tagEnabled && !isValidTag(tag)) {
                throw new IllegalArgumentException("Invalid placeholder tag: " + tag);
            }
            if (syntax == null) {
                syntax = PlaceholderSyntax.CURLY_BRACES;
            }
        }

        static PlaceholderStyle untagged() {
            return new PlaceholderStyle(false, "", PlaceholderSyntax.CURLY_BRACES);
        }
    }

    private VariableNames() {}

    record FolderRemapResult(String text, List<String> replacedVariables, List<String> unmatchedVariables) {
        boolean changed() {
            return !replacedVariables.isEmpty();
        }
    }

    record MaterializationResult(String text, List<String> replacedVariables, List<String> unresolvedVariables) {
        boolean changed() {
            return !replacedVariables.isEmpty();
        }

        boolean hasPlaceholders() {
            return changed() || !unresolvedVariables.isEmpty();
        }
    }

    /**
     * Folder and variable names end up inside placeholders and inside the qualified key, so they
     * are restricted to characters that survive both untouched.
     */
    static boolean isValidComponent(String name) {
        return name != null && COMPONENT.matcher(name.trim()).matches();
    }

    static boolean isValidTag(String tag) {
        return tag != null && TAG.matcher(tag).matches();
    }

    static String qualify(String folder, String variable) {
        return folder == null || folder.isEmpty() ? variable : folder + "." + variable;
    }

    static String placeholder(String variableName, PlaceholderStyle style) {
        PlaceholderStyle activeStyle = style == null ? PlaceholderStyle.untagged() : style;
        String prefix = activeStyle.tagEnabled() ? activeStyle.tag() + ":" : "";
        if (activeStyle.syntax() == PlaceholderSyntax.PARENTHESES) {
            return "((" + prefix + variableName + "))";
        }
        return "{{" + prefix + variableName + "}}";
    }

    static String replacePlaceholders(String text, Map<String, String> variables) {
        return replacePlaceholders(text, variables, PlaceholderStyle.untagged());
    }

    static String replacePlaceholders(String text, Map<String, String> variables, PlaceholderStyle style) {
        return materializePlaceholders(text, variables, style).text();
    }

    static MaterializationResult materializePlaceholders(String text, Map<String, String> variables) {
        return materializePlaceholders(text, variables, PlaceholderStyle.untagged());
    }

    static MaterializationResult materializePlaceholders(String text, Map<String, String> variables,
                                                          PlaceholderStyle style) {
        if (text == null || text.isEmpty()) {
            return new MaterializationResult(text, List.of(), List.of());
        }

        Map<String, String> availableVariables = variables == null ? Map.of() : variables;
        Matcher matcher = placeholderPattern(style).matcher(text);
        StringBuffer rewritten = new StringBuffer();
        Set<String> replaced = new LinkedHashSet<>();
        Set<String> unresolved = new LinkedHashSet<>();

        while (matcher.find()) {
            String variableName = matcher.group(1);
            String value = availableVariables.get(variableName);
            if (value != null) {
                matcher.appendReplacement(rewritten, Matcher.quoteReplacement(value));
                replaced.add(variableName);
            } else {
                matcher.appendReplacement(rewritten, Matcher.quoteReplacement(matcher.group()));
                unresolved.add(variableName);
            }
        }
        matcher.appendTail(rewritten);

        return new MaterializationResult(rewritten.toString(), List.copyOf(replaced), List.copyOf(unresolved));
    }

    static List<String> detectPlaceholderFolders(String text) {
        return detectPlaceholderFolders(text, PlaceholderStyle.untagged());
    }

    static List<String> detectPlaceholderFolders(String text, PlaceholderStyle style) {
        if (text == null || text.isEmpty()) return List.of();
        Set<String> folders = new LinkedHashSet<>();
        Matcher matcher = placeholderPattern(style).matcher(text);
        while (matcher.find()) {
            String variableName = matcher.group(1);
            int separator = variableName.indexOf('.');
            if (separator > 0 && separator == variableName.lastIndexOf('.')
                    && separator < variableName.length() - 1) {
                folders.add(variableName.substring(0, separator));
            }
        }
        return List.copyOf(folders);
    }

    static FolderRemapResult remapFolderPlaceholders(String text, String sourceFolder, String targetFolder,
                                                       Set<String> targetLocalNames) {
        return remapFolderPlaceholders(text, sourceFolder, targetFolder, targetLocalNames,
                PlaceholderStyle.untagged());
    }

    static FolderRemapResult remapFolderPlaceholders(String text, String sourceFolder, String targetFolder,
                                                       Set<String> targetLocalNames, PlaceholderStyle style) {
        if (text == null || text.isEmpty() || sourceFolder == null || targetFolder == null
                || sourceFolder.equals(targetFolder)) {
            return new FolderRemapResult(text, List.of(), List.of());
        }

        Set<String> availableTargets = targetLocalNames == null ? Set.of() : targetLocalNames;
        Matcher matcher = placeholderPattern(style).matcher(text);
        StringBuffer rewritten = new StringBuffer();
        Set<String> replaced = new LinkedHashSet<>();
        Set<String> unmatched = new LinkedHashSet<>();

        while (matcher.find()) {
            String qualifiedName = matcher.group(1);
            String sourcePrefix = sourceFolder + ".";
            if (!qualifiedName.startsWith(sourcePrefix)
                    || qualifiedName.indexOf('.', sourcePrefix.length()) >= 0) {
                matcher.appendReplacement(rewritten, Matcher.quoteReplacement(matcher.group()));
                continue;
            }
            String localName = qualifiedName.substring(sourcePrefix.length());
            if (availableTargets.contains(localName)) {
                matcher.appendReplacement(rewritten, Matcher.quoteReplacement(
                        placeholder(targetFolder + "." + localName, style)));
                replaced.add(localName);
            } else {
                matcher.appendReplacement(rewritten, Matcher.quoteReplacement(matcher.group()));
                unmatched.add(localName);
            }
        }
        matcher.appendTail(rewritten);

        return new FolderRemapResult(rewritten.toString(), List.copyOf(replaced), List.copyOf(unmatched));
    }

    private static Pattern placeholderPattern(PlaceholderStyle style) {
        PlaceholderStyle activeStyle = style == null ? PlaceholderStyle.untagged() : style;
        return PLACEHOLDER_PATTERNS.computeIfAbsent(activeStyle, key -> {
            String prefix = key.tagEnabled() ? Pattern.quote(key.tag() + ":") : "";
            if (key.syntax() == PlaceholderSyntax.PARENTHESES) {
                return Pattern.compile("\\(\\(" + prefix + "([^()]+)\\)\\)");
            }
            return Pattern.compile("\\{\\{" + prefix + "([^{}]+)}}");
        });
    }
}
