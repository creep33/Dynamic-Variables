package burp;

import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;

final class PlaceholderPreferences {
    static final String TAG_ENABLED_KEY = "dynamic_variables_placeholder_tag_enabled";
    static final String TAG_VALUE_KEY = "dynamic_variables_placeholder_tag_value";
    static final String LANGUAGE_KEY = "dynamic_variables_ui_language";
    static final String SYNTAX_KEY = "dynamic_variables_placeholder_syntax";
    static final String DEFAULT_TAG = "dv";

    private PlaceholderPreferences() {}

    static VariableNames.PlaceholderStyle load(Function<String, String> getter, Consumer<String> warningLogger) {
        String enabledValue = getter.apply(TAG_ENABLED_KEY);
        boolean enabled = enabledValue != null && Boolean.parseBoolean(enabledValue);
        String tag = getter.apply(TAG_VALUE_KEY);
        if (tag == null) tag = DEFAULT_TAG;

        String syntaxValue = getter.apply(SYNTAX_KEY);
        VariableNames.PlaceholderSyntax syntax = VariableNames.PlaceholderSyntax.CURLY_BRACES;
        if (syntaxValue != null) {
            try {
                syntax = VariableNames.PlaceholderSyntax.valueOf(syntaxValue);
            } catch (IllegalArgumentException ignored) {
            }
        }

        if (!VariableNames.isValidTag(tag)) {
            if (warningLogger != null) {
                warningLogger.accept("Invalid saved placeholder tag; tagged placeholders were disabled.");
            }
            return new VariableNames.PlaceholderStyle(false, DEFAULT_TAG, syntax);
        }
        return new VariableNames.PlaceholderStyle(enabled, tag, syntax);
    }

    static void save(BiConsumer<String, String> setter, VariableNames.PlaceholderStyle style) {
        setter.accept(TAG_ENABLED_KEY, String.valueOf(style.tagEnabled()));
        setter.accept(TAG_VALUE_KEY, style.tag());
        setter.accept(SYNTAX_KEY, style.syntax().name());
    }

    static UiLanguage loadLanguage(Function<String, String> getter) {
        return UiLanguage.fromCode(getter.apply(LANGUAGE_KEY));
    }

    static void saveLanguage(BiConsumer<String, String> setter, UiLanguage language) {
        setter.accept(LANGUAGE_KEY, language.code());
    }
}
