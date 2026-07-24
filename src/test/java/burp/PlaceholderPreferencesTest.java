package burp;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlaceholderPreferencesTest {
    @Test
    void usesBackwardCompatibleDefaultsWhenPreferencesDoNotExist() {
        VariableNames.PlaceholderStyle style = PlaceholderPreferences.load(key -> null, message -> {});

        assertFalse(style.tagEnabled());
        assertEquals("dv", style.tag());
        assertEquals("{{token}}", VariableNames.placeholder("token", style));
    }

    @Test
    void enabledPreferenceWithoutAStoredTagUsesDv() {
        Map<String, String> preferences = Map.of(PlaceholderPreferences.TAG_ENABLED_KEY, "true");

        VariableNames.PlaceholderStyle style = PlaceholderPreferences.load(preferences::get, message -> {});

        assertTrue(style.tagEnabled());
        assertEquals("dv", style.tag());
    }

    @Test
    void savesAndLoadsAnEnabledCustomTag() {
        Map<String, String> preferences = new HashMap<>();
        PlaceholderPreferences.save(preferences::put,
                new VariableNames.PlaceholderStyle(true, "pentest_2", VariableNames.PlaceholderSyntax.CURLY_BRACES));

        VariableNames.PlaceholderStyle restored = PlaceholderPreferences.load(preferences::get, message -> {});

        assertTrue(restored.tagEnabled());
        assertEquals("pentest_2", restored.tag());
        assertEquals("{{pentest_2:token}}", VariableNames.placeholder("token", restored));
    }

    @Test
    void preservesTheChosenTagWhileTaggingIsDisabled() {
        Map<String, String> preferences = new HashMap<>();
        PlaceholderPreferences.save(preferences::put,
                new VariableNames.PlaceholderStyle(false, "redteam", VariableNames.PlaceholderSyntax.CURLY_BRACES));

        VariableNames.PlaceholderStyle restored = PlaceholderPreferences.load(preferences::get, message -> {});

        assertFalse(restored.tagEnabled());
        assertEquals("redteam", restored.tag());
        assertEquals("{{token}}", VariableNames.placeholder("token", restored));
    }

    @Test
    void invalidStoredTagFallsBackSafelyAndEmitsOneWarning() {
        Map<String, String> preferences = Map.of(
                PlaceholderPreferences.TAG_ENABLED_KEY, "true",
                PlaceholderPreferences.TAG_VALUE_KEY, "bad:tag");
        List<String> warnings = new ArrayList<>();

        VariableNames.PlaceholderStyle restored = PlaceholderPreferences.load(
                preferences::get, warnings::add);

        assertFalse(restored.tagEnabled());
        assertEquals("dv", restored.tag());
        assertEquals(1, warnings.size());
    }

    @Test
    void defaultsToEnglishAndPersistsTheSelectedLanguage() {
        assertEquals(UiLanguage.ENGLISH, PlaceholderPreferences.loadLanguage(key -> null));

        Map<String, String> preferences = new HashMap<>();
        PlaceholderPreferences.saveLanguage(preferences::put, UiLanguage.SPANISH);

        assertEquals(UiLanguage.SPANISH, PlaceholderPreferences.loadLanguage(preferences::get));
    }

    @Test
    void invalidLanguageFallsBackToEnglish() {
        assertEquals(UiLanguage.ENGLISH,
                PlaceholderPreferences.loadLanguage(key -> "unsupported"));
    }
}
