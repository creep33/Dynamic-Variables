package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UiTextTest {
    @Test
    void englishIsUsedAsTheSourceAndDefaultLanguage() {
        assertEquals("Replace variables with their values...",
                UiText.get(UiLanguage.ENGLISH, "Replace variables with their values..."));
        assertEquals("Change variable folder...",
                UiText.get(UiLanguage.ENGLISH, "Change variable folder..."));
    }

    @Test
    void spanishTranslationsAreAvailableForTheRequestMenus() {
        assertEquals("Sustituir variables por sus valores...",
                UiText.get(UiLanguage.SPANISH, "Replace variables with their values..."));
        assertEquals("Cambiar carpeta de variables...",
                UiText.get(UiLanguage.SPANISH, "Change variable folder..."));
    }

    @Test
    void translatesSafetyCriticalAutomationControls() {
        assertEquals("Recuperar sesiones caducadas y reintentar peticiones",
                UiText.get(UiLanguage.SPANISH,
                        "Recover expired sessions and retry requests"));
        assertEquals("Actualiza las variables habilitadas cuando una respuesta coincide con su regla de extracción. No reintenta la petición.",
                UiText.get(UiLanguage.SPANISH,
                        "Updates enabled variables when a response matches their extraction rule. It does not retry the request."));
        assertEquals("Usar esta variable para recuperar sesiones caducadas",
                UiText.get(UiLanguage.SPANISH,
                        "Use this variable for expired-session recovery"));
        assertEquals("Las respuestas coincidentes actualizan el valor de forma pasiva; no se reintenta ninguna petición.",
                UiText.get(UiLanguage.SPANISH,
                        "Matching responses update the value passively; no request is retried."));
        assertEquals("La recuperación de sesión está desactivada globalmente. ¿Quieres activarla ahora?",
                UiText.get(UiLanguage.SPANISH,
                        "Session recovery is disabled globally. Enable it now?"));
        assertEquals("Crear con otro nombre",
                UiText.get(UiLanguage.SPANISH, "Create with another name"));
        assertEquals("En la recuperación de sesión, permitir reintentar peticiones no idempotentes",
                UiText.get(UiLanguage.SPANISH,
                        "In session recovery, allow retrying non-idempotent requests"));
    }

    @Test
    void translatesProgressiveDisclosureControls() {
        assertEquals("Automatización",
                UiText.get(UiLanguage.SPANISH, "Automation"));
        assertEquals("Mostrar opciones avanzadas de automatización",
                UiText.get(UiLanguage.SPANISH, "Show advanced automation options"));
        assertEquals("Todos los filtros configurados deben coincidir. La ruta no incluye la query.",
                UiText.get(UiLanguage.SPANISH,
                        "Every configured filter must match. The path does not include the query string."));
        assertEquals("Selecciona una variable",
                UiText.get(UiLanguage.SPANISH, "Select a variable"));
    }
}
