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
    void translatesTheRepeaterInsertMenu() {
        assertEquals("Insertar", UiText.get(UiLanguage.SPANISH, "Insert"));
        assertEquals("Sin carpeta", UiText.get(UiLanguage.SPANISH, "Ungrouped"));
        assertEquals("No hay variables definidas",
                UiText.get(UiLanguage.SPANISH, "No variables defined"));
        assertEquals("Coloca el cursor en la petición primero.",
                UiText.get(UiLanguage.SPANISH, "Place the cursor in the request first."));
        assertEquals("Insert", UiText.get(UiLanguage.ENGLISH, "Insert"));
    }

    @Test
    void translatesTheNameCharsetErrors() {
        assertEquals(" solo puede contener letras, números y _ en el nombre.",
                UiText.get(UiLanguage.SPANISH, " names may only contain letters, numbers and _."));
        assertEquals("Los nombres de variable solo pueden contener letras, números y _.",
                UiText.get(UiLanguage.SPANISH, "Variable names may only contain letters, numbers and _."));
    }

    @Test
    void translatesTheTwoFactorSetupDialog() {
        assertEquals("Configurar 2FA", UiText.get(UiLanguage.SPANISH, "Setup 2FA"));
        assertEquals("Secreto 2FA (Base32):",
                UiText.get(UiLanguage.SPANISH, "2FA Secret (Base32):"));
        assertEquals("Código actual:", UiText.get(UiLanguage.SPANISH, "Current code:"));
        assertEquals("Secreto 2FA no válido. Usa caracteres Base32 (A-Z, 2-7).",
                UiText.get(UiLanguage.SPANISH, "Invalid 2FA secret. Use Base32 characters (A-Z, 2-7)."));
        assertEquals("Calculado a partir del secreto 2FA.",
                UiText.get(UiLanguage.SPANISH, "Computed from the 2FA secret."));
        assertEquals("Setup 2FA", UiText.get(UiLanguage.ENGLISH, "Setup 2FA"));
        assertEquals("El valor rota automáticamente cada vez que se usa.",
                UiText.get(UiLanguage.SPANISH, "The value rotates automatically every time it is used."));
        assertEquals("Rotar ahora", UiText.get(UiLanguage.SPANISH, "Rotate now"));
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

    @Test
    void translatesTheSessionExpirySignalControls() {
        assertEquals("Señal de expiración de sesión",
                UiText.get(UiLanguage.SPANISH, "Session expiry signal"));
        assertEquals("Códigos de estado de expiración:",
                UiText.get(UiLanguage.SPANISH, "Expiry status codes:"));
        assertEquals("Filtro de cabecera de respuesta:",
                UiText.get(UiLanguage.SPANISH, "Response header filter:"));
        assertEquals("Filtro de cuerpo de respuesta:",
                UiText.get(UiLanguage.SPANISH, "Response body filter:"));
        assertEquals("La sesión ha expirado cuando el filtro NO casa",
                UiText.get(UiLanguage.SPANISH,
                        "The session is expired when the filter does NOT match"));
        assertEquals("Deja todos los campos vacíos para usar los códigos de estado globales.",
                UiText.get(UiLanguage.SPANISH,
                        "Leave every field empty to use the global refresh status codes."));
        assertEquals("Opcional. Se busca dentro del bloque de cabeceras de la respuesta. Vacío no filtra.",
                UiText.get(UiLanguage.SPANISH,
                        "Optional. Searched inside the response header block. Empty does not filter."));
        assertEquals("Opcional. Se busca dentro del cuerpo de la respuesta. Vacío no filtra.",
                UiText.get(UiLanguage.SPANISH,
                        "Optional. Searched inside the response body. Empty does not filter."));
        assertEquals("Los códigos distintos de 401 y 403 requieren un filtro de cabecera o cuerpo; esta señal se ignora.",
                UiText.get(UiLanguage.SPANISH,
                        "Codes other than 401 and 403 require a header or body filter; this signal is ignored."));
    }
}
