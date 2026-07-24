package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.*;

class VariableHttpHandlerAnnotationsTest {
    @Test
    void appendsRecoveryEvidenceWithoutOverwritingExistingNotes() throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);
        VariableManager manager = mock(VariableManager.class);
        Annotations existing = mock(Annotations.class);
        Annotations updated = mock(Annotations.class);
        when(existing.hasNotes()).thenReturn(true);
        when(existing.notes()).thenReturn("Analyst note");
        when(existing.withNotes("Analyst note\nRecovery note")).thenReturn(updated);

        VariableHttpHandler handler = new VariableHttpHandler(api, manager);
        Method appendNote = VariableHttpHandler.class.getDeclaredMethod(
                "appendNote", Annotations.class, String.class);
        appendNote.setAccessible(true);

        Object result = appendNote.invoke(handler, existing, "Recovery note");

        assertSame(updated, result);
        verify(existing).withNotes("Analyst note\nRecovery note");
    }

    @Test
    void diagnosticErrorRedactsExceptionMessages() throws Exception {
        VariableHttpHandler handler = new VariableHttpHandler(
                mock(MontoyaApi.class), mock(VariableManager.class));
        Method safeError = VariableHttpHandler.class.getDeclaredMethod("safeError", Exception.class);
        safeError.setAccessible(true);

        String result = (String) safeError.invoke(
                handler, new IllegalStateException("Authorization: Bearer top-secret"));

        assertEquals("IllegalStateException", result);
        assertFalse(result.contains("top-secret"));
    }
}
