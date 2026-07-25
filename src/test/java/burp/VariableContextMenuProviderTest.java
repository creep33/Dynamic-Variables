package burp;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VariableContextMenuProviderTest {
    @Test
    void offersMaterializationOnlyInRepeaterRequestEditors() {
        assertTrue(VariableContextMenuProvider.isMaterializationContext(
                ToolType.REPEATER,
                InvocationType.MESSAGE_EDITOR_REQUEST,
                MessageEditorHttpRequestResponse.SelectionContext.REQUEST));

        assertFalse(VariableContextMenuProvider.isMaterializationContext(
                ToolType.PROXY,
                InvocationType.MESSAGE_EDITOR_REQUEST,
                MessageEditorHttpRequestResponse.SelectionContext.REQUEST));
        assertFalse(VariableContextMenuProvider.isMaterializationContext(
                ToolType.REPEATER,
                InvocationType.MESSAGE_VIEWER_REQUEST,
                MessageEditorHttpRequestResponse.SelectionContext.REQUEST));
        assertFalse(VariableContextMenuProvider.isMaterializationContext(
                ToolType.REPEATER,
                InvocationType.MESSAGE_EDITOR_RESPONSE,
                MessageEditorHttpRequestResponse.SelectionContext.RESPONSE));
    }

    @Test
    void filtersFoldersAsTheUserTypesWithoutChangingTheirOrder() {
        assertEquals(List.of("Admin", "Tenant Admin"),
                VariableContextMenuProvider.filterFolderNames(
                        List.of("Admin", "Customers", "Tenant Admin"), "adm", "Ungrouped"));
        assertEquals(List.of("Ungrouped", "Admin", "Customers"),
                VariableContextMenuProvider.filterFolderNames(
                        List.of("Admin", "Customers"), "", "Ungrouped"));
    }

    @Test
    void resolvesNativeEditorSelectionsAgainstTheRawMessage() {
        String message = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123\r\n\r\n{\n  \"token\": \"abc123\"\n}";

        // Raw view: the reported offsets already match the raw message.
        int rawStart = message.indexOf("session=abc123") + "session=".length();
        assertEquals(rawStart, VariableManager.locateSelection(
                message, "abc123", rawStart, rawStart + "abc123".length()));

        // Pretty view renumbers offsets, so the nearest occurrence is used instead.
        int bodyStart = message.lastIndexOf("abc123");
        assertEquals(bodyStart, VariableManager.locateSelection(
                message, "abc123", bodyStart + 4, bodyStart + 4 + "abc123".length()));

        assertEquals(-1, VariableManager.locateSelection(message, "not-in-message", 0, 14));
    }

    @Test
    void resolvesExistingFoldersAndTreatsAnEmptyValueAsUngrouped() {
        List<String> folders = List.of("Admin", "Customers");

        assertEquals("", VariableContextMenuProvider.existingFolderName(
                folders, "", "Ungrouped"));
        assertEquals("", VariableContextMenuProvider.existingFolderName(
                folders, "ungrouped", "Ungrouped"));
        assertEquals("Admin", VariableContextMenuProvider.existingFolderName(
                folders, "admin", "Ungrouped"));
        assertNull(VariableContextMenuProvider.existingFolderName(
                folders, "New folder", "Ungrouped"));
    }
}
