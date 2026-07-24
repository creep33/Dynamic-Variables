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
