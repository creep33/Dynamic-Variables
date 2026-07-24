package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VariableRequestEditorTest {

    @Test
    void showsOnlyTheLocalVariableNameInsideFolders() {
        assertEquals("cookie", VariableRequestEditor.localVariableName("user1.cookie", "user1"));
        assertEquals("cookie", VariableRequestEditor.localVariableName("user2.cookie", "user2"));
    }

    @Test
    void keepsUngroupedAndUnexpectedNamesUnchanged() {
        assertEquals("domain", VariableRequestEditor.localVariableName("domain", ""));
        assertEquals("other.cookie", VariableRequestEditor.localVariableName("other.cookie", "user1"));
    }
}
