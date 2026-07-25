package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.editor.Editor;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public class VariableContextMenuProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final VariableManager variableManager;

    public VariableContextMenuProvider(MontoyaApi api, VariableManager variableManager) {
        this.api = api;
        this.variableManager = variableManager;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isEmpty()) {
            return Collections.emptyList();
        }

        MessageEditorHttpRequestResponse reqResp = event.messageEditorRequestResponse().get();
        List<Component> items = new ArrayList<>();

        if (reqResp.selectionOffsets().isPresent()) {
            JMenuItem assignItem = new JMenuItem(text("Assign to Variable..."));
            assignItem.addActionListener(e -> showConfigDialog(event));
            items.add(assignItem);
        }

        if (reqResp.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST) {
            if (isMaterializationContext(event.toolType(), event.invocationType(), reqResp.selectionContext())) {
                items.add(buildInsertMenu(reqResp));

                JMenuItem materializeItem = new JMenuItem(text("Replace variables with their values..."));
                materializeItem.setEnabled(hasAnyPlaceholder(reqResp.requestResponse().request()));
                materializeItem.setToolTipText(text("Converts the placeholders in this request to plain-text values."));
                materializeItem.addActionListener(e -> showMaterializationDialog(reqResp));
                items.add(materializeItem);
            }

            JMenuItem switchFolderItem = new JMenuItem(text("Change variable folder..."));
            switchFolderItem.setEnabled(hasUsefulFolderRemap(reqResp.requestResponse().request()));
            switchFolderItem.setToolTipText(text("Replaces matching placeholders from one folder with those from another."));
            switchFolderItem.addActionListener(e -> showFolderRemapDialog(reqResp));
            items.add(switchFolderItem);
        }

        return items;
    }

    static boolean isMaterializationContext(ToolType toolType, InvocationType invocationType,
                                            MessageEditorHttpRequestResponse.SelectionContext selectionContext) {
        return toolType == ToolType.REPEATER
                && invocationType == InvocationType.MESSAGE_EDITOR_REQUEST
                && selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST;
    }

    private JMenu buildInsertMenu(MessageEditorHttpRequestResponse reqResp) {
        JMenu insertMenu = new JMenu(text("Insert"));
        List<String> folders = new ArrayList<>();
        folders.add("");
        folders.addAll(variableManager.getFolderNames());

        boolean anyVariable = false;
        for (String folder : folders) {
            List<String> localNames = variableManager.getVariableNamesInFolder(folder);
            if (localNames.isEmpty()) continue;
            anyVariable = true;

            JMenu folderMenu = new JMenu(folder.isEmpty() ? text("Ungrouped") : folder);
            for (String localName : localNames) {
                String qualifiedName = variableManager.qualifyVariableName(folder, localName);
                JMenuItem variableItem = new JMenuItem(variableManager.placeholderFor(qualifiedName));
                variableItem.setToolTipText(variableValueTooltip(qualifiedName));
                variableItem.addActionListener(e -> insertPlaceholderIntoRequest(reqResp, qualifiedName));
                folderMenu.add(variableItem);
            }
            insertMenu.add(folderMenu);
        }

        if (!anyVariable) {
            JMenuItem emptyItem = new JMenuItem(text("No variables defined"));
            emptyItem.setEnabled(false);
            insertMenu.add(emptyItem);
        }
        return insertMenu;
    }

    private String variableValueTooltip(String qualifiedName) {
        String value = variableManager.getVariables().get(qualifiedName);
        if (value == null || value.isEmpty()) return text("No value");
        // Burp renders extension tooltips as plain text, so long values are truncated
        // instead of wrapped, exactly like the variable list in the request sub-tab.
        return value.length() > 200 ? value.substring(0, 200) + "..." : value;
    }

    private void insertPlaceholderIntoRequest(MessageEditorHttpRequestResponse reqResp, String qualifiedName) {
        HttpRequest request = reqResp.requestResponse().request();
        String rawRequest = new String(request.toByteArray().getBytes(), StandardCharsets.UTF_8);

        int start;
        int end;
        Optional<Range> selectionOffsets = reqResp.selectionOffsets();
        if (selectionOffsets.isPresent()
                && selectionOffsets.get().startIndexInclusive() < selectionOffsets.get().endIndexExclusive()) {
            // Pretty views renumber offsets, so resolve the selected text against the raw
            // request instead of trusting the reported range.
            Range range = selectionOffsets.get();
            int reportedStart = range.startIndexInclusive();
            int reportedEnd = Math.min(range.endIndexExclusive(), rawRequest.length());
            String selectedText = reportedStart >= 0 && reportedEnd > reportedStart
                    ? rawRequest.substring(reportedStart, reportedEnd)
                    : "";
            start = VariableManager.locateSelection(
                    rawRequest, selectedText, reportedStart, reportedEnd);
            end = start < 0 ? -1 : start + selectedText.length();
        } else {
            start = reqResp.caretPosition();
            end = start;
        }

        String placeholder = variableManager.placeholderFor(qualifiedName);
        String updatedRequest = insertPlaceholderAt(rawRequest, placeholder, start, end);
        if (updatedRequest == null) {
            JOptionPane.showMessageDialog(
                    api.userInterface().swingUtils().suiteFrame(),
                    text("Place the cursor in the request first."),
                    text("Error"), JOptionPane.ERROR_MESSAGE);
            return;
        }

        ByteArray contents = ByteArray.byteArray(updatedRequest.getBytes(StandardCharsets.UTF_8));
        reqResp.setRequest(request.httpService() == null
                ? HttpRequest.httpRequest(contents)
                : HttpRequest.httpRequest(request.httpService(), contents));
    }

    static String insertPlaceholderAt(String rawRequest, String placeholder, int start, int end) {
        if (rawRequest == null || placeholder == null) return null;
        if (start < 0 || end < start || end > rawRequest.length()) return null;
        return rawRequest.substring(0, start) + placeholder + rawRequest.substring(end);
    }

    private boolean hasAnyPlaceholder(HttpRequest request) {
        return VariableNames.materializePlaceholders(
                editableRequestText(request), variableManager.getVariables(),
                variableManager.getPlaceholderStyle()).hasPlaceholders();
    }

    private void showMaterializationDialog(MessageEditorHttpRequestResponse editor) {
        HttpRequest originalRequest = editor.requestResponse().request();
        Map<String, String> variables = variableManager.getVariables();
        VariableNames.PlaceholderStyle placeholderStyle = variableManager.getPlaceholderStyle();
        MaterializedRequestResult result = materializeRequest(originalRequest, variables, placeholderStyle);

        Frame suiteFrame = api.userInterface().swingUtils().suiteFrame();
        JDialog dialog = new JDialog(suiteFrame, text("Replace variables with their values"),
                Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(680, 500);
        dialog.setLocationRelativeTo(suiteFrame);

        JTextArea preview = new JTextArea(18, 56);
        preview.setEditable(false);
        preview.setLineWrap(true);
        preview.setWrapStyleWord(true);
        preview.setText(formatMaterializationPreview(result, variables, placeholderStyle));
        preview.setCaretPosition(0);

        JPanel previewPanel = new JPanel(new BorderLayout(5, 5));
        previewPanel.setBorder(new EmptyBorder(10, 15, 5, 15));
        previewPanel.add(new JLabel(text("Preview of the values that will be written to the request:")),
                BorderLayout.NORTH);
        previewPanel.add(new JScrollPane(preview), BorderLayout.CENTER);

        JButton applyButton = new JButton(text("Replace values"));
        applyButton.setEnabled(!result.replacedVariables().isEmpty());
        applyButton.addActionListener(e -> {
            editor.setRequest(result.request());
            dialog.dispose();
        });
        JButton cancelButton = new JButton(text("Cancel"));
        cancelButton.addActionListener(e -> dialog.dispose());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        buttons.add(applyButton);
        buttons.add(cancelButton);

        dialog.add(previewPanel, BorderLayout.CENTER);
        dialog.add(buttons, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }

    private String formatMaterializationPreview(MaterializedRequestResult result, Map<String, String> variables,
                                                VariableNames.PlaceholderStyle placeholderStyle) {
        StringBuilder text = new StringBuilder();
        if (result.replacedVariables().isEmpty()) {
            text.append(variableManager.text("No defined variables can be replaced.\n"));
        } else {
            text.append(variableManager.text("The following will be replaced:\n"));
            for (String variableName : result.replacedVariables()) {
                text.append("  ").append(VariableNames.placeholder(variableName, placeholderStyle)).append("  \u2192  ");
                String value = variables.get(variableName);
                if (value.isEmpty()) {
                    text.append(variableManager.text("(empty value)"));
                } else {
                    text.append(value.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\n      "));
                }
                text.append('\n');
            }
        }

        if (!result.unresolvedVariables().isEmpty()) {
            text.append(variableManager.text("\nThe following will be kept because they are not defined:\n"));
            for (String variableName : result.unresolvedVariables()) {
                text.append("  ").append(VariableNames.placeholder(variableName, placeholderStyle)).append('\n');
            }
        }

        text.append(variableManager.text("\nThis action modifies the template open in Repeater."));
        return text.toString();
    }

    private MaterializedRequestResult materializeRequest(HttpRequest originalRequest, Map<String, String> variables,
                                                          VariableNames.PlaceholderStyle placeholderStyle) {
        Set<String> replaced = new LinkedHashSet<>();
        Set<String> unresolved = new LinkedHashSet<>();
        HttpRequest rewritten = originalRequest;

        VariableNames.MaterializationResult pathResult = VariableNames.materializePlaceholders(
                originalRequest.path(), variables, placeholderStyle);
        collectMaterialization(pathResult, replaced, unresolved);
        if (!Objects.equals(originalRequest.path(), pathResult.text())) rewritten = rewritten.withPath(pathResult.text());

        List<HttpHeader> newHeaders = new ArrayList<>();
        boolean headersChanged = false;
        for (HttpHeader header : originalRequest.headers()) {
            VariableNames.MaterializationResult headerResult = VariableNames.materializePlaceholders(
                    header.value(), variables, placeholderStyle);
            collectMaterialization(headerResult, replaced, unresolved);
            if (!Objects.equals(header.value(), headerResult.text())) {
                newHeaders.add(HttpHeader.httpHeader(header.name(), headerResult.text()));
                headersChanged = true;
            } else {
                newHeaders.add(header);
            }
        }
        if (headersChanged) {
            rewritten = rewritten.withRemovedHeaders(rewritten.headers()).withAddedHeaders(newHeaders);
        }

        VariableNames.MaterializationResult bodyResult = VariableNames.materializePlaceholders(
                originalRequest.bodyToString(), variables, placeholderStyle);
        collectMaterialization(bodyResult, replaced, unresolved);
        if (!Objects.equals(originalRequest.bodyToString(), bodyResult.text())) {
            rewritten = rewritten.withBody(bodyResult.text());
        }

        return new MaterializedRequestResult(rewritten, List.copyOf(replaced), List.copyOf(unresolved));
    }

    private void collectMaterialization(VariableNames.MaterializationResult result, Set<String> replaced,
                                        Set<String> unresolved) {
        replaced.addAll(result.replacedVariables());
        unresolved.addAll(result.unresolvedVariables());
    }

    private record MaterializedRequestResult(HttpRequest request, List<String> replacedVariables,
                                             List<String> unresolvedVariables) {}

    private boolean hasUsefulFolderRemap(HttpRequest request) {
        String requestText = editableRequestText(request);
        VariableNames.PlaceholderStyle placeholderStyle = variableManager.getPlaceholderStyle();
        List<String> sourceFolders = VariableNames.detectPlaceholderFolders(requestText, placeholderStyle);
        for (String sourceFolder : sourceFolders) {
            for (String targetFolder : variableManager.getFolderNames()) {
                if (sourceFolder.equals(targetFolder)) continue;
                Set<String> targets = new LinkedHashSet<>(variableManager.getVariableNamesInFolder(targetFolder));
                if (VariableNames.remapFolderPlaceholders(
                        requestText, sourceFolder, targetFolder, targets, placeholderStyle).changed()) {
                    return true;
                }
            }
        }
        return false;
    }

    private void showFolderRemapDialog(MessageEditorHttpRequestResponse editor) {
        HttpRequest originalRequest = editor.requestResponse().request();
        String requestText = editableRequestText(originalRequest);
        VariableNames.PlaceholderStyle placeholderStyle = variableManager.getPlaceholderStyle();
        List<String> detectedFolders = VariableNames.detectPlaceholderFolders(requestText, placeholderStyle);
        if (detectedFolders.isEmpty()) {
            JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                    text("The request does not contain placeholders with folders."), text("Change variable folder"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        Frame suiteFrame = api.userInterface().swingUtils().suiteFrame();
        JDialog dialog = new JDialog(suiteFrame, text("Change variable folder"), Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(610, 430);
        dialog.setLocationRelativeTo(suiteFrame);

        JPanel choices = new JPanel(new GridBagLayout());
        choices.setBorder(new EmptyBorder(10, 10, 0, 10));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JComboBox<String> sourceCombo = new JComboBox<>(detectedFolders.toArray(new String[0]));
        JComboBox<String> targetCombo = new JComboBox<>();
        JTextArea preview = new JTextArea(12, 48);
        preview.setEditable(false);
        preview.setLineWrap(true);
        preview.setWrapStyleWord(true);
        JButton applyButton = new JButton(text("Apply change"));
        JButton cancelButton = new JButton(text("Cancel"));

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 0;
        choices.add(new JLabel(text("Source folder:")), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        choices.add(sourceCombo, gbc);
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0;
        choices.add(new JLabel(text("Target folder:")), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        choices.add(targetCombo, gbc);

        Runnable updatePreview = () -> {
            String source = (String) sourceCombo.getSelectedItem();
            String target = (String) targetCombo.getSelectedItem();
            if (source == null || target == null) {
                preview.setText(text("No other folder is available as a target."));
                applyButton.setEnabled(false);
                return;
            }
            Set<String> targetNames = new LinkedHashSet<>(variableManager.getVariableNamesInFolder(target));
            VariableNames.FolderRemapResult result = VariableNames.remapFolderPlaceholders(
                    requestText, source, target, targetNames, placeholderStyle);
            preview.setText(formatRemapPreview(source, target, result, placeholderStyle));
            preview.setCaretPosition(0);
            applyButton.setEnabled(result.changed());
        };

        Runnable updateTargets = () -> {
            String source = (String) sourceCombo.getSelectedItem();
            Object previousTarget = targetCombo.getSelectedItem();
            targetCombo.removeAllItems();
            for (String folder : variableManager.getFolderNames()) {
                if (!folder.equals(source)) targetCombo.addItem(folder);
            }
            if (previousTarget != null) targetCombo.setSelectedItem(previousTarget);
            if (targetCombo.getSelectedIndex() < 0 && targetCombo.getItemCount() > 0) targetCombo.setSelectedIndex(0);
            updatePreview.run();
        };

        sourceCombo.addActionListener(e -> updateTargets.run());
        targetCombo.addActionListener(e -> updatePreview.run());
        applyButton.addActionListener(e -> {
            String source = (String) sourceCombo.getSelectedItem();
            String target = (String) targetCombo.getSelectedItem();
            if (source == null || target == null || source.equals(target)) {
                JOptionPane.showMessageDialog(dialog, text("Select different source and target folders."),
                        text("No changes"), JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            Set<String> targetNames = new LinkedHashSet<>(variableManager.getVariableNamesInFolder(target));
            RequestRemapResult result = remapRequest(
                    originalRequest, source, target, targetNames, placeholderStyle);
            if (result.replacedVariables().isEmpty()) {
                JOptionPane.showMessageDialog(dialog, text("There are no matching variables to replace."),
                        text("No changes"), JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            editor.setRequest(result.request());
            dialog.dispose();
        });
        cancelButton.addActionListener(e -> dialog.dispose());

        JPanel previewPanel = new JPanel(new BorderLayout(5, 5));
        previewPanel.setBorder(new EmptyBorder(5, 15, 5, 15));
        previewPanel.add(new JLabel(text("Preview:")), BorderLayout.NORTH);
        previewPanel.add(new JScrollPane(preview), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        buttons.add(applyButton);
        buttons.add(cancelButton);

        dialog.add(choices, BorderLayout.NORTH);
        dialog.add(previewPanel, BorderLayout.CENTER);
        dialog.add(buttons, BorderLayout.SOUTH);
        updateTargets.run();
        dialog.setVisible(true);
    }

    private String formatRemapPreview(String source, String target, VariableNames.FolderRemapResult result,
                                      VariableNames.PlaceholderStyle placeholderStyle) {
        StringBuilder text = new StringBuilder();
        if (result.replacedVariables().isEmpty()) {
            text.append(variableManager.text("There are no matching variables between these folders."));
        } else {
            text.append(variableManager.text("The following will be replaced:\n"));
            for (String localName : result.replacedVariables()) {
                text.append("  ").append(VariableNames.placeholder(source + "." + localName, placeholderStyle))
                        .append("  \u2192  ").append(VariableNames.placeholder(
                                target + "." + localName, placeholderStyle)).append('\n');
            }
        }
        if (!result.unmatchedVariables().isEmpty()) {
            text.append(variableManager.text("\nThe following will be kept because they do not exist in the target folder:\n"));
            for (String localName : result.unmatchedVariables()) {
                text.append("  ").append(VariableNames.placeholder(
                        source + "." + localName, placeholderStyle)).append('\n');
            }
        }
        return text.toString();
    }

    private String editableRequestText(HttpRequest request) {
        StringBuilder text = new StringBuilder(request.path()).append('\n');
        for (HttpHeader header : request.headers()) text.append(header.value()).append('\n');
        if (request.bodyToString() != null) text.append(request.bodyToString());
        return text.toString();
    }

    private RequestRemapResult remapRequest(HttpRequest request, String source, String target,
                                             Set<String> targetLocalNames,
                                             VariableNames.PlaceholderStyle placeholderStyle) {
        Set<String> replaced = new LinkedHashSet<>();
        Set<String> unmatched = new LinkedHashSet<>();
        HttpRequest rewritten = request;

        VariableNames.FolderRemapResult pathResult = VariableNames.remapFolderPlaceholders(
                request.path(), source, target, targetLocalNames, placeholderStyle);
        collectRemap(pathResult, replaced, unmatched);
        if (pathResult.changed()) rewritten = rewritten.withPath(pathResult.text());

        List<HttpHeader> newHeaders = new ArrayList<>();
        boolean headersChanged = false;
        for (HttpHeader header : request.headers()) {
            VariableNames.FolderRemapResult headerResult = VariableNames.remapFolderPlaceholders(
                    header.value(), source, target, targetLocalNames, placeholderStyle);
            collectRemap(headerResult, replaced, unmatched);
            if (headerResult.changed()) {
                newHeaders.add(HttpHeader.httpHeader(header.name(), headerResult.text()));
                headersChanged = true;
            } else {
                newHeaders.add(header);
            }
        }
        if (headersChanged) {
            rewritten = rewritten.withRemovedHeaders(rewritten.headers()).withAddedHeaders(newHeaders);
        }

        String body = request.bodyToString();
        VariableNames.FolderRemapResult bodyResult = VariableNames.remapFolderPlaceholders(
                body, source, target, targetLocalNames, placeholderStyle);
        collectRemap(bodyResult, replaced, unmatched);
        if (bodyResult.changed()) rewritten = rewritten.withBody(bodyResult.text());

        return new RequestRemapResult(rewritten, List.copyOf(replaced), List.copyOf(unmatched));
    }

    private void collectRemap(VariableNames.FolderRemapResult result, Set<String> replaced, Set<String> unmatched) {
        replaced.addAll(result.replacedVariables());
        unmatched.addAll(result.unmatchedVariables());
    }

    private record RequestRemapResult(HttpRequest request, List<String> replacedVariables,
                                      List<String> unmatchedVariables) {}

    private record SelectedExtraction(String selectedText, String source, String regex) {}

    private final class ExtractionValueEditor {
        private final String name;
        private final String selectedValue;
        private final JComboBox<String> sourceComboBox;
        private final JTextField regexField;

        private ExtractionValueEditor(String name, SelectedExtraction extraction) {
            this.name = name;
            this.selectedValue = extraction.selectedText();
            this.sourceComboBox = new JComboBox<>(new String[]{
                    text("Response Body"), text("Response Headers"),
                    text("Request Body"), text("Request Headers")
            });
            this.sourceComboBox.setSelectedIndex(sourceIndex(extraction.source()));
            this.regexField = new JTextField(extraction.regex(), 50);
        }

        private VariableExtractionRule.ExtractionTarget target() {
            return new VariableExtractionRule.ExtractionTarget(
                    name, extractionSource(sourceComboBox.getSelectedIndex()), regexField.getText().trim());
        }
    }

    private void showConfigDialog(ContextMenuEvent event) {
        MessageEditorHttpRequestResponse reqResp = event.messageEditorRequestResponse().get();
        Range range = reqResp.selectionOffsets().get();
        int start = range.startIndexInclusive();
        int end = range.endIndexExclusive();

        HttpRequestResponse requestResponse = reqResp.requestResponse();
        
        boolean isRequest = reqResp.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST;
        
        byte[] bytes;
        if (isRequest) {
            bytes = requestResponse.request().toByteArray().getBytes();
        } else {
            bytes = requestResponse.response().toByteArray().getBytes();
        }
        
        String textStr = new String(bytes, StandardCharsets.UTF_8);
        String path = requestResponse.request().path();

        // Slice selected text
        if (start < 0 || end > textStr.length() || start >= end) {
            Frame suiteFrame = api.userInterface().swingUtils().suiteFrame();
            JOptionPane.showMessageDialog(suiteFrame, text("Invalid selection range."), text("Error"), JOptionPane.ERROR_MESSAGE);
            return;
        }
        SelectedExtraction initialExtraction = analyzeSelection(textStr, start, end, isRequest);
        String selectedText = initialExtraction.selectedText();
        String source = initialExtraction.source();
        String proposedRegex = initialExtraction.regex();

        // Build the Swing dialog
        Frame suiteFrame = api.userInterface().swingUtils().suiteFrame();
        JDialog dialog = new JDialog(suiteFrame, text("Assign to Variable"), Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));
        Runnable[] fitDialogToContent = {() -> {}};

        JTabbedPane dialogTabs = new JTabbedPane();
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));
        JPanel extractionTabPanel = new JPanel(new GridBagLayout());
        extractionTabPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        dialogTabs.addTab(text("Variable and configuration"), panel);
        dialogTabs.addTab(text("Values and extraction"), extractionTabPanel);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridx = 0;

        // Row 0: Folder
        gbc.gridy = 0;
        gbc.weightx = 0.0;
        panel.add(new JLabel(text("Folder:")), gbc);

        List<String> folderNames = new ArrayList<>(variableManager.getFolderNames());
        JComboBox<String> folderComboBox = new JComboBox<>();
        folderComboBox.addItem(text("Ungrouped"));
        for (String folderName : folderNames) folderComboBox.addItem(folderName);
        folderComboBox.setEditable(true);
        folderComboBox.setToolTipText(text("Search or create a folder"));
        JButton createFolderButton = new JButton(text("Create folder"));
        createFolderButton.setEnabled(false);
        JLabel folderHint = new JLabel(text(
                "Type to filter folders. If the name does not exist, create it here."));
        folderHint.setForeground(UIManager.getColor("Label.disabledForeground"));
        JPanel folderInputPanel = new JPanel(new BorderLayout(6, 2));
        folderInputPanel.add(folderComboBox, BorderLayout.CENTER);
        folderInputPanel.add(createFolderButton, BorderLayout.EAST);
        folderInputPanel.add(folderHint, BorderLayout.SOUTH);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(folderInputPanel, gbc);

        // Row 1: Variable Name (Editable ComboBox)
        gbc.gridy = 1;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        panel.add(new JLabel(text("Variable Name:")), gbc);

        List<String> names = variableManager.getVariableNamesInFolder("");
        JComboBox<String> nameComboBox = new JComboBox<>(names.toArray(new String[0]));
        nameComboBox.setEditable(true);
        if (!names.isEmpty()) {
            nameComboBox.setSelectedIndex(0);
        }
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(nameComboBox, gbc);

        boolean[] updatingFolderSuggestions = {false};
        Runnable reloadVariableNames = () -> {
            if (updatingFolderSuggestions[0]) return;
            String folder = existingFolderName(
                    folderNames, folderEditorText(folderComboBox), text("Ungrouped"));
            if (folder == null) return;
            Object editorValue = nameComboBox.getEditor().getItem();
            nameComboBox.removeAllItems();
            for (String variable : variableManager.getVariableNamesInFolder(folder)) nameComboBox.addItem(variable);
            if (nameComboBox.getItemCount() > 0) nameComboBox.setSelectedIndex(0);
            else if (editorValue != null) nameComboBox.getEditor().setItem(editorValue);
        };
        Runnable updateCreateFolderButton = () -> {
            String candidate = folderEditorText(folderComboBox);
            boolean existing = existingFolderName(
                    folderNames, candidate, text("Ungrouped")) != null;
            createFolderButton.setEnabled(
                    !candidate.isEmpty() && !existing && VariableNames.isValidComponent(candidate));
        };
        Runnable filterFolderSuggestions = () -> {
            if (updatingFolderSuggestions[0]) return;
            String query = folderEditorText(folderComboBox);
            SwingUtilities.invokeLater(() -> {
                if (updatingFolderSuggestions[0]) return;
                updatingFolderSuggestions[0] = true;
                try {
                    DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>();
                    for (String suggestion : filterFolderNames(
                            folderNames, query, text("Ungrouped"))) {
                        model.addElement(suggestion);
                    }
                    folderComboBox.setModel(model);
                    folderComboBox.setSelectedItem(query);
                    Component editor = folderComboBox.getEditor().getEditorComponent();
                    if (editor instanceof JTextField field) {
                        field.setText(query);
                        field.setCaretPosition(query.length());
                    }
                    updateCreateFolderButton.run();
                    if (!query.isEmpty() && model.getSize() > 0
                            && folderComboBox.isShowing()
                            && editor.isFocusOwner()) {
                        folderComboBox.showPopup();
                    }
                } finally {
                    updatingFolderSuggestions[0] = false;
                }
            });
        };
        Component folderEditor = folderComboBox.getEditor().getEditorComponent();
        if (folderEditor instanceof JTextField folderTextField) {
            folderTextField.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent event) {
                    filterFolderSuggestions.run();
                }

                @Override
                public void removeUpdate(DocumentEvent event) {
                    filterFolderSuggestions.run();
                }

                @Override
                public void changedUpdate(DocumentEvent event) {
                    filterFolderSuggestions.run();
                }
            });
        }
        folderComboBox.addActionListener(e -> {
            reloadVariableNames.run();
            updateCreateFolderButton.run();
        });
        createFolderButton.addActionListener(e -> {
            String candidate = folderEditorText(folderComboBox);
            if (!VariableNames.isValidComponent(candidate)) {
                JOptionPane.showMessageDialog(dialog,
                        text("Folder") + text(" names cannot contain '.'."),
                        text("Invalid Name"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            try {
                variableManager.createFolder(candidate);
                folderNames.add(candidate);
                updatingFolderSuggestions[0] = true;
                try {
                    folderComboBox.setModel(new DefaultComboBoxModel<>(
                            filterFolderNames(folderNames, candidate, text("Ungrouped"))
                                    .toArray(new String[0])));
                    folderComboBox.setSelectedItem(candidate);
                    folderComboBox.getEditor().setItem(candidate);
                } finally {
                    updatingFolderSuggestions[0] = false;
                }
                updateCreateFolderButton.run();
                reloadVariableNames.run();
            } catch (IllegalStateException duplicate) {
                JOptionPane.showMessageDialog(dialog,
                        text("A folder with this name already exists."),
                        text("Duplicate Folder"), JOptionPane.ERROR_MESSAGE);
            } catch (IllegalArgumentException invalid) {
                JOptionPane.showMessageDialog(dialog,
                        text("Folder") + text(" names cannot contain '.'."),
                        text("Invalid Name"), JOptionPane.ERROR_MESSAGE);
            }
        });

        GridBagConstraints xgbc = new GridBagConstraints();
        xgbc.fill = GridBagConstraints.HORIZONTAL;
        xgbc.insets = new Insets(5, 5, 5, 5);
        xgbc.anchor = GridBagConstraints.NORTHWEST;

        // Extraction tab, row 0: Optional multiple-value mode
        xgbc.gridy = 0;
        xgbc.gridx = 0;
        xgbc.gridwidth = 2;
        JCheckBox multipleValuesCheckBox = new JCheckBox(text("Extract multiple values"), false);
        multipleValuesCheckBox.setToolTipText(text(
                "Each value has its own source and regex. The final template combines them into the parent variable."));
        extractionTabPanel.add(multipleValuesCheckBox, xgbc);

        // Extraction tab, row 1: Selected Value (single-value mode)
        xgbc.gridy = 1;
        xgbc.gridx = 0;
        xgbc.gridwidth = 1;
        xgbc.weightx = 0.0;
        JLabel selectedValueLabel = new JLabel(text("Selected Value:"));
        extractionTabPanel.add(selectedValueLabel, xgbc);
        JTextArea valuePreview = new JTextArea(3, 20);
        valuePreview.setText(selectedText);
        valuePreview.setEditable(false);
        valuePreview.setLineWrap(true);
        valuePreview.setWrapStyleWord(true);
        valuePreview.setBackground(panel.getBackground());
        xgbc.gridx = 1;
        xgbc.weightx = 1.0;
        JScrollPane valuePreviewScroll = new JScrollPane(valuePreview);
        extractionTabPanel.add(valuePreviewScroll, xgbc);

        // Extraction tab, row 2: Multiple extraction values
        String targetPrefix = text("value");
        List<ExtractionValueEditor> extractionEditors = new ArrayList<>();
        extractionEditors.add(new ExtractionValueEditor(targetPrefix + "1", initialExtraction));
        JComboBox<String> extractionValueSelector = new JComboBox<>();
        JPanel extractionValueDetails = new JPanel(new GridBagLayout());
        JButton addExtractionValueButton = new JButton(text("Add value to extract..."));
        JButton removeExtractionValueButton = new JButton(text("Remove value"));
        JPanel selectorPanel = new JPanel(new BorderLayout(8, 0));
        selectorPanel.add(new JLabel(text("Value to extract:")), BorderLayout.WEST);
        selectorPanel.add(extractionValueSelector, BorderLayout.CENTER);
        JPanel extractionButtons = new JPanel(new GridLayout(1, 2, 8, 0));
        extractionButtons.add(addExtractionValueButton);
        extractionButtons.add(removeExtractionValueButton);
        JPanel multipleValuesPanel = new JPanel(new BorderLayout(5, 5));
        multipleValuesPanel.setBorder(BorderFactory.createTitledBorder(text("Values to extract")));
        multipleValuesPanel.add(selectorPanel, BorderLayout.NORTH);
        multipleValuesPanel.add(extractionValueDetails, BorderLayout.CENTER);
        multipleValuesPanel.add(extractionButtons, BorderLayout.SOUTH);
        multipleValuesPanel.setVisible(false);
        xgbc.gridy = 2;
        xgbc.gridx = 0;
        xgbc.gridwidth = 2;
        xgbc.weightx = 1.0;
        xgbc.weighty = 0.0;
        xgbc.fill = GridBagConstraints.BOTH;
        extractionTabPanel.add(multipleValuesPanel, xgbc);
        xgbc.weighty = 0.0;
        xgbc.fill = GridBagConstraints.HORIZONTAL;

        // Extraction tab, row 3: Final parent value template
        xgbc.gridy = 3;
        xgbc.gridx = 0;
        xgbc.gridwidth = 1;
        xgbc.weightx = 0.0;
        JLabel finalTemplateLabel = new JLabel(text("Final value template:"));
        finalTemplateLabel.setVisible(false);
        extractionTabPanel.add(finalTemplateLabel, xgbc);
        JTextField finalTemplateField = new JTextField(defaultValueTemplate(extractionEditors), 50);
        finalTemplateField.setToolTipText(text(
                "Use placeholders such as {{value1}} and {{value2}} to compose the parent variable."));
        finalTemplateField.setVisible(false);
        xgbc.gridx = 1;
        xgbc.weightx = 1.0;
        extractionTabPanel.add(finalTemplateField, xgbc);

        // Configuration tab, row 2: Match URL/Path
        gbc.gridy = 2;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        panel.add(new JLabel(text("Path (literal; query ignored):")), gbc);

        JTextField pathField = new JTextField(path, 50);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(pathField, gbc);

        // Extraction tab, row 4: Extract From (single-value mode)
        xgbc.gridy = 4;
        xgbc.gridx = 0;
        xgbc.weightx = 0.0;
        JLabel sourceLabel = new JLabel(text("Extract From:"));
        extractionTabPanel.add(sourceLabel, xgbc);

        JComboBox<String> sourceComboBox = new JComboBox<>(new String[]{
            text("Response Body"), text("Response Headers"), text("Request Body"), text("Request Headers")
        });
        if ("request_body".equals(source)) {
            sourceComboBox.setSelectedIndex(2);
        } else if ("request_headers".equals(source)) {
            sourceComboBox.setSelectedIndex(3);
        } else if ("headers".equals(source)) {
            sourceComboBox.setSelectedIndex(1);
        } else {
            sourceComboBox.setSelectedIndex(0);
        }
        xgbc.gridx = 1;
        xgbc.weightx = 1.0;
        extractionTabPanel.add(sourceComboBox, xgbc);

        // Extraction tab, row 5: Regex Pattern (single-value mode)
        xgbc.gridy = 5;
        xgbc.gridx = 0;
        xgbc.weightx = 0.0;
        JLabel regexLabel = new JLabel(text("Regex Pattern (1 group):"));
        extractionTabPanel.add(regexLabel, xgbc);

        JTextField regexField = new JTextField(proposedRegex, 50);
        xgbc.gridx = 1;
        xgbc.weightx = 1.0;
        extractionTabPanel.add(regexField, xgbc);

        xgbc.gridy = 6;
        xgbc.gridx = 0;
        xgbc.gridwidth = 2;
        xgbc.weightx = 1.0;
        xgbc.weighty = 1.0;
        xgbc.fill = GridBagConstraints.BOTH;
        extractionTabPanel.add(Box.createVerticalGlue(), xgbc);
        xgbc.weighty = 0.0;
        xgbc.fill = GridBagConstraints.HORIZONTAL;

        // Configuration tab, row 3: Save Request checkbox
        gbc.gridy = 3;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        JCheckBox saveRequestCheckBox = new JCheckBox(text("Save this request to refresh token in the future"), true);
        panel.add(saveRequestCheckBox, gbc);

        // Configuration tab, row 4: Initial automation state for the variable
        gbc.gridy = 4;
        JPanel automationPanel = new JPanel();
        automationPanel.setLayout(new BoxLayout(automationPanel, BoxLayout.Y_AXIS));
        automationPanel.setBorder(BorderFactory.createTitledBorder(text("Variable automation")));

        JCheckBox passiveExtractionCheckBox = new JCheckBox(
                text("Update this variable from matching responses"), false);
        passiveExtractionCheckBox.setToolTipText(text(
                "Requires global response extraction and extraction for the current Burp tool to be enabled."));
        automationPanel.add(passiveExtractionCheckBox);
        automationPanel.add(secondaryLabel(text(
                "Matching responses update the value passively; no request is retried.")));
        automationPanel.add(Box.createVerticalStrut(6));

        JCheckBox sessionRecoveryCheckBox = new JCheckBox(
                text("Use this variable for expired-session recovery"), false);
        sessionRecoveryCheckBox.setToolTipText(text(
                "Requires global session recovery, recovery for the current Burp tool, and a saved refresh request."));
        automationPanel.add(sessionRecoveryCheckBox);
        automationPanel.add(secondaryLabel(text(
                "After a configured status, the saved request obtains a new value and the original request is retried.")));
        panel.add(automationPanel, gbc);

        gbc.gridy = 5;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(Box.createVerticalGlue(), gbc);
        gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        boolean[] updatingExtractionSelector = {false};
        Runnable refreshSelectedExtractionEditor = () -> {
            if (updatingExtractionSelector[0]) return;
            showSelectedExtractionValue(
                    extractionValueDetails, extractionValueSelector,
                    extractionEditors, removeExtractionValueButton);
        };
        extractionValueSelector.addActionListener(e -> refreshSelectedExtractionEditor.run());
        refreshExtractionValueSelector(
                extractionValueSelector, extractionValueDetails, extractionEditors,
                removeExtractionValueButton, updatingExtractionSelector, 0);
        addExtractionValueButton.addActionListener(e -> {
            SelectedExtraction additional = selectAdditionalExtraction(dialog, textStr, isRequest);
            if (additional == null) return;
            String nextName = nextExtractionValueName(targetPrefix, extractionEditors);
            extractionEditors.add(new ExtractionValueEditor(nextName, additional));
            finalTemplateField.setText(defaultValueTemplate(extractionEditors));
            refreshExtractionValueSelector(
                    extractionValueSelector, extractionValueDetails, extractionEditors,
                    removeExtractionValueButton, updatingExtractionSelector,
                    extractionEditors.size() - 1);
            fitDialogToContent[0].run();
        });
        removeExtractionValueButton.addActionListener(e -> {
            int selectedIndex = extractionValueSelector.getSelectedIndex();
            if (selectedIndex < 0 || extractionEditors.size() <= 1) return;
            extractionEditors.remove(selectedIndex);
            finalTemplateField.setText(defaultValueTemplate(extractionEditors));
            refreshExtractionValueSelector(
                    extractionValueSelector, extractionValueDetails, extractionEditors,
                    removeExtractionValueButton, updatingExtractionSelector,
                    Math.min(selectedIndex, extractionEditors.size() - 1));
            fitDialogToContent[0].run();
        });
        multipleValuesCheckBox.addActionListener(e -> {
            boolean multiple = multipleValuesCheckBox.isSelected();
            if (multiple) {
                ExtractionValueEditor first = extractionEditors.get(0);
                first.sourceComboBox.setSelectedIndex(sourceComboBox.getSelectedIndex());
                first.regexField.setText(regexField.getText());
                refreshSelectedExtractionEditor.run();
            }
            selectedValueLabel.setVisible(!multiple);
            valuePreviewScroll.setVisible(!multiple);
            sourceLabel.setVisible(!multiple);
            sourceComboBox.setVisible(!multiple);
            regexLabel.setVisible(!multiple);
            regexField.setVisible(!multiple);
            multipleValuesPanel.setVisible(multiple);
            finalTemplateLabel.setVisible(multiple);
            finalTemplateField.setVisible(multiple);
            extractionTabPanel.revalidate();
            extractionTabPanel.repaint();
            fitDialogToContent[0].run();
        });

        passiveExtractionCheckBox.addActionListener(e -> {
            if (passiveExtractionCheckBox.isSelected()
                    && !variableManager.ensureGlobalAutomationEnabled(dialog, false)) {
                passiveExtractionCheckBox.setSelected(false);
            }
        });
        sessionRecoveryCheckBox.addActionListener(e -> {
            if (sessionRecoveryCheckBox.isSelected()
                    && !variableManager.ensureGlobalAutomationEnabled(dialog, true)) {
                sessionRecoveryCheckBox.setSelected(false);
            }
        });
        saveRequestCheckBox.addActionListener(e -> {
            boolean requestSaved = saveRequestCheckBox.isSelected();
            sessionRecoveryCheckBox.setEnabled(requestSaved);
            if (!requestSaved) sessionRecoveryCheckBox.setSelected(false);
        });
        Runnable loadExistingAutomationState = () -> {
            Object selectedVariable = nameComboBox.getEditor().getItem();
            if (selectedVariable == null) return;
            String localName = selectedVariable.toString().trim();
            String selectedFolder = existingFolderName(
                    folderNames, folderEditorText(folderComboBox), text("Ungrouped"));
            VariableExtractionRule existingRule = selectedFolder == null ? null
                    : variableManager.getRules().get(
                            variableManager.qualifyVariableName(selectedFolder, localName));
            passiveExtractionCheckBox.setSelected(existingRule != null && existingRule.isEnabled());
            sessionRecoveryCheckBox.setSelected(existingRule != null
                    && existingRule.isAutomaticRefreshEnabled()
                    && saveRequestCheckBox.isSelected());
        };
        nameComboBox.addActionListener(e -> loadExistingAutomationState.run());
        folderComboBox.addActionListener(e ->
                SwingUtilities.invokeLater(loadExistingAutomationState));
        loadExistingAutomationState.run();

        gbc.gridwidth = 1;

        // Row 6: Action Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        JButton saveButton = new JButton(text("Save Rule"));
        JButton cancelButton = new JButton(text("Cancel"));

        saveButton.addActionListener(al -> {
            Object selectedItem = nameComboBox.getEditor().getItem();
            if (selectedItem == null || selectedItem.toString().trim().isEmpty()) {
                dialogTabs.setSelectedIndex(0);
                JOptionPane.showMessageDialog(dialog, text("Please select or type a variable name."), text("Error"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            String varName = selectedItem.toString().trim();
            if (varName.contains(".")) {
                dialogTabs.setSelectedIndex(0);
                JOptionPane.showMessageDialog(dialog, text("Variable names cannot contain '.'. Choose the folder separately."), text("Error"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            String folderInput = folderEditorText(folderComboBox);
            String folderName = existingFolderName(
                    folderNames, folderInput, text("Ungrouped"));
            if (folderName == null) {
                if (!VariableNames.isValidComponent(folderInput)) {
                    dialogTabs.setSelectedIndex(0);
                    JOptionPane.showMessageDialog(dialog,
                            text("Folder") + text(" names cannot contain '.'."),
                            text("Invalid Name"), JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }
            String pathFilter = pathField.getText().trim();
            String chosenSource = storedSource(sourceComboBox.getSelectedIndex());
            String regexPattern = regexField.getText().trim();
            List<VariableExtractionRule.ExtractionTarget> configuredTargets;
            String configuredTemplate;
            String configuredValue;
            if (multipleValuesCheckBox.isSelected()) {
                configuredTargets = extractionEditors.stream()
                        .map(ExtractionValueEditor::target).toList();
                for (VariableExtractionRule.ExtractionTarget target : configuredTargets) {
                    if (!ExtractionEngine.isValidRegex(target.regex())
                            || !ExtractionEngine.hasCaptureGroup(target.regex())) {
                        dialogTabs.setSelectedIndex(1);
                        JOptionPane.showMessageDialog(dialog,
                                text("Every extraction value must have a valid regex with at least one capture group."),
                                text("Error"), JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                }
                configuredTemplate = finalTemplateField.getText();
                if (!ExtractionEngine.isValidValueTemplate(configuredTemplate, configuredTargets)) {
                    dialogTabs.setSelectedIndex(1);
                    JOptionPane.showMessageDialog(dialog,
                            text("The final value template must reference every extraction value."),
                            text("Error"), JOptionPane.ERROR_MESSAGE);
                    return;
                }
                configuredValue = ExtractionEngine.composeValue(
                        configuredTargets,
                        extractionEditors.stream().map(editor -> editor.selectedValue).toList(),
                        configuredTemplate);
                if (configuredValue == null) {
                    dialogTabs.setSelectedIndex(1);
                    JOptionPane.showMessageDialog(dialog,
                            text("The final value template is invalid."),
                            text("Error"), JOptionPane.ERROR_MESSAGE);
                    return;
                }
            } else {
                if (!ExtractionEngine.isValidRegex(regexPattern)
                        || !ExtractionEngine.hasCaptureGroup(regexPattern)) {
                    dialogTabs.setSelectedIndex(1);
                    JOptionPane.showMessageDialog(dialog,
                            text("The extraction regex must be valid and contain at least one capture group."),
                            text("Error"), JOptionPane.ERROR_MESSAGE);
                    return;
                }
                configuredTargets = List.of(new VariableExtractionRule.ExtractionTarget(
                        "value1", VariableExtractionRule.ExtractionSource.fromStored(chosenSource), regexPattern));
                configuredTemplate = "{{value1}}";
                configuredValue = selectedText;
            }

            if (folderName == null) {
                int create = JOptionPane.showConfirmDialog(
                        dialog, text("The folder does not exist. Create it now?"),
                        text("Create folder"), JOptionPane.YES_NO_OPTION,
                        JOptionPane.QUESTION_MESSAGE);
                if (create != JOptionPane.YES_OPTION) return;
                try {
                    variableManager.createFolder(folderInput);
                    folderNames.add(folderInput);
                    folderName = folderInput;
                } catch (IllegalStateException duplicate) {
                    folderName = existingFolderName(
                            variableManager.getFolderNames(), folderInput, text("Ungrouped"));
                    if (folderName == null) return;
                } catch (IllegalArgumentException invalid) {
                    JOptionPane.showMessageDialog(dialog,
                            text("Folder") + text(" names cannot contain '.'."),
                            text("Invalid Name"), JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }

            String qualifiedName = variableManager.qualifyVariableName(folderName, varName);
            if (variableManager.getVariables().containsKey(qualifiedName)) {
                Object[] options = {
                        text("Update existing variable"),
                        text("Create with another name"),
                        text("Cancel")
                };
                int choice = JOptionPane.showOptionDialog(
                        dialog,
                        String.format(text(
                                "The variable \"%s\" already exists in this folder. Choose whether to update it or create a new variable."),
                                varName),
                        text("Variable already exists"),
                        JOptionPane.DEFAULT_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        null,
                        options,
                        options[0]);
                if (choice == 1) {
                    String alternativeName = requestAlternativeVariableName(
                            dialog, folderName, varName);
                    if (alternativeName == null) return;
                    varName = alternativeName;
                    nameComboBox.getEditor().setItem(varName);
                } else if (choice != 0) {
                    return;
                }
            }

            String reqBase64 = "";
            String host = requestResponse.request().httpService().host();
            int port = requestResponse.request().httpService().port();
            boolean secure = requestResponse.request().httpService().secure();

            if (saveRequestCheckBox.isSelected()) {
                byte[] requestBytes = requestResponse.request().toByteArray().getBytes();
                reqBase64 = Base64.getEncoder().encodeToString(requestBytes);
            }

            // Save variables & rules
            if (multipleValuesCheckBox.isSelected()) {
                variableManager.addOrUpdateMultipleExtractionRuleInFolder(
                        folderName,
                        varName,
                        configuredValue,
                        passiveExtractionCheckBox.isSelected(),
                        sessionRecoveryCheckBox.isSelected(),
                        pathFilter,
                        configuredTargets,
                        configuredTemplate,
                        requestResponse.request().method(),
                        reqBase64,
                        host,
                        port,
                        secure
                );
            } else {
                variableManager.addOrUpdateExtractionRuleInFolder(
                        folderName,
                        varName,
                        configuredValue,
                        passiveExtractionCheckBox.isSelected(),
                        sessionRecoveryCheckBox.isSelected(),
                        pathFilter,
                        chosenSource,
                        regexPattern,
                        requestResponse.request().method(),
                        reqBase64,
                        host,
                        port,
                        secure
                );
            }
            dialog.dispose();
        });

        cancelButton.addActionListener(al -> dialog.dispose());

        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);

        dialog.add(dialogTabs, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        fitDialogToContent[0] = () -> fitAssignmentDialogToContent(dialog, suiteFrame);
        dialogTabs.addChangeListener(e -> fitDialogToContent[0].run());
        fitDialogToContent[0].run();
        dialog.setVisible(true);
    }

    private void fitAssignmentDialogToContent(JDialog dialog, Frame owner) {
        dialog.pack();
        Rectangle screen = owner.getGraphicsConfiguration().getBounds();
        int width = Math.max(760, Math.min(dialog.getWidth(), 1050));
        int maximumHeight = Math.max(520, (int) (screen.height * 0.88));
        int height = dialog.getHeight();
        Component center = ((BorderLayout) dialog.getContentPane().getLayout())
                .getLayoutComponent(BorderLayout.CENTER);
        if (center instanceof JTabbedPane tabs && tabs.getSelectedComponent() != null) {
            Dimension tabsPreferred = tabs.getPreferredSize();
            int largestPageHeight = 0;
            for (int index = 0; index < tabs.getTabCount(); index++) {
                largestPageHeight = Math.max(
                        largestPageHeight, tabs.getComponentAt(index).getPreferredSize().height);
            }
            int tabChromeHeight = Math.max(0, tabsPreferred.height - largestPageHeight);
            int nonTabHeight = Math.max(0, dialog.getHeight() - tabsPreferred.height);
            height = nonTabHeight + tabChromeHeight
                    + tabs.getSelectedComponent().getPreferredSize().height;
        }
        height = Math.min(height, maximumHeight);
        dialog.setSize(width, height);
        dialog.setLocationRelativeTo(owner);
    }

    private SelectedExtraction analyzeSelection(String rawMessage, int start, int end, boolean requestContent) {
        String selected = rawMessage.substring(start, end);
        int separator = rawMessage.indexOf("\r\n\r\n");
        int separatorLength = 4;
        if (separator < 0) {
            separator = rawMessage.indexOf("\n\n");
            separatorLength = 2;
        }

        String source = requestContent ? "request_body" : "body";
        String contextText = rawMessage;
        int contextStart = start;
        int contextEnd = end;
        if (separator >= 0) {
            if (start < separator) {
                source = requestContent ? "request_headers" : "headers";
                contextText = rawMessage.substring(0, separator);
            } else {
                contextText = rawMessage.substring(separator + separatorLength);
                contextStart = Math.max(0, start - separator - separatorLength);
                contextEnd = Math.max(0, end - separator - separatorLength);
            }
        }
        return new SelectedExtraction(
                selected, source, generateProposedRegex(contextText, contextStart, contextEnd));
    }

    private SelectedExtraction selectAdditionalExtraction(
            Component parent, String rawMessage, boolean requestContent) {
        SelectedExtraction[] result = {null};
        Window owner = SwingUtilities.getWindowAncestor(parent);
        JDialog selector = new JDialog(owner, text("Select another value to extract"),
                Dialog.ModalityType.APPLICATION_MODAL);
        selector.setLayout(new BorderLayout(8, 8));
        selector.setSize(820, 620);
        selector.setLocationRelativeTo(parent);

        JLabel instructions = new JLabel(text(
                "Select one value in the message below, then click Use selected value."));
        instructions.setBorder(new EmptyBorder(8, 8, 0, 8));
        selector.add(instructions, BorderLayout.NORTH);

        // Burp's native message editor so the value can be selected from Pretty as well
        // as Raw, exactly like the "Update Rule from Response..." selector does.
        byte[] messageBytes = rawMessage.getBytes(StandardCharsets.UTF_8);
        Editor messageEditor;
        if (requestContent) {
            HttpRequestEditor requestEditor = api.userInterface()
                    .createHttpRequestEditor(EditorOptions.READ_ONLY);
            requestEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(messageBytes)));
            messageEditor = requestEditor;
        } else {
            HttpResponseEditor responseEditor = api.userInterface()
                    .createHttpResponseEditor(EditorOptions.READ_ONLY);
            responseEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(messageBytes)));
            messageEditor = responseEditor;
        }
        selector.add(messageEditor.uiComponent(), BorderLayout.CENTER);

        // Native editors don't expose a caret listener, so poll their selection while
        // this modal dialog is open and remember the last non-empty one.
        String[] lastSelectedText = {""};
        int[] lastSelectionStart = {-1};
        javax.swing.Timer selectionTimer = new javax.swing.Timer(150, event -> {
            Optional<Selection> currentSelection = messageEditor.selection();
            if (currentSelection.isEmpty()) return;
            Selection selection = currentSelection.get();
            String selectedText = new String(
                    selection.contents().getBytes(), StandardCharsets.UTF_8);
            if (selectedText.isEmpty()) return;
            lastSelectedText[0] = selectedText;
            lastSelectionStart[0] = selection.offsets().startIndexInclusive();
        });
        selectionTimer.start();

        JButton useSelection = new JButton(text("Use selected value"));
        useSelection.addActionListener(e -> {
            String selectedText = lastSelectedText[0];
            if (selectedText.isEmpty()) {
                JOptionPane.showMessageDialog(selector,
                        text("Select a value in the message first."),
                        text("Error"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            // Pretty views renumber offsets, so resolve the selection against the raw message.
            int start = VariableManager.locateSelection(
                    rawMessage, selectedText, lastSelectionStart[0],
                    lastSelectionStart[0] + selectedText.length());
            if (start < 0) {
                JOptionPane.showMessageDialog(selector,
                        text("Select a value in the message first."),
                        text("Error"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            result[0] = analyzeSelection(
                    rawMessage, start, start + selectedText.length(), requestContent);
            selector.dispose();
        });
        JButton cancel = new JButton(text("Cancel"));
        cancel.addActionListener(e -> selector.dispose());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 6));
        buttons.add(useSelection);
        buttons.add(cancel);
        selector.add(buttons, BorderLayout.SOUTH);
        selector.setVisible(true);
        selectionTimer.stop();
        return result[0];
    }

    private void refreshExtractionValueSelector(
            JComboBox<String> selector, JPanel details,
            List<ExtractionValueEditor> editors, JButton removeButton,
            boolean[] updatingSelector, int selectedIndex) {
        updatingSelector[0] = true;
        try {
            selector.removeAllItems();
            for (ExtractionValueEditor editor : editors) selector.addItem(editor.name);
            if (!editors.isEmpty()) {
                selector.setSelectedIndex(Math.max(0, Math.min(selectedIndex, editors.size() - 1)));
            }
        } finally {
            updatingSelector[0] = false;
        }
        showSelectedExtractionValue(details, selector, editors, removeButton);
    }

    private void showSelectedExtractionValue(
            JPanel details, JComboBox<String> selector,
            List<ExtractionValueEditor> editors, JButton removeButton) {
        details.removeAll();
        int selectedIndex = selector.getSelectedIndex();
        if (selectedIndex < 0 || selectedIndex >= editors.size()) {
            removeButton.setEnabled(false);
            details.revalidate();
            details.repaint();
            return;
        }
        ExtractionValueEditor editor = editors.get(selectedIndex);
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.insets = new Insets(3, 5, 3, 5);
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.gridy = 0;
        constraints.gridx = 0;
        constraints.weightx = 0.0;
        details.add(new JLabel(text("Selected Value:")), constraints);
        JTextField selectedField = new JTextField(editor.selectedValue, 50);
        selectedField.setEditable(false);
        constraints.gridx = 1;
        constraints.weightx = 1.0;
        details.add(selectedField, constraints);

        constraints.gridy = 1;
        constraints.gridx = 0;
        constraints.weightx = 0.0;
        details.add(new JLabel(text("Extract From:")), constraints);
        constraints.gridx = 1;
        constraints.weightx = 1.0;
        details.add(editor.sourceComboBox, constraints);

        constraints.gridy = 2;
        constraints.gridx = 0;
        constraints.weightx = 0.0;
        details.add(new JLabel(text("Regex Pattern (1 group):")), constraints);
        constraints.gridx = 1;
        constraints.weightx = 1.0;
        details.add(editor.regexField, constraints);

        removeButton.setEnabled(editors.size() > 1);
        details.revalidate();
        details.repaint();
    }

    private String nextExtractionValueName(
            String prefix, List<ExtractionValueEditor> editors) {
        int suffix = 1;
        Set<String> usedNames = editors.stream()
                .map(editor -> editor.name).collect(java.util.stream.Collectors.toSet());
        while (usedNames.contains(prefix + suffix)) suffix++;
        return prefix + suffix;
    }

    private String defaultValueTemplate(List<ExtractionValueEditor> editors) {
        return editors.stream().map(editor -> "{{" + editor.name + "}}")
                .collect(java.util.stream.Collectors.joining("; "));
    }

    private int sourceIndex(String source) {
        return switch (source == null ? "" : source) {
            case "headers" -> 1;
            case "request_body" -> 2;
            case "request_headers" -> 3;
            default -> 0;
        };
    }

    private String storedSource(int sourceIndex) {
        return switch (sourceIndex) {
            case 1 -> "headers";
            case 2 -> "request_body";
            case 3 -> "request_headers";
            default -> "body";
        };
    }

    private VariableExtractionRule.ExtractionSource extractionSource(int sourceIndex) {
        return VariableExtractionRule.ExtractionSource.fromStored(storedSource(sourceIndex));
    }

    private String requestAlternativeVariableName(Component parent, String folderName, String originalName) {
        String suggestion = nextAvailableVariableName(folderName, originalName);
        while (true) {
            Object entered = JOptionPane.showInputDialog(
                    parent,
                    text("New variable name:"),
                    text("Create new variable"),
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    null,
                    suggestion);
            if (entered == null) return null;
            String candidate = entered.toString().trim();
            if (!VariableNames.isValidComponent(candidate)) {
                JOptionPane.showMessageDialog(parent,
                        text("Variable names cannot contain '.'. Choose the folder separately."),
                        text("Invalid Name"), JOptionPane.ERROR_MESSAGE);
                suggestion = candidate;
                continue;
            }
            String qualified = variableManager.qualifyVariableName(folderName, candidate);
            if (variableManager.getVariables().containsKey(qualified)) {
                JOptionPane.showMessageDialog(parent,
                        text("Variable '") + qualified + text("' already exists."),
                        text("Duplicate Variable"), JOptionPane.ERROR_MESSAGE);
                suggestion = nextAvailableVariableName(folderName, candidate);
                continue;
            }
            return candidate;
        }
    }

    private String nextAvailableVariableName(String folderName, String originalName) {
        Map<String, String> variables = variableManager.getVariables();
        int suffix = 2;
        String candidate;
        do {
            candidate = originalName + "_" + suffix++;
        } while (variables.containsKey(variableManager.qualifyVariableName(folderName, candidate)));
        return candidate;
    }

    private JLabel secondaryLabel(String value) {
        JLabel label = new JLabel(value);
        label.setForeground(UIManager.getColor("Label.disabledForeground"));
        label.setBorder(new EmptyBorder(0, 24, 0, 0));
        return label;
    }

    static List<String> filterFolderNames(List<String> folderNames, String query, String ungroupedLabel) {
        String normalizedQuery = query == null ? "" : query.trim().toLowerCase(java.util.Locale.ROOT);
        List<String> matches = new ArrayList<>();
        if (ungroupedLabel.toLowerCase(java.util.Locale.ROOT).contains(normalizedQuery)) {
            matches.add(ungroupedLabel);
        }
        if (folderNames != null) {
            for (String folderName : folderNames) {
                if (folderName != null
                        && folderName.toLowerCase(java.util.Locale.ROOT).contains(normalizedQuery)) {
                    matches.add(folderName);
                }
            }
        }
        return matches;
    }

    static String existingFolderName(List<String> folderNames, String input, String ungroupedLabel) {
        String normalized = input == null ? "" : input.trim();
        if (normalized.isEmpty() || normalized.equalsIgnoreCase(ungroupedLabel)) return "";
        if (folderNames == null) return null;
        return folderNames.stream()
                .filter(folder -> folder.equalsIgnoreCase(normalized))
                .findFirst()
                .orElse(null);
    }

    private String folderEditorText(JComboBox<String> folderComboBox) {
        Object editorValue = folderComboBox.getEditor().getItem();
        return editorValue == null ? "" : editorValue.toString().trim();
    }

    private String generateProposedRegex(String fullText, int start, int end) {
        if (fullText == null || start < 0 || end > fullText.length() || start >= end) {
            return "";
        }

        // Context search limits
        int precedingLimit = Math.max(0, start - 50);
        String preceding = fullText.substring(precedingLimit, start);

        int succeedingLimit = Math.min(fullText.length(), end + 30);
        String succeeding = fullText.substring(end, succeedingLimit);

        // 1. JSON key match: "key" : "value"
        java.util.regex.Pattern jsonPattern = java.util.regex.Pattern.compile("\"([a-zA-Z0-9_\\-]+)\"\\s*:\\s*\"$");
        java.util.regex.Matcher jsonMatcher = jsonPattern.matcher(preceding);
        if (jsonMatcher.find()) {
            String key = jsonMatcher.group(1);
            return "\"" + key + "\"\\s*:\\s*\"([^\"]+)\"";
        }

        // 2. Query/Form parameter match: key=value
        java.util.regex.Pattern paramPattern = java.util.regex.Pattern.compile("(?:[?&\\s]|^)([a-zA-Z0-9_\\-]+)=$");
        java.util.regex.Matcher paramMatcher = paramPattern.matcher(preceding);
        if (paramMatcher.find()) {
            String key = paramMatcher.group(1);
            return key + "=([^&\\s;]+)";
        }

        // 3. XML tag match: <tag>value</tag>
        java.util.regex.Pattern xmlPattern = java.util.regex.Pattern.compile("<([a-zA-Z0-9_\\-]+)>$");
        java.util.regex.Matcher xmlMatcher = xmlPattern.matcher(preceding);
        if (xmlMatcher.find()) {
            String tag = xmlMatcher.group(1);
            return "<" + tag + ">(.*?)</" + tag + ">";
        }

        // 4. Default fallback: escape surrounding characters on the same line
        int lastNewline = preceding.lastIndexOf('\n');
        if (lastNewline >= 0) {
            preceding = preceding.substring(lastNewline + 1);
        }
        int firstNewline = succeeding.indexOf('\n');
        if (firstNewline >= 0) {
            succeeding = succeeding.substring(0, firstNewline);
        }

        String prefix = preceding.substring(Math.max(0, preceding.length() - 10));
        String suffix = succeeding.substring(0, Math.min(succeeding.length(), 5));

        return java.util.regex.Pattern.quote(prefix) + "(.*?)" + java.util.regex.Pattern.quote(suffix);
    }

    private String text(String englishText) {
        return variableManager.text(englishText);
    }
}
