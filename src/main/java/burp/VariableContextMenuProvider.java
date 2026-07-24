package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
        String selectedText = textStr.substring(start, end);

        // Determine if selection is in headers or body
        int doubleNewline = textStr.indexOf("\r\n\r\n");
        int separatorLength = 4;
        if (doubleNewline < 0) {
            doubleNewline = textStr.indexOf("\n\n");
            separatorLength = 2;
        }

        String source = isRequest ? "request_body" : "body";
        String contextText = textStr;
        int contextStart = start;
        int contextEnd = end;

        if (doubleNewline >= 0) {
            if (start < doubleNewline) {
                source = isRequest ? "request_headers" : "headers";
                contextText = textStr.substring(0, doubleNewline);
            } else {
                source = isRequest ? "request_body" : "body";
                contextText = textStr.substring(doubleNewline + separatorLength);
                contextStart = Math.max(0, start - (doubleNewline + separatorLength));
                contextEnd = Math.max(0, end - (doubleNewline + separatorLength));
            }
        }

        // Generate proposed regex
        String proposedRegex = generateProposedRegex(contextText, contextStart, contextEnd);

        // Build the Swing dialog
        Frame suiteFrame = api.userInterface().swingUtils().suiteFrame();
        JDialog dialog = new JDialog(suiteFrame, text("Assign to Variable"), Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(520, 465);
        dialog.setLocationRelativeTo(suiteFrame);

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;

        // Row 0: Folder
        gbc.gridy = 0;
        gbc.weightx = 0.0;
        panel.add(new JLabel(text("Folder:")), gbc);

        List<String> folderNames = variableManager.getFolderNames();
        JComboBox<String> folderComboBox = new JComboBox<>();
        folderComboBox.addItem(text("Ungrouped"));
        for (String folderName : folderNames) folderComboBox.addItem(folderName);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(folderComboBox, gbc);

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

        folderComboBox.addActionListener(e -> {
            Object editorValue = nameComboBox.getEditor().getItem();
            String folder = folderComboBox.getSelectedIndex() == 0 ? "" : folderComboBox.getSelectedItem().toString();
            nameComboBox.removeAllItems();
            for (String variable : variableManager.getVariableNamesInFolder(folder)) nameComboBox.addItem(variable);
            if (nameComboBox.getItemCount() > 0) nameComboBox.setSelectedIndex(0);
            else if (editorValue != null) nameComboBox.getEditor().setItem(editorValue);
        });

        // Row 2: Selected Value (Read-only scrollpane)
        gbc.gridy = 2;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        panel.add(new JLabel(text("Selected Value:")), gbc);

        JTextArea valuePreview = new JTextArea(3, 20);
        valuePreview.setText(selectedText);
        valuePreview.setEditable(false);
        valuePreview.setLineWrap(true);
        valuePreview.setWrapStyleWord(true);
        valuePreview.setBackground(panel.getBackground());
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(new JScrollPane(valuePreview), gbc);

        // Row 3: Match URL/Path
        gbc.gridy = 3;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        panel.add(new JLabel(text("Path (literal; query ignored):")), gbc);

        JTextField pathField = new JTextField(path);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(pathField, gbc);

        // Row 4: Extract From
        gbc.gridy = 4;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        panel.add(new JLabel(text("Extract From:")), gbc);

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
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(sourceComboBox, gbc);

        // Row 5: Regex Pattern
        gbc.gridy = 5;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        panel.add(new JLabel(text("Regex Pattern (1 group):")), gbc);

        JTextField regexField = new JTextField(proposedRegex);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(regexField, gbc);

        // Row 6: Save Request checkbox
        gbc.gridy = 6;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        JCheckBox saveRequestCheckBox = new JCheckBox(text("Save this request to refresh token in the future"), true);
        panel.add(saveRequestCheckBox, gbc);

        gbc.gridwidth = 1;

        // Row 6: Action Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        JButton saveButton = new JButton(text("Save Rule"));
        JButton cancelButton = new JButton(text("Cancel"));

        saveButton.addActionListener(al -> {
            Object selectedItem = nameComboBox.getSelectedItem();
            if (selectedItem == null || selectedItem.toString().trim().isEmpty()) {
                JOptionPane.showMessageDialog(dialog, text("Please select or type a variable name."), text("Error"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            String varName = selectedItem.toString().trim();
            if (varName.contains(".")) {
                JOptionPane.showMessageDialog(dialog, text("Variable names cannot contain '.'. Choose the folder separately."), text("Error"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            String folderName = folderComboBox.getSelectedIndex() == 0 ? "" : folderComboBox.getSelectedItem().toString();
            String pathFilter = pathField.getText().trim();
            String chosenSource;
            switch (sourceComboBox.getSelectedIndex()) {
                case 1: chosenSource = "headers"; break;
                case 2: chosenSource = "request_body"; break;
                case 3: chosenSource = "request_headers"; break;
                default: chosenSource = "body"; break;
            }
            String regexPattern = regexField.getText().trim();
            if (!ExtractionEngine.isValidRegex(regexPattern)
                    || !ExtractionEngine.hasCaptureGroup(regexPattern)) {
                JOptionPane.showMessageDialog(dialog,
                        text("The extraction regex must be valid and contain at least one capture group."),
                        text("Error"), JOptionPane.ERROR_MESSAGE);
                return;
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
            variableManager.addOrUpdateExtractionRuleInFolder(
                    folderName,
                    varName,
                    selectedText, 
                    false,
                    pathFilter, 
                    chosenSource, 
                    regexPattern,
                    requestResponse.request().method(),
                    reqBase64,
                    host,
                    port,
                    secure
            );
            dialog.dispose();
        });

        cancelButton.addActionListener(al -> dialog.dispose());

        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);

        dialog.add(panel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
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
