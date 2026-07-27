package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.Editor;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public final class VariableManager {
    record VariableListSnapshot(long revision, List<String> names, List<String> folders) {}

    private final MontoyaApi api;
    private final Object lock = new Object();
    private final List<String> variableNames = new ArrayList<>();
    private final Map<String, String> values = new ConcurrentHashMap<>();
    private final Map<String, VariableExtractionRule> rules = new ConcurrentHashMap<>();
    private final List<VariableFolder> folders = new ArrayList<>();
    private final List<VariableDefinition> definitions = new ArrayList<>();
    private volatile long variableRevision;
    private String variableSearch = "";
    private static final String STATE_V2_KEY = "dynamic_variables_state_v2";
    private static final String STATE_V3_KEY = "dynamic_variables_state_v3";

    private boolean replacementMasterEnabled = true;
    private boolean replacementEnabled = true;
    private boolean replacementIntruderEnabled = false;
    private boolean replacementScannerEnabled = false;
    private boolean replacementProxyEnabled = false;
    private boolean extractionEnabled = true;
    private boolean sessionRecoveryEnabled = true;
    private boolean extractionDebugEnabled = true;
    private EnumSet<AutomationTool> extractionTools = EnumSet.of(AutomationTool.REPEATER);
    private EnumSet<AutomationTool> recoveryTools = EnumSet.of(AutomationTool.REPEATER);
    private String refreshStatusCodes = "401, 403";
    private volatile boolean placeholderTagEnabled = false;
    private volatile String placeholderTag = "dv";
    private volatile VariableNames.PlaceholderSyntax placeholderSyntax = VariableNames.PlaceholderSyntax.CURLY_BRACES;
    private volatile UiLanguage uiLanguage = UiLanguage.ENGLISH;

    // UI Components
    private JPanel mainPanel;
    private JTable variablesTable;
    private VariablesTableModel tableModel;
    private JTextArea valueTextArea;
    
    private JCheckBox replacementMasterCheckBox;
    private JLabel placeholderUsageLabel;
    private JLabel automationStatusLabel;
    private CardLayout detailsCardLayout;
    private JPanel detailsCards;
    private JTabbedPane detailsTabs;

    // Rule Panel Components
    private JCheckBox ruleEnabledCheckBox;
    private JCheckBox automaticRefreshCheckBox;
    private JButton advancedRecoveryButton;
    private JPanel advancedRecoveryPanel;
    private JCheckBox allowNonIdempotentReplayCheckBox;
    private JTextField matchUrlField;
    private JLabel matchStrategyLabel;
    private JButton convertMatchButton;
    private JTextField matchMethodField;
    private JTextField matchHostField;
    private JTextField matchPortField;
    private JCheckBox matchSecureCheckBox;
    private JComboBox<String> pathModeComboBox;
    private JTextField queryField;
    private JComboBox<String> queryModeComboBox;
    private JComboBox<String> discriminatorSourceComboBox;
    private JTextField discriminatorRegexField;
    private JComboBox<String> extractionZoneComboBox;
    private JComboBox<String> sourceComboBox;
    private JTextField regexField;
    private JTextField delimiterField;
    private JButton removeExtractionZoneButton;
    private JButton updateRuleButton;
    private JToggleButton advancedMatchToggle;
    private JPanel advancedMatchPanel;
    private JTextField signalStatusCodesField;
    private JTextField signalHeaderRegexField;
    private JComboBox<String> signalHeaderModeComboBox;
    private JTextField signalBodyRegexField;
    private JComboBox<String> signalBodyModeComboBox;
    private JCheckBox signalNegateCheckBox;
    private JLabel signalWarningLabel;

    // Refresh Panel Components
    private JLabel savedRequestLabel;
    private JButton refreshRequestButton;
    private JButton sendToRepeaterButton;
    private JButton editRequestButton;

    private static final int DEFAULT_DIVIDER_LOCATION = 450;
    // Amber reads as a warning against both the light and the dark Burp themes.
    private static final Color WARNING_FOREGROUND = new Color(0xB3, 0x5C, 0x00);

    private boolean isUpdatingUI = false;
    // Variable ids whose 2FA secret already failed to decode, so the error is logged once.
    private final Set<String> loggedTotpFailures = new HashSet<>();

    // 2FA-only details: the Automation tab is removed and the Value tab gains a manual rotation.
    private JLabel valueHint;
    private JPanel totpValuePanel;
    private JButton rotateTotpButton;
    private JPanel automationDetailsPanel;
    private JPanel totpConfigDetailsPanel;
    private JTextField totpSecretField;
    private JComboBox<Integer> totpDigitsComboBox;
    private JTextField totpPeriodField;
    private JComboBox<String> totpAlgorithmComboBox;

    public VariableManager(MontoyaApi api) {
        this.api = api;
        loadPreferences();
        createUI();
    }

    public Component getTabComponent() {
        return mainPanel;
    }

    public Map<String, String> getVariables() {
        synchronized (lock) {
            refreshTotpValues();
            return new HashMap<>(values);
        }
    }

    /**
     * Recomputes 2FA values right before they are read. Every consumer of a variable value
     * goes through {@link #getVariables()}, so a code is refreshed exactly when it is used
     * and only if its time step advanced - no background rotation.
     */
    private void refreshTotpValues() {
        long epochSeconds = System.currentTimeMillis() / 1000L;
        for (VariableDefinition definition : definitions) {
            if (!definition.isTotpVariable()) continue;
            try {
                String code = definition.totpCodeFor(epochSeconds);
                if (!code.equals(definition.getValue())) definition.setValue(code);
                values.put(qualifiedName(definition), code);
            } catch (RuntimeException e) {
                // A stored secret that no longer decodes must never break request handling.
                if (loggedTotpFailures.add(definition.getId())) {
                    api.logging().logToError("Cannot compute the 2FA code for "
                            + qualifiedName(definition) + ": " + e.getMessage());
                }
            }
        }
    }

    public Map<String, VariableExtractionRule> getRules() {
        synchronized (lock) {
            return new HashMap<>(rules);
        }
    }

    public List<String> getVariableNames() {
        synchronized (lock) {
            return new ArrayList<>(variableNames);
        }
    }

    public List<String> getFolderNames() {
        synchronized (lock) {
            return folders.stream().sorted(Comparator.comparingInt(VariableFolder::getPosition))
                    .map(VariableFolder::getName).toList();
        }
    }

    VariableListSnapshot getVariableListSnapshot() {
        synchronized (lock) {
            return new VariableListSnapshot(
                    variableRevision,
                    List.copyOf(variableNames),
                    folders.stream().sorted(Comparator.comparingInt(VariableFolder::getPosition))
                            .map(VariableFolder::getName).toList());
        }
    }

    boolean folderExists(String name) {
        synchronized (lock) {
            return findFolderByName(name == null ? "" : name.trim()) != null;
        }
    }

    void createFolder(String name) {
        String normalized = name == null ? "" : name.trim();
        if (!VariableNames.isValidComponent(normalized)) {
            throw new IllegalArgumentException("Invalid folder name");
        }
        synchronized (lock) {
            if (findFolderByName(normalized) != null) {
                throw new IllegalStateException("Folder already exists");
            }
            folders.add(new VariableFolder(normalized, folders.size()));
            savePreferences();
        }
        if (tableModel != null) tableModel.fireTableDataChanged();
    }

    public String getFolderNameForVariable(String qualifiedName) {
        synchronized (lock) {
            VariableDefinition definition = findDefinitionByKey(qualifiedName);
            VariableFolder folder = definition == null ? null : findFolder(definition.getFolderId());
            return folder == null ? "" : folder.getName();
        }
    }

    public List<String> getVariableNamesInFolder(String folderName) {
        synchronized (lock) {
            VariableFolder folder = folderName == null || folderName.isEmpty() ? null : findFolderByName(folderName);
            String folderId = folder == null ? null : folder.getId();
            return definitions.stream().filter(definition -> Objects.equals(folderId, definition.getFolderId()))
                    .sorted(Comparator.comparingInt(VariableDefinition::getPosition))
                    .map(VariableDefinition::getName).toList();
        }
    }

    public String qualifyVariableName(String folderName, String localName) {
        return VariableNames.qualify(folderName, localName);
    }

    public VariableNames.PlaceholderStyle getPlaceholderStyle() {
        return new VariableNames.PlaceholderStyle(placeholderTagEnabled, placeholderTag, placeholderSyntax);
    }

    public String placeholderFor(String qualifiedName) {
        return VariableNames.placeholder(qualifiedName, getPlaceholderStyle());
    }

    String text(String englishText) {
        return UiText.get(uiLanguage, englishText);
    }

    public void addOrUpdateExtractionRuleInFolder(String folderName, String localName, String value,
                                                   boolean ruleEnabled, boolean automaticRefreshEnabled,
                                                   String matchUrl, String source,
                                                   String regex, String matchMethod, String reqBase64,
                                                   String host, int port, boolean secure) {
        String qualified = qualifyVariableName(folderName, localName);
        synchronized (lock) {
            if (!variableNames.contains(qualified)) {
                VariableFolder folder = folderName == null || folderName.isEmpty() ? null : findFolderByName(folderName);
                if (folderName != null && !folderName.isEmpty() && folder == null) {
                    throw new IllegalArgumentException("Folder does not exist: " + folderName);
                }
                definitions.add(new VariableDefinition(localName, folder == null ? null : folder.getId(), value,
                        new VariableExtractionRule(), countVariablesInFolder(folder == null ? null : folder.getId())));
                rebuildRuntimeMapsFromDefinitions();
            }
        }
        addOrUpdateExtractionRule(qualified, value, ruleEnabled, automaticRefreshEnabled,
                matchUrl, source, regex,
                matchMethod, reqBase64, host, port, secure);
    }

    public void addOrUpdateMultipleExtractionRuleInFolder(
            String folderName, String localName, String value,
            boolean ruleEnabled, boolean automaticRefreshEnabled,
            String matchUrl, List<VariableExtractionRule.ExtractionTarget> targets,
            String valueTemplate, String matchMethod, String reqBase64,
            String host, int port, boolean secure) {
        if (targets == null || targets.isEmpty()) {
            throw new IllegalArgumentException("At least one extraction value is required");
        }
        VariableExtractionRule.ExtractionTarget primary = targets.get(0);
        addOrUpdateExtractionRuleInFolder(
                folderName, localName, value, ruleEnabled, automaticRefreshEnabled,
                matchUrl, primary.source().storedValue(), primary.regex(),
                matchMethod, reqBase64, host, port, secure);

        String qualified = qualifyVariableName(folderName, localName);
        synchronized (lock) {
            VariableExtractionRule rule = rules.get(qualified).copy();
            rule.setTargets(targets);
            rule.setValueTemplate(valueTemplate);
            rules.put(qualified, rule);
            VariableDefinition definition = findDefinitionByKey(qualified);
            if (definition != null) definition.setRule(rule);
            savePreferences();
        }
        SwingUtilities.invokeLater(() -> {
            tableModel.fireTableDataChanged();
            int row = tableModel.findVariableRow(qualified);
            if (row >= 0) variablesTable.setRowSelectionInterval(row, row);
        });
    }

    public void appendExtractionZoneInFolder(String folderName, String localName, String newPartValue,
                                            boolean ruleEnabled, boolean automaticRefreshEnabled,
                                            String matchUrl, String source,
                                            String regex, String matchMethod, String reqBase64,
                                            String host, int port, boolean secure) {
        String qualified = qualifyVariableName(folderName, localName);
        synchronized (lock) {
            VariableExtractionRule existingRule = rules.get(qualified);
            String existingVal = values.getOrDefault(qualified, "");
            if (existingRule == null || !hasValidExtractionTargets(existingRule)) {
                addOrUpdateExtractionRuleInFolder(folderName, localName, newPartValue,
                        ruleEnabled, automaticRefreshEnabled, matchUrl, source, regex,
                        matchMethod, reqBase64, host, port, secure);
                return;
            }
            String delimiter = existingRule.getJoinDelimiter();
            String combinedVal = existingVal.isEmpty() ? newPartValue : existingVal + delimiter + newPartValue;
            values.put(qualified, combinedVal);

            existingRule.setEnabled(ruleEnabled);
            existingRule.setAutomaticRefreshEnabled(automaticRefreshEnabled);
            String previousTemplate = existingRule.getValueTemplate();
            existingRule.addTarget(VariableExtractionRule.ExtractionSource.fromStored(source), regex);
            VariableExtractionRule.ExtractionTarget addedTarget =
                    existingRule.getTargets().get(existingRule.getTargets().size() - 1);
            existingRule.setValueTemplate(previousTemplate + delimiter
                    + "{{" + addedTarget.name() + "}}");

            if (reqBase64 != null && !reqBase64.isEmpty()) {
                existingRule.setSavedRequestBase64(reqBase64);
                existingRule.setSavedHost(host);
                existingRule.setSavedPort(port);
                existingRule.setSavedSecure(secure);
            }

            VariableDefinition definition = findDefinitionByKey(qualified);
            if (definition != null) {
                definition.setValue(combinedVal);
                definition.setRule(existingRule);
            }
            savePreferences();
        }
        SwingUtilities.invokeLater(() -> {
            tableModel.fireTableDataChanged();
            int row = tableModel.findVariableRow(qualified);
            if (row >= 0) {
                variablesTable.setRowSelectionInterval(row, row);
            }
        });
    }

    public boolean isReplacementMasterEnabled() {
        return replacementMasterEnabled;
    }

    public boolean isReplacementEnabled() {
        return replacementEnabled;
    }

    public boolean isReplacementIntruderEnabled() {
        return replacementIntruderEnabled;
    }

    public boolean isReplacementScannerEnabled() {
        return replacementScannerEnabled;
    }

    public boolean isReplacementProxyEnabled() {
        return replacementProxyEnabled;
    }

    public boolean isExtractionEnabled() {
        return extractionEnabled;
    }

    public boolean isSessionRecoveryEnabled() {
        return sessionRecoveryEnabled;
    }

    public boolean isExtractionDebugEnabled() {
        return extractionDebugEnabled;
    }

    public boolean isExtractionToolEnabled(AutomationTool tool) {
        synchronized (lock) {
            return tool != null && extractionTools.contains(tool);
        }
    }

    public boolean isRecoveryToolEnabled(AutomationTool tool) {
        synchronized (lock) {
            return tool != null && recoveryTools.contains(tool);
        }
    }

    public String getVariableContext(String name) {
        synchronized (lock) {
            VariableDefinition definition = findDefinitionByKey(name);
            return definition == null || definition.getFolderId() == null
                    ? "__ungrouped__" : definition.getFolderId();
        }
    }

    public Set<Integer> getRefreshStatusCodes() {
        Set<Integer> codes = new HashSet<>();
        try {
            String[] parts = refreshStatusCodes.split(",");
            for (String part : parts) {
                String trimmed = part.trim();
                if (!trimmed.isEmpty()) {
                    codes.add(Integer.parseInt(trimmed));
                }
            }
        } catch (Exception e) {
            codes.clear();
            codes.add(401);
            codes.add(403);
        }
        return codes;
    }

    public void updateVariableValue(String name, String value) {
        updateVariableValues(Map.of(name, value));
    }

    public void updateVariableValues(Map<String, String> updates) {
        if (updates == null || updates.isEmpty()) return;
        synchronized (lock) {
            for (Map.Entry<String, String> update : updates.entrySet()) {
                values.put(update.getKey(), update.getValue());
                VariableDefinition definition = findDefinitionByKey(update.getKey());
                if (definition != null) definition.setValue(update.getValue());
            }
            savePreferences();
        }
        SwingUtilities.invokeLater(() -> {
            for (Map.Entry<String, String> update : updates.entrySet()) {
                int row = tableModel == null ? -1 : tableModel.findVariableRow(update.getKey());
                if (row >= 0) {
                    tableModel.fireTableCellUpdated(row, 1);
                    int selectedRow = variablesTable.getSelectedRow();
                    if (selectedRow == row) {
                        isUpdatingUI = true;
                        valueTextArea.setText(update.getValue());
                        isUpdatingUI = false;
                    }
                }
            }
        });
    }

    public void addOrUpdateExtractionRule(String name, String value, boolean ruleEnabled,
                                          boolean automaticRefreshEnabled, String matchUrl, String source,
                                          String regex, String matchMethod, String reqBase64,
                                          String host, int port, boolean secure) {
        synchronized (lock) {
            VariableExtractionRule previousRule = rules.get(name);
            if (!variableNames.contains(name)) {
                variableNames.add(name);
                String folderName = "";
                String localName = name;
                int dot = name.indexOf('.');
                if (dot > 0) {
                    VariableFolder candidate = findFolderByName(name.substring(0, dot));
                    if (candidate != null) {
                        folderName = candidate.getName();
                        localName = name.substring(dot + 1);
                    }
                }
                VariableFolder folder = folderName.isEmpty() ? null : findFolderByName(folderName);
                definitions.add(new VariableDefinition(localName, folder == null ? null : folder.getId(), value,
                        new VariableExtractionRule(), countVariablesInFolder(folder == null ? null : folder.getId())));
            }
            values.put(name, value);
            VariableExtractionRule rule = new VariableExtractionRule(ruleEnabled, matchUrl, source, regex, 
                    reqBase64, host, port, secure);
            rule.setAutomaticRefreshEnabled(automaticRefreshEnabled);
            if (previousRule != null) {
                rule.setAllowNonIdempotentReplay(previousRule.isAllowNonIdempotentReplay());
            }
            if (matchMethod != null && !matchMethod.isEmpty() && host != null && !host.isEmpty()) {
                try {
                    String fullPath = matchUrl == null ? "" : matchUrl;
                    int queryAt = fullPath.indexOf('?');
                    String path = queryAt < 0 ? fullPath : fullPath.substring(0, queryAt);
                    rule.configureExplicitMatch(matchMethod, host, port, secure, path,
                            VariableExtractionRule.PatternMode.LITERAL, "",
                            VariableExtractionRule.PatternMode.LITERAL,
                            VariableExtractionRule.DiscriminatorSource.NONE, "");
                } catch (Exception error) {
                    api.logging().logToError("Could not initialize explicit matching for '" + name
                            + "': " + error.getMessage());
                }
            }
            rules.put(name, rule);
            VariableDefinition definition = findDefinitionByKey(name);
            if (definition != null) {
                definition.setValue(value);
                definition.setRule(rule);
            }
            savePreferences();
        }
        SwingUtilities.invokeLater(() -> {
            tableModel.fireTableDataChanged();
            // Highlight the row that was added or updated
            int row = tableModel.findVariableRow(name);
            if (row >= 0) {
                variablesTable.setRowSelectionInterval(row, row);
                updateDetailsPanel(row);
            }
        });
    }

    private void createUI() {
        if (mainPanel == null) {
            mainPanel = new JPanel(new BorderLayout(10, 10));
        } else {
            mainPanel.removeAll();
            mainPanel.setLayout(new BorderLayout(10, 10));
        }
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // --- COMPACT STATUS BAR ---
        replacementMasterCheckBox = new JCheckBox(text("Enable Variable Replacement"), replacementMasterEnabled);
        replacementMasterCheckBox.setFont(new Font(replacementMasterCheckBox.getFont().getName(), Font.BOLD, 12));
        JCheckBox repeaterReplacementCheckBox = new JCheckBox("Repeater", replacementEnabled);
        JCheckBox intruderReplacementCheckBox = new JCheckBox("Intruder", replacementIntruderEnabled);
        JCheckBox scannerReplacementCheckBox = new JCheckBox("Scanner", replacementScannerEnabled);
        JCheckBox proxyReplacementCheckBox = new JCheckBox("Proxy", replacementProxyEnabled);
        List<JCheckBox> replacementToolCheckBoxes = List.of(
                repeaterReplacementCheckBox,
                intruderReplacementCheckBox,
                scannerReplacementCheckBox,
                proxyReplacementCheckBox);
        Runnable updateReplacementToolVisibility = () -> {
            boolean visible = replacementMasterCheckBox.isSelected();
            for (JCheckBox checkBox : replacementToolCheckBoxes) {
                checkBox.setVisible(visible);
            }
        };
        replacementMasterCheckBox.addActionListener(e -> {
            replacementMasterEnabled = replacementMasterCheckBox.isSelected();
            updateReplacementToolVisibility.run();
            updateGlobalStatusLabels();
            savePreferences();
        });
        repeaterReplacementCheckBox.addActionListener(e -> {
            replacementEnabled = repeaterReplacementCheckBox.isSelected();
            savePreferences();
        });
        intruderReplacementCheckBox.addActionListener(e -> {
            replacementIntruderEnabled = intruderReplacementCheckBox.isSelected();
            savePreferences();
        });
        scannerReplacementCheckBox.addActionListener(e -> {
            replacementScannerEnabled = scannerReplacementCheckBox.isSelected();
            savePreferences();
        });
        proxyReplacementCheckBox.addActionListener(e -> {
            replacementProxyEnabled = proxyReplacementCheckBox.isSelected();
            savePreferences();
        });

        JButton settingsButton = new JButton(text("Configuration..."));
        settingsButton.setToolTipText(text("Configure the interface language and the optional tag that uniquely identifies variable placeholders."));
        settingsButton.addActionListener(e -> showPlaceholderSettingsDialog());

        JPanel topPanel = new JPanel(new BorderLayout(12, 0));
        topPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(0, 0, 0, 35)),
                new EmptyBorder(0, 0, 8, 0)));
        JPanel primaryStatus = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 3));
        primaryStatus.add(replacementMasterCheckBox);
        primaryStatus.add(repeaterReplacementCheckBox);
        primaryStatus.add(intruderReplacementCheckBox);
        primaryStatus.add(scannerReplacementCheckBox);
        primaryStatus.add(proxyReplacementCheckBox);
        updateReplacementToolVisibility.run();
        automationStatusLabel = new JLabel();
        automationStatusLabel.setHorizontalAlignment(SwingConstants.RIGHT);
        JPanel settingsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 3));
        settingsPanel.add(automationStatusLabel);
        settingsPanel.add(settingsButton);
        topPanel.add(primaryStatus, BorderLayout.WEST);
        topPanel.add(settingsPanel, BorderLayout.EAST);
        updateGlobalStatusLabels();
        mainPanel.add(topPanel, BorderLayout.NORTH);

        // --- CENTER SPLIT PANE ---
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.4);

        // Left Side: Variables Table & Buttons
        JPanel leftPanel = new JPanel(new BorderLayout(5, 5));
        tableModel = new VariablesTableModel();
        variablesTable = new JTable(tableModel);
        variablesTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        variablesTable.setDragEnabled(true);
        variablesTable.setDropMode(DropMode.INSERT_ROWS);
        variablesTable.setTransferHandler(new VariableRowTransferHandler());
        variablesTable.setToolTipText(text("Drag to reorder or move variables between folders."));
        variablesTable.getColumnModel().getColumn(0).setCellRenderer(new HierarchyCellRenderer());
        DefaultCellEditor variableNameEditor = new DefaultCellEditor(new JTextField());
        variableNameEditor.setClickCountToStart(2);
        variablesTable.getColumnModel().getColumn(0).setCellEditor(variableNameEditor);
        variablesTable.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                .put(KeyStroke.getKeyStroke("F2"), "renameSelectedNode");
        variablesTable.getActionMap().put("renameSelectedNode", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                int[] selectedRows = variablesTable.getSelectedRows();
                if (selectedRows.length != 1) return;
                int row = selectedRows[0];
                TableRow selected = tableModel.rowAt(row);
                if (selected == null || (selected.folderRow && selected.ungrouped)) return;
                if (selected.variable != null) {
                    variablesTable.editCellAt(row, 0);
                    Component editor = variablesTable.getEditorComponent();
                    if (editor != null) editor.requestFocusInWindow();
                } else {
                    renameNode(selected);
                }
            }
        });
        variablesTable.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), "deleteSelectedNodes");
        variablesTable.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SPACE, 0), "deleteSelectedNodes");
        variablesTable.getActionMap().put("deleteSelectedNodes", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                deleteSelectedNodes();
            }
        });
        variablesTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                showPopupIfTriggered(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                showPopupIfTriggered(e);
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                int row = variablesTable.rowAtPoint(e.getPoint());
                if (row < 0) return;
                if (SwingUtilities.isLeftMouseButton(e) && e.getClickCount() == 2 && tableModel.isFolderRow(row)) {
                    toggleFolderAt(row);
                }
            }

            private void showPopupIfTriggered(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int row = variablesTable.rowAtPoint(e.getPoint());
                if (row < 0) return;

                if (variablesTable.isEditing()) {
                    variablesTable.getCellEditor().stopCellEditing();
                }
                if (!variablesTable.isRowSelected(row)) {
                    variablesTable.setRowSelectionInterval(row, row);
                }
                createVariablesPopup().show(variablesTable, e.getX(), e.getY());
                e.consume();
            }
        });
        variablesTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int[] selectedRows = variablesTable.getSelectedRows();
                if (selectedRows.length == 1) {
                    updateDetailsPanel(selectedRows[0]);
                } else if (selectedRows.length > 1) {
                    disableDetails(text(selectedRows.length + " items selected."));
                } else {
                    updateDetailsPanel(-1);
                }
            }
        });

        JPanel navigationPanel = new JPanel(new BorderLayout(5, 5));
        JTextField searchField = new JTextField();
        searchField.putClientProperty("JTextField.placeholderText", text("Search folders or variables"));
        searchField.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            variableSearch = searchField.getText().trim().toLowerCase(Locale.ROOT);
            tableModel.fireTableDataChanged();
            updateDetailsPanel(-1);
        }));
        navigationPanel.add(searchField, BorderLayout.NORTH);
        navigationPanel.add(new JScrollPane(variablesTable), BorderLayout.CENTER);
        leftPanel.add(navigationPanel, BorderLayout.CENTER);

        // Buttons Panel under Table
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        JButton addButton = new JButton(text("Add..."));
        JButton clearAllButton = new JButton(text("Clear All"));

        JPopupMenu addMenu = new JPopupMenu();
        JMenuItem addVariableItem = new JMenuItem(text("New Variable"));
        addVariableItem.addActionListener(e -> createVariableDialog(null));
        JMenuItem addFolderItem = new JMenuItem(text("New Folder"));
        addFolderItem.addActionListener(e -> createFolderDialog());
        JMenuItem setupTotpItem = new JMenuItem(text("Add 2FA variable"));
        setupTotpItem.setToolTipText(text("Creates a variable whose value is a 2FA code computed from a secret."));
        setupTotpItem.addActionListener(e -> showTotpSetupDialog(selectedFolderId()));

        addMenu.add(addVariableItem);
        addMenu.add(addFolderItem);
        addMenu.addSeparator();
        addMenu.add(setupTotpItem);

        addButton.addActionListener(e -> addMenu.show(addButton, 0, addButton.getHeight()));

        clearAllButton.addActionListener(e -> {
            if (confirmDialog(text("Are you sure you want to clear all variables?"), text("Confirm Clear"), JOptionPane.QUESTION_MESSAGE)) {
                synchronized (lock) {
                    variableNames.clear();
                    values.clear();
                    rules.clear();
                    definitions.clear();
                    folders.clear();
                    savePreferences();
                }
                tableModel.fireTableDataChanged();
                valueTextArea.setText("");
                clearRuleFields();
            }
        });

        buttonPanel.add(addButton);
        buttonPanel.add(clearAllButton);
        leftPanel.add(buttonPanel, BorderLayout.SOUTH);

        // The button row is what decides how narrow this side may get: without a minimum the
        // split pane opens on the table's preferred width and clips buttons.
        int leftPanelMinimumWidth = buttonPanel.getPreferredSize().width + 20;
        leftPanel.setMinimumSize(new Dimension(leftPanelMinimumWidth, 150));
        leftPanel.setPreferredSize(new Dimension(
                Math.max(leftPanelMinimumWidth, DEFAULT_DIVIDER_LOCATION), 400));

        // 1. Current Value JTextArea
        JPanel valuePanel = new JPanel(new BorderLayout(5, 5));
        valuePanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(),
                text("Current value"),
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font(mainPanel.getFont().getName(), Font.BOLD, 12)
        ));
        valueHint = new JLabel(text("Changes are saved automatically."));
        valueHint.setForeground(UIManager.getColor("Label.disabledForeground"));
        valueHint.setBorder(new EmptyBorder(0, 4, 4, 0));

        // Only shown for 2FA variables: the value is derived from the secret, so the panel
        // explains the rotation and offers an explicit recompute above the hint.
        totpValuePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        rotateTotpButton = new JButton(text("Rotate now"));
        rotateTotpButton.setToolTipText(text(
                "Recomputes the code now. The code only changes when its period elapses."));
        rotateTotpButton.addActionListener(e -> rotateSelectedTotpValue());
        totpValuePanel.add(rotateTotpButton);
        totpValuePanel.setVisible(false);

        JPanel valueHeaderPanel = new JPanel(new BorderLayout());
        valueHeaderPanel.add(totpValuePanel, BorderLayout.NORTH);
        valueHeaderPanel.add(valueHint, BorderLayout.SOUTH);
        valuePanel.add(valueHeaderPanel, BorderLayout.NORTH);
        valueTextArea = new JTextArea(5, 20);
        valueTextArea.setLineWrap(true);
        valueTextArea.setWrapStyleWord(true);
        valueTextArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { updateValue(); }
            @Override
            public void removeUpdate(DocumentEvent e) { updateValue(); }
            @Override
            public void changedUpdate(DocumentEvent e) { updateValue(); }

            private void updateValue() {
                if (isUpdatingUI) return;
                int selectedRow = variablesTable.getSelectedRow();
                String name = tableModel.variableKeyAt(selectedRow);
                if (name != null) {
                    String val = valueTextArea.getText();
                    synchronized (lock) {
                        values.put(name, val);
                        VariableDefinition definition = findDefinitionByKey(name);
                        if (definition != null) definition.setValue(val);
                        savePreferences();
                    }
                    tableModel.fireTableCellUpdated(selectedRow, 1);
                }
            }
        });
        valuePanel.add(new JScrollPane(valueTextArea), BorderLayout.CENTER);

        // 2. Extraction Rule Editor Panel. The common path stays visible while
        // request matching details are progressively disclosed.
        JPanel rulePanel = new JPanel();
        rulePanel.setLayout(new BoxLayout(rulePanel, BoxLayout.Y_AXIS));
        rulePanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), 
                text("Variable automation"),
                TitledBorder.LEFT, 
                TitledBorder.TOP, 
                new Font(mainPanel.getFont().getName(), Font.PLAIN, 12)
        ));
        
        ruleEnabledCheckBox = new JCheckBox(text("Update this variable from matching responses"));
        ruleEnabledCheckBox.setToolTipText(text(
                "Requires global response extraction and extraction for the current Burp tool to be enabled."));
        ruleEnabledCheckBox.addActionListener(e -> handleRuleActivation(ruleEnabledCheckBox, false));
        ruleEnabledCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        rulePanel.add(ruleEnabledCheckBox);
        JLabel passiveExtractionExplanation = automationExplanationLabel(text(
                "Matching responses update the value passively; no request is retried."));
        passiveExtractionExplanation.setAlignmentX(Component.LEFT_ALIGNMENT);
        rulePanel.add(passiveExtractionExplanation);
        rulePanel.add(Box.createVerticalStrut(6));

        JPanel recoveryTogglePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        recoveryTogglePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        automaticRefreshCheckBox = new JCheckBox(text("Use this variable for expired-session recovery"));
        automaticRefreshCheckBox.setToolTipText(text(
                "Requires global session recovery, recovery for the current Burp tool, and a saved refresh request."));
        automaticRefreshCheckBox.addActionListener(e -> {
            handleRuleActivation(automaticRefreshCheckBox, true);
            if (advancedRecoveryButton != null) {
                advancedRecoveryButton.setEnabled(automaticRefreshCheckBox.isSelected());
            }
        });
        
        advancedRecoveryButton = new JButton("⚙");
        advancedRecoveryButton.setToolTipText(text("Configure advanced session recovery options"));
        advancedRecoveryButton.setMargin(new Insets(2, 4, 2, 4));
        advancedRecoveryButton.addActionListener(e -> showAdvancedRecoveryDialog());
        
        recoveryTogglePanel.add(automaticRefreshCheckBox);
        recoveryTogglePanel.add(Box.createHorizontalStrut(5));
        recoveryTogglePanel.add(advancedRecoveryButton);
        rulePanel.add(recoveryTogglePanel);
        
        JLabel sessionRecoveryExplanation = automationExplanationLabel(text(
                "After a configured status, the saved request obtains a new value and the original request is retried."));
        sessionRecoveryExplanation.setAlignmentX(Component.LEFT_ALIGNMENT);
        rulePanel.add(sessionRecoveryExplanation);
        rulePanel.add(Box.createVerticalStrut(6));

        JPanel extractionPanel = new JPanel(new GridBagLayout());
        extractionPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints egbc = new GridBagConstraints();
        egbc.fill = GridBagConstraints.HORIZONTAL;
        egbc.insets = new Insets(4, 5, 4, 5);
        egbc.gridy = 0;
        egbc.gridx = 0;
        egbc.weightx = 0.0;
        extractionPanel.add(new JLabel(text("Extraction zone:")), egbc);
        extractionZoneComboBox = new JComboBox<>();
        extractionZoneComboBox.addActionListener(e -> loadSelectedExtractionZone());
        egbc.gridx = 1;
        egbc.weightx = 1.0;
        extractionPanel.add(extractionZoneComboBox, egbc);

        egbc.gridy = 1;
        egbc.gridx = 0;
        egbc.weightx = 0.0;
        extractionPanel.add(new JLabel(text("Extract From:")), egbc);
        sourceComboBox = new JComboBox<>(new String[]{
            text("Response Body"), text("Response Headers"), text("Request Body"), text("Request Headers")
        });
        sourceComboBox.addActionListener(e -> updateActiveRuleFromUI());
        egbc.gridx = 1;
        egbc.weightx = 1.0;
        extractionPanel.add(sourceComboBox, egbc);

        egbc.gridy = 2;
        egbc.gridx = 0;
        egbc.weightx = 0.0;
        extractionPanel.add(new JLabel(text("Regex (with 1 capture group):")), egbc);
        regexField = new JTextField();
        regexField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        egbc.gridx = 1;
        egbc.weightx = 1.0;
        extractionPanel.add(regexField, egbc);

        egbc.gridy = 3;
        egbc.gridx = 0;
        egbc.weightx = 0.0;
        egbc.gridwidth = 1;
        extractionPanel.add(new JLabel(text("Final value template:")), egbc);
        delimiterField = new JTextField(placeholderSyntax == VariableNames.PlaceholderSyntax.PARENTHESES ? "((value1))" : "{{value1}}");
        delimiterField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        egbc.gridx = 1;
        egbc.weightx = 1.0;
        extractionPanel.add(delimiterField, egbc);

        egbc.gridy = 4;
        egbc.gridx = 0;
        egbc.gridwidth = 1;
        updateRuleButton = new JButton(text("Update Rule from Response..."));
        updateRuleButton.addActionListener(e -> triggerUpdateRuleFromResponse());
        extractionPanel.add(updateRuleButton, egbc);
        egbc.gridx = 1;
        removeExtractionZoneButton = new JButton(text("Remove Zone"));
        removeExtractionZoneButton.addActionListener(e -> removeSelectedExtractionZone());
        extractionPanel.add(removeExtractionZoneButton, egbc);
        rulePanel.add(extractionPanel);

        advancedMatchToggle = new JToggleButton(text("Show advanced automation options"));
        advancedMatchToggle.setAlignmentX(Component.LEFT_ALIGNMENT);
        advancedMatchToggle.setToolTipText(text(
                "Configure passive-extraction matching and session-recovery retry safety."));
        rulePanel.add(advancedMatchToggle);

        advancedMatchPanel = new JPanel(new GridBagLayout());
        advancedMatchPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        advancedMatchPanel.setBorder(new EmptyBorder(2, 18, 2, 0));
        GridBagConstraints rgbc = new GridBagConstraints();
        rgbc.fill = GridBagConstraints.HORIZONTAL;
        rgbc.insets = new Insets(4, 5, 4, 5);
        rgbc.gridx = 0;

        // GridBagLayout with the same insets as the other two boxes, so that their contents and
        // their explanation lines start at the same x.
        JPanel retrySafetyPanel = new JPanel(new GridBagLayout());
        retrySafetyPanel.setBorder(BorderFactory.createTitledBorder(text("Session recovery retry safety")));
        GridBagConstraints tgbc = new GridBagConstraints();
        tgbc.fill = GridBagConstraints.HORIZONTAL;
        tgbc.insets = new Insets(4, 5, 4, 5);
        tgbc.gridx = 0;
        tgbc.gridwidth = 2;
        tgbc.weightx = 1.0;
        JLabel retrySafetyExplanation = automationExplanationLabel(text(
                "Allows retrying methods such as POST, PUT, PATCH, and DELETE after refreshing the value. Enable only when repeating the operation is safe."));
        tgbc.gridy = 0;
        retrySafetyPanel.add(retrySafetyExplanation, tgbc);
        allowNonIdempotentReplayCheckBox = new JCheckBox(
                text("In session recovery, allow retrying non-idempotent requests"));
        allowNonIdempotentReplayCheckBox.setToolTipText(text(
                "Allows retrying methods such as POST, PUT, PATCH, and DELETE after refreshing the value. Enable only when repeating the operation is safe."));
        allowNonIdempotentReplayCheckBox.addActionListener(e -> updateActiveRuleFromUI());
        tgbc.gridy = 1;
        retrySafetyPanel.add(allowNonIdempotentReplayCheckBox, tgbc);
        advancedRecoveryPanel = new JPanel(new GridBagLayout());
        rgbc.gridy = 0;
        rgbc.gridwidth = 2;
        advancedRecoveryPanel.add(retrySafetyPanel, rgbc);

        JPanel expiryPanel = new JPanel(new GridBagLayout());
        expiryPanel.setBorder(BorderFactory.createTitledBorder(text("Session expiry signal")));
        GridBagConstraints sgbc = new GridBagConstraints();
        sgbc.fill = GridBagConstraints.HORIZONTAL;
        sgbc.insets = new Insets(4, 5, 4, 5);
        sgbc.gridx = 0;
        sgbc.gridwidth = 2;
        sgbc.gridy = 0;
        expiryPanel.add(automationExplanationLabel(text(
                "Describes how a response announces that this session has expired.")), sgbc);
        sgbc.gridy = 1;
        expiryPanel.add(automationExplanationLabel(text(
                "Leave every field empty to use the global refresh status codes.")), sgbc);
        sgbc.gridy = 2;
        expiryPanel.add(automationExplanationLabel(text(
                "Login redirect example: codes 301, 302 with header filter Location:\\s*/login")), sgbc);

        String signalStatusToolTip = text(
                "Comma-separated status codes. Empty accepts any status code.");
        sgbc.gridwidth = 1;
        sgbc.gridy = 3;
        sgbc.gridx = 0;
        sgbc.weightx = 0.0;
        JLabel signalStatusLabel = new JLabel(text("Expiry status codes:"));
        signalStatusLabel.setToolTipText(signalStatusToolTip);
        expiryPanel.add(signalStatusLabel, sgbc);
        signalStatusCodesField = new JTextField();
        signalStatusCodesField.setToolTipText(signalStatusToolTip);
        signalStatusCodesField.getDocument().addDocumentListener(
                new SimpleDocumentListener(this::updateActiveRuleFromUI));
        sgbc.gridx = 1;
        sgbc.weightx = 1.0;
        expiryPanel.add(signalStatusCodesField, sgbc);

        String signalHeaderToolTip = text(
                "Optional. Searched inside the response header block. Empty does not filter.");
        sgbc.gridy = 4;
        sgbc.gridx = 0;
        sgbc.weightx = 0.0;
        JLabel signalHeaderLabel = new JLabel(text("Response header filter:"));
        signalHeaderLabel.setToolTipText(signalHeaderToolTip);
        expiryPanel.add(signalHeaderLabel, sgbc);
        JPanel signalHeaderPanel = new JPanel(new BorderLayout(5, 0));
        signalHeaderModeComboBox = new JComboBox<>(
                new String[]{text("Regular expression"), text("Literal")});
        signalHeaderModeComboBox.setToolTipText(signalHeaderToolTip);
        signalHeaderModeComboBox.addActionListener(e -> updateActiveRuleFromUI());
        signalHeaderRegexField = new JTextField();
        signalHeaderRegexField.setToolTipText(signalHeaderToolTip);
        signalHeaderRegexField.getDocument().addDocumentListener(
                new SimpleDocumentListener(this::updateActiveRuleFromUI));
        signalHeaderPanel.add(signalHeaderModeComboBox, BorderLayout.WEST);
        signalHeaderPanel.add(signalHeaderRegexField, BorderLayout.CENTER);
        sgbc.gridx = 1;
        sgbc.weightx = 1.0;
        expiryPanel.add(signalHeaderPanel, sgbc);

        String signalBodyToolTip = text(
                "Optional. Searched inside the response body. Empty does not filter.");
        sgbc.gridy = 5;
        sgbc.gridx = 0;
        sgbc.weightx = 0.0;
        JLabel signalBodyLabel = new JLabel(text("Response body filter:"));
        signalBodyLabel.setToolTipText(signalBodyToolTip);
        expiryPanel.add(signalBodyLabel, sgbc);
        JPanel signalBodyPanel = new JPanel(new BorderLayout(5, 0));
        signalBodyModeComboBox = new JComboBox<>(
                new String[]{text("Regular expression"), text("Literal")});
        signalBodyModeComboBox.setToolTipText(signalBodyToolTip);
        signalBodyModeComboBox.addActionListener(e -> updateActiveRuleFromUI());
        signalBodyRegexField = new JTextField();
        signalBodyRegexField.setToolTipText(signalBodyToolTip);
        signalBodyRegexField.getDocument().addDocumentListener(
                new SimpleDocumentListener(this::updateActiveRuleFromUI));
        signalBodyPanel.add(signalBodyModeComboBox, BorderLayout.WEST);
        signalBodyPanel.add(signalBodyRegexField, BorderLayout.CENTER);
        sgbc.gridx = 1;
        sgbc.weightx = 1.0;
        expiryPanel.add(signalBodyPanel, sgbc);

        sgbc.gridy = 6;
        sgbc.gridx = 0;
        sgbc.gridwidth = 2;
        sgbc.weightx = 1.0;
        signalNegateCheckBox = new JCheckBox(
                text("The session is expired when the filter does NOT match"));
        signalNegateCheckBox.setToolTipText(text(
                "Inverts the verdict of the whole signal, not of individual fields."));
        signalNegateCheckBox.addActionListener(e -> updateActiveRuleFromUI());
        expiryPanel.add(signalNegateCheckBox, sgbc);

        sgbc.gridy = 7;
        signalWarningLabel = new JLabel(" ");
        signalWarningLabel.setForeground(WARNING_FOREGROUND);
        signalWarningLabel.setBorder(new EmptyBorder(0, 24, 0, 0));
        expiryPanel.add(signalWarningLabel, sgbc);

        // Built here but added last, below the passive-matching filters.

        JPanel passiveMatchingPanel = new JPanel(new GridBagLayout());
        passiveMatchingPanel.setBorder(BorderFactory.createTitledBorder(
                text("Passive extraction request matching")));
        GridBagConstraints pgbc = new GridBagConstraints();
        pgbc.fill = GridBagConstraints.HORIZONTAL;
        pgbc.insets = new Insets(4, 5, 4, 5);
        pgbc.gridx = 0;
        pgbc.gridwidth = 2;
        pgbc.gridy = 0;
        passiveMatchingPanel.add(automationExplanationLabel(text(
                "Every configured filter must match. The path does not include the query string.")), pgbc);
        pgbc.gridy = 1;
        passiveMatchingPanel.add(automationExplanationLabel(text(
                "An empty query and a None discriminator do not filter requests.")), pgbc);
        pgbc.gridy = 2;
        passiveMatchingPanel.add(automationExplanationLabel(text(
                "Literal requires an exact match; a regular expression only needs to find a match.")), pgbc);

        pgbc.gridwidth = 1;
        pgbc.gridy = 3;
        pgbc.gridx = 0;
        pgbc.weightx = 0.0;
        passiveMatchingPanel.add(new JLabel(text("Matching mode:")), pgbc);
        JPanel strategyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        matchStrategyLabel = new JLabel();
        convertMatchButton = new JButton(text("Convert to explicit filters"));
        convertMatchButton.addActionListener(e -> convertActiveRuleToExplicitMatch());
        strategyPanel.add(matchStrategyLabel);
        strategyPanel.add(convertMatchButton);
        pgbc.gridx = 1;
        pgbc.weightx = 1.0;
        passiveMatchingPanel.add(strategyPanel, pgbc);

        pgbc.gridy = 4;
        pgbc.gridx = 0;
        pgbc.weightx = 0.0;
        JLabel methodLabel = new JLabel(text("Method:"));
        methodLabel.setToolTipText(text(
                "The HTTP method must match exactly, ignoring letter case."));
        passiveMatchingPanel.add(methodLabel, pgbc);
        matchMethodField = new JTextField();
        matchMethodField.setToolTipText(text(
                "The HTTP method must match exactly, ignoring letter case."));
        matchMethodField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        pgbc.gridx = 1;
        pgbc.weightx = 1.0;
        passiveMatchingPanel.add(matchMethodField, pgbc);

        pgbc.gridy = 5;
        pgbc.gridx = 0;
        pgbc.weightx = 0.0;
        JLabel serviceLabel = new JLabel(text("Service:"));
        serviceLabel.setToolTipText(text(
                "Host, port, and HTTP or HTTPS must all match exactly."));
        passiveMatchingPanel.add(serviceLabel, pgbc);
        // FlowLayout also inserts its hgap before the first component, which would push this row
        // right of every other one; the gaps between fields are added explicitly instead.
        JPanel servicePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        matchHostField = new JTextField(16);
        matchPortField = new JTextField(5);
        matchSecureCheckBox = new JCheckBox("HTTPS");
        String serviceToolTip = text("Host, port, and HTTP or HTTPS must all match exactly.");
        matchHostField.setToolTipText(serviceToolTip);
        matchPortField.setToolTipText(serviceToolTip);
        matchSecureCheckBox.setToolTipText(serviceToolTip);
        matchHostField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        matchPortField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        matchSecureCheckBox.addActionListener(e -> updateActiveRuleFromUI());
        servicePanel.add(matchHostField);
        servicePanel.add(Box.createHorizontalStrut(5));
        servicePanel.add(matchPortField);
        servicePanel.add(Box.createHorizontalStrut(5));
        servicePanel.add(matchSecureCheckBox);
        pgbc.gridx = 1;
        pgbc.weightx = 1.0;
        passiveMatchingPanel.add(servicePanel, pgbc);

        pgbc.gridy = 6;
        pgbc.gridx = 0;
        pgbc.weightx = 0.0;
        JLabel pathLabel = new JLabel(text("Path filter:"));
        String pathToolTip = text(
                "Matches only the path, without query parameters. Literal compares the full path; a regular expression searches for a match.");
        pathLabel.setToolTipText(pathToolTip);
        passiveMatchingPanel.add(pathLabel, pgbc);
        JPanel pathPanel = new JPanel(new BorderLayout(5, 0));
        pathModeComboBox = new JComboBox<>(new String[]{text("Literal"), text("Regular expression")});
        pathModeComboBox.setToolTipText(pathToolTip);
        pathModeComboBox.addActionListener(e -> updateActiveRuleFromUI());
        matchUrlField = new JTextField();
        matchUrlField.setToolTipText(pathToolTip);
        matchUrlField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        pathPanel.add(pathModeComboBox, BorderLayout.WEST);
        pathPanel.add(matchUrlField, BorderLayout.CENTER);
        pgbc.gridx = 1;
        pgbc.weightx = 1.0;
        passiveMatchingPanel.add(pathPanel, pgbc);

        pgbc.gridy = 7;
        pgbc.gridx = 0;
        pgbc.weightx = 0.0;
        JLabel queryLabel = new JLabel(text("Query filter:"));
        String queryToolTip = text(
                "Optional. Matches the complete raw query string. Leave empty to accept any query.");
        queryLabel.setToolTipText(queryToolTip);
        passiveMatchingPanel.add(queryLabel, pgbc);
        JPanel queryPanel = new JPanel(new BorderLayout(5, 0));
        queryModeComboBox = new JComboBox<>(new String[]{text("Literal"), text("Regular expression")});
        queryModeComboBox.setToolTipText(queryToolTip);
        queryModeComboBox.addActionListener(e -> updateActiveRuleFromUI());
        queryField = new JTextField();
        queryField.setToolTipText(queryToolTip);
        queryField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        queryPanel.add(queryModeComboBox, BorderLayout.WEST);
        queryPanel.add(queryField, BorderLayout.CENTER);
        pgbc.gridx = 1;
        pgbc.weightx = 1.0;
        passiveMatchingPanel.add(queryPanel, pgbc);

        pgbc.gridy = 8;
        pgbc.gridx = 0;
        pgbc.weightx = 0.0;
        JLabel discriminatorLabel = new JLabel(text("Request discriminator:"));
        String discriminatorToolTip = text(
                "Optional. A regular expression must match the selected request body or headers. Use it to distinguish requests to the same endpoint.");
        discriminatorLabel.setToolTipText(discriminatorToolTip);
        passiveMatchingPanel.add(discriminatorLabel, pgbc);
        JPanel discriminatorPanel = new JPanel(new BorderLayout(5, 0));
        discriminatorSourceComboBox = new JComboBox<>(new String[]{
                text("None"), text("Request Body"), text("Request Headers")});
        discriminatorSourceComboBox.setToolTipText(discriminatorToolTip);
        discriminatorSourceComboBox.addActionListener(e -> updateActiveRuleFromUI());
        discriminatorRegexField = new JTextField();
        discriminatorRegexField.setToolTipText(discriminatorToolTip);
        discriminatorRegexField.getDocument().addDocumentListener(
                new SimpleDocumentListener(this::updateActiveRuleFromUI));
        discriminatorPanel.add(discriminatorSourceComboBox, BorderLayout.WEST);
        discriminatorPanel.add(discriminatorRegexField, BorderLayout.CENTER);
        pgbc.gridx = 1;
        pgbc.weightx = 1.0;
        passiveMatchingPanel.add(discriminatorPanel, pgbc);

        rgbc.gridy = 1;
        rgbc.gridx = 0;
        rgbc.gridwidth = 2;
        rgbc.weightx = 1.0;
        advancedMatchPanel.add(passiveMatchingPanel, rgbc);

        rgbc.gridy = 1;
        advancedRecoveryPanel.add(expiryPanel, rgbc);

        advancedMatchPanel.setVisible(false);
        advancedMatchToggle.addActionListener(e ->
                setAdvancedMatchingExpanded(advancedMatchToggle.isSelected()));
        rulePanel.add(advancedMatchPanel);

        // 3. Refresh Action Panel (background request sender, edit request & send to repeater)
        JPanel refreshPanel = new JPanel(new BorderLayout(5, 5));
        refreshPanel.setBorder(BorderFactory.createTitledBorder(text("Token Refresh Request")));
        
        savedRequestLabel = new JLabel(text("Saved Request: None"));
        savedRequestLabel.setFont(new Font(savedRequestLabel.getFont().getName(), Font.ITALIC, 11));
        savedRequestLabel.setBorder(new EmptyBorder(5, 10, 5, 10));
        refreshPanel.add(savedRequestLabel, BorderLayout.NORTH);

        JPanel refreshButtonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        
        refreshRequestButton = new JButton(text("Refresh Variable"));
        refreshRequestButton.addActionListener(e -> triggerBackgroundRefresh());
        
        sendToRepeaterButton = new JButton(text("Send to Repeater"));
        sendToRepeaterButton.addActionListener(e -> triggerSendToRepeater());

        editRequestButton = new JButton(text("Edit Request"));
        editRequestButton.addActionListener(e -> showEditRequestDialog());

        refreshButtonsPanel.add(refreshRequestButton);
        refreshButtonsPanel.add(sendToRepeaterButton);
        refreshButtonsPanel.add(editRequestButton);
        refreshPanel.add(refreshButtonsPanel, BorderLayout.CENTER);

        detailsTabs = new JTabbedPane();
        detailsTabs.addTab(text("Value"), valuePanel);

        JPanel automationDetails = new JPanel(new BorderLayout(5, 8));
        automationDetails.setBorder(new EmptyBorder(8, 8, 8, 8));
        automationDetails.add(refreshPanel, BorderLayout.NORTH);
        JPanel ruleContainer = new JPanel(new BorderLayout());
        ruleContainer.add(rulePanel, BorderLayout.NORTH);
        JScrollPane ruleScrollPane = new JScrollPane(ruleContainer);
        ruleScrollPane.setBorder(null);
        ruleScrollPane.getVerticalScrollBar().setUnitIncrement(16);
        automationDetails.add(ruleScrollPane, BorderLayout.CENTER);
        automationDetailsPanel = automationDetails;
        detailsTabs.addTab(text("Automation"), automationDetails);

        // 2FA Configuration tab panel
        JPanel totpConfigPanel = new JPanel(new GridBagLayout());
        totpConfigPanel.setBorder(new EmptyBorder(12, 15, 12, 15));
        tgbc = new GridBagConstraints();
        tgbc.fill = GridBagConstraints.HORIZONTAL;
        tgbc.insets = new Insets(6, 6, 6, 6);
        tgbc.anchor = GridBagConstraints.NORTHWEST;

        tgbc.gridx = 0; tgbc.gridy = 0; tgbc.weightx = 0.0;
        totpConfigPanel.add(new JLabel(text("2FA Secret (Base32):")), tgbc);
        totpSecretField = new JTextField(24);
        totpSecretField.getDocument().addDocumentListener(new SimpleDocumentListener(this::saveTotpConfig));
        tgbc.gridx = 1; tgbc.weightx = 1.0;
        totpConfigPanel.add(totpSecretField, tgbc);

        tgbc.gridx = 0; tgbc.gridy = 1; tgbc.weightx = 0.0;
        totpConfigPanel.add(new JLabel(text("Digits:")), tgbc);
        totpDigitsComboBox = new JComboBox<>(new Integer[]{6, 7, 8});
        totpDigitsComboBox.addActionListener(e -> saveTotpConfig());
        tgbc.gridx = 1; tgbc.weightx = 1.0;
        totpConfigPanel.add(totpDigitsComboBox, tgbc);

        tgbc.gridx = 0; tgbc.gridy = 2; tgbc.weightx = 0.0;
        totpConfigPanel.add(new JLabel(text("Period (seconds):")), tgbc);
        totpPeriodField = new JTextField(String.valueOf(TotpGenerator.DEFAULT_PERIOD_SECONDS), 10);
        totpPeriodField.getDocument().addDocumentListener(new SimpleDocumentListener(this::saveTotpConfig));
        tgbc.gridx = 1; tgbc.weightx = 1.0;
        totpConfigPanel.add(totpPeriodField, tgbc);

        tgbc.gridx = 0; tgbc.gridy = 3; tgbc.weightx = 0.0;
        totpConfigPanel.add(new JLabel(text("Algorithm:")), tgbc);
        totpAlgorithmComboBox = new JComboBox<>(new String[]{"SHA1", "SHA256", "SHA512"});
        totpAlgorithmComboBox.addActionListener(e -> saveTotpConfig());
        tgbc.gridx = 1; tgbc.weightx = 1.0;
        totpConfigPanel.add(totpAlgorithmComboBox, tgbc);

        // Vertical filler
        tgbc.gridx = 0; tgbc.gridy = 4; tgbc.weighty = 1.0; tgbc.gridwidth = 2;
        totpConfigPanel.add(new JPanel(), tgbc);

        JPanel totpContainer = new JPanel(new BorderLayout());
        totpContainer.add(totpConfigPanel, BorderLayout.NORTH);
        totpConfigDetailsPanel = totpContainer;

        JPanel emptyDetailsPanel = new JPanel(new GridBagLayout());
        JPanel emptyMessagePanel = new JPanel();
        emptyMessagePanel.setLayout(new BoxLayout(emptyMessagePanel, BoxLayout.Y_AXIS));
        JLabel emptyTitle = new JLabel(text("Select a variable"));
        emptyTitle.setFont(emptyTitle.getFont().deriveFont(Font.BOLD, 16f));
        emptyTitle.setAlignmentX(Component.CENTER_ALIGNMENT);
        JLabel emptyHint = new JLabel(text("Choose a variable on the left to edit its value or configure automation."));
        emptyHint.setForeground(UIManager.getColor("Label.disabledForeground"));
        emptyHint.setAlignmentX(Component.CENTER_ALIGNMENT);
        emptyMessagePanel.add(emptyTitle);
        emptyMessagePanel.add(Box.createVerticalStrut(6));
        emptyMessagePanel.add(emptyHint);
        emptyDetailsPanel.add(emptyMessagePanel);

        detailsCardLayout = new CardLayout();
        detailsCards = new JPanel(detailsCardLayout);
        detailsCards.add(emptyDetailsPanel, "empty");
        detailsCards.add(detailsTabs, "variable");

        splitPane.setLeftComponent(leftPanel);
        splitPane.setRightComponent(detailsCards);
        // The divider must be placed once the split pane has both components and a real size:
        // setting it before Burp shows the tab is discarded on the first layout pass.
        int initialDividerLocation = Math.max(
                leftPanel.getPreferredSize().width, DEFAULT_DIVIDER_LOCATION);
        splitPane.setDividerLocation(initialDividerLocation);
        splitPane.addHierarchyListener(new java.awt.event.HierarchyListener() {
            @Override
            public void hierarchyChanged(java.awt.event.HierarchyEvent event) {
                if ((event.getChangeFlags() & java.awt.event.HierarchyEvent.SHOWING_CHANGED) == 0) return;
                if (!splitPane.isShowing()) return;
                splitPane.removeHierarchyListener(this);
                SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(initialDividerLocation));
            }
        });
        mainPanel.add(splitPane, BorderLayout.CENTER);

        // --- FOOTER INSTRUCTIONS ---
        placeholderUsageLabel = new JLabel();
        placeholderUsageLabel.setBorder(new EmptyBorder(5, 5, 5, 5));
        updatePlaceholderUsageLabel();
        mainPanel.add(placeholderUsageLabel, BorderLayout.SOUTH);

        // Disable details until selection
        updateDetailsPanel(-1);
        mainPanel.revalidate();
        mainPanel.repaint();
    }

    private void showPlaceholderSettingsDialog() {
        JComboBox<UiLanguage> languageComboBox = new JComboBox<>(UiLanguage.values());
        languageComboBox.setSelectedItem(uiLanguage);
        languageComboBox.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                           boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value == UiLanguage.ENGLISH) setText(text("English"));
                if (value == UiLanguage.SPANISH) setText(text("Spanish"));
                return this;
            }
        });
        
        JComboBox<String> syntaxComboBox = new JComboBox<>(new String[]{"{{variable}}", "((variable))"});
        syntaxComboBox.setSelectedIndex(placeholderSyntax == VariableNames.PlaceholderSyntax.PARENTHESES ? 1 : 0);

        JCheckBox tagEnabledCheckBox = new JCheckBox(text("Use a tag in variable placeholders"), placeholderTagEnabled);
        JCheckBox diagnosticCheckBox = new JCheckBox(
                text("Enable auto-extraction diagnostic logs"), extractionDebugEnabled);
        JCheckBox extractionEnabledCheckBox = new JCheckBox(
                text("Extract variable values from matching responses"), extractionEnabled);
        String extractionExplanation = text(
                "Updates enabled variables when a response matches their extraction rule. It does not retry the request.");
        extractionEnabledCheckBox.setToolTipText(extractionExplanation);
        JCheckBox recoveryEnabledCheckBox = new JCheckBox(
                text("Recover expired sessions and retry requests"), sessionRecoveryEnabled);
        String recoveryExplanation = text(
                "After a configured status code, runs the saved refresh request and retries the original request. Requires refresh to be enabled for the variable.");
        recoveryEnabledCheckBox.setToolTipText(recoveryExplanation);
        JTextField statusCodesField = new JTextField(refreshStatusCodes, 10);
        statusCodesField.setToolTipText(text(
                "Default HTTP status codes (comma separated) that trigger an automatic token refresh (e.g., 401, 403). A variable with its own expiry signal ignores this list."));
        Map<AutomationTool, JCheckBox> extractionToolChecks = new EnumMap<>(AutomationTool.class);
        Map<AutomationTool, JCheckBox> recoveryToolChecks = new EnumMap<>(AutomationTool.class);
        JTextField tagField = new JTextField(placeholderTag, 20);
        JLabel previewLabel = new JLabel();
        JLabel validationLabel = new JLabel(" ");
        validationLabel.setForeground(new Color(180, 40, 40));

        Runnable updateState = () -> {
            boolean enabled = tagEnabledCheckBox.isSelected();
            tagField.setEnabled(enabled);
            String candidate = tagField.getText().trim();
            boolean valid = !enabled || VariableNames.isValidTag(candidate);
            validationLabel.setText(valid ? " "
                    : text("The tag must start with a letter and contain only letters, numbers, _ or -. "));
            VariableNames.PlaceholderSyntax previewSyntax = syntaxComboBox.getSelectedIndex() == 1 
                    ? VariableNames.PlaceholderSyntax.PARENTHESES 
                    : VariableNames.PlaceholderSyntax.CURLY_BRACES;
            previewLabel.setText(text("Example: ") + (valid
                    ? VariableNames.placeholder("token", new VariableNames.PlaceholderStyle(enabled,
                            enabled ? candidate : "", previewSyntax))
                    : (previewSyntax == VariableNames.PlaceholderSyntax.PARENTHESES ? "((tag:token))" : "{{tag:token}}")));
        };

        tagEnabledCheckBox.addActionListener(e -> updateState.run());
        tagField.getDocument().addDocumentListener(new SimpleDocumentListener(updateState::run));
        syntaxComboBox.addActionListener(e -> updateState.run());
        updateState.run();

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        panel.add(new JLabel(text("Language:")), gbc);
        gbc.gridy = 1;
        panel.add(languageComboBox, gbc);
        gbc.gridy = 2;
        panel.add(new JLabel(text("Syntax:")), gbc);
        gbc.gridy = 3;
        panel.add(syntaxComboBox, gbc);
        gbc.gridy = 4;
        panel.add(tagEnabledCheckBox, gbc);
        gbc.gridy = 5;
        gbc.gridwidth = 1;
        gbc.weightx = 0;
        panel.add(new JLabel(text("Tag:")), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        panel.add(tagField, gbc);
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.gridwidth = 2;
        panel.add(previewLabel, gbc);
        gbc.gridy = 7;
        panel.add(validationLabel, gbc);
        gbc.gridy = 8;
        JPanel behaviorNotice = new JPanel();
        behaviorNotice.setLayout(new BoxLayout(behaviorNotice, BoxLayout.Y_AXIS));
        behaviorNotice.add(new JLabel(text("Existing requests are not rewritten automatically. When tagging is enabled,")));
        behaviorNotice.add(new JLabel(text("only placeholders containing the configured tag are replaced.")));
        panel.add(behaviorNotice, gbc);
        JPanel automationScopePanel = new JPanel();
        automationScopePanel.setBorder(BorderFactory.createTitledBorder(text("Automation tool scope")));
        for (AutomationTool tool : AutomationTool.values()) {
            JCheckBox extraction = new JCheckBox("", extractionTools.contains(tool));
            JCheckBox recovery = new JCheckBox("", recoveryTools.contains(tool));
            extractionToolChecks.put(tool, extraction);
            recoveryToolChecks.put(tool, recovery);
        }
        Runnable updateAutomationScope = () -> {
            boolean showExtraction = extractionEnabledCheckBox.isSelected();
            boolean showRecovery = recoveryEnabledCheckBox.isSelected();
            automationScopePanel.removeAll();
            automationScopePanel.setVisible(showExtraction || showRecovery);
            if (showExtraction || showRecovery) {
                int columns = 1 + (showExtraction ? 1 : 0) + (showRecovery ? 1 : 0);
                automationScopePanel.setLayout(new GridLayout(0, columns, 8, 4));
                automationScopePanel.add(new JLabel(text("Tool")));
                if (showExtraction) {
                    automationScopePanel.add(new JLabel(text("Response extraction")));
                }
                if (showRecovery) {
                    automationScopePanel.add(new JLabel(text("Session recovery")));
                }
                for (AutomationTool tool : AutomationTool.values()) {
                    automationScopePanel.add(new JLabel(tool.name().charAt(0)
                            + tool.name().substring(1).toLowerCase(Locale.ROOT)));
                    if (showExtraction) {
                        automationScopePanel.add(extractionToolChecks.get(tool));
                    }
                    if (showRecovery) {
                        automationScopePanel.add(recoveryToolChecks.get(tool));
                    }
                }
            }
            automationScopePanel.revalidate();
            automationScopePanel.repaint();
        };

        JPanel recoveryCodesPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        recoveryCodesPanel.add(new JLabel(text("Recovery trigger status codes:")));
        recoveryCodesPanel.add(statusCodesField);
        Runnable updateRecoveryOptions = () -> {
            boolean visible = recoveryEnabledCheckBox.isSelected();
            recoveryCodesPanel.setVisible(visible);
            for (JCheckBox checkBox : recoveryToolChecks.values()) {
                checkBox.setEnabled(visible);
            }
            recoveryCodesPanel.revalidate();
        };
        extractionEnabledCheckBox.addActionListener(e -> updateAutomationScope.run());
        recoveryEnabledCheckBox.addActionListener(e -> {
            updateRecoveryOptions.run();
            updateAutomationScope.run();
        });

        JPanel automationSettingsPanel = new JPanel();
        automationSettingsPanel.setLayout(new BoxLayout(automationSettingsPanel, BoxLayout.Y_AXIS));
        JLabel extractionExplanationLabel = automationExplanationLabel(extractionExplanation);
        JLabel recoveryExplanationLabel = automationExplanationLabel(recoveryExplanation);
        extractionEnabledCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        extractionExplanationLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        recoveryEnabledCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        recoveryExplanationLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        recoveryCodesPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        automationScopePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        diagnosticCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        automationSettingsPanel.add(extractionEnabledCheckBox);
        automationSettingsPanel.add(extractionExplanationLabel);
        automationSettingsPanel.add(Box.createVerticalStrut(8));
        automationSettingsPanel.add(recoveryEnabledCheckBox);
        automationSettingsPanel.add(recoveryExplanationLabel);
        automationSettingsPanel.add(recoveryCodesPanel);
        automationSettingsPanel.add(Box.createVerticalStrut(8));
        automationSettingsPanel.add(automationScopePanel);
        automationSettingsPanel.add(Box.createVerticalStrut(8));
        automationSettingsPanel.add(diagnosticCheckBox);
        updateRecoveryOptions.run();
        updateAutomationScope.run();

        JTabbedPane settingsTabs = new JTabbedPane();
        settingsTabs.addTab(text("General"), panel);
        settingsTabs.addTab(text("Automation"), automationSettingsPanel);

        boolean enabled;
        String tag;
        while (true) {
            int result = JOptionPane.showConfirmDialog(mainPanel, settingsTabs, text("Tool Configuration"),
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (result != JOptionPane.OK_OPTION) return;

            enabled = tagEnabledCheckBox.isSelected();
            tag = tagField.getText().trim();
            if (!enabled || VariableNames.isValidTag(tag)) break;
            JOptionPane.showMessageDialog(mainPanel,
                    text("The tag must start with a letter and contain only letters, numbers, _ or -."),
                    text("Invalid Tag"), JOptionPane.ERROR_MESSAGE);
        }

        placeholderTagEnabled = enabled;
        if (!tag.isEmpty()) placeholderTag = tag;
        placeholderSyntax = syntaxComboBox.getSelectedIndex() == 1 
                ? VariableNames.PlaceholderSyntax.PARENTHESES 
                : VariableNames.PlaceholderSyntax.CURLY_BRACES;
        extractionEnabled = extractionEnabledCheckBox.isSelected();
        sessionRecoveryEnabled = recoveryEnabledCheckBox.isSelected();
        refreshStatusCodes = statusCodesField.getText().trim();
        extractionDebugEnabled = diagnosticCheckBox.isSelected();
        extractionTools = EnumSet.noneOf(AutomationTool.class);
        recoveryTools = EnumSet.noneOf(AutomationTool.class);
        for (AutomationTool tool : AutomationTool.values()) {
            if (extractionToolChecks.get(tool).isSelected()) extractionTools.add(tool);
            if (recoveryToolChecks.get(tool).isSelected()) recoveryTools.add(tool);
        }
        UiLanguage selectedLanguage = (UiLanguage) languageComboBox.getSelectedItem();
        boolean languageChanged = selectedLanguage != null && selectedLanguage != uiLanguage;
        if (selectedLanguage != null) uiLanguage = selectedLanguage;
        savePreferences();
        if (languageChanged) {
            createUI();
        } else {
            updatePlaceholderUsageLabel();
            updateGlobalStatusLabels();
            tableModel.fireTableDataChanged();
        }
    }

    private JLabel automationExplanationLabel(String explanation) {
        JLabel label = new JLabel(explanation);
        label.setForeground(UIManager.getColor("Label.disabledForeground"));
        label.setBorder(new EmptyBorder(0, 24, 0, 0));
        return label;
    }

    private void updatePlaceholderUsageLabel() {
        if (placeholderUsageLabel == null) return;
        if (uiLanguage == UiLanguage.SPANISH) {
            placeholderUsageLabel.setText("Uso: " + placeholderFor("variable") + " para variables sin carpeta o "
                    + placeholderFor("folder.variable")
                    + " para variables agrupadas. Haz clic derecho en una selección de respuesta para automatizar la extracción.");
        } else {
            placeholderUsageLabel.setText("Usage: " + placeholderFor("variable") + " for Ungrouped or "
                    + placeholderFor("folder.variable")
                    + " for grouped variables. Right-click a response selection to automate extraction.");
        }
    }

    private void updateGlobalStatusLabels() {
        if (automationStatusLabel != null) {
            String extractionStatus = extractionEnabled ? text("On") : text("Off");
            String recoveryStatus = sessionRecoveryEnabled ? text("On") : text("Off");
            automationStatusLabel.setText(text("Extraction") + ": " + extractionStatus
                    + "  ·  " + text("Recovery") + ": " + recoveryStatus);
            automationStatusLabel.setToolTipText(text(
                    "Open configuration to change automation behavior and tool scope."));
        }
    }

    private void updateDetailsPanel(int selectedRow) {
        if (selectedRow < 0) {
            if (detailsCardLayout != null) detailsCardLayout.show(detailsCards, "empty");
            setAdvancedMatchingExpanded(false);
            setTotpDetailsVisible(false);
            isUpdatingUI = true;
            valueTextArea.setText("");
            valueTextArea.setEnabled(false);
            ruleEnabledCheckBox.setSelected(false);
            ruleEnabledCheckBox.setEnabled(false);
            automaticRefreshCheckBox.setSelected(false);
            automaticRefreshCheckBox.setEnabled(false);
            if (advancedRecoveryButton != null) {
                advancedRecoveryButton.setEnabled(false);
            }
            allowNonIdempotentReplayCheckBox.setSelected(false);
            allowNonIdempotentReplayCheckBox.setEnabled(false);
            setMatchFieldsEnabled(false);
            matchUrlField.setText("");
            matchUrlField.setEnabled(false);
            extractionZoneComboBox.removeAllItems();
            extractionZoneComboBox.setEnabled(false);
            sourceComboBox.setSelectedIndex(0);
            sourceComboBox.setEnabled(false);
            regexField.setText("");
            regexField.setEnabled(false);
            delimiterField.setText(placeholderSyntax == VariableNames.PlaceholderSyntax.PARENTHESES ? "((value1))" : "{{value1}}");
            delimiterField.setEnabled(false);
            removeExtractionZoneButton.setEnabled(false);
            updateRuleButton.setEnabled(false);
            savedRequestLabel.setText(text("Saved Request: None"));
            refreshRequestButton.setEnabled(false);
            sendToRepeaterButton.setEnabled(false);
            editRequestButton.setEnabled(false);
            isUpdatingUI = false;
            return;
        }

        String name = tableModel.variableKeyAt(selectedRow);
        if (name == null) {
            disableDetails(tableModel.isFolderRow(selectedRow)
                    ? text("Select a variable inside this folder to edit its details.")
                    : text("Select a variable to edit its details."));
            return;
        }
        if (detailsCardLayout != null) detailsCardLayout.show(detailsCards, "variable");
        String val = values.getOrDefault(name, "");
        VariableExtractionRule rule = rules.getOrDefault(name, new VariableExtractionRule());

        VariableDefinition selectedDefinition = findDefinitionByKey(name);
        // A 2FA variable owns its value: it is computed from the secret on every use, and it
        // is never extracted from a response nor replayed during session recovery.
        boolean totpVariable = selectedDefinition != null && selectedDefinition.isTotpVariable();

        isUpdatingUI = true;
        setTotpDetailsVisible(totpVariable);

        if (totpVariable && selectedDefinition != null) {
            TotpGenerator.TotpConfig cfg = selectedDefinition.getTotpConfig();
            totpSecretField.setText(cfg.secret());
            totpDigitsComboBox.setSelectedItem(cfg.digits());
            totpPeriodField.setText(String.valueOf(cfg.periodSeconds()));
            totpAlgorithmComboBox.setSelectedItem(cfg.algorithm());
        }

        valueTextArea.setText(val);
        valueTextArea.setEnabled(!totpVariable);
        valueTextArea.setToolTipText(totpVariable ? text("Computed from the 2FA secret.") : null);

        ruleEnabledCheckBox.setEnabled(!totpVariable);
        ruleEnabledCheckBox.setSelected(!totpVariable && rule.isEnabled());
        automaticRefreshCheckBox.setEnabled(!totpVariable);
        automaticRefreshCheckBox.setSelected(!totpVariable && rule.isAutomaticRefreshEnabled());
        if (advancedRecoveryButton != null) {
            advancedRecoveryButton.setEnabled(automaticRefreshCheckBox.isSelected());
        }
        allowNonIdempotentReplayCheckBox.setEnabled(!totpVariable);
        allowNonIdempotentReplayCheckBox.setSelected(!totpVariable && rule.isAllowNonIdempotentReplay());
        // A 2FA variable is computed from its secret, so it never recovers a session over the wire.
        displayExpirySignal(rule.getExpirySignal(), !totpVariable);

        boolean explicit = rule.getMatchStrategy() == VariableExtractionRule.MatchStrategy.EXPLICIT;
        setAdvancedMatchingExpanded(!explicit || rule.isAllowNonIdempotentReplay()
                || rule.getExpirySignal() != null);
        matchStrategyLabel.setText(switch (rule.getMatchStrategy()) {
            case EXPLICIT -> text("Explicit filters");
            case LEGACY_EXACT -> text("Legacy exact saved request matching");
            case LEGACY_PATH -> text("Legacy path regex matching");
        });
        convertMatchButton.setVisible(!explicit);
        setMatchFieldsEnabled(explicit);
        matchMethodField.setText(rule.getMatchMethod());
        matchHostField.setText(rule.getMatchHost());
        matchPortField.setText(rule.getMatchPort() <= 0 ? "" : Integer.toString(rule.getMatchPort()));
        matchSecureCheckBox.setSelected(rule.isMatchSecure());
        pathModeComboBox.setSelectedIndex(
                rule.getPathMatchMode() == VariableExtractionRule.PatternMode.REGEX ? 1 : 0);
        matchUrlField.setText(explicit ? rule.getMatchPath() : rule.getMatchUrl());
        queryModeComboBox.setSelectedIndex(
                rule.getQueryMatchMode() == VariableExtractionRule.PatternMode.REGEX ? 1 : 0);
        queryField.setText(rule.getMatchQuery());
        discriminatorSourceComboBox.setSelectedIndex(switch (rule.getDiscriminatorSource()) {
            case REQUEST_BODY -> 1;
            case REQUEST_HEADERS -> 2;
            default -> 0;
        });
        discriminatorRegexField.setText(rule.getDiscriminatorRegex());

        extractionZoneComboBox.removeAllItems();
        for (int index = 0; index < rule.getTargets().size(); index++) {
            extractionZoneComboBox.addItem(rule.getTargets().get(index).name());
        }
        extractionZoneComboBox.setEnabled(true);
        extractionZoneComboBox.setSelectedIndex(0);
        displayExtractionTarget(rule.getTargets().get(0));
        removeExtractionZoneButton.setEnabled(rule.getTargets().size() > 1);
        delimiterField.setEnabled(true);
        delimiterField.setText(rule.getValueTemplate());

        // Update refresh request details
        if (rule.getSavedRequestBase64() == null || rule.getSavedRequestBase64().isEmpty()) {
            savedRequestLabel.setText(text("Saved Request: None"));
            refreshRequestButton.setEnabled(false);
            sendToRepeaterButton.setEnabled(false);
            // No saved request yet: the editor still opens on a blank template so the
            // request can be crafted from scratch. The other buttons need a real request.
            editRequestButton.setEnabled(true);
            updateRuleButton.setEnabled(false);
        } else {
            try {
                byte[] requestBytes = Base64.getDecoder().decode(rule.getSavedRequestBase64());
                HttpRequest savedReq = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
                savedRequestLabel.setText((uiLanguage == UiLanguage.SPANISH ? "Petición guardada: " : "Saved Request: ")
                        + savedReq.method() + " " + savedReq.path());
                refreshRequestButton.setEnabled(true);
                sendToRepeaterButton.setEnabled(true);
                editRequestButton.setEnabled(true);
                updateRuleButton.setEnabled(true);
            } catch (Exception e) {
                savedRequestLabel.setText(text("Saved Request: Error parsing request data"));
                refreshRequestButton.setEnabled(false);
                sendToRepeaterButton.setEnabled(false);
                // Unparseable stored data: allow the editor so the request can be rewritten.
                editRequestButton.setEnabled(true);
                updateRuleButton.setEnabled(false);
            }
        }
        isUpdatingUI = false;
    }

    private void showAdvancedRecoveryDialog() {
        JOptionPane.showMessageDialog(mainPanel, advancedRecoveryPanel, text("Advanced Session Recovery Options"), JOptionPane.PLAIN_MESSAGE);
    }

    private void setAdvancedMatchingExpanded(boolean expanded) {
        if (advancedMatchToggle == null || advancedMatchPanel == null) return;
        advancedMatchToggle.setSelected(expanded);
        advancedMatchToggle.setText(text(expanded
                ? "Hide advanced automation options"
                : "Show advanced automation options"));
        advancedMatchPanel.setVisible(expanded);
        advancedMatchPanel.revalidate();
        advancedMatchPanel.repaint();
    }

    private void clearRuleFields() {
        isUpdatingUI = true;
        ruleEnabledCheckBox.setSelected(false);
        automaticRefreshCheckBox.setSelected(false);
        if (advancedRecoveryButton != null) {
            advancedRecoveryButton.setEnabled(false);
        }
        allowNonIdempotentReplayCheckBox.setSelected(false);
        displayExpirySignal(null, false);
        matchStrategyLabel.setText("");
        convertMatchButton.setVisible(false);
        setMatchFieldsEnabled(false);
        matchMethodField.setText("");
        matchHostField.setText("");
        matchPortField.setText("");
        matchSecureCheckBox.setSelected(false);
        matchUrlField.setText("");
        queryField.setText("");
        discriminatorRegexField.setText("");
        extractionZoneComboBox.removeAllItems();
        extractionZoneComboBox.setEnabled(false);
        sourceComboBox.setSelectedIndex(0);
        regexField.setText("");
        delimiterField.setText(placeholderSyntax == VariableNames.PlaceholderSyntax.PARENTHESES ? "((value1))" : "{{value1}}");
        removeExtractionZoneButton.setEnabled(false);
        updateRuleButton.setEnabled(false);
        savedRequestLabel.setText(text("Saved Request: None"));
        refreshRequestButton.setEnabled(false);
        sendToRepeaterButton.setEnabled(false);
        editRequestButton.setEnabled(false);
        isUpdatingUI = false;
    }

    private void updateActiveRuleFromUI() {
        if (isUpdatingUI) return;
        int selectedRow = variablesTable.getSelectedRow();
        String name = tableModel.variableKeyAt(selectedRow);
        if (name != null) {
            boolean ruleEnabled = ruleEnabledCheckBox.isSelected();
            String source;
            switch (sourceComboBox.getSelectedIndex()) {
                case 1: source = "headers"; break;
                case 2: source = "request_body"; break;
                case 3: source = "request_headers"; break;
                default: source = "body"; break;
            }
            String regex = regexField.getText().trim();
            String valueTemplate = delimiterField.getText();

            synchronized (lock) {
                VariableExtractionRule existingRule = rules.get(name);
                VariableExtractionRule rule = existingRule == null
                        ? new VariableExtractionRule() : existingRule.copy();
                rule.setEnabled(ruleEnabled);
                rule.setAutomaticRefreshEnabled(automaticRefreshCheckBox.isSelected());
                rule.setAllowNonIdempotentReplay(allowNonIdempotentReplayCheckBox.isSelected());
                // Kept outside the EXPLICIT branch: an expiry signal is meaningful for legacy rules too.
                rule.setExpirySignal(readExpirySignalFromUI());
                updateExpirySignalWarning(rule.getExpirySignal());
                int targetIndex = Math.max(0, extractionZoneComboBox.getSelectedIndex());
                if (targetIndex < rule.getTargets().size()) {
                    rule.replaceTarget(targetIndex,
                            VariableExtractionRule.ExtractionSource.fromStored(source), regex);
                }
                rule.setValueTemplate(valueTemplate);
                if (rule.getMatchStrategy() == VariableExtractionRule.MatchStrategy.EXPLICIT) {
                    int port = parsePort(matchPortField.getText());
                    rule.configureExplicitMatch(
                            matchMethodField.getText().trim().toUpperCase(Locale.ROOT),
                            matchHostField.getText().trim(), port, matchSecureCheckBox.isSelected(),
                            matchUrlField.getText().trim(),
                            pathModeComboBox.getSelectedIndex() == 1
                                    ? VariableExtractionRule.PatternMode.REGEX
                                    : VariableExtractionRule.PatternMode.LITERAL,
                            queryField.getText().trim(),
                            queryModeComboBox.getSelectedIndex() == 1
                                    ? VariableExtractionRule.PatternMode.REGEX
                                    : VariableExtractionRule.PatternMode.LITERAL,
                            switch (discriminatorSourceComboBox.getSelectedIndex()) {
                                case 1 -> VariableExtractionRule.DiscriminatorSource.REQUEST_BODY;
                                case 2 -> VariableExtractionRule.DiscriminatorSource.REQUEST_HEADERS;
                                default -> VariableExtractionRule.DiscriminatorSource.NONE;
                            },
                            discriminatorRegexField.getText().trim());
                }
                rules.put(name, rule);
                VariableDefinition definition = findDefinitionByKey(name);
                if (definition != null) definition.setRule(rule);
                savePreferences();
            }
            // Update Table display
            tableModel.fireTableCellUpdated(selectedRow, 2);
        }
    }

    private void loadSelectedExtractionZone() {
        if (isUpdatingUI) return;
        int selectedRow = variablesTable.getSelectedRow();
        String name = tableModel.variableKeyAt(selectedRow);
        VariableExtractionRule rule = name == null ? null : rules.get(name);
        int targetIndex = extractionZoneComboBox.getSelectedIndex();
        if (rule == null || targetIndex < 0 || targetIndex >= rule.getTargets().size()) return;

        isUpdatingUI = true;
        displayExtractionTarget(rule.getTargets().get(targetIndex));
        removeExtractionZoneButton.setEnabled(rule.getTargets().size() > 1);
        isUpdatingUI = false;
    }

    private void displayExtractionTarget(VariableExtractionRule.ExtractionTarget target) {
        sourceComboBox.setEnabled(true);
        sourceComboBox.setSelectedIndex(switch (target.source()) {
            case RESPONSE_HEADERS -> 1;
            case REQUEST_BODY -> 2;
            case REQUEST_HEADERS -> 3;
            case RESPONSE_BODY -> 0;
        });
        regexField.setEnabled(true);
        regexField.setText(target.regex());
    }

    private void removeSelectedExtractionZone() {
        int selectedRow = variablesTable.getSelectedRow();
        String name = tableModel.variableKeyAt(selectedRow);
        int targetIndex = extractionZoneComboBox.getSelectedIndex();
        if (name == null || targetIndex < 0) return;
        if (!confirmDialog(text("Remove the selected extraction zone?"),
                text("Remove Zone"), JOptionPane.WARNING_MESSAGE)) return;

        synchronized (lock) {
            VariableExtractionRule existingRule = rules.get(name);
            if (existingRule == null || existingRule.getTargets().size() <= 1) return;
            VariableExtractionRule rule = existingRule.copy();
            rule.removeTarget(targetIndex);
            rule.resetValueTemplate();
            rules.put(name, rule);
            VariableDefinition definition = findDefinitionByKey(name);
            if (definition != null) definition.setRule(rule);
            savePreferences();
        }
        updateDetailsPanel(selectedRow);
        int remainingIndex = Math.min(targetIndex, extractionZoneComboBox.getItemCount() - 1);
        if (remainingIndex >= 0) extractionZoneComboBox.setSelectedIndex(remainingIndex);
    }

    private void handleRuleActivation(JCheckBox checkBox, boolean refresh) {
        if (isUpdatingUI) return;
        if (checkBox.isSelected()) {
            String error = activeRuleValidationError(refresh);
            if (error != null) {
                checkBox.setSelected(false);
                JOptionPane.showMessageDialog(mainPanel, text(error), text("Error"),
                        JOptionPane.ERROR_MESSAGE);
            } else if (!ensureGlobalAutomationEnabled(mainPanel, refresh)) {
                checkBox.setSelected(false);
            }
        }
        updateActiveRuleFromUI();
    }

    boolean ensureGlobalAutomationEnabled(Component parent, boolean refresh) {
        boolean globallyEnabled = refresh ? sessionRecoveryEnabled : extractionEnabled;
        if (globallyEnabled) return true;

        String question = refresh
                ? "Session recovery is disabled globally. Enable it now?"
                : "Response extraction is disabled globally. Enable it now?";
        String title = refresh
                ? "Enable global session recovery"
                : "Enable global response extraction";
        int choice = JOptionPane.showConfirmDialog(
                parent, text(question), text(title),
                JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (choice != JOptionPane.YES_OPTION) return false;

        if (refresh) {
            sessionRecoveryEnabled = true;
        } else {
            extractionEnabled = true;
        }
        savePreferences();
        updateGlobalStatusLabels();
        return true;
    }

    private String activeRuleValidationError(boolean refresh) {
        String extractionRegex = regexField.getText().trim();
        if (!ExtractionEngine.isValidRegex(extractionRegex)
                || !ExtractionEngine.hasCaptureGroup(extractionRegex)) {
            return "The extraction regex must be valid and contain at least one capture group.";
        }
        int selectedRow = variablesTable.getSelectedRow();
        String selectedName = tableModel.variableKeyAt(selectedRow);
        VariableExtractionRule selectedRule = selectedName == null ? null : rules.get(selectedName);
        if (selectedRule != null && !hasValidExtractionTargets(selectedRule)) {
            return "Every extraction zone must have a valid regex with at least one capture group.";
        }
        if (selectedRule != null && !ExtractionEngine.isValidValueTemplate(
                delimiterField.getText(), selectedRule.getTargets())) {
            return "The final value template must reference every extraction value.";
        }
        if (refresh) {
            VariableExtractionRule rule = selectedRule;
            if (rule == null || rule.getSavedRequestBase64() == null
                    || rule.getSavedRequestBase64().isEmpty()) {
                return "Automatic refresh requires a saved request.";
            }
            return null;
        }
        VariableExtractionRule current = selectedRule;
        if (current != null
                && current.getMatchStrategy() != VariableExtractionRule.MatchStrategy.EXPLICIT) {
            return null;
        }
        if (matchMethodField.getText().trim().isEmpty()
                || matchHostField.getText().trim().isEmpty()
                || parsePort(matchPortField.getText()) <= 0
                || matchUrlField.getText().trim().isEmpty()) {
            return "Explicit matching requires method, service, port, and path.";
        }
        if (pathModeComboBox.getSelectedIndex() == 1
                && !ExtractionEngine.isValidRegex(matchUrlField.getText().trim())) {
            return "The path regular expression is invalid.";
        }
        if (!queryField.getText().trim().isEmpty() && queryModeComboBox.getSelectedIndex() == 1
                && !ExtractionEngine.isValidRegex(queryField.getText().trim())) {
            return "The query regular expression is invalid.";
        }
        if (discriminatorSourceComboBox.getSelectedIndex() != 0
                && !ExtractionEngine.isValidRegex(discriminatorRegexField.getText().trim())) {
            return "The request discriminator regular expression is invalid.";
        }
        return null;
    }

    private int parsePort(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (Exception ignored) {
            return 0;
        }
    }

    private void displayExpirySignal(VariableExtractionRule.ExpirySignal signal, boolean editable) {
        if (signalStatusCodesField == null) return;
        signalStatusCodesField.setEnabled(editable);
        signalHeaderModeComboBox.setEnabled(editable);
        signalHeaderRegexField.setEnabled(editable);
        signalBodyModeComboBox.setEnabled(editable);
        signalBodyRegexField.setEnabled(editable);
        signalNegateCheckBox.setEnabled(editable);

        VariableExtractionRule.ExpirySignal shown = editable ? signal : null;
        signalStatusCodesField.setText(shown == null
                ? "" : VariableExtractionRule.formatStatusCodes(shown.statusCodes()));
        signalHeaderModeComboBox.setSelectedIndex(
                shown == null ? 0 : patternModeIndex(shown.headerMode()));
        signalHeaderRegexField.setText(shown == null ? "" : shown.headerRegex());
        signalBodyModeComboBox.setSelectedIndex(
                shown == null ? 0 : patternModeIndex(shown.bodyMode()));
        signalBodyRegexField.setText(shown == null ? "" : shown.bodyRegex());
        signalNegateCheckBox.setSelected(shown != null && shown.negate());
        updateExpirySignalWarning(shown);
    }

    private VariableExtractionRule.ExpirySignal readExpirySignalFromUI() {
        if (signalStatusCodesField == null) return null;
        VariableExtractionRule.ExpirySignal signal = new VariableExtractionRule.ExpirySignal(
                VariableExtractionRule.parseStatusCodes(signalStatusCodesField.getText()),
                signalHeaderRegexField.getText().trim(), patternModeAt(signalHeaderModeComboBox),
                signalBodyRegexField.getText().trim(), patternModeAt(signalBodyModeComboBox),
                signalNegateCheckBox.isSelected());
        return signal.isEmpty() ? null : signal;
    }

    /**
     * The resolver already ignores an unusable signal and logs it, so this only warns; it never
     * blocks saving. Otherwise a half-typed status code would fight the user on every keystroke.
     */
    private void updateExpirySignalWarning(VariableExtractionRule.ExpirySignal signal) {
        if (signalWarningLabel == null) return;
        boolean unusable = signal != null && !AutomationPolicy.isExpirySignalUsable(signal);
        signalWarningLabel.setText(unusable
                ? text("Codes other than 401 and 403 require a header or body filter; this signal is ignored.")
                : " ");
    }

    private static int patternModeIndex(VariableExtractionRule.PatternMode mode) {
        return mode == VariableExtractionRule.PatternMode.LITERAL ? 1 : 0;
    }

    private static VariableExtractionRule.PatternMode patternModeAt(JComboBox<String> comboBox) {
        return comboBox.getSelectedIndex() == 1
                ? VariableExtractionRule.PatternMode.LITERAL
                : VariableExtractionRule.PatternMode.REGEX;
    }

    private void setMatchFieldsEnabled(boolean enabled) {
        if (matchMethodField == null) return;
        matchMethodField.setEnabled(enabled);
        matchHostField.setEnabled(enabled);
        matchPortField.setEnabled(enabled);
        matchSecureCheckBox.setEnabled(enabled);
        pathModeComboBox.setEnabled(enabled);
        matchUrlField.setEnabled(enabled);
        queryModeComboBox.setEnabled(enabled);
        queryField.setEnabled(enabled);
        discriminatorSourceComboBox.setEnabled(enabled);
        discriminatorRegexField.setEnabled(enabled);
    }

    private void convertActiveRuleToExplicitMatch() {
        int selectedRow = variablesTable.getSelectedRow();
        String name = tableModel.variableKeyAt(selectedRow);
        if (name == null) return;
        synchronized (lock) {
            VariableExtractionRule rule = rules.get(name);
            if (rule == null) return;
            String method = "";
            String host = rule.getSavedHost();
            int port = rule.getSavedPort();
            boolean secure = rule.isSavedSecure();
            String path = rule.getMatchUrl();
            try {
                if (!rule.getSavedRequestBase64().isEmpty()) {
                    HttpRequest request = HttpRequest.httpRequest(ByteArray.byteArray(
                            Base64.getDecoder().decode(rule.getSavedRequestBase64())));
                    method = request.method();
                    String fullPath = request.path();
                    int queryAt = fullPath.indexOf('?');
                    path = queryAt < 0 ? fullPath : fullPath.substring(0, queryAt);
                }
            } catch (Exception error) {
                api.logging().logToError("Could not convert legacy match for '" + name + "': "
                        + error.getMessage());
                return;
            }
            rule.configureExplicitMatch(method, host, port, secure, path,
                    VariableExtractionRule.PatternMode.LITERAL, "",
                    VariableExtractionRule.PatternMode.LITERAL,
                    VariableExtractionRule.DiscriminatorSource.NONE, "");
            rule.setEnabled(false);
            rule.setAutomaticRefreshEnabled(false);
            savePreferences();
        }
        updateDetailsPanel(selectedRow);
    }

    private void triggerSendToRepeater() {
        int selectedRow = variablesTable.getSelectedRow();
        String name = tableModel.variableKeyAt(selectedRow);
        if (name != null) {
            VariableExtractionRule rule = rules.get(name);
            if (rule != null && rule.getSavedRequestBase64() != null && !rule.getSavedRequestBase64().isEmpty()) {
                try {
                    byte[] requestBytes = Base64.getDecoder().decode(rule.getSavedRequestBase64());
                    HttpRequest savedReq = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
                    HttpService service = HttpService.httpService(
                            rule.getSavedHost(),
                            rule.getSavedPort(),
                            rule.isSavedSecure()
                    );
                    savedReq = savedReq.withService(service);
                    
                    // Send to Repeater tool natively
                    api.repeater().sendToRepeater(savedReq, "Refresh " + name);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(mainPanel, text("Failed to send request to Repeater: ") + ex.getMessage(), text("Error"), JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    private void showEditRequestDialog() {
        int selectedRow = variablesTable.getSelectedRow();
        String name = tableModel.variableKeyAt(selectedRow);
        if (name == null) return;
        // A variable without a saved refresh request must still be able to craft one from
        // scratch, so create the rule on demand instead of refusing to open the editor.
        VariableExtractionRule existingRule = rules.get(name);
        VariableExtractionRule rule = existingRule != null ? existingRule : new VariableExtractionRule();

        try {
            String savedRequestBase64 = rule.getSavedRequestBase64();
            HttpRequest savedRequest = null;
            if (savedRequestBase64 != null && !savedRequestBase64.isEmpty()) {
                try {
                    byte[] requestBytes = Base64.getDecoder().decode(savedRequestBase64);
                    savedRequest = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
                } catch (Exception ex) {
                    api.logging().logToError("Stored refresh request could not be decoded for "
                            + name + ", starting from a blank template: " + ex.getMessage());
                }
            }
            String seedHost = rule.getSavedHost() == null ? "" : rule.getSavedHost();
            if (savedRequest == null) {
                savedRequest = HttpRequest.httpRequest(
                        "GET / HTTP/1.1\r\nHost: " + seedHost + "\r\n\r\n");
            }

            JDialog editDialog = new JDialog(api.userInterface().swingUtils().suiteFrame(), text("Edit Saved Request - ") + name, Dialog.ModalityType.APPLICATION_MODAL);
            editDialog.setLayout(new BorderLayout(10, 10));
            editDialog.setSize(650, 500);
            editDialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());

            // Header inputs panel
            JPanel headerPanel = new JPanel(new GridBagLayout());
            headerPanel.setBorder(new EmptyBorder(10, 10, 0, 10));
            GridBagConstraints hgbc = new GridBagConstraints();
            hgbc.fill = GridBagConstraints.HORIZONTAL;
            hgbc.insets = new Insets(5, 5, 5, 5);

            hgbc.gridx = 0; hgbc.gridy = 0; hgbc.weightx = 0.0;
            headerPanel.add(new JLabel(text("Host:")), hgbc);
            JTextField hostField = new JTextField(rule.getSavedHost());
            hgbc.gridx = 1; hgbc.weightx = 1.0;
            headerPanel.add(hostField, hgbc);

            hgbc.gridx = 2; hgbc.weightx = 0.0;
            headerPanel.add(new JLabel(text("Port:")), hgbc);
            JTextField portField = new JTextField(rule.getSavedPort() > 0
                    ? String.valueOf(rule.getSavedPort())
                    : (rule.isSavedSecure() ? "443" : "80"));
            hgbc.gridx = 3; hgbc.weightx = 0.5;
            headerPanel.add(portField, hgbc);

            hgbc.gridx = 4; hgbc.weightx = 0.0;
            JCheckBox secureCheckBox = new JCheckBox("HTTPS", rule.isSavedSecure());
            headerPanel.add(secureCheckBox, hgbc);

            editDialog.add(headerPanel, BorderLayout.NORTH);

            // Burp's native request editor provides Pretty, Raw and the other
            // standard message views while remaining fully editable.
            JPanel editorPanel = new JPanel(new BorderLayout(5, 5));
            editorPanel.setBorder(new EmptyBorder(5, 10, 5, 10));
            HttpRequestEditor requestEditor = api.userInterface().createHttpRequestEditor();
            requestEditor.setRequest(savedRequest);
            editorPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
            editDialog.add(editorPanel, BorderLayout.CENTER);

            // Footer buttons
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
            JButton saveButton = new JButton(text("Save Changes"));
            JButton copyButton = new JButton(text("Copy to Clipboard"));
            JButton cancelButton = new JButton(text("Cancel"));

            copyButton.addActionListener(e -> {
                try {
                    String requestText = new String(
                            requestEditor.getRequest().toByteArray().getBytes(),
                            StandardCharsets.UTF_8);
                    StringSelection selection = new StringSelection(requestText);
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
                    JOptionPane.showMessageDialog(editDialog, text("Request copied to clipboard."), text("Copied"), JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(editDialog, text("Failed to copy to clipboard: ") + ex.getMessage(), text("Error"), JOptionPane.ERROR_MESSAGE);
                }
            });

            saveButton.addActionListener(e -> {
                String newHost = hostField.getText().trim();
                int newPort = 0;
                try {
                    newPort = Integer.parseInt(portField.getText().trim());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(editDialog, text("Invalid port number."), text("Error"), JOptionPane.ERROR_MESSAGE);
                    return;
                }
                boolean newSecure = secureCheckBox.isSelected();

                if (newHost.isEmpty()) {
                    JOptionPane.showMessageDialog(editDialog, text("Host cannot be empty."), text("Error"), JOptionPane.ERROR_MESSAGE);
                    return;
                }

                HttpRequest editedRequest;
                try {
                    editedRequest = requestEditor.getRequest();
                    if (editedRequest == null) throw new IllegalArgumentException("Empty request");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(editDialog, text("Failed to parse HTTP request. Please verify the format."), text("Error"), JOptionPane.ERROR_MESSAGE);
                    return;
                }

                String newReqBase64 = Base64.getEncoder().encodeToString(
                        editedRequest.toByteArray().getBytes());
                synchronized (lock) {
                    rule.setSavedRequestBase64(newReqBase64);
                    rule.setSavedHost(newHost);
                    rule.setSavedPort(newPort);
                    rule.setSavedSecure(newSecure);
                    // The rule may have been created by this dialog, so attach it to the
                    // runtime map and its definition before persisting.
                    rules.put(name, rule);
                    VariableDefinition definition = findDefinitionByKey(name);
                    if (definition != null) definition.setRule(rule);
                    savePreferences();
                }
                editDialog.dispose();
                updateDetailsPanel(selectedRow);
            });

            cancelButton.addActionListener(e -> editDialog.dispose());

            buttonPanel.add(cancelButton);
            buttonPanel.add(copyButton);
            buttonPanel.add(saveButton);
            editDialog.add(buttonPanel, BorderLayout.SOUTH);

            editDialog.setVisible(true);
        } catch (Exception e) {
            api.logging().logToError("Error displaying edit request dialog: " + e.getMessage());
        }
    }

    private void triggerUpdateRuleFromResponse() {
        int selectedRow = variablesTable.getSelectedRow();
        String name = tableModel.variableKeyAt(selectedRow);
        if (name == null) return;
        VariableExtractionRule rule = rules.get(name);
        if (rule == null || rule.getSavedRequestBase64() == null || rule.getSavedRequestBase64().isEmpty()) return;
        int targetIndex = Math.max(0, extractionZoneComboBox.getSelectedIndex());
        if (targetIndex >= rule.getTargets().size()) return;
        VariableExtractionRule.ExtractionTarget selectedTarget = rule.getTargets().get(targetIndex);

        updateRuleButton.setEnabled(false);
        updateRuleButton.setText(text("Fetching Response..."));

        // Run network operation in background thread
        new Thread(() -> {
            try {
                byte[] requestBytes = Base64.getDecoder().decode(rule.getSavedRequestBase64());
                HttpRequest savedReq = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
                
                HttpService service = HttpService.httpService(
                        rule.getSavedHost(),
                        rule.getSavedPort(),
                        rule.isSavedSecure()
                );
                savedReq = savedReq.withService(service);

                // Replace placeholders using current variable values
                Map<String, String> variables = getVariables();

                // 1. Path
                String path = savedReq.path();
                String newPath = replacePlaceholders(path, variables);
                if (!path.equals(newPath)) {
                    savedReq = savedReq.withPath(newPath);
                }

                // 2. Headers
                List<HttpHeader> headers = savedReq.headers();
                List<HttpHeader> newHeaders = new ArrayList<>();
                boolean headersModified = false;
                for (HttpHeader header : headers) {
                    String value = header.value();
                    String newValue = replacePlaceholders(value, variables);
                    if (!value.equals(newValue)) {
                        newHeaders.add(HttpHeader.httpHeader(header.name(), newValue));
                        headersModified = true;
                    } else {
                        newHeaders.add(header);
                    }
                }
                if (headersModified) {
                    savedReq = savedReq.withRemovedHeaders(savedReq.headers()).withAddedHeaders(newHeaders);
                }

                // 3. Body
                String body = savedReq.bodyToString();
                if (body != null && !body.isEmpty()) {
                    String newBody = replacePlaceholders(body, variables);
                    if (!body.equals(newBody)) {
                        savedReq = savedReq.withBody(newBody);
                    }
                }

                // Fetch new response
                HttpRequestResponse reqResp = api.http().sendRequest(savedReq);
                if (reqResp.response() == null) {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(mainPanel, text("Failed to get response from server."), text("Fetch Error"), JOptionPane.ERROR_MESSAGE);
                    });
                    return;
                }

                String textStr;
                if (selectedTarget.source() == VariableExtractionRule.ExtractionSource.REQUEST_BODY
                        || selectedTarget.source() == VariableExtractionRule.ExtractionSource.REQUEST_HEADERS) {
                    textStr = new String(reqResp.request().toByteArray().getBytes(), StandardCharsets.UTF_8);
                } else {
                    textStr = new String(reqResp.response().toByteArray().getBytes(), StandardCharsets.UTF_8);
                }

                // Open selection dialog on EDT
                SwingUtilities.invokeLater(() -> {
                    showResponseSelectorDialog(name, rule, targetIndex, textStr, selectedRow);
                });

            } catch (Exception ex) {
                api.logging().logToError("Error fetching response for extraction: " + ex.getMessage());
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(mainPanel, text("Error fetching response: ") + ex.getMessage(), text("Fetch Error"), JOptionPane.ERROR_MESSAGE);
                });
            } finally {
                SwingUtilities.invokeLater(() -> {
                    updateRuleButton.setEnabled(true);
                    updateRuleButton.setText(text("Update Rule from Response..."));
                });
            }
        }).start();
    }

    private void showResponseSelectorDialog(String varName, VariableExtractionRule rule, int targetIndex,
                                            String responseStr, int rowIndex) {
        JDialog selectorDialog = new JDialog(api.userInterface().swingUtils().suiteFrame(), text("Highlight New Token - ") + varName, Dialog.ModalityType.APPLICATION_MODAL);
        selectorDialog.setLayout(new BorderLayout(10, 10));
        selectorDialog.setSize(700, 550);
        selectorDialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());

        // Header instructions
        JLabel instrLabel = new JLabel(text("Highlight/select the text you want to extract from the response below. The regex will be auto-generated."));
        instrLabel.setBorder(new EmptyBorder(5, 5, 5, 5));
        selectorDialog.add(instrLabel, BorderLayout.NORTH);

        VariableExtractionRule.ExtractionTarget selectedTarget = rule.getTargets().get(targetIndex);
        boolean requestContent = selectedTarget.source() == VariableExtractionRule.ExtractionSource.REQUEST_BODY
                || selectedTarget.source() == VariableExtractionRule.ExtractionSource.REQUEST_HEADERS;

        // Use Burp's native message editor so users can switch between Pretty and Raw.
        // The same dialog also supports request-based extraction rules.
        Editor messageEditor;
        byte[] messageBytes = responseStr.getBytes(StandardCharsets.UTF_8);
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
        selectorDialog.add(messageEditor.uiComponent(), BorderLayout.CENTER);

        // South Panel details & settings
        JPanel southPanel = new JPanel(new GridBagLayout());
        southPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        GridBagConstraints sgbc = new GridBagConstraints();
        sgbc.fill = GridBagConstraints.HORIZONTAL;
        sgbc.insets = new Insets(5, 5, 5, 5);
        sgbc.gridx = 0;

        // Row 0: Value preview
        sgbc.gridy = 0; sgbc.weightx = 0.0;
        southPanel.add(new JLabel(text("Selected Value:")), sgbc);
        JTextField selectedValField = new JTextField(30);
        selectedValField.setEditable(false);
        sgbc.gridx = 1; sgbc.weightx = 1.0;
        southPanel.add(selectedValField, sgbc);

        // Row 1: Regex proposed
        sgbc.gridy = 1; sgbc.gridx = 0; sgbc.weightx = 0.0;
        southPanel.add(new JLabel(text("Proposed Regex:")), sgbc);
        JTextField regexPropField = new JTextField(30);
        sgbc.gridx = 1; sgbc.weightx = 1.0;
        southPanel.add(regexPropField, sgbc);

        // Row 2: Extract from
        sgbc.gridy = 2; sgbc.gridx = 0; sgbc.weightx = 0.0;
        southPanel.add(new JLabel(text("Extract From:")), sgbc);
        JComboBox<String> extractSrcCombo = new JComboBox<>(new String[]{
            text("Response Body"), text("Response Headers"), text("Request Body"), text("Request Headers")
        });
        extractSrcCombo.setSelectedIndex(switch (selectedTarget.source()) {
            case RESPONSE_HEADERS -> 1;
            case REQUEST_BODY -> 2;
            case REQUEST_HEADERS -> 3;
            case RESPONSE_BODY -> 0;
        });
        sgbc.gridx = 1; sgbc.weightx = 1.0;
        southPanel.add(extractSrcCombo, sgbc);

        // Native editors don't expose a caret listener, so poll their selection while
        // this modal dialog is open. This works across both Pretty and Raw tabs.
        String[] lastSelection = {""};
        javax.swing.Timer selectionTimer = new javax.swing.Timer(150, event -> {
            Optional<Selection> currentSelection = messageEditor.selection();
            if (currentSelection.isPresent()) {
                Selection selection = currentSelection.get();
                String selectedText = new String(
                        selection.contents().getBytes(), StandardCharsets.UTF_8);
                int reportedStart = selection.offsets().startIndexInclusive();
                int reportedEnd = selection.offsets().endIndexExclusive();
                String signature = reportedStart + ":" + reportedEnd + ":" + selectedText;
                if (selectedText.isEmpty() || signature.equals(lastSelection[0])) return;
                lastSelection[0] = signature;

                int start = locateSelection(responseStr, selectedText, reportedStart, reportedEnd);
                if (start < 0) return;
                int end = start + selectedText.length();
                selectedValField.setText(selectedText);

                // Analyze source (headers vs body)
                int doubleNewline = responseStr.indexOf("\r\n\r\n");
                int separatorLength = 4;
                if (doubleNewline < 0) {
                    doubleNewline = responseStr.indexOf("\n\n");
                    separatorLength = 2;
                }

                String source = requestContent ? "request_body" : "body";
                String contextText = responseStr;
                int contextStart = start;
                int contextEnd = end;

                if (doubleNewline >= 0) {
                    if (start < doubleNewline) {
                        source = requestContent ? "request_headers" : "headers";
                        contextText = responseStr.substring(0, doubleNewline);
                    } else {
                        source = requestContent ? "request_body" : "body";
                        contextText = responseStr.substring(doubleNewline + separatorLength);
                        contextStart = Math.max(0, start - (doubleNewline + separatorLength));
                        contextEnd = Math.max(0, end - (doubleNewline + separatorLength));
                    }
                }

                String proposedRegex = generateProposedRegex(contextText, contextStart, contextEnd);
                regexPropField.setText(proposedRegex);
                if ("request_body".equals(source)) {
                    extractSrcCombo.setSelectedIndex(2);
                } else if ("request_headers".equals(source)) {
                    extractSrcCombo.setSelectedIndex(3);
                } else if ("headers".equalsIgnoreCase(source)) {
                    extractSrcCombo.setSelectedIndex(1);
                } else {
                    extractSrcCombo.setSelectedIndex(0);
                }
            }
        });
        selectionTimer.start();
        selectorDialog.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosed(java.awt.event.WindowEvent event) {
                selectionTimer.stop();
            }
        });

        // Action Buttons panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        JButton saveBtn = new JButton(text("Save Extraction Rule"));
        JButton cancelBtn = new JButton(text("Cancel"));

        saveBtn.addActionListener(al -> {
            String finalRegex = regexPropField.getText().trim();
            if (finalRegex.isEmpty()) {
                JOptionPane.showMessageDialog(selectorDialog, text("Please select some text to generate a regex."), text("Error"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (!ExtractionEngine.isValidRegex(finalRegex)
                    || !ExtractionEngine.hasCaptureGroup(finalRegex)) {
                JOptionPane.showMessageDialog(selectorDialog,
                        text("The extraction regex must be valid and contain at least one capture group."),
                        text("Error"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            String chosenSource;
            switch (extractSrcCombo.getSelectedIndex()) {
                case 1: chosenSource = "headers"; break;
                case 2: chosenSource = "request_body"; break;
                case 3: chosenSource = "request_headers"; break;
                default: chosenSource = "body"; break;
            }

            synchronized (lock) {
                rule.replaceTarget(targetIndex,
                        VariableExtractionRule.ExtractionSource.fromStored(chosenSource), finalRegex);
                savePreferences();
            }
            selectorDialog.dispose();
            updateDetailsPanel(rowIndex);
            // Flash a success notification
            JOptionPane.showMessageDialog(mainPanel, text("Extraction rule updated successfully for variable: ") + varName, text("Rule Updated"), JOptionPane.INFORMATION_MESSAGE);
        });

        cancelBtn.addActionListener(al -> selectorDialog.dispose());
        buttonPanel.add(cancelBtn);
        buttonPanel.add(saveBtn);

        // Put panels together
        JPanel wrapperPanel = new JPanel(new BorderLayout(5, 5));
        wrapperPanel.add(southPanel, BorderLayout.CENTER);
        wrapperPanel.add(buttonPanel, BorderLayout.SOUTH);
        selectorDialog.add(wrapperPanel, BorderLayout.SOUTH);

        selectorDialog.setVisible(true);
        selectionTimer.stop();
    }

    static int locateSelection(String rawMessage, String selectedText,
                               int reportedStart, int reportedEnd) {
        if (reportedStart >= 0 && reportedEnd >= reportedStart
                && reportedEnd <= rawMessage.length()
                && rawMessage.substring(reportedStart, reportedEnd).equals(selectedText)) {
            return reportedStart;
        }

        int firstMatch = rawMessage.indexOf(selectedText);
        if (firstMatch < 0) return -1;

        // Pretty views can change whitespace and therefore selection offsets. When
        // the selected token occurs more than once, choose the occurrence nearest
        // to the offset reported by Burp.
        int bestMatch = firstMatch;
        int bestDistance = Math.abs(firstMatch - Math.max(0, reportedStart));
        int nextMatch = rawMessage.indexOf(selectedText, firstMatch + 1);
        while (nextMatch >= 0) {
            int distance = Math.abs(nextMatch - Math.max(0, reportedStart));
            if (distance < bestDistance) {
                bestMatch = nextMatch;
                bestDistance = distance;
            }
            nextMatch = rawMessage.indexOf(selectedText, nextMatch + 1);
        }
        return bestMatch;
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

    private void triggerBackgroundRefresh() {
        int selectedRow = variablesTable.getSelectedRow();
        String name = tableModel.variableKeyAt(selectedRow);
        if (name != null) {
            VariableExtractionRule rule = rules.get(name);
            if (rule != null && rule.getSavedRequestBase64() != null && !rule.getSavedRequestBase64().isEmpty()) {
                refreshRequestButton.setEnabled(false);
                refreshRequestButton.setText(text("Refreshing..."));
                
                // Run background thread to comply with BApp responsiveness guidelines
                new Thread(() -> {
                    try {
                        refreshVariableSynchronously(name, rule);
                        SwingUtilities.invokeLater(() -> {
                            JOptionPane.showMessageDialog(mainPanel, 
                                    text("Variable refreshed successfully: ") + name,
                                    text("Refresh Success"), JOptionPane.INFORMATION_MESSAGE);
                        });
                    } catch (Exception ex) {
                        api.logging().logToError("Error refreshing variable '" + name + "': " + ex.getMessage());
                        SwingUtilities.invokeLater(() -> {
                            JOptionPane.showMessageDialog(mainPanel, text("Error during refresh: ") + ex.getMessage(), text("Refresh Error"), JOptionPane.ERROR_MESSAGE);
                        });
                    } finally {
                        SwingUtilities.invokeLater(() -> {
                            refreshRequestButton.setEnabled(true);
                            refreshRequestButton.setText(text("Refresh Variable"));
                        });
                    }
                }).start();
            }
        }
    }

    // Synchronous execution (can block the calling thread)
    public void refreshVariableSynchronously(String name, VariableExtractionRule rule) throws Exception {
        String refreshedValue = fetchRefreshedVariable(name, rule);
        updateVariableValue(name, refreshedValue);
    }

    public String fetchRefreshedVariable(String name, VariableExtractionRule rule) throws Exception {
        return fetchRefreshedVariable(name, rule, getVariables());
    }

    public String fetchRefreshedVariable(String name, VariableExtractionRule rule,
                                         Map<String, String> variables) throws Exception {
        if (rule == null || rule.getSavedRequestBase64() == null || rule.getSavedRequestBase64().isEmpty()) {
            throw new Exception("No saved refresh request.");
        }
        
        byte[] requestBytes = Base64.getDecoder().decode(rule.getSavedRequestBase64());
        HttpRequest savedReq = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
        
        HttpService service = HttpService.httpService(
                rule.getSavedHost(),
                rule.getSavedPort(),
                rule.isSavedSecure()
        );
        savedReq = savedReq.withService(service);

        // Replace placeholders in the refresh request template using current variables!
        // 1. Path replacement
        String path = savedReq.path();
        String newPath = replacePlaceholders(path, variables);
        if (!path.equals(newPath)) {
            savedReq = savedReq.withPath(newPath);
        }

        // 2. Headers replacement
        List<HttpHeader> headers = savedReq.headers();
        List<HttpHeader> newHeaders = new ArrayList<>();
        boolean headersModified = false;
        for (HttpHeader header : headers) {
            String value = header.value();
            String newValue = replacePlaceholders(value, variables);
            if (!value.equals(newValue)) {
                newHeaders.add(HttpHeader.httpHeader(header.name(), newValue));
                headersModified = true;
            } else {
                newHeaders.add(header);
            }
        }
        if (headersModified) {
            savedReq = savedReq.withRemovedHeaders(savedReq.headers()).withAddedHeaders(newHeaders);
        }

        // 3. Body replacement
        String body = savedReq.bodyToString();
        if (body != null && !body.isEmpty()) {
            String newBody = replacePlaceholders(body, variables);
            if (!body.equals(newBody)) {
                savedReq = savedReq.withBody(newBody);
            }
        }

        // Send request programmatically via Burp HTTP engine
        HttpRequestResponse reqResp = api.http().sendRequest(savedReq);

        if (reqResp.response() == null) throw new Exception("No response received from target.");

        ExtractionEngine.RequestSnapshot requestSnapshot = new ExtractionEngine.RequestSnapshot(
                reqResp.request().method(), rule.getSavedHost(), rule.getSavedPort(), rule.isSavedSecure(),
                reqResp.request().path(),
                reqResp.request().headers().stream()
                        .map(header -> header.name() + ": " + header.value()).toList(),
                reqResp.request().bodyToString());
        ExtractionEngine.ResponseSnapshot responseSnapshot = new ExtractionEngine.ResponseSnapshot(
                reqResp.response().statusCode(),
                reqResp.response().headers().stream()
                        .map(header -> header.name() + ": " + header.value()).toList(),
                reqResp.response().bodyToString());
        ExtractionEngine.Evaluation evaluation = ExtractionEngine.extract(
                rule, requestSnapshot, responseSnapshot);
        if (evaluation.outcome() == ExtractionOutcome.UPDATED) return evaluation.value();
        throw new Exception("Extraction failed: " + evaluation.outcome());
    }

    private String replacePlaceholders(String text, Map<String, String> variables) {
        return VariableNames.replacePlaceholders(text, variables, getPlaceholderStyle());
    }

    public void savePreferences() {
        synchronized (lock) {
            variableRevision++;
            try {
                synchronizeDefinitionsFromRuntimeMaps();
                api.persistence().preferences().setString(STATE_V3_KEY,
                        VariableStateCodec.encode(folders, definitions));
                // Save variable values
                StringBuilder valSb = new StringBuilder();
                for (String name : variableNames) {
                    String val = values.getOrDefault(name, "");
                    valSb.append(URLEncoder.encode(name, StandardCharsets.UTF_8.name()))
                         .append("=")
                         .append(URLEncoder.encode(val, StandardCharsets.UTF_8.name()))
                         .append("&");
                }
                api.persistence().preferences().setString("repeater_variables_values", valSb.toString());

                // Save variable rules
                StringBuilder ruleSb = new StringBuilder();
                for (String name : variableNames) {
                    VariableExtractionRule rule = rules.get(name);
                    if (rule != null) {
                        ruleSb.append(URLEncoder.encode(name, StandardCharsets.UTF_8.name()))
                              .append("=")
                              .append(URLEncoder.encode(rule.serialize(), StandardCharsets.UTF_8.name()))
                              .append("&");
                    }
                }
                api.persistence().preferences().setString("repeater_variables_rules", ruleSb.toString());

                // Save global toggles
                api.persistence().preferences().setString("repeater_variables_replacement_master_enabled", String.valueOf(replacementMasterEnabled));
                api.persistence().preferences().setString("repeater_variables_replacement_enabled", String.valueOf(replacementEnabled));
                api.persistence().preferences().setString("repeater_variables_replacement_intruder_enabled", String.valueOf(replacementIntruderEnabled));
                api.persistence().preferences().setString("repeater_variables_replacement_scanner_enabled", String.valueOf(replacementScannerEnabled));
                api.persistence().preferences().setString("repeater_variables_replacement_proxy_enabled", String.valueOf(replacementProxyEnabled));
                api.persistence().preferences().setString("repeater_variables_extraction_enabled", String.valueOf(extractionEnabled));
                api.persistence().preferences().setString("dynamic_variables_session_recovery_enabled",
                        String.valueOf(sessionRecoveryEnabled));
                api.persistence().preferences().setString("dynamic_variables_extraction_debug_enabled",
                        String.valueOf(extractionDebugEnabled));
                api.persistence().preferences().setString("dynamic_variables_extraction_tools",
                        AutomationTool.serialize(extractionTools));
                api.persistence().preferences().setString("dynamic_variables_recovery_tools",
                        AutomationTool.serialize(recoveryTools));
                api.persistence().preferences().setString("repeater_variables_refresh_status_codes", refreshStatusCodes);
                PlaceholderPreferences.save(api.persistence().preferences()::setString, getPlaceholderStyle());
                PlaceholderPreferences.saveLanguage(api.persistence().preferences()::setString, uiLanguage);
            } catch (Exception e) {
                api.logging().logToError("Failed to save variables preferences: " + e.getMessage());
            }
        }
    }

    public void loadPreferences() {
        synchronized (lock) {
            try {
                variableNames.clear();
                values.clear();
                rules.clear();
                folders.clear();
                definitions.clear();

                String stateV2 = api.persistence().preferences().getString(STATE_V3_KEY);
                boolean migratingV2State = stateV2 == null || stateV2.isEmpty();
                if (migratingV2State) stateV2 = api.persistence().preferences().getString(STATE_V2_KEY);
                boolean loadedV2 = false;
                if (stateV2 != null && !stateV2.isEmpty()) {
                    try {
                        VariableStateCodec.State state = VariableStateCodec.decode(stateV2);
                        folders.addAll(state.folders());
                        definitions.addAll(state.variables());
                        rebuildRuntimeMapsFromDefinitions();
                        loadedV2 = true;
                    } catch (Exception stateError) {
                        api.logging().logToError("Invalid variable state; falling back to legacy preferences: "
                                + stateError.getMessage());
                    }
                }
                if (!loadedV2) {

                String valPref = api.persistence().preferences().getString("repeater_variables_values");
                if (valPref != null && !valPref.isEmpty()) {
                    String[] pairs = valPref.split("&");
                    for (String pair : pairs) {
                        if (pair.isEmpty()) continue;
                        int idx = pair.indexOf("=");
                        if (idx > 0) {
                            String name = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.name());
                            String val = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.name());
                            variableNames.add(name);
                            values.put(name, val);
                        }
                    }
                }

                String rulePref = api.persistence().preferences().getString("repeater_variables_rules");
                if (rulePref != null && !rulePref.isEmpty()) {
                    String[] pairs = rulePref.split("&");
                    for (String pair : pairs) {
                        if (pair.isEmpty()) continue;
                        int idx = pair.indexOf("=");
                        if (idx > 0) {
                            String name = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.name());
                            String ruleData = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.name());
                            rules.put(name, VariableExtractionRule.deserialize(ruleData));
                        }
                    }
                }

                // Default empty rules for variables without them
                for (String name : variableNames) {
                    if (!rules.containsKey(name)) {
                        rules.put(name, new VariableExtractionRule());
                    }
                }
                    definitions.addAll(VariableStateCodec.migrateLegacy(variableNames, values, rules).variables());
                    api.persistence().preferences().setString(STATE_V3_KEY,
                            VariableStateCodec.encode(folders, definitions));
                }

                String replaceMasterPref = api.persistence().preferences().getString("repeater_variables_replacement_master_enabled");
                if (replaceMasterPref != null) {
                    replacementMasterEnabled = Boolean.parseBoolean(replaceMasterPref);
                }

                String replaceEnabledPref = api.persistence().preferences().getString("repeater_variables_replacement_enabled");
                if (replaceEnabledPref != null) {
                    replacementEnabled = Boolean.parseBoolean(replaceEnabledPref);
                }
                
                String replaceIntruderPref = api.persistence().preferences().getString("repeater_variables_replacement_intruder_enabled");
                if (replaceIntruderPref != null) {
                    replacementIntruderEnabled = Boolean.parseBoolean(replaceIntruderPref);
                }

                String replaceScannerPref = api.persistence().preferences().getString("repeater_variables_replacement_scanner_enabled");
                if (replaceScannerPref != null) {
                    replacementScannerEnabled = Boolean.parseBoolean(replaceScannerPref);
                }

                String replaceProxyPref = api.persistence().preferences().getString("repeater_variables_replacement_proxy_enabled");
                if (replaceProxyPref != null) {
                    replacementProxyEnabled = Boolean.parseBoolean(replaceProxyPref);
                }

                String extractEnabledPref = api.persistence().preferences().getString("repeater_variables_extraction_enabled");
                if (extractEnabledPref != null) {
                    extractionEnabled = Boolean.parseBoolean(extractEnabledPref);
                }
                String recoveryEnabledPref = api.persistence().preferences().getString(
                        "dynamic_variables_session_recovery_enabled");
                if (recoveryEnabledPref != null) {
                    sessionRecoveryEnabled = Boolean.parseBoolean(recoveryEnabledPref);
                }
                String debugPref = api.persistence().preferences().getString(
                        "dynamic_variables_extraction_debug_enabled");
                if (debugPref != null) {
                    extractionDebugEnabled = Boolean.parseBoolean(debugPref);
                }
                String extractionToolsPref = api.persistence().preferences().getString(
                        "dynamic_variables_extraction_tools");
                extractionTools = extractionToolsPref == null
                        ? EnumSet.of(AutomationTool.REPEATER)
                        : AutomationTool.deserialize(extractionToolsPref);
                String recoveryToolsPref = api.persistence().preferences().getString(
                        "dynamic_variables_recovery_tools");
                recoveryTools = recoveryToolsPref == null
                        ? EnumSet.of(AutomationTool.REPEATER)
                        : AutomationTool.deserialize(recoveryToolsPref);
                
                String codesPref = api.persistence().preferences().getString("repeater_variables_refresh_status_codes");
                if (codesPref != null) {
                    refreshStatusCodes = codesPref;
                }
                validateLoadedRules();
                if (migratingV2State && loadedV2) {
                    synchronizeDefinitionsFromRuntimeMaps();
                    api.persistence().preferences().setString(STATE_V3_KEY,
                            VariableStateCodec.encode(folders, definitions));
                }
                VariableNames.PlaceholderStyle placeholderStyle = PlaceholderPreferences.load(
                        api.persistence().preferences()::getString, api.logging()::logToError);
                placeholderTagEnabled = placeholderStyle.tagEnabled();
                placeholderTag = placeholderStyle.tag();
                placeholderSyntax = placeholderStyle.syntax();
                uiLanguage = PlaceholderPreferences.loadLanguage(api.persistence().preferences()::getString);
                String ungroupedPref = api.persistence().preferences().getString("dynamic_variables_ungrouped_expanded");
                if (ungroupedPref != null) ungroupedExpanded = Boolean.parseBoolean(ungroupedPref);
            } catch (Exception e) {
                api.logging().logToError("Failed to load variables preferences: " + e.getMessage());
            }
        }
    }

    private void validateLoadedRules() {
        for (Map.Entry<String, VariableExtractionRule> entry : rules.entrySet()) {
            VariableExtractionRule rule = entry.getValue();
            boolean valid = hasValidExtractionTargets(rule);
            if (valid && rule.getMatchStrategy() == VariableExtractionRule.MatchStrategy.EXPLICIT) {
                valid = !rule.getMatchMethod().isEmpty()
                        && !rule.getMatchHost().isEmpty()
                        && rule.getMatchPort() > 0
                        && !rule.getMatchPath().isEmpty();
                if (valid && rule.getPathMatchMode() == VariableExtractionRule.PatternMode.REGEX) {
                    valid = ExtractionEngine.isValidRegex(rule.getMatchPath());
                }
                if (valid && !rule.getMatchQuery().isEmpty()
                        && rule.getQueryMatchMode() == VariableExtractionRule.PatternMode.REGEX) {
                    valid = ExtractionEngine.isValidRegex(rule.getMatchQuery());
                }
                if (valid && rule.getDiscriminatorSource()
                        != VariableExtractionRule.DiscriminatorSource.NONE) {
                    valid = ExtractionEngine.isValidRegex(rule.getDiscriminatorRegex());
                }
            } else if (valid && !rule.getMatchUrl().isEmpty()) {
                valid = ExtractionEngine.isValidRegex(rule.getMatchUrl());
            }
            if (!valid && (rule.isEnabled() || rule.isAutomaticRefreshEnabled())) {
                rule.setEnabled(false);
                rule.setAutomaticRefreshEnabled(false);
                VariableDefinition definition = findDefinitionByKey(entry.getKey());
                if (definition != null) definition.setRule(rule);
                api.logging().logToError("Disabled invalid automation rule for variable '"
                        + entry.getKey() + "'.");
            }
        }
    }

    private boolean hasValidExtractionTargets(VariableExtractionRule rule) {
        if (rule == null || rule.getTargets().isEmpty()) return false;
        for (VariableExtractionRule.ExtractionTarget target : rule.getTargets()) {
            if (target.name().isBlank()
                    || !ExtractionEngine.isValidRegex(target.regex())
                    || !ExtractionEngine.hasCaptureGroup(target.regex())) {
                return false;
            }
        }
        return ExtractionEngine.isValidValueTemplate(
                rule.getValueTemplate(), rule.getTargets());
    }

    /**
     * 2FA variables have no automation at all: their value comes from the secret, never from a
     * response, so the Automation tab is removed instead of just disabled.
     */
    private void setTotpDetailsVisible(boolean totpVariable) {
        if (detailsTabs == null || automationDetailsPanel == null || totpConfigDetailsPanel == null) return;
        valueHint.setText(totpVariable
                ? text("The value rotates automatically every time it is used.")
                : text("Changes are saved automatically."));
        totpValuePanel.setVisible(totpVariable);

        int automationIndex = detailsTabs.indexOfComponent(automationDetailsPanel);
        int totpConfigIndex = detailsTabs.indexOfComponent(totpConfigDetailsPanel);

        if (totpVariable) {
            if (automationIndex >= 0) detailsTabs.removeTabAt(automationIndex);
            if (totpConfigIndex < 0) detailsTabs.addTab(text("2FA Configuration"), totpConfigDetailsPanel);
        } else {
            if (totpConfigIndex >= 0) detailsTabs.removeTabAt(totpConfigIndex);
            if (automationIndex < 0) detailsTabs.addTab(text("Automation"), automationDetailsPanel);
        }
    }

    private void saveTotpConfig() {
        if (isUpdatingUI) return;
        int selectedRow = variablesTable.getSelectedRow();
        if (selectedRow < 0) return;
        String name = tableModel.variableKeyAt(selectedRow);
        if (name == null) return;
        VariableDefinition definition = findDefinitionByKey(name);
        if (definition == null || !definition.isTotpVariable()) return;

        String secret = totpSecretField.getText().trim();
        int digits = totpDigitsComboBox.getSelectedItem() != null
                ? (Integer) totpDigitsComboBox.getSelectedItem() : TotpGenerator.DEFAULT_DIGITS;
        int period = TotpGenerator.DEFAULT_PERIOD_SECONDS;
        try {
            period = Integer.parseInt(totpPeriodField.getText().trim());
            if (period <= 0) period = TotpGenerator.DEFAULT_PERIOD_SECONDS;
        } catch (NumberFormatException ignored) {}

        String algorithm = totpAlgorithmComboBox.getSelectedItem() != null
                ? (String) totpAlgorithmComboBox.getSelectedItem() : TotpGenerator.DEFAULT_ALGORITHM;

        TotpGenerator.TotpConfig newConfig = new TotpGenerator.TotpConfig(secret, digits, period, algorithm);
        definition.setTotpConfig(newConfig);
        savePreferences();
        synchronized (lock) {
            refreshTotpValues();
        }
        isUpdatingUI = true;
        try {
            String val = values.getOrDefault(name, "");
            valueTextArea.setText(val);
        } finally {
            isUpdatingUI = false;
        }
        tableModel.fireTableCellUpdated(selectedRow, 1);
    }

    private void rotateSelectedTotpValue() {
        int selectedRow = variablesTable.getSelectedRow();
        String name = tableModel.variableKeyAt(selectedRow);
        if (name == null) return;

        String code;
        int secondsLeft;
        synchronized (lock) {
            VariableDefinition definition = findDefinitionByKey(name);
            if (definition == null || !definition.isTotpVariable()) return;
            long epochSeconds = System.currentTimeMillis() / 1000L;
            try {
                code = definition.totpCodeFor(epochSeconds);
            } catch (RuntimeException e) {
                JOptionPane.showMessageDialog(mainPanel,
                        text("Invalid 2FA secret. Use Base32 characters (A-Z, 2-7)."),
                        text("Error"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            secondsLeft = TotpGenerator.secondsRemaining(
                    epochSeconds, definition.getTotpConfig().periodSeconds());
            definition.setValue(code);
            values.put(name, code);
            savePreferences();
        }

        isUpdatingUI = true;
        valueTextArea.setText(code);
        isUpdatingUI = false;
        tableModel.fireTableCellUpdated(selectedRow, 1);
        showTemporaryStatus(text("Current code:") + " " + code + " (" + secondsLeft + "s)");
    }

    private void disableDetails(String message) {
        updateDetailsPanel(-1);
        savedRequestLabel.setText(message);
    }

    private VariableFolder findFolder(String id) {
        if (id == null) return null;
        return folders.stream().filter(folder -> folder.getId().equals(id)).findFirst().orElse(null);
    }

    private VariableFolder findFolderByName(String name) {
        return folders.stream().filter(folder -> folder.getName().equals(name)).findFirst().orElse(null);
    }

    private VariableDefinition findDefinitionByKey(String key) {
        return definitions.stream().filter(definition -> qualifiedName(definition).equals(key)).findFirst().orElse(null);
    }

    private String qualifiedName(VariableDefinition definition) {
        return definition.qualifiedName(findFolder(definition.getFolderId()));
    }

    private int countVariablesInFolder(String folderId) {
        return (int) definitions.stream().filter(definition -> Objects.equals(folderId, definition.getFolderId())).count();
    }

    private void synchronizeDefinitionsFromRuntimeMaps() {
        for (VariableDefinition definition : definitions) {
            String key = qualifiedName(definition);
            definition.setValue(values.getOrDefault(key, definition.getValue()));
            definition.setRule(rules.getOrDefault(key, definition.getRule()));
        }
    }

    private void rebuildRuntimeMapsFromDefinitions() {
        variableNames.clear();
        values.clear();
        rules.clear();
        definitions.sort(Comparator.comparing((VariableDefinition definition) ->
                definition.getFolderId() == null ? "" : definition.getFolderId())
                .thenComparingInt(VariableDefinition::getPosition));
        for (VariableDefinition definition : definitions) {
            String key = qualifiedName(definition);
            if (values.containsKey(key)) {
                api.logging().logToError("Duplicate variable key ignored while loading: " + key);
                continue;
            }
            variableNames.add(key);
            values.put(key, definition.getValue());
            rules.put(key, definition.getRule());
        }
    }

    private boolean validNewName(String name, String type) {
        return validNewName(name, type, mainPanel);
    }

    /**
     * @param parent component the error is attached to. A modal dialog must pass itself: an error
     *               parented to the main panel would be blocked behind it and never seen.
     */
    private boolean validNewName(String name, String type, Component parent) {
        if (name == null || name.trim().isEmpty()) {
            JOptionPane.showMessageDialog(parent, text(type) + text(" name cannot be empty."), text("Invalid Name"), JOptionPane.ERROR_MESSAGE);
            return false;
        }
        if (!VariableNames.isValidComponent(name)) {
            JOptionPane.showMessageDialog(parent, text(type) + text(" names may only contain letters, numbers and _."), text("Invalid Name"), JOptionPane.ERROR_MESSAGE);
            return false;
        }
        return true;
    }

    private String selectedFolderId() {
        int row = variablesTable == null ? -1 : variablesTable.getSelectedRow();
        if (row < 0) return null;
        TableRow selected = tableModel.rowAt(row);
        if (selected == null) return null;
        if (selected.folder != null) return selected.folder.getId();
        return selected.variable == null ? null : selected.variable.getFolderId();
    }

    /**
     * Yes/No confirmation whose Enter key accepts. {@link JOptionPane#showConfirmDialog} focuses the
     * affirmative button and even installs it as the default button, yet Enter still does nothing,
     * so the buttons are built here and the key is bound on the dialog's root pane.
     *
     * @return {@code true} only when the user accepted; No, Escape and closing the window all
     *         return {@code false}.
     */
    private boolean confirmDialog(Object message, String title, int messageType) {
        JButton yesButton = new JButton(buttonText("OptionPane.yesButtonText", "Yes"));
        JButton noButton = new JButton(buttonText("OptionPane.noButtonText", "No"));
        JOptionPane optionPane = new JOptionPane(message, messageType, JOptionPane.YES_NO_OPTION,
                null, new Object[]{noButton, yesButton}, yesButton);
        yesButton.addActionListener(e -> optionPane.setValue(JOptionPane.YES_OPTION));
        noButton.addActionListener(e -> optionPane.setValue(JOptionPane.NO_OPTION));

        JDialog dialog = optionPane.createDialog(mainPanel, title);
        acceptOnEnter(dialog, yesButton, () -> optionPane.setValue(JOptionPane.YES_OPTION));
        dialog.setVisible(true);
        dialog.dispose();
        return Integer.valueOf(JOptionPane.YES_OPTION).equals(optionPane.getValue());
    }

    /**
     * Multiple-choice variant of {@link #confirmDialog}. Enter picks {@code defaultIndex}.
     *
     * @return the index of the chosen option, or {@link JOptionPane#CLOSED_OPTION} if the dialog was
     *         dismissed with Escape or the window close button.
     */
    private int optionDialog(Object message, String title, int messageType, String[] options, int defaultIndex) {
        JButton[] buttons = new JButton[options.length];
        for (int i = 0; i < options.length; i++) buttons[i] = new JButton(options[i]);
        JOptionPane optionPane = new JOptionPane(message, messageType, JOptionPane.DEFAULT_OPTION,
                null, buttons, buttons[defaultIndex]);
        for (int i = 0; i < buttons.length; i++) {
            int index = i;
            buttons[i].addActionListener(e -> optionPane.setValue(index));
        }

        JDialog dialog = optionPane.createDialog(mainPanel, title);
        acceptOnEnter(dialog, buttons[defaultIndex], () -> optionPane.setValue(defaultIndex));
        dialog.setVisible(true);
        dialog.dispose();
        Object result = optionPane.getValue();
        return result instanceof Integer choice ? choice : JOptionPane.CLOSED_OPTION;
    }

    /**
     * Makes Enter run {@code action} on a dialog. All three steps are needed: the focus has to land
     * on a component, because a dialog whose focus owner is the window itself never processes
     * {@code WHEN_IN_FOCUSED_WINDOW} bindings, and the binding in turn covers the cases where the
     * default button alone does not fire.
     */
    private static void acceptOnEnter(JDialog dialog, JButton acceptButton, Runnable action) {
        dialog.getRootPane().setDefaultButton(acceptButton);
        dialog.getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "acceptDialog");
        dialog.getRootPane().getActionMap().put("acceptDialog", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                action.run();
            }
        });
        dialog.addWindowListener(new WindowAdapter() {
            @Override
            public void windowOpened(WindowEvent e) {
                acceptButton.requestFocusInWindow();
            }
        });
    }

    /** Keeps the look and feel's own button wording, which is already localized. */
    private static String buttonText(String uiKey, String fallback) {
        String label = UIManager.getString(uiKey);
        return label == null || label.isEmpty() ? fallback : label;
    }

    private void createFolderDialog() {
        String name = JOptionPane.showInputDialog(mainPanel, text("Folder name:"), text("New Folder"), JOptionPane.PLAIN_MESSAGE);
        if (name == null) return;
        name = name.trim();
        if (!validNewName(name, "Folder")) return;
        synchronized (lock) {
            if (findFolderByName(name) != null) {
                JOptionPane.showMessageDialog(mainPanel, text("A folder with this name already exists."), text("Duplicate Folder"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            folders.add(new VariableFolder(name, folders.size()));
            savePreferences();
        }
        tableModel.fireTableDataChanged();
    }

    /**
     * @param preselectedFolderId folder to start on, or {@code null} to start on Ungrouped.
     *                            The table's context menu passes the folder that was clicked.
     */
    private static class FolderSelector {
        final JComboBox<String> comboBox;
        final JButton createButton;
        final JPanel panel;
        final List<String> folderNames;

        FolderSelector(JComboBox<String> comboBox, JButton createButton, JPanel panel, List<String> folderNames) {
            this.comboBox = comboBox;
            this.createButton = createButton;
            this.panel = panel;
            this.folderNames = folderNames;
        }

        String resolveSelectedFolderName(VariableManager manager, Component parentComponent) {
            String folderInput = VariableContextMenuProvider.folderEditorText(comboBox);
            String folderName = VariableContextMenuProvider.existingFolderName(
                    folderNames, folderInput, manager.text("Ungrouped"));
            if (folderName == null) {
                if (!VariableNames.isValidComponent(folderInput)) {
                    JOptionPane.showMessageDialog(parentComponent,
                            manager.text("Folder") + manager.text(" names may only contain letters, numbers and _."),
                            manager.text("Invalid Name"), JOptionPane.ERROR_MESSAGE);
                    return null;
                }
                try {
                    manager.createFolder(folderInput);
                    folderName = folderInput;
                } catch (IllegalStateException duplicate) {
                    folderName = VariableContextMenuProvider.existingFolderName(
                            manager.getFolderNames(), folderInput, manager.text("Ungrouped"));
                } catch (IllegalArgumentException invalid) {
                    JOptionPane.showMessageDialog(parentComponent,
                            manager.text("Folder") + manager.text(" names may only contain letters, numbers and _."),
                            manager.text("Invalid Name"), JOptionPane.ERROR_MESSAGE);
                    return null;
                }
            }
            return folderName;
        }
    }

    private FolderSelector buildFolderSelectorPanel(String preselectedFolderId, Component parentComponent) {
        List<String> folderNames = new ArrayList<>(getFolderNames());
        JComboBox<String> folderComboBox = new JComboBox<>();
        folderComboBox.addItem(text("Ungrouped"));
        for (String folderName : folderNames) folderComboBox.addItem(folderName);
        folderComboBox.setEditable(true);
        folderComboBox.setToolTipText(text("Search or create a folder"));

        VariableFolder preselectedFolder = findFolder(preselectedFolderId);
        if (preselectedFolder != null) {
            folderComboBox.setSelectedItem(preselectedFolder.getName());
            folderComboBox.getEditor().setItem(preselectedFolder.getName());
        }

        JButton createFolderButton = new JButton(text("Create folder"));
        createFolderButton.setEnabled(false);
        JLabel folderHint = new JLabel(text(
                "Type to filter folders. If the name does not exist, create it here."));
        folderHint.setForeground(UIManager.getColor("Label.disabledForeground"));
        JPanel folderInputPanel = new JPanel(new BorderLayout(6, 2));
        folderInputPanel.add(folderComboBox, BorderLayout.CENTER);
        folderInputPanel.add(createFolderButton, BorderLayout.EAST);
        folderInputPanel.add(folderHint, BorderLayout.SOUTH);

        boolean[] updatingFolderSuggestions = {false};
        Runnable updateCreateFolderButton = () -> {
            String candidate = VariableContextMenuProvider.folderEditorText(folderComboBox);
            boolean existing = VariableContextMenuProvider.existingFolderName(
                    folderNames, candidate, text("Ungrouped")) != null;
            createFolderButton.setEnabled(
                    !candidate.isEmpty() && !existing && VariableNames.isValidComponent(candidate));
        };

        Runnable filterFolderSuggestions = () -> {
            if (updatingFolderSuggestions[0]) return;
            String query = VariableContextMenuProvider.folderEditorText(folderComboBox);
            SwingUtilities.invokeLater(() -> {
                if (updatingFolderSuggestions[0]) return;
                updatingFolderSuggestions[0] = true;
                try {
                    DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>();
                    for (String suggestion : VariableContextMenuProvider.filterFolderNames(
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
                public void insertUpdate(DocumentEvent event) { filterFolderSuggestions.run(); }
                @Override
                public void removeUpdate(DocumentEvent event) { filterFolderSuggestions.run(); }
                @Override
                public void changedUpdate(DocumentEvent event) { filterFolderSuggestions.run(); }
            });
        }
        folderComboBox.addActionListener(e -> updateCreateFolderButton.run());
        createFolderButton.addActionListener(e -> {
            String candidate = VariableContextMenuProvider.folderEditorText(folderComboBox);
            if (!VariableNames.isValidComponent(candidate)) {
                JOptionPane.showMessageDialog(parentComponent,
                        text("Folder") + text(" names may only contain letters, numbers and _."),
                        text("Invalid Name"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            try {
                createFolder(candidate);
                folderNames.add(candidate);
                updatingFolderSuggestions[0] = true;
                try {
                    folderComboBox.setModel(new DefaultComboBoxModel<>(
                            VariableContextMenuProvider.filterFolderNames(folderNames, candidate, text("Ungrouped"))
                                    .toArray(new String[0])));
                    folderComboBox.setSelectedItem(candidate);
                    folderComboBox.getEditor().setItem(candidate);
                } finally {
                    updatingFolderSuggestions[0] = false;
                }
                updateCreateFolderButton.run();
            } catch (IllegalStateException duplicate) {
                JOptionPane.showMessageDialog(parentComponent,
                        text("A folder with this name already exists."),
                        text("Duplicate Folder"), JOptionPane.ERROR_MESSAGE);
            } catch (IllegalArgumentException invalid) {
                JOptionPane.showMessageDialog(parentComponent,
                        text("Folder") + text(" names may only contain letters, numbers and _."),
                        text("Invalid Name"), JOptionPane.ERROR_MESSAGE);
            }
        });

        return new FolderSelector(folderComboBox, createFolderButton, folderInputPanel, folderNames);
    }

    private void createVariableDialog(String preselectedFolderId) {
        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(4, 5, 4, 5);

        FolderSelector folderSelector = buildFolderSelectorPanel(preselectedFolderId, mainPanel);
        JTextField nameField = new JTextField(20);

        gbc.gridy = 0; gbc.gridx = 0; gbc.weightx = 0.0;
        form.add(new JLabel(text("Folder:")), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        form.add(folderSelector.panel, gbc);

        gbc.gridy = 1; gbc.gridx = 0; gbc.weightx = 0.0;
        form.add(new JLabel(text("Variable name:")), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        form.add(nameField, gbc);

        // Built by hand instead of showConfirmDialog: a text field embedded in a message panel
        // never gets the initial focus that showInputDialog gives its own field, and Enter has
        // to mean "create" the way it used to.
        JOptionPane optionPane = new JOptionPane(form, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION) {
            @Override
            public void selectInitialValue() {
                nameField.requestFocusInWindow();
            }
        };
        JDialog dialog = optionPane.createDialog(mainPanel, text("New Variable"));
        nameField.addActionListener(e -> optionPane.setValue(JOptionPane.OK_OPTION));
        dialog.setVisible(true);
        dialog.dispose();

        Object result = optionPane.getValue();
        if (!(result instanceof Integer choice) || choice != JOptionPane.OK_OPTION) return;

        String name = nameField.getText().trim();
        if (!validNewName(name, "Variable")) return;

        String folderName = folderSelector.resolveSelectedFolderName(this, mainPanel);
        if (folderName == null) return;

        String key;
        synchronized (lock) {
            VariableFolder folder = folderName.isEmpty() ? null : findFolderByName(folderName);
            String folderId = folder == null ? null : folder.getId();
            key = qualifyVariableName(folderName, name);
            if (values.containsKey(key)) {
                JOptionPane.showMessageDialog(mainPanel, text("Variable '") + key + text("' already exists."), text("Duplicate Variable"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            VariableDefinition definition = new VariableDefinition(name, folderId, "", new VariableExtractionRule(),
                    countVariablesInFolder(folderId));
            definitions.add(definition);
            rebuildRuntimeMapsFromDefinitions();
            savePreferences();
        }
        tableModel.fireTableDataChanged();
        selectVariable(key);
    }

    private void showTotpSetupDialog(String preselectedFolderId) {
        Frame suiteFrame = api.userInterface().swingUtils().suiteFrame();
        JDialog dialog = new JDialog(suiteFrame, text("Add 2FA Variable"), Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(new EmptyBorder(12, 15, 5, 15));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(4, 5, 4, 5);

        FolderSelector folderSelector = buildFolderSelectorPanel(preselectedFolderId, dialog);

        JTextField nameField = new JTextField(24);
        JTextField secretField = new JTextField(24);

        gbc.gridy = 0; gbc.gridx = 0; gbc.weightx = 0.0;
        form.add(new JLabel(text("Folder:")), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        form.add(folderSelector.panel, gbc);

        gbc.gridy = 1; gbc.gridx = 0; gbc.weightx = 0.0;
        form.add(new JLabel(text("Variable name:")), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        form.add(nameField, gbc);

        gbc.gridy = 2; gbc.gridx = 0; gbc.weightx = 0.0;
        form.add(new JLabel(text("2FA Secret (Base32):")), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        form.add(secretField, gbc);

        // Advanced settings stay collapsed: SHA1 / 6 digits / 30 s covers almost every service.
        JCheckBox advancedCheckBox = new JCheckBox(text("Advanced"));
        JPanel advancedPanel = new JPanel(new GridBagLayout());
        advancedPanel.setVisible(false);
        GridBagConstraints agbc = new GridBagConstraints();
        agbc.fill = GridBagConstraints.HORIZONTAL;
        agbc.insets = new Insets(4, 5, 4, 5);

        JComboBox<String> digitsComboBox = new JComboBox<>(new String[]{"6", "7", "8"});
        JTextField periodField = new JTextField(String.valueOf(TotpGenerator.DEFAULT_PERIOD_SECONDS), 6);
        JComboBox<String> algorithmComboBox = new JComboBox<>(new String[]{"SHA1", "SHA256", "SHA512"});

        agbc.gridy = 0; agbc.gridx = 0; agbc.weightx = 0.0;
        advancedPanel.add(new JLabel(text("Digits:")), agbc);
        agbc.gridx = 1; agbc.weightx = 1.0;
        advancedPanel.add(digitsComboBox, agbc);
        agbc.gridy = 1; agbc.gridx = 0; agbc.weightx = 0.0;
        advancedPanel.add(new JLabel(text("Period (seconds):")), agbc);
        agbc.gridx = 1; agbc.weightx = 1.0;
        advancedPanel.add(periodField, agbc);
        agbc.gridy = 2; agbc.gridx = 0; agbc.weightx = 0.0;
        advancedPanel.add(new JLabel(text("Algorithm:")), agbc);
        agbc.gridx = 1; agbc.weightx = 1.0;
        advancedPanel.add(algorithmComboBox, agbc);

        gbc.gridy = 3; gbc.gridx = 0; gbc.gridwidth = 2;
        form.add(advancedCheckBox, gbc);
        gbc.gridy = 4;
        form.add(advancedPanel, gbc);

        JLabel previewLabel = new JLabel(" ");
        gbc.gridy = 5;
        form.add(previewLabel, gbc);
        gbc.gridwidth = 1;

        advancedCheckBox.addActionListener(e -> {
            advancedPanel.setVisible(advancedCheckBox.isSelected());
            dialog.pack();
        });

        // Preview runs on the EDT only: no I/O, and the timer is stopped when the dialog closes.
        SimpleCallback updatePreview = () -> {
            TotpGenerator.TotpConfig config = totpConfigFrom(secretField, digitsComboBox, periodField, algorithmComboBox);
            if (config == null || !config.isConfigured()) {
                previewLabel.setText(" ");
                return;
            }
            long epochSeconds = System.currentTimeMillis() / 1000L;
            try {
                previewLabel.setText(text("Current code:") + " " + TotpGenerator.code(config, epochSeconds)
                        + "  (" + TotpGenerator.secondsRemaining(epochSeconds, config.periodSeconds()) + "s)");
            } catch (RuntimeException ex) {
                previewLabel.setText(text("Invalid 2FA secret. Use Base32 characters (A-Z, 2-7)."));
            }
        };
        javax.swing.Timer previewTimer = new javax.swing.Timer(1000, e -> updatePreview.run());
        previewTimer.setCoalesce(true);
        secretField.getDocument().addDocumentListener(new SimpleDocumentListener(updatePreview));

        JButton createButton = new JButton(text("Create"));
        JButton cancelButton = new JButton(text("Cancel"));
        createButton.addActionListener(e -> {
            String name = nameField.getText().trim();
            if (!validNewName(name, "Variable", dialog)) return;

            TotpGenerator.TotpConfig config = totpConfigFrom(secretField, digitsComboBox, periodField, algorithmComboBox);
            if (config == null || !config.isConfigured()) {
                JOptionPane.showMessageDialog(dialog,
                        text("Invalid 2FA secret. Use Base32 characters (A-Z, 2-7)."),
                        text("Error"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            String initialCode;
            try {
                initialCode = TotpGenerator.code(config, System.currentTimeMillis() / 1000L);
            } catch (RuntimeException ex) {
                JOptionPane.showMessageDialog(dialog,
                        text("Invalid 2FA secret. Use Base32 characters (A-Z, 2-7)."),
                        text("Error"), JOptionPane.ERROR_MESSAGE);
                return;
            }

            String folderName = folderSelector.resolveSelectedFolderName(this, dialog);
            if (folderName == null) return;
            String key;
            synchronized (lock) {
                VariableFolder folder = folderName.isEmpty() ? null : findFolderByName(folderName);
                String folderId = folder == null ? null : folder.getId();
                key = qualifyVariableName(folderName, name);
                if (values.containsKey(key)) {
                    JOptionPane.showMessageDialog(dialog,
                            text("Variable '") + key + text("' already exists."),
                            text("Duplicate Variable"), JOptionPane.ERROR_MESSAGE);
                    return;
                }
                VariableDefinition definition = new VariableDefinition(name, folderId, initialCode,
                        new VariableExtractionRule(), countVariablesInFolder(folderId));
                definition.setTotpConfig(config);
                definitions.add(definition);
                rebuildRuntimeMapsFromDefinitions();
                savePreferences();
            }
            previewTimer.stop();
            dialog.dispose();
            tableModel.fireTableDataChanged();
            selectVariable(key);
        });
        cancelButton.addActionListener(e -> {
            previewTimer.stop();
            dialog.dispose();
        });

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        buttons.add(cancelButton);
        buttons.add(createButton);

        dialog.add(form, BorderLayout.CENTER);
        dialog.add(buttons, BorderLayout.SOUTH);
        dialog.pack();
        dialog.setLocationRelativeTo(suiteFrame);
        // Without these the focus lands on the folder combo box and Enter does nothing.
        dialog.getRootPane().setDefaultButton(createButton);
        dialog.addWindowListener(new WindowAdapter() {
            @Override
            public void windowOpened(WindowEvent e) {
                nameField.requestFocusInWindow();
            }
        });
        previewTimer.start();
        dialog.setVisible(true);
        previewTimer.stop();
    }

    private TotpGenerator.TotpConfig totpConfigFrom(JTextField secretField, JComboBox<String> digitsComboBox,
                                                    JTextField periodField, JComboBox<String> algorithmComboBox) {
        String secret = secretField.getText().trim();
        if (secret.isEmpty()) return null;
        int digits = Integer.parseInt(String.valueOf(digitsComboBox.getSelectedItem()));
        int period;
        try {
            period = Integer.parseInt(periodField.getText().trim());
        } catch (NumberFormatException e) {
            return null;
        }
        if (period <= 0) return null;
        return new TotpGenerator.TotpConfig(secret, digits, period,
                String.valueOf(algorithmComboBox.getSelectedItem()));
    }

    private void selectVariable(String key) {
        int row = tableModel.findVariableRow(key);
        if (row >= 0) {
            variablesTable.setRowSelectionInterval(row, row);
            variablesTable.scrollRectToVisible(variablesTable.getCellRect(row, 0, true));
        }
    }

    private void toggleFolderAt(int row) {
        TableRow tableRow = tableModel.rowAt(row);
        if (tableRow == null || !tableRow.folderRow) return;
        if (tableRow.ungrouped) {
            ungroupedExpanded = !ungroupedExpanded;
            api.persistence().preferences().setString("dynamic_variables_ungrouped_expanded", String.valueOf(ungroupedExpanded));
        } else if (tableRow.folder != null) {
            tableRow.folder.setExpanded(!tableRow.folder.isExpanded());
            savePreferences();
        }
        tableModel.fireTableDataChanged();
    }

    private JPopupMenu createVariablesPopup() {
        int[] selectedRows = variablesTable.getSelectedRows();
        List<TableRow> targetRows = new ArrayList<>();
        if (selectedRows != null) {
            for (int r : selectedRows) {
                TableRow tr = tableModel.rowAt(r);
                if (tr != null) targetRows.add(tr);
            }
        }

        List<VariableDefinition> selectedVariables = targetRows.stream()
                .filter(r -> r.variable != null)
                .map(r -> r.variable).toList();

        List<VariableFolder> selectedFolders = targetRows.stream()
                .filter(r -> r.folder != null && r.folderRow && !r.ungrouped)
                .map(r -> r.folder).toList();

        boolean canRename = targetRows.size() == 1 && !(targetRows.get(0).folderRow && targetRows.get(0).ungrouped);
        boolean canCopy = !selectedVariables.isEmpty();
        boolean canMove = !selectedVariables.isEmpty() || !selectedFolders.isEmpty();
        boolean canDelete = targetRows.stream().anyMatch(r -> !(r.folderRow && r.ungrouped));

        JPopupMenu menu = new JPopupMenu();
        JMenuItem rename = new JMenuItem(text("Rename"));
        rename.setEnabled(canRename);
        if (canRename) {
            rename.addActionListener(e -> renameNode(targetRows.get(0)));
        }

        JMenuItem copy = new JMenuItem(text("Copy Placeholder"));
        copy.setEnabled(canCopy);
        copy.addActionListener(e -> copyPlaceholders(selectedVariables));

        JMenuItem move = new JMenuItem(text("Move to..."));
        move.setEnabled(canMove);
        move.addActionListener(e -> SwingUtilities.invokeLater(() -> showMoveDialogForSelected(selectedVariables, selectedFolders)));

        JMenu addSubMenu = new JMenu(text("Add..."));
        JMenuItem addVariable = new JMenuItem(text("New Variable"));
        addVariable.addActionListener(e -> createVariableDialog(selectedFolderId()));
        JMenuItem addFolder = new JMenuItem(text("New Folder"));
        addFolder.addActionListener(e -> createFolderDialog());
        JMenuItem setupTotp = new JMenuItem(text("Add 2FA variable"));
        setupTotp.setToolTipText(text("Creates a variable whose value is a 2FA code computed from a secret."));
        setupTotp.addActionListener(e -> showTotpSetupDialog(selectedFolderId()));

        addSubMenu.add(addVariable);
        addSubMenu.add(addFolder);
        addSubMenu.addSeparator();
        addSubMenu.add(setupTotp);

        JMenuItem delete = new JMenuItem(text("Delete"));
        delete.setEnabled(canDelete);
        delete.addActionListener(e -> deleteSelectedNodes());

        menu.add(rename);
        menu.add(copy);
        menu.add(move);
        menu.addSeparator();
        menu.add(addSubMenu);
        menu.add(delete);
        return menu;
    }

    private void copyPlaceholders(List<VariableDefinition> definitions) {
        if (definitions == null || definitions.isEmpty()) return;
        String textToCopy = definitions.stream()
                .map(d -> placeholderFor(qualifiedName(d)))
                .collect(Collectors.joining("\n"));
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(textToCopy), null);
            if (definitions.size() == 1) {
                showTemporaryStatus(text("Copied ") + textToCopy + text(" to the clipboard."));
            } else {
                showTemporaryStatus(text("Copied ") + definitions.size() + text(" placeholders to the clipboard."));
            }
        } catch (IllegalStateException | HeadlessException clipboardError) {
            api.logging().logToError("Failed to copy placeholder: " + clipboardError.getMessage());
            JOptionPane.showMessageDialog(mainPanel,
                    text("The placeholder could not be copied to the system clipboard."),
                    text("Copy Placeholder"), JOptionPane.ERROR_MESSAGE);
        }
    }

    private void showTemporaryStatus(String message) {
        if (placeholderUsageLabel == null) return;
        placeholderUsageLabel.setText(message);
        javax.swing.Timer restoreTimer = new javax.swing.Timer(2500, e -> updatePlaceholderUsageLabel());
        restoreTimer.setRepeats(false);
        restoreTimer.start();
    }

    private void renameNode(TableRow row) {
        if (row == null) return;
        // Variable rows also carry their parent folder, so only folderRow tells them apart.
        boolean folderRow = row.folderRow;
        if (folderRow && row.folder == null) return;
        String oldName = folderRow ? row.folder.getName() : row.variable.getName();
        String type = folderRow ? "Folder" : "Variable";
        String name = JOptionPane.showInputDialog(mainPanel, text(type) + (uiLanguage == UiLanguage.SPANISH ? ":" : " name:"), oldName);
        if (name == null || oldName.equals(name.trim())) return;
        name = name.trim();
        if (!validNewName(name, type)) return;
        if (folderRow) renameFolder(row.folder, name);
        else renameVariable(row.variable, name);
    }

    private void renameVariable(VariableDefinition definition, String newName) {
        String oldKey = qualifiedName(definition);
        VariableFolder folder = findFolder(definition.getFolderId());
        String newKey = folder == null ? newName : folder.getName() + "." + newName;
        if (values.containsKey(newKey)) {
            JOptionPane.showMessageDialog(mainPanel, text("Variable '") + newKey + text("' already exists."), text("Duplicate Variable"), JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (JOptionPane.showConfirmDialog(mainPanel, text("Placeholder will change:\n") + placeholderFor(oldKey)
                + " -> " + placeholderFor(newKey),
                text("Rename Variable"), JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
        definition.setName(newName);
        rebuildRuntimeMapsFromDefinitions();
        savePreferences();
        tableModel.fireTableDataChanged();
        selectVariable(newKey);
    }

    private void renameFolder(VariableFolder folder, String newName) {
        if (findFolderByName(newName) != null) {
            JOptionPane.showMessageDialog(mainPanel, text("A folder with this name already exists."), text("Duplicate Folder"), JOptionPane.ERROR_MESSAGE);
            return;
        }
        List<VariableDefinition> children = definitions.stream().filter(v -> folder.getId().equals(v.getFolderId())).toList();
        for (VariableDefinition child : children) {
            String newKey = newName + "." + child.getName();
            if (values.containsKey(newKey) && findDefinitionByKey(newKey) != child) {
                JOptionPane.showMessageDialog(mainPanel, text("Renaming would conflict with '") + newKey + "'.", text("Rename Folder"), JOptionPane.ERROR_MESSAGE);
                return;
            }
        }
        StringBuilder changes = new StringBuilder(text("The following placeholders will change:\n"));
        for (VariableDefinition child : children) changes.append(placeholderFor(qualifiedName(child))).append(" -> ")
                .append(placeholderFor(newName + "." + child.getName())).append('\n');
        if (!children.isEmpty() && JOptionPane.showConfirmDialog(mainPanel, changes.toString(), text("Rename Folder"),
                JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
        folder.setName(newName);
        rebuildRuntimeMapsFromDefinitions();
        savePreferences();
        tableModel.fireTableDataChanged();
    }

    private boolean moveDefinition(VariableDefinition definition, String targetFolderId, int targetPosition, boolean confirm) {
        String oldKey = qualifiedName(definition);
        VariableFolder target = findFolder(targetFolderId);
        String newKey = target == null ? definition.getName() : target.getName() + "." + definition.getName();
        if (!oldKey.equals(newKey) && values.containsKey(newKey)) {
            JOptionPane.showMessageDialog(mainPanel, text("Variable '") + newKey + text("' already exists."), text("Move Variable"), JOptionPane.ERROR_MESSAGE);
            return false;
        }
        if (confirm && !oldKey.equals(newKey) && JOptionPane.showConfirmDialog(mainPanel,
                text("Placeholder will change:\n") + placeholderFor(oldKey) + " -> " + placeholderFor(newKey), text("Move Variable"),
                JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return false;
        String oldFolderId = definition.getFolderId();
        List<VariableDefinition> oldGroup = new ArrayList<>(definitions.stream()
                .filter(v -> Objects.equals(oldFolderId, v.getFolderId()) && v != definition)
                .sorted(Comparator.comparingInt(VariableDefinition::getPosition)).toList());
        for (int i = 0; i < oldGroup.size(); i++) oldGroup.get(i).setPosition(i);
        definition.setFolderId(targetFolderId);
        List<VariableDefinition> targetGroup = new ArrayList<>(definitions.stream()
                .filter(v -> Objects.equals(targetFolderId, v.getFolderId()) && v != definition)
                .sorted(Comparator.comparingInt(VariableDefinition::getPosition)).toList());
        targetGroup.add(Math.max(0, Math.min(targetPosition, targetGroup.size())), definition);
        for (int i = 0; i < targetGroup.size(); i++) targetGroup.get(i).setPosition(i);
        rebuildRuntimeMapsFromDefinitions();
        savePreferences();
        tableModel.fireTableDataChanged();
        selectVariable(newKey);
        return true;
    }

    private void showMoveDialogForSelected(List<VariableDefinition> selectedVariables, List<VariableFolder> selectedFolders) {
        List<String> choices = new ArrayList<>();
        choices.add(text("Ungrouped"));
        folders.stream()
                .filter(folder -> !selectedFolders.contains(folder))
                .sorted(Comparator.comparingInt(VariableFolder::getPosition))
                .forEach(folder -> choices.add(folder.getName()));

        if (choices.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel,
                    text("Create another folder before moving items."),
                    text("Move Items"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        Object selected = JOptionPane.showInputDialog(mainPanel, text("Move selected items to:"), text("Move Items"),
                JOptionPane.PLAIN_MESSAGE, null, choices.toArray(), choices.get(0));
        if (selected == null) return;
        VariableFolder targetFolder = text("Ungrouped").equals(selected) ? null : findFolderByName(selected.toString());
        String targetFolderId = targetFolder == null ? null : targetFolder.getId();

        boolean anyKeyChanges = false;
        for (VariableDefinition def : selectedVariables) {
            String oldKey = qualifiedName(def);
            String newKey = targetFolder == null ? def.getName() : targetFolder.getName() + "." + def.getName();
            if (!oldKey.equals(newKey)) {
                if (values.containsKey(newKey) && findDefinitionByKey(newKey) != def && !selectedVariables.contains(findDefinitionByKey(newKey))) {
                    JOptionPane.showMessageDialog(mainPanel, text("Variable '") + newKey + text("' already exists."), text("Move Items"), JOptionPane.ERROR_MESSAGE);
                    return;
                }
                anyKeyChanges = true;
            }
        }

        if (anyKeyChanges) {
            if (JOptionPane.showConfirmDialog(mainPanel,
                    text("Moving selected variables will change placeholder names.\nDo you want to proceed?"),
                    text("Move Items"), JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) {
                return;
            }
        }

        int targetPos = countVariablesInFolder(targetFolderId);
        for (VariableDefinition def : selectedVariables) {
            moveDefinition(def, targetFolderId, targetPos++, false);
        }
        rebuildRuntimeMapsFromDefinitions();
        savePreferences();
        tableModel.fireTableDataChanged();
        updateDetailsPanel(-1);
    }

    private void deleteSelectedNodes() {
        int[] selectedRows = variablesTable.getSelectedRows();
        if (selectedRows == null || selectedRows.length == 0) return;

        List<TableRow> targetRows = new ArrayList<>();
        for (int r : selectedRows) {
            TableRow row = tableModel.rowAt(r);
            if (row != null && !(row.folderRow && row.ungrouped)) {
                targetRows.add(row);
            }
        }
        if (targetRows.isEmpty()) return;

        List<VariableDefinition> varsToDelete = targetRows.stream()
                .filter(r -> r.variable != null)
                .map(r -> r.variable)
                .distinct().toList();

        List<VariableFolder> foldersToDelete = targetRows.stream()
                .filter(r -> r.folder != null && r.folderRow)
                .map(r -> r.folder)
                .distinct().toList();

        if (varsToDelete.isEmpty() && foldersToDelete.isEmpty()) return;

        String message;
        if (targetRows.size() == 1) {
            TableRow single = targetRows.get(0);
            if (single.variable != null) {
                message = text("Delete variable '") + qualifiedName(single.variable) + "'?";
            } else {
                message = text("Delete folder '") + single.folder.getName() + "'?";
            }
        } else {
            message = text("Delete ") + targetRows.size() + text(" selected items?");
        }

        if (!confirmDialog(message, text("Delete Selected"), JOptionPane.QUESTION_MESSAGE)) return;

        for (VariableFolder folder : foldersToDelete) {
            List<VariableDefinition> children = definitions.stream()
                    .filter(v -> folder.getId().equals(v.getFolderId()) && !varsToDelete.contains(v))
                    .toList();
            if (!children.isEmpty()) {
                String[] options = {text("Cancel"), text("Move variables to Ungrouped"), text("Delete folder and variables")};
                // Enter takes the second option (index 1): it lets the deletion go through without destroying
                // the variables that were never selected.
                int choice = optionDialog(
                        text("Folder '") + folder.getName() + text("' contains ") + children.size() + text(" variables not selected for deletion."),
                        text("Delete Folder"), JOptionPane.WARNING_MESSAGE, options, 1);
                if (choice == 1) {
                    int rootPosition = countVariablesInFolder(null);
                    for (VariableDefinition child : children) {
                        child.setFolderId(null);
                        child.setPosition(rootPosition++);
                    }
                } else if (choice == 2) {
                    definitions.removeAll(children);
                } else {
                    return;
                }
            }
        }

        definitions.removeAll(varsToDelete);
        folders.removeAll(foldersToDelete);
        folders.sort(Comparator.comparingInt(VariableFolder::getPosition));
        for (int i = 0; i < folders.size(); i++) folders.get(i).setPosition(i);

        rebuildRuntimeMapsFromDefinitions();
        savePreferences();
        tableModel.fireTableDataChanged();
        updateDetailsPanel(-1);
    }

    private class VariableRowTransferHandler extends TransferHandler {
        private static final long serialVersionUID = 1L;
        private final DataFlavor rowsFlavor = new DataFlavor(int[].class, "Variable rows");

        @Override
        protected Transferable createTransferable(JComponent component) {
            int[] sourceRows = variablesTable.getSelectedRows();
            return sourceRows == null || sourceRows.length == 0 ? null : new VariableRowTransferable(sourceRows, rowsFlavor);
        }

        @Override
        public int getSourceActions(JComponent component) {
            return MOVE;
        }

        @Override
        public boolean canImport(TransferSupport support) {
            return support.getComponent() == variablesTable
                    && support.isDrop()
                    && support.isDataFlavorSupported(rowsFlavor);
        }

        @Override
        public boolean importData(TransferSupport support) {
            if (!canImport(support)) {
                return false;
            }

            try {
                int[] sourceRows = (int[]) support.getTransferable().getTransferData(rowsFlavor);
                JTable.DropLocation dropLocation = (JTable.DropLocation) support.getDropLocation();
                int requestedDropRow = dropLocation.getRow();
                int dropRow = Math.min(requestedDropRow, tableModel.getRowCount() - 1);
                TableRow target = tableModel.rowAt(dropRow);
                if (target == null || sourceRows == null || sourceRows.length == 0) return false;

                String folderId = target.folder != null ? target.folder.getId()
                        : target.ungrouped ? null : target.variable != null ? target.variable.getFolderId() : null;

                List<VariableDefinition> varsToMove = new ArrayList<>();
                for (int r : sourceRows) {
                    TableRow tr = tableModel.rowAt(r);
                    if (tr != null && tr.variable != null) {
                        varsToMove.add(tr.variable);
                    }
                }

                if (!varsToMove.isEmpty()) {
                    int position = requestedDropRow >= tableModel.getRowCount() ? countVariablesInFolder(folderId)
                            : target.variable == null ? countVariablesInFolder(folderId) : target.variable.getPosition();
                    boolean movedAny = false;
                    for (VariableDefinition def : varsToMove) {
                        if (moveDefinition(def, folderId, position++, true)) {
                            movedAny = true;
                        }
                    }
                    return movedAny;
                }
                return false;
            } catch (UnsupportedFlavorException | IOException e) {
                api.logging().logToError("Failed to reorder variables: " + e.getMessage());
                return false;
            }
        }
    }

    private static class VariableRowTransferable implements Transferable {
        private final int[] rows;
        private final DataFlavor rowFlavor;

        private VariableRowTransferable(int[] rows, DataFlavor rowFlavor) {
            this.rows = rows;
            this.rowFlavor = rowFlavor;
        }

        @Override
        public DataFlavor[] getTransferDataFlavors() {
            return new DataFlavor[]{rowFlavor};
        }

        @Override
        public boolean isDataFlavorSupported(DataFlavor flavor) {
            return rowFlavor.equals(flavor);
        }

        @Override
        public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException {
            if (!isDataFlavorSupported(flavor)) {
                throw new UnsupportedFlavorException(flavor);
            }
            return rows;
        }
    }

    private static final class TableRow {
        final VariableFolder folder;
        final VariableDefinition variable;
        final boolean folderRow;
        final boolean ungrouped;

        private TableRow(VariableFolder folder, VariableDefinition variable, boolean folderRow, boolean ungrouped) {
            this.folder = folder;
            this.variable = variable;
            this.folderRow = folderRow;
            this.ungrouped = ungrouped;
        }
    }

    private boolean ungroupedExpanded = true;

    private class VariablesTableModel extends AbstractTableModel {
        private static final long serialVersionUID = 1L;
        private final String[] columns = {text("Variable Name"), text("Current Value"), text("Auto Extract?")};

        private List<TableRow> rows() {
            List<TableRow> result = new ArrayList<>();
            addGroupRows(result, null, null, true, ungroupedExpanded);
            folders.stream().sorted(Comparator.comparingInt(VariableFolder::getPosition))
                    .forEach(folder -> addGroupRows(result, folder.getId(), folder, false, folder.isExpanded()));
            return result;
        }

        private void addGroupRows(List<TableRow> result, String folderId, VariableFolder folder,
                                  boolean ungrouped, boolean expanded) {
            List<VariableDefinition> children = definitions.stream()
                    .filter(v -> Objects.equals(folderId, v.getFolderId()))
                    .sorted(Comparator.comparingInt(VariableDefinition::getPosition)).toList();
            String groupName = ungrouped ? text("Ungrouped") : folder.getName();
            boolean groupMatches = variableSearch.isEmpty() || groupName.toLowerCase(Locale.ROOT).contains(variableSearch);
            List<VariableDefinition> matches = children.stream().filter(v -> variableSearch.isEmpty()
                    || v.getName().toLowerCase(Locale.ROOT).contains(variableSearch)
                    || qualifiedName(v).toLowerCase(Locale.ROOT).contains(variableSearch)).toList();
            if (!groupMatches && matches.isEmpty()) return;
            result.add(new TableRow(folder, null, true, ungrouped));
            if (expanded || !variableSearch.isEmpty()) {
                for (VariableDefinition child : groupMatches && !variableSearch.isEmpty() ? children : matches)
                    result.add(new TableRow(folder, child, false, ungrouped));
            }
        }

        @Override
        public int getRowCount() {
            synchronized (lock) {
                return rows().size();
            }
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            synchronized (lock) {
                TableRow row = rowAt(rowIndex);
                if (row == null) return null;
                if (row.folderRow) {
                    if (columnIndex != 0) return "";
                    String name = row.ungrouped ? text("Ungrouped") : row.folder.getName();
                    return name + " (" +
                            countVariablesInFolder(row.ungrouped ? null : row.folder.getId()) + ")";
                }
                String name = qualifiedName(row.variable);
                switch (columnIndex) {
                    case 0:
                        return row.variable.getName();
                    case 1:
                        String val = values.getOrDefault(name, "");
                        return val.length() > 50 ? val.substring(0, 47) + "..." : val;
                    case 2:
                        // 2FA variables generate codes locally from their secret and do not extract
                        // values from HTTP responses.
                        if (row.variable.isTotpVariable()) return text("No");
                        VariableExtractionRule rule = rules.get(name);
                        return (rule != null && rule.isEnabled()) ? text("Yes") : text("No");
                }
            }
            return null;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            TableRow row = rowAt(rowIndex);
            return columnIndex == 0 && row != null && row.variable != null;
        }

        @Override
        public void setValueAt(Object value, int rowIndex, int columnIndex) {
            if (columnIndex != 0 || value == null) return;
            TableRow row = rowAt(rowIndex);
            if (row == null || row.variable == null) return;

            String newName = value.toString().trim();
            if (newName.equals(row.variable.getName())) return;
            if (!validNewName(newName, "Variable")) {
                fireTableRowsUpdated(rowIndex, rowIndex);
                return;
            }
            renameVariable(row.variable, newName);
        }

        TableRow rowAt(int row) {
            List<TableRow> rows = rows();
            return row < 0 || row >= rows.size() ? null : rows.get(row);
        }

        boolean isFolderRow(int row) {
            TableRow tableRow = rowAt(row);
            return tableRow != null && tableRow.folderRow;
        }

        String variableKeyAt(int row) {
            TableRow tableRow = rowAt(row);
            return tableRow == null || tableRow.variable == null ? null : qualifiedName(tableRow.variable);
        }

        int findVariableRow(String key) {
            List<TableRow> rows = rows();
            for (int i = 0; i < rows.size(); i++) {
                if (rows.get(i).variable != null && qualifiedName(rows.get(i).variable).equals(key)) return i;
            }
            return -1;
        }
    }

    private class HierarchyCellRenderer extends DefaultTableCellRenderer {
        private static final long serialVersionUID = 1L;
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean selected,
                                                       boolean focused, int row, int column) {
            JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, selected, focused, row, column);
            TableRow tableRow = tableModel.rowAt(row);
            label.setFont(label.getFont().deriveFont(tableRow != null && tableRow.folderRow ? Font.BOLD : Font.PLAIN));
            if (tableRow != null && tableRow.folderRow) {
                boolean expanded = tableRow.ungrouped
                        ? ungroupedExpanded
                        : tableRow.folder.isExpanded();
                label.setIcon(new FolderRowIcon(expanded));
                label.setIconTextGap(5);
                label.setToolTipText(null);
            } else if (tableRow != null && tableRow.variable != null) {
                label.setIcon(null);
                label.setText("      " + value);
                label.setToolTipText(placeholderFor(qualifiedName(tableRow.variable)));
            } else {
                label.setIcon(null);
                label.setToolTipText(null);
            }
            return label;
        }
    }

    private static final class FolderRowIcon implements Icon {
        private static final int WIDTH = 29;
        private static final int HEIGHT = 16;
        private final boolean expanded;

        private FolderRowIcon(boolean expanded) {
            this.expanded = expanded;
        }

        @Override
        public void paintIcon(Component component, Graphics graphics, int x, int y) {
            Graphics2D g = (Graphics2D) graphics.create();
            try {
                g.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);
                g.setColor(component.getForeground());

                if (expanded) {
                    g.fillPolygon(
                            new int[]{x + 1, x + 9, x + 5},
                            new int[]{y + 5, y + 5, y + 10},
                            3);
                } else {
                    g.fillPolygon(
                            new int[]{x + 3, x + 3, x + 8},
                            new int[]{y + 3, y + 11, y + 7},
                            3);
                }

                int folderX = x + 12;
                g.fillRoundRect(folderX + 2, y + 2, 8, 5, 2, 2);
                g.fillRoundRect(folderX, y + 5, 17, 10, 3, 3);
            } finally {
                g.dispose();
            }
        }

        @Override
        public int getIconWidth() {
            return WIDTH;
        }

        @Override
        public int getIconHeight() {
            return HEIGHT;
        }
    }

    // --- HELPERS ---
    private interface SimpleCallback {
        void run();
    }

    private static class SimpleDocumentListener implements DocumentListener {
        private final SimpleCallback callback;

        public SimpleDocumentListener(SimpleCallback callback) {
            this.callback = callback;
        }

        @Override
        public void insertUpdate(DocumentEvent e) { callback.run(); }

        @Override
        public void removeUpdate(DocumentEvent e) { callback.run(); }

        @Override
        public void changedUpdate(DocumentEvent e) { callback.run(); }
    }
}
