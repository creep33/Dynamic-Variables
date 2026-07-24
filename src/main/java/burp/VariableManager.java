package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
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

public final class VariableManager {
    private final MontoyaApi api;
    private final Object lock = new Object();
    private final List<String> variableNames = new ArrayList<>();
    private final Map<String, String> values = new ConcurrentHashMap<>();
    private final Map<String, VariableExtractionRule> rules = new ConcurrentHashMap<>();
    private final List<VariableFolder> folders = new ArrayList<>();
    private final List<VariableDefinition> definitions = new ArrayList<>();
    private String variableSearch = "";
    private static final String STATE_V2_KEY = "dynamic_variables_state_v2";
    private static final String STATE_V3_KEY = "dynamic_variables_state_v3";

    private boolean replacementMasterEnabled = true;
    private boolean replacementEnabled = true;
    private boolean replacementIntruderEnabled = true;
    private boolean replacementScannerEnabled = true;
    private boolean replacementProxyEnabled = false;
    private boolean extractionEnabled = true;
    private boolean sessionRecoveryEnabled = false;
    private boolean extractionDebugEnabled = false;
    private EnumSet<AutomationTool> extractionTools = EnumSet.of(AutomationTool.REPEATER);
    private EnumSet<AutomationTool> recoveryTools = EnumSet.of(AutomationTool.REPEATER);
    private String refreshStatusCodes = "401, 403";
    private volatile boolean placeholderTagEnabled = false;
    private volatile String placeholderTag = "dv";
    private volatile UiLanguage uiLanguage = UiLanguage.ENGLISH;

    // UI Components
    private JPanel mainPanel;
    private JTable variablesTable;
    private VariablesTableModel tableModel;
    private JTextArea valueTextArea;
    
    private JCheckBox replacementMasterCheckBox;
    private JCheckBox globalReplaceCheckBox;
    private JCheckBox intruderReplaceCheckBox;
    private JCheckBox scannerReplaceCheckBox;
    private JCheckBox proxyReplaceCheckBox;
    private JCheckBox globalExtractCheckBox;
    private JCheckBox globalRecoveryCheckBox;
    private JTextField refreshStatusCodesField;
    private JLabel refreshStatusCodesLabel;
    private JSeparator refreshStatusCodesSeparator;
    private JLabel placeholderUsageLabel;

    // Rule Panel Components
    private JCheckBox ruleEnabledCheckBox;
    private JCheckBox automaticRefreshCheckBox;
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
    private JComboBox<String> sourceComboBox;
    private JTextField regexField;
    private JButton updateRuleButton;

    // Refresh Panel Components
    private JLabel savedRequestLabel;
    private JButton refreshRequestButton;
    private JButton sendToRepeaterButton;
    private JButton editRequestButton;

    private boolean isUpdatingUI = false;

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
            return new HashMap<>(values);
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
        return new VariableNames.PlaceholderStyle(placeholderTagEnabled, placeholderTag);
    }

    public String placeholderFor(String qualifiedName) {
        return VariableNames.placeholder(qualifiedName, getPlaceholderStyle());
    }

    String text(String englishText) {
        return UiText.get(uiLanguage, englishText);
    }

    public void addOrUpdateExtractionRuleInFolder(String folderName, String localName, String value,
                                                   boolean ruleEnabled, String matchUrl, String source,
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
        addOrUpdateExtractionRule(qualified, value, ruleEnabled, matchUrl, source, regex,
                matchMethod, reqBase64, host, port, secure);
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

    public void addOrUpdateExtractionRule(String name, String value, boolean ruleEnabled, String matchUrl, String source, 
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
            if (previousRule != null) {
                rule.setEnabled(previousRule.isEnabled());
                rule.setAutomaticRefreshEnabled(previousRule.isAutomaticRefreshEnabled());
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

        // --- TOP GLOBAL SETTINGS PANEL ---
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        JPanel replacementPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        JPanel automationPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        
        globalReplaceCheckBox = new JCheckBox("Repeater", replacementEnabled);
        globalReplaceCheckBox.setFont(new Font(globalReplaceCheckBox.getFont().getName(), Font.BOLD, 12));
        globalReplaceCheckBox.addActionListener(e -> {
            replacementEnabled = globalReplaceCheckBox.isSelected();
            savePreferences();
        });

        intruderReplaceCheckBox = new JCheckBox("Intruder", replacementIntruderEnabled);
        intruderReplaceCheckBox.setFont(new Font(intruderReplaceCheckBox.getFont().getName(), Font.BOLD, 12));
        intruderReplaceCheckBox.addActionListener(e -> {
            replacementIntruderEnabled = intruderReplaceCheckBox.isSelected();
            savePreferences();
        });

        scannerReplaceCheckBox = new JCheckBox("Scanner", replacementScannerEnabled);
        scannerReplaceCheckBox.setFont(new Font(scannerReplaceCheckBox.getFont().getName(), Font.BOLD, 12));
        scannerReplaceCheckBox.addActionListener(e -> {
            replacementScannerEnabled = scannerReplaceCheckBox.isSelected();
            savePreferences();
        });

        proxyReplaceCheckBox = new JCheckBox("Proxy", replacementProxyEnabled);
        proxyReplaceCheckBox.setFont(new Font(proxyReplaceCheckBox.getFont().getName(), Font.BOLD, 12));
        proxyReplaceCheckBox.addActionListener(e -> {
            replacementProxyEnabled = proxyReplaceCheckBox.isSelected();
            savePreferences();
        });

        // Set initial visibility of tool checkboxes based on master checkbox state
        globalReplaceCheckBox.setVisible(replacementMasterEnabled);
        intruderReplaceCheckBox.setVisible(replacementMasterEnabled);
        scannerReplaceCheckBox.setVisible(replacementMasterEnabled);
        proxyReplaceCheckBox.setVisible(replacementMasterEnabled);

        replacementMasterCheckBox = new JCheckBox(text("Enable Variable Replacement"), replacementMasterEnabled);
        replacementMasterCheckBox.setFont(new Font(replacementMasterCheckBox.getFont().getName(), Font.BOLD, 12));
        replacementMasterCheckBox.addActionListener(e -> {
            replacementMasterEnabled = replacementMasterCheckBox.isSelected();
            boolean visible = replacementMasterEnabled;
            globalReplaceCheckBox.setVisible(visible);
            intruderReplaceCheckBox.setVisible(visible);
            scannerReplaceCheckBox.setVisible(visible);
            proxyReplaceCheckBox.setVisible(visible);
            savePreferences();
            replacementPanel.revalidate();
            replacementPanel.repaint();
        });

        globalExtractCheckBox = new JCheckBox(text("Enable Response Auto-Extraction"), extractionEnabled);
        globalExtractCheckBox.setFont(new Font(globalExtractCheckBox.getFont().getName(), Font.BOLD, 12));
        globalExtractCheckBox.setToolTipText(text("Automatically extracts variable values from responses to keep them updated in the background."));
        globalExtractCheckBox.addActionListener(e -> {
            extractionEnabled = globalExtractCheckBox.isSelected();
            savePreferences();
        });

        globalRecoveryCheckBox = new JCheckBox(
                text("Enable automatic session recovery (401/403)"), sessionRecoveryEnabled);
        globalRecoveryCheckBox.setFont(new Font(
                globalRecoveryCheckBox.getFont().getName(), Font.BOLD, 12));
        globalRecoveryCheckBox.setToolTipText(text(
                "Refreshes enabled variables and retries authorized requests after configured status codes."));
        globalRecoveryCheckBox.addActionListener(e -> {
            sessionRecoveryEnabled = globalRecoveryCheckBox.isSelected();
            updateRecoveryControlsVisibility();
            savePreferences();
        });

        replacementPanel.add(replacementMasterCheckBox);
        replacementPanel.add(globalReplaceCheckBox);
        replacementPanel.add(intruderReplaceCheckBox);
        replacementPanel.add(scannerReplaceCheckBox);
        replacementPanel.add(proxyReplaceCheckBox);
        
        // Custom vertical divider
        JSeparator separator = new JSeparator(JSeparator.VERTICAL);
        separator.setPreferredSize(new Dimension(3, 20));
        replacementPanel.add(separator);
        
        automationPanel.add(globalExtractCheckBox);
        automationPanel.add(globalRecoveryCheckBox);

        // Custom vertical divider 2
        refreshStatusCodesSeparator = new JSeparator(JSeparator.VERTICAL);
        refreshStatusCodesSeparator.setPreferredSize(new Dimension(3, 20));
        automationPanel.add(refreshStatusCodesSeparator);

        refreshStatusCodesLabel = new JLabel(text("Refresh Status Codes:"));
        refreshStatusCodesLabel.setToolTipText(text("HTTP status codes (comma separated) that trigger an automatic token refresh (e.g., 401, 403)."));
        automationPanel.add(refreshStatusCodesLabel);
        refreshStatusCodesField = new JTextField(refreshStatusCodes, 8);
        refreshStatusCodesField.setToolTipText(text("HTTP status codes (comma separated) that trigger an automatic token refresh (e.g., 401, 403)."));
        refreshStatusCodesField.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            refreshStatusCodes = refreshStatusCodesField.getText();
            savePreferences();
        }));
        automationPanel.add(refreshStatusCodesField);

        JSeparator separator3 = new JSeparator(JSeparator.VERTICAL);
        separator3.setPreferredSize(new Dimension(3, 20));
        automationPanel.add(separator3);

        JButton settingsButton = new JButton(text("Configuration..."));
        settingsButton.setToolTipText(text("Configure the interface language and the optional tag that uniquely identifies variable placeholders."));
        settingsButton.addActionListener(e -> showPlaceholderSettingsDialog());
        automationPanel.add(settingsButton);

        topPanel.add(replacementPanel);
        topPanel.add(automationPanel);
        updateRecoveryControlsVisibility();

        mainPanel.add(topPanel, BorderLayout.NORTH);

        // --- CENTER SPLIT PANE ---
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setDividerLocation(450);
        splitPane.setResizeWeight(0.4);

        // Left Side: Variables Table & Buttons
        JPanel leftPanel = new JPanel(new BorderLayout(5, 5));
        tableModel = new VariablesTableModel();
        variablesTable = new JTable(tableModel);
        variablesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
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
                int row = variablesTable.getSelectedRow();
                TableRow selected = tableModel.rowAt(row);
                if (selected == null || selected.ungrouped) return;
                if (selected.variable != null) {
                    variablesTable.editCellAt(row, 0);
                    Component editor = variablesTable.getEditorComponent();
                    if (editor != null) editor.requestFocusInWindow();
                } else {
                    renameNode(selected);
                }
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
                variablesTable.setRowSelectionInterval(row, row);
                createVariablesPopup(row).show(variablesTable, e.getX(), e.getY());
                e.consume();
            }
        });
        variablesTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = variablesTable.getSelectedRow();
                updateDetailsPanel(selectedRow);
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
        JButton addFolderButton = new JButton(text("New Folder"));
        JButton addButton = new JButton(text("New Variable"));
        JButton deleteButton = new JButton(text("Delete Selected"));
        JButton clearButton = new JButton(text("Clear All"));

        addFolderButton.addActionListener(e -> createFolderDialog());
        addButton.addActionListener(e -> createVariableDialog(selectedFolderId()));

        deleteButton.addActionListener(e -> {
            deleteSelectedNode();
        });

        clearButton.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(mainPanel, text("Are you sure you want to clear all variables?"), text("Confirm Clear"), JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
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

        buttonPanel.add(addFolderButton);
        buttonPanel.add(addButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(clearButton);
        leftPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Right Side: Variable Details, Regex Configuration, and Refresh Action
        JPanel rightPanel = new JPanel(new GridBagLayout());
        rightPanel.setBorder(new EmptyBorder(0, 10, 0, 0));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(5, 5, 5, 5);

        // 1. Current Value JTextArea
        JPanel valuePanel = new JPanel(new BorderLayout(5, 5));
        valuePanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(),
                text("Variable Value Editor (Paste long values here)"),
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font(mainPanel.getFont().getName(), Font.BOLD, 12)
        ));
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

        // 2. Extraction Rule Editor Panel
        JPanel rulePanel = new JPanel(new GridBagLayout());
        rulePanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), 
                text("Response Auto-Extraction Rule"),
                TitledBorder.LEFT, 
                TitledBorder.TOP, 
                new Font(mainPanel.getFont().getName(), Font.PLAIN, 12)
        ));
        
        GridBagConstraints rgbc = new GridBagConstraints();
        rgbc.fill = GridBagConstraints.HORIZONTAL;
        rgbc.insets = new Insets(4, 5, 4, 5);
        rgbc.gridx = 0;

        // Checkbox: Enable rule
        ruleEnabledCheckBox = new JCheckBox(text("Enable auto-extraction for this variable"));
        ruleEnabledCheckBox.addActionListener(e -> handleRuleActivation(ruleEnabledCheckBox, false));
        rgbc.gridy = 0;
        rgbc.gridwidth = 2;
        rulePanel.add(ruleEnabledCheckBox, rgbc);

        automaticRefreshCheckBox = new JCheckBox(text("Enable automatic refresh for this variable"));
        automaticRefreshCheckBox.addActionListener(e -> handleRuleActivation(automaticRefreshCheckBox, true));
        rgbc.gridy = 1;
        rulePanel.add(automaticRefreshCheckBox, rgbc);

        allowNonIdempotentReplayCheckBox = new JCheckBox(
                text("Allow replay of non-idempotent requests"));
        allowNonIdempotentReplayCheckBox.setToolTipText(text(
                "Allows automatic replay of methods other than GET, HEAD, and OPTIONS."));
        allowNonIdempotentReplayCheckBox.addActionListener(e -> updateActiveRuleFromUI());
        rgbc.gridy = 2;
        rulePanel.add(allowNonIdempotentReplayCheckBox, rgbc);

        rgbc.gridwidth = 1;

        rgbc.gridy = 3;
        rgbc.gridx = 0;
        rgbc.weightx = 0.0;
        rulePanel.add(new JLabel(text("Matching mode:")), rgbc);
        JPanel strategyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        matchStrategyLabel = new JLabel();
        convertMatchButton = new JButton(text("Convert to explicit filters"));
        convertMatchButton.addActionListener(e -> convertActiveRuleToExplicitMatch());
        strategyPanel.add(matchStrategyLabel);
        strategyPanel.add(convertMatchButton);
        rgbc.gridx = 1;
        rgbc.weightx = 1.0;
        rulePanel.add(strategyPanel, rgbc);

        rgbc.gridy = 4;
        rgbc.gridx = 0;
        rgbc.weightx = 0.0;
        rulePanel.add(new JLabel(text("Method:")), rgbc);
        matchMethodField = new JTextField();
        matchMethodField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        rgbc.gridx = 1;
        rgbc.weightx = 1.0;
        rulePanel.add(matchMethodField, rgbc);

        rgbc.gridy = 5;
        rgbc.gridx = 0;
        rgbc.weightx = 0.0;
        rulePanel.add(new JLabel(text("Service:")), rgbc);
        JPanel servicePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        matchHostField = new JTextField(16);
        matchPortField = new JTextField(5);
        matchSecureCheckBox = new JCheckBox("HTTPS");
        matchHostField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        matchPortField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        matchSecureCheckBox.addActionListener(e -> updateActiveRuleFromUI());
        servicePanel.add(matchHostField);
        servicePanel.add(matchPortField);
        servicePanel.add(matchSecureCheckBox);
        rgbc.gridx = 1;
        rgbc.weightx = 1.0;
        rulePanel.add(servicePanel, rgbc);

        rgbc.gridy = 6;
        rgbc.gridx = 0;
        rgbc.weightx = 0.0;
        rulePanel.add(new JLabel(text("Path filter:")), rgbc);
        JPanel pathPanel = new JPanel(new BorderLayout(5, 0));
        pathModeComboBox = new JComboBox<>(new String[]{text("Literal"), text("Regular expression")});
        pathModeComboBox.addActionListener(e -> updateActiveRuleFromUI());
        matchUrlField = new JTextField();
        matchUrlField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        pathPanel.add(pathModeComboBox, BorderLayout.WEST);
        pathPanel.add(matchUrlField, BorderLayout.CENTER);
        rgbc.gridx = 1;
        rgbc.weightx = 1.0;
        rulePanel.add(pathPanel, rgbc);

        rgbc.gridy = 7;
        rgbc.gridx = 0;
        rgbc.weightx = 0.0;
        rulePanel.add(new JLabel(text("Query filter:")), rgbc);
        JPanel queryPanel = new JPanel(new BorderLayout(5, 0));
        queryModeComboBox = new JComboBox<>(new String[]{text("Literal"), text("Regular expression")});
        queryModeComboBox.addActionListener(e -> updateActiveRuleFromUI());
        queryField = new JTextField();
        queryField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        queryPanel.add(queryModeComboBox, BorderLayout.WEST);
        queryPanel.add(queryField, BorderLayout.CENTER);
        rgbc.gridx = 1;
        rgbc.weightx = 1.0;
        rulePanel.add(queryPanel, rgbc);

        rgbc.gridy = 8;
        rgbc.gridx = 0;
        rgbc.weightx = 0.0;
        rulePanel.add(new JLabel(text("Request discriminator:")), rgbc);
        JPanel discriminatorPanel = new JPanel(new BorderLayout(5, 0));
        discriminatorSourceComboBox = new JComboBox<>(new String[]{
                text("None"), text("Request Body"), text("Request Headers")});
        discriminatorSourceComboBox.addActionListener(e -> updateActiveRuleFromUI());
        discriminatorRegexField = new JTextField();
        discriminatorRegexField.getDocument().addDocumentListener(
                new SimpleDocumentListener(this::updateActiveRuleFromUI));
        discriminatorPanel.add(discriminatorSourceComboBox, BorderLayout.WEST);
        discriminatorPanel.add(discriminatorRegexField, BorderLayout.CENTER);
        rgbc.gridx = 1;
        rgbc.weightx = 1.0;
        rulePanel.add(discriminatorPanel, rgbc);

        rgbc.gridy = 9;
        rgbc.gridx = 0;
        rgbc.weightx = 0.0;
        rulePanel.add(new JLabel(text("Extract From:")), rgbc);

        sourceComboBox = new JComboBox<>(new String[]{
            text("Response Body"), text("Response Headers"), text("Request Body"), text("Request Headers")
        });
        sourceComboBox.addActionListener(e -> updateActiveRuleFromUI());
        rgbc.gridx = 1;
        rgbc.weightx = 1.0;
        rulePanel.add(sourceComboBox, rgbc);

        rgbc.gridy = 10;
        rgbc.gridx = 0;
        rgbc.weightx = 0.0;
        rulePanel.add(new JLabel(text("Regex (with 1 capture group):")), rgbc);

        regexField = new JTextField();
        regexField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        rgbc.gridx = 1;
        rgbc.weightx = 1.0;
        rulePanel.add(regexField, rgbc);

        rgbc.gridy = 11;
        rgbc.gridx = 0;
        rgbc.gridwidth = 2;
        updateRuleButton = new JButton(text("Update Rule from Response..."));
        updateRuleButton.addActionListener(e -> triggerUpdateRuleFromResponse());
        rulePanel.add(updateRuleButton, rgbc);

        rgbc.gridwidth = 1; // reset

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

        // ADD PANES TO THE DETAILS PANEL IN THE SPECIFIED LAYOUT POSITIONS:
        // Refresh Panel (Row 0) - height adjusted to content
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        rightPanel.add(refreshPanel, gbc);

        // Extraction Rule Panel (Row 1) - height adjusted to content
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        rightPanel.add(rulePanel, gbc);

        // Value Editor Panel (Row 2) - expands to occupy all remaining space
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        rightPanel.add(valuePanel, gbc);

        splitPane.setLeftComponent(leftPanel);
        JScrollPane detailsScrollPane = new JScrollPane(rightPanel);
        detailsScrollPane.setBorder(null);
        detailsScrollPane.getVerticalScrollBar().setUnitIncrement(16);
        splitPane.setRightComponent(detailsScrollPane);
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
        JCheckBox tagEnabledCheckBox = new JCheckBox(text("Use a tag in variable placeholders"), placeholderTagEnabled);
        JCheckBox diagnosticCheckBox = new JCheckBox(
                text("Enable auto-extraction diagnostic logs"), extractionDebugEnabled);
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
            previewLabel.setText(text("Example: ") + (valid
                    ? VariableNames.placeholder("token", new VariableNames.PlaceholderStyle(enabled,
                            enabled ? candidate : ""))
                    : "{{tag:token}}"));
        };

        tagEnabledCheckBox.addActionListener(e -> updateState.run());
        tagField.getDocument().addDocumentListener(new SimpleDocumentListener(updateState::run));
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
        panel.add(tagEnabledCheckBox, gbc);
        gbc.gridy = 3;
        gbc.gridwidth = 1;
        gbc.weightx = 0;
        panel.add(new JLabel(text("Tag:")), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        panel.add(tagField, gbc);
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 2;
        panel.add(previewLabel, gbc);
        gbc.gridy = 5;
        panel.add(validationLabel, gbc);
        gbc.gridy = 6;
        JPanel behaviorNotice = new JPanel();
        behaviorNotice.setLayout(new BoxLayout(behaviorNotice, BoxLayout.Y_AXIS));
        behaviorNotice.add(new JLabel(text("Existing requests are not rewritten automatically. When tagging is enabled,")));
        behaviorNotice.add(new JLabel(text("only placeholders containing the configured tag are replaced.")));
        panel.add(behaviorNotice, gbc);
        gbc.gridy = 7;
        panel.add(diagnosticCheckBox, gbc);

        gbc.gridy = 8;
        JPanel automationScopePanel = new JPanel(new GridLayout(0, 3, 8, 4));
        automationScopePanel.setBorder(BorderFactory.createTitledBorder(text("Automation tool scope")));
        automationScopePanel.add(new JLabel(text("Tool")));
        automationScopePanel.add(new JLabel(text("Response extraction")));
        automationScopePanel.add(new JLabel(text("Session recovery")));
        for (AutomationTool tool : AutomationTool.values()) {
            JCheckBox extraction = new JCheckBox("", extractionTools.contains(tool));
            JCheckBox recovery = new JCheckBox("", recoveryTools.contains(tool));
            extractionToolChecks.put(tool, extraction);
            recoveryToolChecks.put(tool, recovery);
            automationScopePanel.add(new JLabel(tool.name().charAt(0)
                    + tool.name().substring(1).toLowerCase(Locale.ROOT)));
            automationScopePanel.add(extraction);
            automationScopePanel.add(recovery);
        }
        panel.add(automationScopePanel, gbc);

        boolean enabled;
        String tag;
        while (true) {
            int result = JOptionPane.showConfirmDialog(mainPanel, panel, text("Tool Configuration"),
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
            tableModel.fireTableDataChanged();
        }
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

    private void updateRecoveryControlsVisibility() {
        boolean visible = globalRecoveryCheckBox != null && globalRecoveryCheckBox.isSelected();
        if (refreshStatusCodesSeparator != null) refreshStatusCodesSeparator.setVisible(visible);
        if (refreshStatusCodesLabel != null) refreshStatusCodesLabel.setVisible(visible);
        if (refreshStatusCodesField != null) refreshStatusCodesField.setVisible(visible);
        if (globalRecoveryCheckBox != null && globalRecoveryCheckBox.getParent() != null) {
            globalRecoveryCheckBox.getParent().revalidate();
            globalRecoveryCheckBox.getParent().repaint();
        }
    }

    private void updateDetailsPanel(int selectedRow) {
        if (selectedRow < 0) {
            isUpdatingUI = true;
            valueTextArea.setText("");
            valueTextArea.setEnabled(false);
            ruleEnabledCheckBox.setSelected(false);
            ruleEnabledCheckBox.setEnabled(false);
            automaticRefreshCheckBox.setSelected(false);
            automaticRefreshCheckBox.setEnabled(false);
            allowNonIdempotentReplayCheckBox.setSelected(false);
            allowNonIdempotentReplayCheckBox.setEnabled(false);
            setMatchFieldsEnabled(false);
            matchUrlField.setText("");
            matchUrlField.setEnabled(false);
            sourceComboBox.setSelectedIndex(0);
            sourceComboBox.setEnabled(false);
            regexField.setText("");
            regexField.setEnabled(false);
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
        String val = values.getOrDefault(name, "");
        VariableExtractionRule rule = rules.getOrDefault(name, new VariableExtractionRule());

        isUpdatingUI = true;
        valueTextArea.setText(val);
        valueTextArea.setEnabled(true);

        ruleEnabledCheckBox.setEnabled(true);
        ruleEnabledCheckBox.setSelected(rule.isEnabled());
        automaticRefreshCheckBox.setEnabled(true);
        automaticRefreshCheckBox.setSelected(rule.isAutomaticRefreshEnabled());
        allowNonIdempotentReplayCheckBox.setEnabled(true);
        allowNonIdempotentReplayCheckBox.setSelected(rule.isAllowNonIdempotentReplay());

        boolean explicit = rule.getMatchStrategy() == VariableExtractionRule.MatchStrategy.EXPLICIT;
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

        sourceComboBox.setEnabled(true);
        if ("request_body".equals(rule.getSource())) {
            sourceComboBox.setSelectedIndex(2);
        } else if ("request_headers".equals(rule.getSource())) {
            sourceComboBox.setSelectedIndex(3);
        } else if ("headers".equalsIgnoreCase(rule.getSource())) {
            sourceComboBox.setSelectedIndex(1);
        } else {
            sourceComboBox.setSelectedIndex(0);
        }

        regexField.setEnabled(true);
        regexField.setText(rule.getRegex());

        // Update refresh request details
        if (rule.getSavedRequestBase64() == null || rule.getSavedRequestBase64().isEmpty()) {
            savedRequestLabel.setText(text("Saved Request: None"));
            refreshRequestButton.setEnabled(false);
            sendToRepeaterButton.setEnabled(false);
            editRequestButton.setEnabled(false);
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
                editRequestButton.setEnabled(false);
                updateRuleButton.setEnabled(false);
            }
        }
        isUpdatingUI = false;
    }

    private void clearRuleFields() {
        isUpdatingUI = true;
        ruleEnabledCheckBox.setSelected(false);
        automaticRefreshCheckBox.setSelected(false);
        allowNonIdempotentReplayCheckBox.setSelected(false);
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
        sourceComboBox.setSelectedIndex(0);
        regexField.setText("");
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

            synchronized (lock) {
                VariableExtractionRule existingRule = rules.get(name);
                VariableExtractionRule rule = existingRule == null
                        ? new VariableExtractionRule() : existingRule.copy();
                rule.setEnabled(ruleEnabled);
                rule.setAutomaticRefreshEnabled(automaticRefreshCheckBox.isSelected());
                rule.setAllowNonIdempotentReplay(allowNonIdempotentReplayCheckBox.isSelected());
                rule.setSource(source);
                rule.setRegex(regex);
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

    private void handleRuleActivation(JCheckBox checkBox, boolean refresh) {
        if (isUpdatingUI) return;
        if (checkBox.isSelected()) {
            String error = activeRuleValidationError(refresh);
            if (error != null) {
                checkBox.setSelected(false);
                JOptionPane.showMessageDialog(mainPanel, text(error), text("Error"),
                        JOptionPane.ERROR_MESSAGE);
            }
        }
        updateActiveRuleFromUI();
    }

    private String activeRuleValidationError(boolean refresh) {
        String extractionRegex = regexField.getText().trim();
        if (!ExtractionEngine.isValidRegex(extractionRegex)
                || !ExtractionEngine.hasCaptureGroup(extractionRegex)) {
            return "The extraction regex must be valid and contain at least one capture group.";
        }
        if (refresh) {
            int row = variablesTable.getSelectedRow();
            String name = tableModel.variableKeyAt(row);
            VariableExtractionRule rule = name == null ? null : rules.get(name);
            if (rule == null || rule.getSavedRequestBase64() == null
                    || rule.getSavedRequestBase64().isEmpty()) {
                return "Automatic refresh requires a saved request.";
            }
            return null;
        }
        int row = variablesTable.getSelectedRow();
        String name = tableModel.variableKeyAt(row);
        VariableExtractionRule current = name == null ? null : rules.get(name);
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
        VariableExtractionRule rule = rules.get(name);
        if (rule == null || rule.getSavedRequestBase64().isEmpty()) return;

        try {
            byte[] requestBytes = Base64.getDecoder().decode(rule.getSavedRequestBase64());
            String rawReqText = new String(requestBytes, StandardCharsets.UTF_8);

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
            JTextField portField = new JTextField(String.valueOf(rule.getSavedPort()));
            hgbc.gridx = 3; hgbc.weightx = 0.5;
            headerPanel.add(portField, hgbc);

            hgbc.gridx = 4; hgbc.weightx = 0.0;
            JCheckBox secureCheckBox = new JCheckBox("HTTPS", rule.isSavedSecure());
            headerPanel.add(secureCheckBox, hgbc);

            editDialog.add(headerPanel, BorderLayout.NORTH);

            // Editor panel
            JPanel editorPanel = new JPanel(new BorderLayout(5, 5));
            editorPanel.setBorder(new EmptyBorder(5, 10, 5, 10));
            JTextArea requestEditor = new JTextArea(rawReqText);
            requestEditor.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            editorPanel.add(new JScrollPane(requestEditor), BorderLayout.CENTER);
            editDialog.add(editorPanel, BorderLayout.CENTER);

            // Footer buttons
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
            JButton saveButton = new JButton(text("Save Changes"));
            JButton copyButton = new JButton(text("Copy to Clipboard"));
            JButton cancelButton = new JButton(text("Cancel"));

            copyButton.addActionListener(e -> {
                try {
                    StringSelection selection = new StringSelection(requestEditor.getText());
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
                    JOptionPane.showMessageDialog(editDialog, text("Request copied to clipboard."), text("Copied"), JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(editDialog, text("Failed to copy to clipboard: ") + ex.getMessage(), text("Error"), JOptionPane.ERROR_MESSAGE);
                }
            });

            saveButton.addActionListener(e -> {
                String newRawReq = requestEditor.getText();
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

                try {
                    // Verify that it is parseable as HTTP request
                    HttpRequest.httpRequest(ByteArray.byteArray(newRawReq.getBytes(StandardCharsets.UTF_8)));
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(editDialog, text("Failed to parse HTTP request. Please verify the format."), text("Error"), JOptionPane.ERROR_MESSAGE);
                    return;
                }

                String newReqBase64 = Base64.getEncoder().encodeToString(newRawReq.getBytes(StandardCharsets.UTF_8));
                synchronized (lock) {
                    rule.setSavedRequestBase64(newReqBase64);
                    rule.setSavedHost(newHost);
                    rule.setSavedPort(newPort);
                    rule.setSavedSecure(newSecure);
                    savePreferences();
                }
                editDialog.dispose();
                updateDetailsPanel(selectedRow);
            });

            cancelButton.addActionListener(e -> editDialog.dispose());

            buttonPanel.add(copyButton);
            buttonPanel.add(saveButton);
            buttonPanel.add(cancelButton);
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
                if (rule.getSource() != null && rule.getSource().startsWith("request_")) {
                    textStr = new String(reqResp.request().toByteArray().getBytes(), StandardCharsets.UTF_8);
                } else {
                    textStr = new String(reqResp.response().toByteArray().getBytes(), StandardCharsets.UTF_8);
                }

                // Open selection dialog on EDT
                SwingUtilities.invokeLater(() -> {
                    showResponseSelectorDialog(name, rule, textStr, selectedRow);
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

    private void showResponseSelectorDialog(String varName, VariableExtractionRule rule, String responseStr, int rowIndex) {
        JDialog selectorDialog = new JDialog(api.userInterface().swingUtils().suiteFrame(), text("Highlight New Token - ") + varName, Dialog.ModalityType.APPLICATION_MODAL);
        selectorDialog.setLayout(new BorderLayout(10, 10));
        selectorDialog.setSize(700, 550);
        selectorDialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());

        // Header instructions
        JLabel instrLabel = new JLabel(text("Highlight/select the text you want to extract from the response below. The regex will be auto-generated."));
        instrLabel.setBorder(new EmptyBorder(5, 5, 5, 5));
        selectorDialog.add(instrLabel, BorderLayout.NORTH);

        // Editor
        JTextArea responseEditor = new JTextArea(responseStr);
        responseEditor.setEditable(false);
        responseEditor.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(responseEditor);
        selectorDialog.add(scrollPane, BorderLayout.CENTER);

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
        boolean requestContent = rule.getSource() != null && rule.getSource().startsWith("request_");
        if ("request_headers".equals(rule.getSource())) extractSrcCombo.setSelectedIndex(3);
        else if ("request_body".equals(rule.getSource())) extractSrcCombo.setSelectedIndex(2);
        else if ("headers".equals(rule.getSource())) extractSrcCombo.setSelectedIndex(1);
        sgbc.gridx = 1; sgbc.weightx = 1.0;
        southPanel.add(extractSrcCombo, sgbc);

        // Add selection listener to editor
        responseEditor.addCaretListener(ce -> {
            int start = Math.min(ce.getDot(), ce.getMark());
            int end = Math.max(ce.getDot(), ce.getMark());
            if (start != end && start >= 0 && end <= responseStr.length()) {
                String selectedText = responseStr.substring(start, end);
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
                rule.setRegex(finalRegex);
                rule.setSource(chosenSource);
                savePreferences();
            }
            selectorDialog.dispose();
            updateDetailsPanel(rowIndex);
            // Flash a success notification
            JOptionPane.showMessageDialog(mainPanel, text("Extraction rule updated successfully for variable: ") + varName, text("Rule Updated"), JOptionPane.INFORMATION_MESSAGE);
        });

        cancelBtn.addActionListener(al -> selectorDialog.dispose());
        buttonPanel.add(saveBtn);
        buttonPanel.add(cancelBtn);

        // Put panels together
        JPanel wrapperPanel = new JPanel(new BorderLayout(5, 5));
        wrapperPanel.add(southPanel, BorderLayout.CENTER);
        wrapperPanel.add(buttonPanel, BorderLayout.SOUTH);
        selectorDialog.add(wrapperPanel, BorderLayout.SOUTH);

        selectorDialog.setVisible(true);
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

        if (reqResp.response() != null) {
            String sourceContent = "";
            String source = rule.getSource() != null ? rule.getSource().toLowerCase() : "body";
            
            if ("request_headers".equals(source)) {
                StringBuilder sb = new StringBuilder();
                for (HttpHeader header : reqResp.request().headers()) {
                    sb.append(header.name()).append(": ").append(header.value()).append("\r\n");
                }
                sourceContent = sb.toString();
            } else if ("request_body".equals(source)) {
                sourceContent = reqResp.request().bodyToString();
            } else if ("headers".equals(source)) {
                StringBuilder sb = new StringBuilder();
                for (HttpHeader header : reqResp.response().headers()) {
                    sb.append(header.name()).append(": ").append(header.value()).append("\r\n");
                }
                sourceContent = sb.toString();
            } else {
                sourceContent = reqResp.response().bodyToString();
            }

            if (sourceContent != null && !sourceContent.isEmpty()) {
                java.util.regex.Pattern regexPattern = java.util.regex.Pattern.compile(rule.getRegex(), java.util.regex.Pattern.DOTALL);
                java.util.regex.Matcher matcher = regexPattern.matcher(sourceContent);
                if (matcher.find() && matcher.groupCount() >= 1) {
                    String extractedValue = matcher.group(1);
                    if (extractedValue != null) {
                        return extractedValue;
                    }
                } else {
                    throw new Exception("Regex pattern did not match response.");
                }
            } else {
                throw new Exception("Server response was empty.");
            }
        } else {
            throw new Exception("No response received from target.");
        }
        throw new Exception("Regex capture group did not produce a value.");
    }

    private String replacePlaceholders(String text, Map<String, String> variables) {
        return VariableNames.replacePlaceholders(text, variables, getPlaceholderStyle());
    }

    public void savePreferences() {
        synchronized (lock) {
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
                sessionRecoveryEnabled = recoveryEnabledPref != null
                        && Boolean.parseBoolean(recoveryEnabledPref);
                String debugPref = api.persistence().preferences().getString(
                        "dynamic_variables_extraction_debug_enabled");
                extractionDebugEnabled = debugPref != null && Boolean.parseBoolean(debugPref);
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
            boolean valid = ExtractionEngine.isValidRegex(rule.getRegex())
                    && ExtractionEngine.hasCaptureGroup(rule.getRegex());
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
        if (name == null || name.trim().isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, text(type) + text(" name cannot be empty."), text("Invalid Name"), JOptionPane.ERROR_MESSAGE);
            return false;
        }
        if (!VariableNames.isValidComponent(name)) {
            JOptionPane.showMessageDialog(mainPanel, text(type) + text(" names cannot contain '.'."), text("Invalid Name"), JOptionPane.ERROR_MESSAGE);
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

    private void createVariableDialog(String folderId) {
        String name = JOptionPane.showInputDialog(mainPanel, text("Variable name:"), text("New Variable"), JOptionPane.PLAIN_MESSAGE);
        if (name == null) return;
        name = name.trim();
        if (!validNewName(name, "Variable")) return;
        VariableFolder folder = findFolder(folderId);
        String key = folder == null ? name : folder.getName() + "." + name;
        synchronized (lock) {
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

    private JPopupMenu createVariablesPopup(int row) {
        TableRow tableRow = tableModel.rowAt(row);
        VariableDefinition selectedVariable = tableRow == null ? null : tableRow.variable;
        JPopupMenu menu = new JPopupMenu();
        JMenuItem rename = new JMenuItem(text("Rename"));
        rename.setEnabled(tableRow != null && !tableRow.ungrouped);
        rename.addActionListener(e -> renameNode(tableRow));
        JMenuItem copy = new JMenuItem(text("Copy Placeholder"));
        copy.setEnabled(selectedVariable != null);
        copy.addActionListener(e -> copyPlaceholder(selectedVariable));
        JMenuItem move = new JMenuItem(text("Move to..."));
        move.setEnabled(selectedVariable != null);
        move.addActionListener(e -> SwingUtilities.invokeLater(() -> showMoveDialog(selectedVariable)));
        JMenuItem add = new JMenuItem(text("New Variable"));
        add.addActionListener(e -> createVariableDialog(tableRow == null ? null
                : tableRow.folder != null ? tableRow.folder.getId()
                : tableRow.variable != null ? tableRow.variable.getFolderId() : null));
        JMenuItem delete = new JMenuItem(text("Delete"));
        delete.setEnabled(tableRow != null && !tableRow.ungrouped);
        delete.addActionListener(e -> deleteNode(tableRow));
        menu.add(rename);
        menu.add(copy);
        menu.add(move);
        menu.addSeparator();
        menu.add(add);
        menu.add(delete);
        return menu;
    }

    private void copyPlaceholder(VariableDefinition definition) {
        if (definition == null) return;
        String placeholder = placeholderFor(qualifiedName(definition));
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(placeholder), null);
            showTemporaryStatus(text("Copied ") + placeholder + text(" to the clipboard."));
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
        String oldName = row.folder != null ? row.folder.getName() : row.variable.getName();
        String type = row.folder != null ? "Folder" : "Variable";
        String name = JOptionPane.showInputDialog(mainPanel, text(type) + (uiLanguage == UiLanguage.SPANISH ? ":" : " name:"), oldName);
        if (name == null || oldName.equals(name.trim())) return;
        name = name.trim();
        if (!validNewName(name, type)) return;
        if (row.folder != null) renameFolder(row.folder, name);
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

    private void showMoveDialog(VariableDefinition definition) {
        List<String> choices = new ArrayList<>();
        String currentFolderId = definition.getFolderId();
        if (currentFolderId != null) choices.add(text("Ungrouped"));
        folders.stream()
                .filter(folder -> !Objects.equals(folder.getId(), currentFolderId))
                .sorted(Comparator.comparingInt(VariableFolder::getPosition))
                .forEach(folder -> choices.add(folder.getName()));
        if (choices.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel,
                    text("Create another folder before moving this variable."),
                    text("Move Variable"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        Object selected = JOptionPane.showInputDialog(mainPanel, text("Move variable to:"), text("Move Variable"),
                JOptionPane.PLAIN_MESSAGE, null, choices.toArray(), choices.get(0));
        if (selected == null) return;
        VariableFolder target = text("Ungrouped").equals(selected) ? null : findFolderByName(selected.toString());
        moveDefinition(definition, target == null ? null : target.getId(), countVariablesInFolder(target == null ? null : target.getId()), true);
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

    private void normalizePositions(String folderId) {
        List<VariableDefinition> group = definitions.stream().filter(v -> Objects.equals(folderId, v.getFolderId()))
                .sorted(Comparator.comparingInt(VariableDefinition::getPosition)).toList();
        for (int i = 0; i < group.size(); i++) group.get(i).setPosition(i);
    }

    private void deleteSelectedNode() {
        int row = variablesTable.getSelectedRow();
        if (row >= 0) deleteNode(tableModel.rowAt(row));
    }

    private void deleteNode(TableRow row) {
        if (row == null || row.ungrouped) return;
        if (row.variable != null) {
            String key = qualifiedName(row.variable);
            if (JOptionPane.showConfirmDialog(mainPanel, text("Delete variable '") + key + "'?", text("Delete Variable"),
                    JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) return;
            definitions.remove(row.variable);
        } else if (row.folder != null) {
            List<VariableDefinition> children = definitions.stream().filter(v -> row.folder.getId().equals(v.getFolderId())).toList();
            if (!children.isEmpty()) {
                Object[] options = {text("Move variables to Ungrouped"), text("Delete folder and variables"), text("Cancel")};
                int choice = JOptionPane.showOptionDialog(mainPanel, text("Folder contains ") + children.size() + text(" variables."),
                        text("Delete Folder"), JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[2]);
                if (choice == 0) {
                    for (VariableDefinition child : children) {
                        if (values.containsKey(child.getName()) && findDefinitionByKey(child.getName()) != child) {
                            JOptionPane.showMessageDialog(mainPanel, text("Cannot move: '") + child.getName() + text("' already exists in Ungrouped."),
                                    text("Delete Folder"), JOptionPane.ERROR_MESSAGE);
                            return;
                        }
                    }
                    int rootPosition = countVariablesInFolder(null);
                    for (VariableDefinition child : children) {
                        child.setFolderId(null);
                        child.setPosition(rootPosition++);
                    }
                } else if (choice == 1) definitions.removeAll(children);
                else return;
            }
            folders.remove(row.folder);
            folders.sort(Comparator.comparingInt(VariableFolder::getPosition));
            for (int i = 0; i < folders.size(); i++) folders.get(i).setPosition(i);
        }
        rebuildRuntimeMapsFromDefinitions();
        savePreferences();
        tableModel.fireTableDataChanged();
        updateDetailsPanel(-1);
    }

    private class VariableRowTransferHandler extends TransferHandler {
        private static final long serialVersionUID = 1L;
        private final DataFlavor rowFlavor = new DataFlavor(Integer.class, "Variable row");

        @Override
        protected Transferable createTransferable(JComponent component) {
            int sourceRow = variablesTable.getSelectedRow();
            return sourceRow < 0 ? null : new VariableRowTransferable(sourceRow, rowFlavor);
        }

        @Override
        public int getSourceActions(JComponent component) {
            return MOVE;
        }

        @Override
        public boolean canImport(TransferSupport support) {
            return support.getComponent() == variablesTable
                    && support.isDrop()
                    && support.isDataFlavorSupported(rowFlavor);
        }

        @Override
        public boolean importData(TransferSupport support) {
            if (!canImport(support)) {
                return false;
            }

            try {
                int sourceRow = (Integer) support.getTransferable().getTransferData(rowFlavor);
                JTable.DropLocation dropLocation = (JTable.DropLocation) support.getDropLocation();
                TableRow source = tableModel.rowAt(sourceRow);
                int requestedDropRow = dropLocation.getRow();
                int dropRow = Math.min(requestedDropRow, tableModel.getRowCount() - 1);
                TableRow target = tableModel.rowAt(dropRow);
                if (source == null || target == null) return false;
                if (source.variable != null) {
                    String folderId = target.folder != null ? target.folder.getId()
                            : target.ungrouped ? null : target.variable.getFolderId();
                    int position = requestedDropRow >= tableModel.getRowCount() ? countVariablesInFolder(folderId)
                            : target.variable == null ? countVariablesInFolder(folderId) : target.variable.getPosition();
                    return moveDefinition(source.variable, folderId, position, true);
                }
                VariableFolder targetFolder = target.folder != null ? target.folder
                        : target.variable == null ? null : findFolder(target.variable.getFolderId());
                if (source.folder != null && targetFolder != null && source.folder != targetFolder) {
                    int old = source.folder.getPosition();
                    int next = targetFolder.getPosition();
                    for (VariableFolder folder : folders) {
                        if (folder == source.folder) continue;
                        if (old < next && folder.getPosition() > old && folder.getPosition() <= next) folder.setPosition(folder.getPosition() - 1);
                        if (old > next && folder.getPosition() >= next && folder.getPosition() < old) folder.setPosition(folder.getPosition() + 1);
                    }
                    source.folder.setPosition(next);
                    savePreferences();
                    tableModel.fireTableDataChanged();
                    return true;
                }
                return false;
            } catch (UnsupportedFlavorException | IOException e) {
                api.logging().logToError("Failed to reorder variable: " + e.getMessage());
                return false;
            }
        }
    }

    private static class VariableRowTransferable implements Transferable {
        private final Integer row;
        private final DataFlavor rowFlavor;

        private VariableRowTransferable(int row, DataFlavor rowFlavor) {
            this.row = row;
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
            return row;
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
                    boolean expanded = row.ungrouped ? ungroupedExpanded : row.folder.isExpanded();
                    String name = row.ungrouped ? text("Ungrouped") : row.folder.getName();
                    return (expanded ? "▾ " : "▸ ") + "📁 " + name + " (" +
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
            if (tableRow != null && tableRow.variable != null) {
                label.setText("    " + value);
                label.setToolTipText(placeholderFor(qualifiedName(tableRow.variable)));
            } else {
                label.setToolTipText(null);
            }
            return label;
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
