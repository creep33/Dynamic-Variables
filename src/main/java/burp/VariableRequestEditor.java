package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.HierarchyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class VariableRequestEditor implements ExtensionProvidedHttpRequestEditor {
    private final VariableManager variableManager;
    private final EditorCreationContext creationContext;
    private final HttpRequestEditor nativeEditor;

    private JPanel mainPanel;
    private JList<String> varList;
    private DefaultListModel<String> listModel;
    private JSplitPane splitPane;
    private final List<String> variableByRow = new ArrayList<>();
    private final Set<String> collapsedFolders = new HashSet<>();
    private final Timer variableRefreshTimer;
    private List<String> renderedVariableNames = List.of();
    private List<String> renderedFolderNames = List.of();
    private long observedVariableRevision;
    private String filter = "";

    public VariableRequestEditor(MontoyaApi api, VariableManager variableManager, EditorCreationContext creationContext) {
        this.variableManager = variableManager;
        this.creationContext = creationContext;

        // Use Burp's full HTTP editor so the request has the native Pretty,
        // Raw and Hex views.
        if (creationContext.editorMode() == EditorMode.READ_ONLY) {
            this.nativeEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        } else {
            this.nativeEditor = api.userInterface().createHttpRequestEditor();
        }

        createUI();
        variableRefreshTimer = new Timer(500, e -> refreshVariableListIfChanged());
        variableRefreshTimer.setCoalesce(true);
        mainPanel.addHierarchyListener(e -> {
            if ((e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) == 0) return;
            if (mainPanel.isShowing()) {
                refreshVariableListIfChanged();
                variableRefreshTimer.start();
            } else {
                variableRefreshTimer.stop();
            }
        });
    }

    private void createUI() {
        if (mainPanel == null) {
            mainPanel = new JPanel(new BorderLayout());
        } else {
            mainPanel.removeAll();
            mainPanel.setLayout(new BorderLayout());
        }

        // Left Sidebar: Variables list panel
        JPanel sidebarPanel = new JPanel(new BorderLayout(5, 5));
        sidebarPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        sidebarPanel.setMinimumSize(new Dimension(130, 100));
        sidebarPanel.setPreferredSize(new Dimension(150, 200));

        // Header label
        JLabel headerLabel = new JLabel(text("Double-click a variable to insert:"));
        headerLabel.setFont(new Font(headerLabel.getFont().getName(), Font.BOLD, 11));
        JTextField searchField = new JTextField();
        searchField.putClientProperty("JTextField.placeholderText", text("Search variables"));
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            private void update() {
                filter = searchField.getText().trim().toLowerCase(java.util.Locale.ROOT);
                refreshVariableList();
            }
            @Override public void insertUpdate(DocumentEvent e) { update(); }
            @Override public void removeUpdate(DocumentEvent e) { update(); }
            @Override public void changedUpdate(DocumentEvent e) { update(); }
        });
        JPanel sidebarHeader = new JPanel(new BorderLayout(3, 3));
        sidebarHeader.add(headerLabel, BorderLayout.NORTH);
        sidebarHeader.add(searchField, BorderLayout.SOUTH);
        sidebarPanel.add(sidebarHeader, BorderLayout.NORTH);

        // Variables List
        listModel = new DefaultListModel<>();
        varList = new JList<>(listModel);
        varList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        varList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));

        // Custom cell renderer to show variable value as tooltip
        varList.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                Component c = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value != null) {
                    String varName = variableAt(index);
                    if (varName == null) {
                        setFont(getFont().deriveFont(Font.BOLD));
                        setToolTipText(text("Double-click to expand or collapse"));
                        return c;
                    }
                    String varValue = variableManager.getVariables().get(varName);
                    if (varValue != null) {
                        // Truncate long values for tooltip
                        if (varValue.length() > 200) {
                            varValue = varValue.substring(0, 200) + "...";
                        }
                        // Burp renders extension tooltips as plain text, so HTML markup would
                        // be shown literally instead of wrapping the value.
                        setToolTipText(varValue);
                    } else {
                        setToolTipText(text("No value"));
                    }
                }
                return c;
            }
        });

        // Double-click selection action listener
        varList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && !varList.isSelectionEmpty()) {
                    String display = varList.getSelectedValue();
                    String selectedVar = selectedVariable();
                    if (selectedVar != null) insertPlaceholder(selectedVar);
                    else toggleFolder(display);
                }
            }
        });

        sidebarPanel.add(new JScrollPane(varList), BorderLayout.CENTER);

        // Sidebar Bottom Buttons Panel
        JPanel sidebarButtonsPanel = new JPanel(new BorderLayout(4, 0));
        JButton insertButton = new JButton(text("Insert"));
        insertButton.setFont(new Font(insertButton.getFont().getName(), Font.PLAIN, 10));
        insertButton.addActionListener(e -> {
            if (!varList.isSelectionEmpty()) {
                String selected = selectedVariable();
                if (selected != null) insertPlaceholder(selected);
            }
        });

        JButton refreshButton = new JButton(new RefreshIcon());
        refreshButton.setToolTipText(text("Refresh"));
        refreshButton.getAccessibleContext().setAccessibleName(text("Refresh"));
        refreshButton.setMargin(new Insets(2, 6, 2, 6));
        refreshButton.addActionListener(e -> refreshVariableList());

        sidebarButtonsPanel.add(insertButton, BorderLayout.CENTER);
        sidebarButtonsPanel.add(refreshButton, BorderLayout.EAST);
        sidebarPanel.add(sidebarButtonsPanel, BorderLayout.SOUTH);

        // Split Pane wrapping the sidebar on the left and native editor on the right
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setLeftComponent(sidebarPanel);
        splitPane.setRightComponent(nativeEditor.uiComponent());
        splitPane.setDividerLocation(150);

        mainPanel.add(splitPane, BorderLayout.CENTER);
        
        // Load initial list contents
        refreshVariableList();
    }

    private void refreshVariableList() {
        refreshVariableList(variableManager.getVariableListSnapshot());
    }

    private void refreshVariableList(VariableManager.VariableListSnapshot snapshot) {
        String selectedVariable = selectedVariable();
        listModel.clear();
        variableByRow.clear();
        List<String> names = snapshot.names();
        List<String> configuredFolders = snapshot.folders();
        renderedVariableNames = List.copyOf(names);
        renderedFolderNames = List.copyOf(configuredFolders);
        observedVariableRevision = snapshot.revision();

        List<String> folders = new ArrayList<>();
        folders.add("");
        folders.addAll(configuredFolders);
        for (String folder : folders) {
            List<String> matches = names.stream().filter(name -> variableManager.getFolderNameForVariable(name).equals(folder))
                    .filter(name -> filter.isEmpty() || name.toLowerCase(java.util.Locale.ROOT).contains(filter)
                            || folder.toLowerCase(java.util.Locale.ROOT).contains(filter)).toList();
            if (matches.isEmpty() && !filter.isEmpty()) continue;
            String label = (collapsedFolders.contains(folder) && filter.isEmpty() ? "▸ " : "▾ ") + "📁 "
                    + (folder.isEmpty() ? text("Ungrouped") : folder) + " (" + matches.size() + ")";
            listModel.addElement(label);
            variableByRow.add(null);
            if (!collapsedFolders.contains(folder) || !filter.isEmpty()) {
                for (String name : matches) {
                    String display = "    " + localVariableName(name, folder);
                    listModel.addElement(display);
                    variableByRow.add(name);
                }
            }
        }
        if (selectedVariable != null) {
            int selectedRow = variableByRow.indexOf(selectedVariable);
            if (selectedRow >= 0) varList.setSelectedIndex(selectedRow);
        }
    }

    private void refreshVariableListIfChanged() {
        VariableManager.VariableListSnapshot snapshot = variableManager.getVariableListSnapshot();
        if (snapshot.revision() == observedVariableRevision) return;

        List<String> names = snapshot.names();
        List<String> folders = snapshot.folders();
        if (!names.equals(renderedVariableNames) || !folders.equals(renderedFolderNames)) {
            refreshVariableList(snapshot);
        } else {
            observedVariableRevision = snapshot.revision();
            varList.repaint();
        }
    }

    static String localVariableName(String qualifiedName, String folder) {
        if (qualifiedName == null || folder == null || folder.isEmpty()) return qualifiedName;
        String prefix = folder + ".";
        return qualifiedName.startsWith(prefix)
                ? qualifiedName.substring(prefix.length())
                : qualifiedName;
    }

    private String selectedVariable() {
        return variableAt(varList.getSelectedIndex());
    }

    private String variableAt(int row) {
        return row >= 0 && row < variableByRow.size() ? variableByRow.get(row) : null;
    }

    private void toggleFolder(String display) {
        if (display == null) return;
        int marker = display.indexOf("📁 ");
        int count = display.lastIndexOf(" (");
        if (marker < 0 || count < marker) return;
        String folder = display.substring(marker + 3, count);
        if (text("Ungrouped").equals(folder)) folder = "";
        if (!collapsedFolders.add(folder)) collapsedFolders.remove(folder);
        refreshVariableList();
    }

    private static final class RefreshIcon implements Icon {
        private static final int SIZE = 14;

        @Override
        public void paintIcon(Component component, Graphics graphics, int x, int y) {
            Graphics2D g = (Graphics2D) graphics.create();
            try {
                g.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);
                g.setColor(component.getForeground());
                g.setStroke(new BasicStroke(1.7f, BasicStroke.CAP_ROUND,
                        BasicStroke.JOIN_ROUND));
                g.drawArc(x + 2, y + 2, 9, 9, 35, 285);
                g.fillPolygon(
                        new int[]{x + 10, x + 13, x + 12},
                        new int[]{y + 1, y + 4, y + 6},
                        3);
            } finally {
                g.dispose();
            }
        }

        @Override
        public int getIconWidth() {
            return SIZE;
        }

        @Override
        public int getIconHeight() {
            return SIZE;
        }
    }

    private boolean isLocallyModified = false;

    private void insertPlaceholder(String varName) {
        if (creationContext.editorMode() == EditorMode.READ_ONLY) {
            return;
        }

        HttpRequest currentRequest = nativeEditor.getRequest();
        if (currentRequest != null) {
            byte[] requestBytes = currentRequest.toByteArray().getBytes();
            String reqStr = new String(requestBytes, StandardCharsets.UTF_8);
            
            Selection selection = nativeEditor.selection().orElse(null);
            int caret = nativeEditor.caretPosition();
            
            String placeholder = variableManager.placeholderFor(varName);
            String newReqStr;
            int newCaret;

            if (selection != null && selection.offsets().startIndexInclusive() < selection.offsets().endIndexExclusive()) {
                int start = selection.offsets().startIndexInclusive();
                int end = selection.offsets().endIndexExclusive();
                String prefix = reqStr.substring(0, start);
                String suffix = reqStr.substring(end);
                newReqStr = prefix + placeholder + suffix;
                newCaret = start + placeholder.length();
            } else if (caret >= 0 && caret <= reqStr.length()) {
                String prefix = reqStr.substring(0, caret);
                String suffix = reqStr.substring(caret);
                newReqStr = prefix + placeholder + suffix;
                newCaret = caret + placeholder.length();
            } else {
                return;
            }

            ByteArray newContents = ByteArray.byteArray(newReqStr.getBytes(StandardCharsets.UTF_8));
            HttpRequest updatedRequest = currentRequest.httpService() == null
                    ? HttpRequest.httpRequest(newContents)
                    : HttpRequest.httpRequest(currentRequest.httpService(), newContents);
            nativeEditor.setRequest(updatedRequest);
            this.isLocallyModified = true;

            if (newCaret <= newReqStr.length()) {
                nativeEditor.setCaretPosition(newCaret);
            }
            
            // Grab focus back to the editor for continuous editing
            nativeEditor.uiComponent().requestFocusInWindow();
        }
    }

    @Override
    public HttpRequest getRequest() {
        return nativeEditor.getRequest();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.isLocallyModified = false;
        if (requestResponse != null && requestResponse.request() != null) {
            nativeEditor.setRequest(requestResponse.request());
        } else {
            nativeEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(new byte[0])));
        }
        refreshVariableList();
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        // Only display if the context isn't an extension creating its own editor (avoids infinite loops if another extension embeds editors)
        if (creationContext.toolSource().toolType() == burp.api.montoya.core.ToolType.EXTENSIONS) {
            return false;
        }
        return true;
    }

    @Override
    public String caption() {
        return "Dynamic Variables";
    }

    private String text(String englishText) {
        return variableManager.text(englishText);
    }

    @Override
    public Component uiComponent() {
        return mainPanel;
    }

    @Override
    public Selection selectedData() {
        return nativeEditor.selection().orElse(null);
    }

    @Override
    public boolean isModified() {
        return isLocallyModified || nativeEditor.isModified();
    }
}
