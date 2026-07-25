package burp;

import java.util.Objects;
import java.util.UUID;

public final class VariableDefinition {
    private final String id;
    private String name;
    private String folderId;
    private String value;
    private VariableExtractionRule rule;
    private int position;
    private TotpGenerator.TotpConfig totpConfig = TotpGenerator.TotpConfig.empty();
    // Cached 2FA code, kept out of persistence: a TOTP value is only recomputed when the
    // time step it belongs to changes, never on a background timer.
    private transient long lastTotpStep = -1;
    private transient String lastTotpCode = "";

    public VariableDefinition(String name, String folderId, String value,
                              VariableExtractionRule rule, int position) {
        this(UUID.randomUUID().toString(), name, folderId, value, rule, position);
    }

    public VariableDefinition(String id, String name, String folderId, String value,
                              VariableExtractionRule rule, int position) {
        this.id = Objects.requireNonNull(id);
        this.name = Objects.requireNonNull(name);
        this.folderId = folderId;
        this.value = value == null ? "" : value;
        this.rule = rule == null ? new VariableExtractionRule() : rule;
        this.position = position;
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = Objects.requireNonNull(name); }
    public String getFolderId() { return folderId; }
    public void setFolderId(String folderId) { this.folderId = folderId; }
    public String getValue() { return value; }
    public void setValue(String value) { this.value = value == null ? "" : value; }
    public VariableExtractionRule getRule() { return rule; }
    public void setRule(VariableExtractionRule rule) { this.rule = rule == null ? new VariableExtractionRule() : rule; }
    public int getPosition() { return position; }
    public void setPosition(int position) { this.position = position; }

    public TotpGenerator.TotpConfig getTotpConfig() { return totpConfig; }

    public void setTotpConfig(TotpGenerator.TotpConfig totpConfig) {
        this.totpConfig = totpConfig == null ? TotpGenerator.TotpConfig.empty() : totpConfig;
        this.lastTotpStep = -1;
        this.lastTotpCode = "";
    }

    public boolean isTotpVariable() { return totpConfig.isConfigured(); }

    /**
     * Returns the code for the given instant, reusing the cached one while the time step
     * has not advanced. Never called on a timer: only when a value is actually read.
     */
    public String totpCodeFor(long epochSeconds) {
        long step = TotpGenerator.timeStep(epochSeconds, totpConfig.periodSeconds());
        if (step == lastTotpStep && !lastTotpCode.isEmpty()) return lastTotpCode;
        String code = TotpGenerator.code(totpConfig, epochSeconds);
        lastTotpStep = step;
        lastTotpCode = code;
        return code;
    }

    public String qualifiedName(VariableFolder folder) {
        return folder == null ? name : folder.getName() + "." + name;
    }
}
