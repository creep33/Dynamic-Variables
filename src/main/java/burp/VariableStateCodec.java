package burp;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

final class VariableStateCodec {
    static final String VERSION = "5";

    record State(List<VariableFolder> folders, List<VariableDefinition> variables) {}

    private VariableStateCodec() {}

    static String encode(List<VariableFolder> folders, List<VariableDefinition> variables) {
        StringBuilder out = new StringBuilder(VERSION).append('\n');
        for (VariableFolder folder : folders) {
            out.append("F\t").append(enc(folder.getId())).append('\t')
                    .append(enc(folder.getName())).append('\t').append(folder.getPosition()).append('\t')
                    .append(folder.isExpanded()).append('\n');
        }
        for (VariableDefinition variable : variables) {
            out.append("V\t").append(enc(variable.getId())).append('\t')
                    .append(enc(variable.getName())).append('\t')
                    .append(enc(variable.getFolderId() == null ? "" : variable.getFolderId())).append('\t')
                    .append(variable.getPosition()).append('\t').append(enc(variable.getValue())).append('\t')
                    .append(enc(variable.getRule().serialize())).append('\n');
        }
        return out.toString();
    }

    static State decode(String data) {
        if (data == null || data.isEmpty()) return new State(new ArrayList<>(), new ArrayList<>());
        String[] lines = data.split("\\n", -1);
        if (lines.length == 0 || !(VERSION.equals(lines[0]) || "4".equals(lines[0])
                || "3".equals(lines[0]) || "2".equals(lines[0]))) {
            throw new IllegalArgumentException("Unsupported variable state version");
        }
        List<VariableFolder> folders = new ArrayList<>();
        List<VariableDefinition> variables = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].isEmpty()) continue;
            String[] parts = lines[i].split("\\t", -1);
            if ("F".equals(parts[0]) && parts.length == 5) {
                folders.add(new VariableFolder(dec(parts[1]), dec(parts[2]),
                        Integer.parseInt(parts[3]), Boolean.parseBoolean(parts[4])));
            } else if ("V".equals(parts[0]) && parts.length == 7) {
                String folderId = dec(parts[3]);
                variables.add(new VariableDefinition(dec(parts[1]), dec(parts[2]),
                        folderId.isEmpty() ? null : folderId, dec(parts[5]),
                        VariableExtractionRule.deserialize(dec(parts[6])), Integer.parseInt(parts[4])));
            }
        }
        return new State(folders, variables);
    }

    static State migrateLegacy(List<String> orderedNames, Map<String, String> values,
                               Map<String, VariableExtractionRule> rules) {
        List<VariableDefinition> variables = new ArrayList<>();
        for (int i = 0; i < orderedNames.size(); i++) {
            String name = orderedNames.get(i);
            variables.add(new VariableDefinition(name, null, values.getOrDefault(name, ""),
                    rules.getOrDefault(name, new VariableExtractionRule()), i));
        }
        return new State(new ArrayList<>(), variables);
    }

    private static String enc(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }

    private static String dec(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }
}
