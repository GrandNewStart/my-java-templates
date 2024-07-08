package json;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Stack;

public class JSONObject {

    private final Hashtable<String, Object> table = new Hashtable<>();

    public JSONObject() {}

    public JSONObject(String string) {
        string = string.trim();
        if (string.startsWith("{") && string.endsWith("}")) {
            string = string.substring(1, string.length() - 1).trim();
            Stack<Character> stack = new Stack<>();
            StringBuilder keyBuffer = new StringBuilder();
            StringBuilder valueBuffer = new StringBuilder();
            boolean parsingKey = true;
            boolean inQuotes = false;
            char previousChar = 0;

            for (char c : string.toCharArray()) {
                if (c == '"' && previousChar != '\\') {
                    inQuotes = !inQuotes;
                }

                if (inQuotes) {
                    if (parsingKey) {
                        keyBuffer.append(c);
                    } else {
                        valueBuffer.append(c);
                    }
                } else {
                    switch (c) {
                        case '{':
                        case '[':
                            stack.push(c);
                            if (!parsingKey) {
                                valueBuffer.append(c);
                            }
                            break;
                        case '}':
                        case ']':
                            stack.pop();
                            if (!parsingKey) {
                                valueBuffer.append(c);
                            }
                            break;
                        case ':':
                            if (parsingKey) {
                                parsingKey = false;
                            } else {
                                valueBuffer.append(c);
                            }
                            break;
                        case ',':
                            if (stack.isEmpty()) {
                                putKeyValue(keyBuffer.toString(), valueBuffer.toString());
                                keyBuffer.setLength(0);
                                valueBuffer.setLength(0);
                                parsingKey = true;
                            } else {
                                valueBuffer.append(c);
                            }
                            break;
                        default:
                            if (parsingKey) {
                                keyBuffer.append(c);
                            } else {
                                valueBuffer.append(c);
                            }
                            break;
                    }
                }
                previousChar = c;
            }
            if (keyBuffer.length() > 0 && valueBuffer.length() > 0) {
                putKeyValue(keyBuffer.toString(), valueBuffer.toString());
            }
        } else {
            throw new IllegalArgumentException("Invalid JSON string");
        }
    }

    private void putKeyValue(String key, String value) {
        key = key.trim().replaceAll("^\"|\"$", "");
        value = value.trim();
        try {
            if (value.startsWith("\"") && value.endsWith("\"")) {
                table.put(key, value.substring(1, value.length() - 1));
            } else if (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("false")) {
                table.put(key, Boolean.parseBoolean(value));
            } else if (value.contains(".")) {
                table.put(key, Double.parseDouble(value));
            } else {
                table.put(key, Integer.parseInt(value));
            }
        } catch (NumberFormatException e) {
            // Handle nested JSONObjects
            if (value.startsWith("{") && value.endsWith("}")) {
                table.put(key, new JSONObject(value));
            }
        }
    }

    public void addString(String key, String value) {
        table.put(key, value);
    }

    public void addInteger(String key, Integer value) {
        table.put(key, value);
    }

    public void addDouble(String key, Double value) {
        table.put(key, value);
    }

    public void addBoolean(String key, Boolean value) {
        table.put(key, value);
    }

    public void addJSONObject(String key, JSONObject value) {
        table.put(key, value);
    }

    public String getString(String key) {
        return (String) table.get(key);
    }

    public Integer getInteger(String key) {
        return (Integer) table.get(key);
    }

    public Double getDouble(String key) {
        return (Double) table.get(key);
    }

    public Boolean getBoolean(String key) {
        return (Boolean) table.get(key);
    }

    public JSONObject getJSONObject(String key) {
        return (JSONObject) table.get(key);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        Enumeration<String> keys = table.keys();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            Object value = table.get(key);
            sb.append("\"").append(key).append("\":");
            if (value instanceof String) {
                sb.append("\"").append(value).append("\"");
            } else if (value instanceof JSONObject) {
                sb.append(value);
            } else {
                sb.append(value);
            }
            if (keys.hasMoreElements()) {
                sb.append(",");
            }
        }
        sb.append("}");
        return sb.toString();
    }
}
