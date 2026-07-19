package com.hips.agent.osquery;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.util.*;

/**
 * ============================================================
 * HIPS Agent — Safe osquery JSON Result Parser
 * ============================================================
 * Parses osquery's JSON result log format with comprehensive
 * error handling. Never throws — returns empty collections on
 * any parse failure and logs warnings.
 *
 * osquery result log format (one JSON object per line):
 * {
 *   "name": "processes",
 *   "hostIdentifier": "hostname",
 *   "calendarTime": "...",
 *   "unixTime": 1234567890,
 *   "epoch": 0,
 *   "counter": 1,
 *   "numerics": false,
 *   "columns": { ... },             // for differential queries
 *   "action": "added" | "removed",  // for differential queries
 *   "decorations": { ... }
 * }
 *
 * Or for snapshot queries, an array of row objects:
 * [
 *   {"pid": "1234", "name": "svchost.exe", ...},
 *   {"pid": "5678", "name": "chrome.exe", ...}
 * ]
 */
public class OsqueryResultParser {

    private static final Gson GSON = new Gson();

    private OsqueryResultParser() {} // Utility class — no instantiation

    /**
     * Parses a single JSON line from the osquery result log.
     * Returns a list of row Maps, handling both snapshot (array)
     * and differential (single object with "columns") formats.
     *
     * @param jsonLine A single line of JSON from the result log
     * @return List of parsed rows as Maps, never null
     */
    public static List<Map<String, String>> parseLine(String jsonLine) {
        List<Map<String, String>> results = new ArrayList<>();

        if (jsonLine == null || jsonLine.trim().isEmpty()) {
            return results;
        }

        try {
            String trimmed = jsonLine.trim();
            JsonElement root = JsonParser.parseString(trimmed);

            if (root.isJsonArray()) {
                // Snapshot query result: array of row objects
                JsonArray arr = root.getAsJsonArray();
                for (JsonElement elem : arr) {
                    if (elem.isJsonObject()) {
                        results.add(jsonObjectToMap(elem.getAsJsonObject()));
                    }
                }
            } else if (root.isJsonObject()) {
                JsonObject obj = root.getAsJsonObject();

                // Check for differential query format (has "columns" key)
                if (obj.has("columns") && obj.get("columns").isJsonObject()) {
                    Map<String, String> row = jsonObjectToMap(obj.getAsJsonObject("columns"));
                    // Attach action (added/removed) as metadata
                    if (obj.has("action")) {
                        row.put("_action", safeGetString(obj, "action"));
                    }
                    if (obj.has("name")) {
                        row.put("_query_name", safeGetString(obj, "name"));
                    }
                    results.add(row);
                } else {
                    // Flat row object (e.g., from osqueryi)
                    results.add(jsonObjectToMap(obj));
                }
            }
        } catch (JsonSyntaxException e) {
            System.err.println("[OsqueryParser] Malformed JSON (skipping): " + e.getMessage());
        } catch (Exception e) {
            System.err.println("[OsqueryParser] Unexpected parse error: " + e.getMessage());
        }

        return results;
    }

    /**
     * Parses the full output of an osquery interactive query
     * (e.g., `osqueryi --json "SELECT * FROM processes"`).
     * Expects a JSON array at the top level.
     *
     * @param jsonOutput The complete JSON output string
     * @return List of parsed rows, never null
     */
    public static List<Map<String, String>> parseQueryOutput(String jsonOutput) {
        List<Map<String, String>> results = new ArrayList<>();

        if (jsonOutput == null || jsonOutput.trim().isEmpty()) {
            return results;
        }

        try {
            JsonElement root = JsonParser.parseString(jsonOutput.trim());
            if (root.isJsonArray()) {
                for (JsonElement elem : root.getAsJsonArray()) {
                    if (elem.isJsonObject()) {
                        results.add(jsonObjectToMap(elem.getAsJsonObject()));
                    }
                }
            }
        } catch (JsonSyntaxException e) {
            System.err.println("[OsqueryParser] Failed to parse query output: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("[OsqueryParser] Unexpected error in parseQueryOutput: " + e.getMessage());
        }

        return results;
    }

    /**
     * Converts a JsonObject to a Map<String, String>, safely
     * converting all values to strings.
     */
    private static Map<String, String> jsonObjectToMap(JsonObject obj) {
        Map<String, String> map = new LinkedHashMap<>();
        for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
            JsonElement val = entry.getValue();
            if (val == null || val.isJsonNull()) {
                map.put(entry.getKey(), "");
            } else if (val.isJsonPrimitive()) {
                map.put(entry.getKey(), val.getAsString());
            } else {
                // Nested object/array — serialize to string
                map.put(entry.getKey(), val.toString());
            }
        }
        return map;
    }

    /**
     * Safely extracts a string value from a JsonObject.
     * Returns empty string if key is missing or null.
     */
    public static String safeGetString(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) {
            return "";
        }
        try {
            return obj.get(key).getAsString();
        } catch (Exception e) {
            return obj.get(key).toString();
        }
    }

    /**
     * Safely extracts an integer value from a JsonObject.
     * Returns defaultValue if key is missing, null, or unparseable.
     */
    public static int safeGetInt(JsonObject obj, String key, int defaultValue) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) {
            return defaultValue;
        }
        try {
            return obj.get(key).getAsInt();
        } catch (Exception e) {
            try {
                return Integer.parseInt(obj.get(key).getAsString().trim());
            } catch (NumberFormatException nfe) {
                return defaultValue;
            }
        }
    }

    /**
     * Safely gets a string from a Map row, returning empty string if absent.
     */
    public static String rowGet(Map<String, String> row, String key) {
        if (row == null) return "";
        String val = row.get(key);
        return val != null ? val : "";
    }

    /**
     * Safely gets an int from a Map row, returning default if absent/unparseable.
     */
    public static int rowGetInt(Map<String, String> row, String key, int defaultValue) {
        String val = rowGet(row, key);
        if (val.isEmpty()) return defaultValue;
        try {
            return Integer.parseInt(val.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
