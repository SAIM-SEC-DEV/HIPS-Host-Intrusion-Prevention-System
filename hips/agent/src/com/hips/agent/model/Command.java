package com.hips.agent.model;

import com.google.gson.annotations.SerializedName;
import java.util.Map;

/**
 * ============================================================
 * HIPS Agent — Command Model
 * ============================================================
 * Represents a command received from the server. The agent
 * polls /api/commands.php every 10 seconds; each response
 * may contain zero or more Command objects to execute.
 *
 * Supported command types:
 *   BLOCK_IP          — Block an IP address via firewall rules
 *   UNBLOCK_IP        — Remove a blocked IP
 *   SCAN_FILE         — Integrity check on a specific file
 *   FULL_SCAN         — Complete hash check of all baseline files
 *   RESTART           — Restart the agent service
 *   SHUTDOWN          — Gracefully stop the agent
 *   UPDATE_RULES      — Reload detection rules from server
 *   WHITELIST_ADD     — Add an entry to the whitelist
 *   WHITELIST_REMOVE  — Remove an entry from the whitelist
 */
public class Command {

    private int id;

    @SerializedName("command_type")
    private String commandType;

    private Map<String, Object> parameters;

    private String priority;

    @SerializedName("admin_note")
    private String adminNote;

    @SerializedName("issued_at")
    private String issuedAt;

    // ── Getters ──────────────────────────────────────────────

    public int                   getId()          { return id; }
    public String                getCommandType() { return commandType; }
    public Map<String, Object>   getParameters()  { return parameters; }
    public String                getPriority()    { return priority; }
    public String                getAdminNote()   { return adminNote; }
    public String                getIssuedAt()    { return issuedAt; }

    // ── Setters ──────────────────────────────────────────────

    public void setId(int id)                             { this.id = id; }
    public void setCommandType(String commandType)        { this.commandType = commandType; }
    public void setParameters(Map<String, Object> params) { this.parameters = params; }
    public void setPriority(String priority)               { this.priority = priority; }
    public void setAdminNote(String adminNote)             { this.adminNote = adminNote; }
    public void setIssuedAt(String issuedAt)               { this.issuedAt = issuedAt; }

    /**
     * Convenience method to get a specific parameter value by key.
     * Returns null if the key doesn't exist or parameters is null.
     */
    public Object getParam(String key) {
        if (parameters == null) return null;
        return parameters.get(key);
    }

    /**
     * Convenience method to get a parameter as a String.
     */
    public String getParamString(String key) {
        Object val = getParam(key);
        return val != null ? val.toString() : null;
    }

    @Override
    public String toString() {
        return String.format("Command{id=%d, type='%s', priority='%s'}", id, commandType, priority);
    }
}
