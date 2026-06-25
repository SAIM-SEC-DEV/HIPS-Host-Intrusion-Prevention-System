package com.hips.agent.model;

import com.google.gson.annotations.SerializedName;
import java.time.LocalDateTime;

/**
 * ============================================================
 * HIPS Agent — Event Model
 * ============================================================
 * Represents a single security event detected by the file or
 * network monitoring module. This object is serialized to JSON
 * and POSTed to /api/report.php.
 */
public class Event {

    /**
     * Severity levels matching the server's ENUM values.
     * CRITICAL = system-level threats (file tampering, SYN flood)
     * HIGH     = significant threats (blacklisted IP, off-hours)
     * MEDIUM   = notable anomalies (traffic spike, unknown IP)
     * LOW      = informational events (long connection, config access)
     */
    public enum Severity { CRITICAL, HIGH, MEDIUM, LOW }

    /** Which monitoring module generated this event */
    public enum Module { file, network, process, registry }

    private Module module;

    @SerializedName("event_type")
    private String eventType;

    private Severity severity;
    private String title;
    private String description;

    @SerializedName("source_path")
    private String sourcePath;

    private String destination;

    @SerializedName("hash_value")
    private String hashValue;

    private Object metadata;

    @SerializedName("is_anomaly")
    private boolean isAnomaly;

    @SerializedName("mitre_technique_id")
    private String mitreTechniqueId;

    @SerializedName("mitre_tactic")
    private String mitreTactic;

    // Local timestamp (not sent to server; server uses its own clock)
    private transient LocalDateTime detectedAt;

    // ── Constructors ─────────────────────────────────────────

    public Event() {
        this.detectedAt = LocalDateTime.now();
    }

    public Event(Module module, String eventType, Severity severity, String title) {
        this();
        this.module    = module;
        this.eventType = eventType;
        this.severity  = severity;
        this.title     = title;
    }

    // ── Builder-style setters for fluent API usage ───────────
    // Example: new Event(FILE, "FILE_MODIFIED", HIGH, "System file changed")
    //            .withDescription("...")
    //            .withSourcePath("C:\\Windows\\...")
    //            .withHash("abc123...");

    public Event withDescription(String description) {
        this.description = description;
        return this;
    }

    public Event withSourcePath(String sourcePath) {
        this.sourcePath = sourcePath;
        return this;
    }

    public Event withDestination(String destination) {
        this.destination = destination;
        return this;
    }

    public Event withHash(String hashValue) {
        this.hashValue = hashValue;
        return this;
    }

    public Event withMetadata(Object metadata) {
        this.metadata = metadata;
        return this;
    }

    public Event withAnomaly(boolean isAnomaly) {
        this.isAnomaly = isAnomaly;
        return this;
    }

    public Event withMitre(String techniqueId, String tactic) {
        this.mitreTechniqueId = techniqueId;
        this.mitreTactic = tactic;
        return this;
    }

    // ── Standard Getters and Setters ─────────────────────────

    public Module    getModule()      { return module; }
    public String    getEventType()   { return eventType; }
    public Severity  getSeverity()    { return severity; }
    public String    getTitle()       { return title; }
    public String    getDescription() { return description; }
    public String    getSourcePath()  { return sourcePath; }
    public String    getDestination() { return destination; }
    public String    getHashValue()   { return hashValue; }
    public Object    getMetadata()    { return metadata; }
    public boolean   isAnomaly()      { return isAnomaly; }
    public String    getMitreTechniqueId() { return mitreTechniqueId; }
    public String    getMitreTactic()      { return mitreTactic; }
    public LocalDateTime getDetectedAt() { return detectedAt; }

    public void setModule(Module module)           { this.module = module; }
    public void setEventType(String eventType)     { this.eventType = eventType; }
    public void setSeverity(Severity severity)     { this.severity = severity; }
    public void setTitle(String title)             { this.title = title; }
    public void setDescription(String description) { this.description = description; }
    public void setSourcePath(String sourcePath)   { this.sourcePath = sourcePath; }
    public void setDestination(String destination) { this.destination = destination; }
    public void setHashValue(String hashValue)     { this.hashValue = hashValue; }
    public void setMetadata(Object metadata)       { this.metadata = metadata; }
    public void setAnomaly(boolean anomaly)        { this.isAnomaly = anomaly; }
    public void setMitreTechniqueId(String id)     { this.mitreTechniqueId = id; }
    public void setMitreTactic(String tactic)      { this.mitreTactic = tactic; }

    @Override
    public String toString() {
        return String.format("[%s] %s | %s — %s", severity, module, eventType, title);
    }
}
