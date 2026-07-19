package com.hips.agent.mitre;

import com.hips.agent.model.Event;

import java.util.HashMap;
import java.util.Map;

/**
 * ============================================================
 * HIPS Agent — MITRE ATT&CK Mapper
 * ============================================================
 * Maps HIPS events to corresponding MITRE ATT&CK techniques.
 * Used to enrich alerts with industry-standard threat taxonomy
 * before sending to the server.
 */
public class MitreMapper {

    private static final Map<String, MitreAttack> MAPPINGS = new HashMap<>();

    static {
        // ── File Events ──────────────────────────────────────────
        MAPPINGS.put("FILE_CREATED", new MitreAttack("T1204.002", "User Execution: Malicious File", "Execution"));
        MAPPINGS.put("FILE_MODIFIED", new MitreAttack("T1565.001", "Stored Data Manipulation", "Impact"));
        MAPPINGS.put("FILE_DELETED", new MitreAttack("T1485", "Data Destruction", "Impact"));
        MAPPINGS.put("HASH_MISMATCH", new MitreAttack("T1036", "Masquerading", "Defense Evasion"));

        // ── Network Events ───────────────────────────────────────
        MAPPINGS.put("BLACKLISTED_IP", new MitreAttack("T1071.001", "Application Layer Protocol", "Command & Control"));
        MAPPINGS.put("BEACONING_DETECTED", new MitreAttack("T1571", "Non-Standard Port", "Command & Control"));
        MAPPINGS.put("CONNECTION_SPIKE", new MitreAttack("T1498", "Network Denial of Service", "Impact"));
        MAPPINGS.put("PORT_SCAN", new MitreAttack("T1046", "Network Service Scanning", "Discovery"));
        MAPPINGS.put("DNS_TUNNEL", new MitreAttack("T1572", "Protocol Tunneling", "Command & Control"));

        // ── Process Events ───────────────────────────────────────
        MAPPINGS.put("PROCESS_SUSPICIOUS_PARENT", new MitreAttack("T1055", "Process Injection", "Defense Evasion"));
        MAPPINGS.put("PROCESS_NEW_SERVICE", new MitreAttack("T1543.003", "Create/Modify System Service", "Persistence"));
        MAPPINGS.put("PROCESS_SUSPICIOUS_EXEC", new MitreAttack("T1059", "Command and Scripting Interpreter", "Execution"));

        // ── Registry Events ──────────────────────────────────────
        MAPPINGS.put("REGISTRY_RUN_KEY_MODIFIED", new MitreAttack("T1547.001", "Registry Run Keys / Startup Folder", "Persistence"));
        MAPPINGS.put("REGISTRY_SERVICE_MODIFIED", new MitreAttack("T1543.003", "Create/Modify System Service", "Persistence"));
        MAPPINGS.put("REGISTRY_FIREWALL_MODIFIED", new MitreAttack("T1562.004", "Disable/Modify System Firewall", "Defense Evasion"));
    }

    /**
     * Enriches the given Event with MITRE ATT&CK information if a mapping exists.
     * @param event The event to enrich. Modifies the event in place.
     */
    public static void enrichEvent(Event event) {
        if (event == null || event.getEventType() == null) return;
        
        MitreAttack attack = MAPPINGS.get(event.getEventType().toUpperCase());
        if (attack != null) {
            event.withMitre(attack.getTechniqueId(), attack.getTactic());
        }
    }
}
