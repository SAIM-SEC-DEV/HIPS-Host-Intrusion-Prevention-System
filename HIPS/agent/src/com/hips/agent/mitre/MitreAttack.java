package com.hips.agent.mitre;

/**
 * Data model representing a MITRE ATT&CK technique and its corresponding tactic.
 */
public class MitreAttack {
    private final String techniqueId;
    private final String techniqueName;
    private final String tactic;

    public MitreAttack(String techniqueId, String techniqueName, String tactic) {
        this.techniqueId = techniqueId;
        this.techniqueName = techniqueName;
        this.tactic = tactic;
    }

    public String getTechniqueId() {
        return techniqueId;
    }

    public String getTechniqueName() {
        return techniqueName;
    }

    public String getTactic() {
        return tactic;
    }

    @Override
    public String toString() {
        return String.format("%s (%s) - %s", techniqueId, techniqueName, tactic);
    }
}
