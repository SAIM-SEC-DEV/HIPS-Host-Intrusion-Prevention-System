package com.hips.agent.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Properties;
import java.util.Set;

/**
 * ============================================================
 * HIPS Agent — Configuration Manager
 * ============================================================
 * Manages the agent's persistent configuration file. On first
 * startup, default values are used. After registration, the
 * auth token and agent ID are written to the config file so
 * they survive reboots.
 *
 * Config file location: ./hips-agent.properties
 *
 * Security Note:
 *   The auth token is stored in plaintext in this file.
 *   In production, you would encrypt it using Java's KeyStore
 *   API or a secrets management tool. For this academic project,
 *   file-system permissions are relied upon for protection.
 */
public class AgentConfig {

    // ── Default configuration values ─────────────────────────
    private static final String DEFAULT_SERVER_URL  = "http://localhost/hips";
    private static final int    DEFAULT_HEARTBEAT   = 30;     // seconds
    private static final int    DEFAULT_POLL_INTERVAL = 10;   // seconds

    // Configuration file path — overridable via system property:
    //   java -Dhips.config=/path/to/custom.properties ...
    private static final String DEFAULT_CONFIG_FILE = "hips-agent.properties";
    private final String configFilePath;

    // ── Configuration fields ─────────────────────────────────
    private String serverUrl;
    private String authToken;
    private int    agentId;
    private String agentUuid;
    private int    heartbeatIntervalSec;
    private int    pollIntervalSec;
    private String owner;
    private String baselineStart;
    private boolean baselineComplete;

    // Threat Intel APIs
    private String virusTotalApiKey;
    private String abuseIpDbApiKey;

    // Directories to monitor for file changes
    private String[] watchDirectories;

    // Whitelisted IPs (comma-separated in config)
    private Set<String> whitelistIPs = new java.util.LinkedHashSet<>();

    // Whitelisted Processes
    private String[] processWhitelist = new String[0];

    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    // ── Constructors ─────────────────────────────────────────

    /**
     * Default constructor — uses system property hips.config or
     * falls back to hips-agent.properties in the current directory.
     */
    public AgentConfig() {
        this(System.getProperty("hips.config", DEFAULT_CONFIG_FILE));
    }

    /**
     * Parameterized constructor — allows specifying a custom
     * config file path (useful for testing and multi-instance
     * deployments).
     */
    public AgentConfig(String configFilePath) {
        this.configFilePath = configFilePath;
        loadConfig();
    }

    /**
     * Loads configuration from the properties file on disk.
     * If the file doesn't exist, defaults are used and the
     * agent will need to register before becoming functional.
     */
    private void loadConfig() {
        Properties props = new Properties();
        Path configPath = Paths.get(configFilePath);

        if (Files.exists(configPath)) {
            try (InputStream in = Files.newInputStream(configPath)) {
                props.load(in);
                System.out.println("[HIPS] Configuration loaded from " + configPath.toAbsolutePath());
            } catch (IOException e) {
                System.err.println("[HIPS] Failed to read config file: " + e.getMessage());
            }
        } else {
            System.out.println("[HIPS] No config file found. Using default values.");
        }

        // ── Parse properties with safe defaults ──────────────
        this.serverUrl           = props.getProperty("server.url", DEFAULT_SERVER_URL);
        this.authToken           = props.getProperty("auth.token", "");
        try {
            this.agentId         = Integer.parseInt(props.getProperty("agent.id", "0"));
        } catch (NumberFormatException e) {
            System.err.println("[HIPS] Invalid agent.id in config, defaulting to 0.");
            this.agentId = 0;
        }
        this.agentUuid           = props.getProperty("agent.uuid", "");
        try {
            this.heartbeatIntervalSec = Integer.parseInt(props.getProperty("heartbeat.interval", String.valueOf(DEFAULT_HEARTBEAT)));
        } catch (NumberFormatException e) {
            System.err.println("[HIPS] Invalid heartbeat.interval, defaulting to " + DEFAULT_HEARTBEAT);
            this.heartbeatIntervalSec = DEFAULT_HEARTBEAT;
        }
        try {
            this.pollIntervalSec     = Integer.parseInt(props.getProperty("poll.interval", String.valueOf(DEFAULT_POLL_INTERVAL)));
        } catch (NumberFormatException e) {
            System.err.println("[HIPS] Invalid poll.interval, defaulting to " + DEFAULT_POLL_INTERVAL);
            this.pollIntervalSec = DEFAULT_POLL_INTERVAL;
        }
        this.owner               = props.getProperty("agent.owner", System.getProperty("user.name", "Unknown"));
        this.baselineStart       = props.getProperty("baseline.start", "");
        this.baselineComplete    = Boolean.parseBoolean(props.getProperty("baseline.complete", "false"));

        this.virusTotalApiKey = props.getProperty("virustotal.api.key", "");
        this.abuseIpDbApiKey = props.getProperty("abuseipdb.api.key", "");

        // Parse monitored directories (comma-separated)
        String dirs = props.getProperty("watch.directories",
            "C:\\Windows\\System32,C:\\Users\\" + System.getProperty("user.name") + "\\Desktop");
        this.watchDirectories = dirs.split(",");

        // Parse whitelisted IPs (comma-separated)
        String wlIps = props.getProperty("whitelist.ips", "").trim();
        this.whitelistIPs = new java.util.LinkedHashSet<>();
        if (!wlIps.isEmpty()) {
            for (String ip : wlIps.split(",")) {
                String trimmed = ip.trim();
                if (!trimmed.isEmpty()) whitelistIPs.add(trimmed);
            }
        }

        // Parse whitelisted processes
        String wlProcs = props.getProperty("process.whitelist", "");
        this.processWhitelist = wlProcs.split(",");
    }

    /**
     * Persists the current configuration to the properties file.
     * Called after successful registration to save the auth token
     * and agent ID for future startups.
     */
    public void saveConfig() {
        Properties props = new Properties();
        props.setProperty("server.url",          serverUrl);
        props.setProperty("auth.token",          authToken);
        props.setProperty("agent.id",            String.valueOf(agentId));
        props.setProperty("agent.uuid",          agentUuid);
        props.setProperty("heartbeat.interval",  String.valueOf(heartbeatIntervalSec));
        props.setProperty("poll.interval",       String.valueOf(pollIntervalSec));
        props.setProperty("agent.owner",         owner);
        props.setProperty("baseline.start",      baselineStart);
        props.setProperty("baseline.complete",   String.valueOf(baselineComplete));
        props.setProperty("virustotal.api.key",  virusTotalApiKey != null ? virusTotalApiKey : "");
        props.setProperty("abuseipdb.api.key",   abuseIpDbApiKey != null ? abuseIpDbApiKey : "");
        props.setProperty("watch.directories",   String.join(",", watchDirectories));
        props.setProperty("whitelist.ips",        String.join(",", whitelistIPs));
        props.setProperty("process.whitelist",    String.join(",", processWhitelist));

        try (OutputStream out = Files.newOutputStream(Paths.get(configFilePath))) {
            props.store(out, "HIPS Agent Configuration — Auto-generated. Do not edit manually.");
            System.out.println("[HIPS] Configuration saved to " + Paths.get(configFilePath).toAbsolutePath());
        } catch (IOException e) {
            System.err.println("[HIPS] Failed to save config: " + e.getMessage());
        }
    }

    /**
     * Checks if the agent has already been registered with the
     * server (i.e., has a valid auth token and agent ID).
     */
    public boolean isRegistered() {
        return authToken != null && !authToken.isEmpty() && agentId > 0;
    }

    // ── Getters and Setters ──────────────────────────────────

    public String   getServerUrl()            { return serverUrl; }
    public String   getAuthToken()            { return authToken; }
    public int      getAgentId()              { return agentId; }
    public String   getAgentUuid()            { return agentUuid; }
    public int      getHeartbeatIntervalSec() { return heartbeatIntervalSec; }
    public int      getPollIntervalSec()      { return pollIntervalSec; }
    public String   getOwner()                { return owner; }
    public String   getBaselineStart()        { return baselineStart; }
    public boolean  isBaselineComplete()      { return baselineComplete; }
    public String[] getWatchDirectories()     { return watchDirectories; }
    public String[] getProcessWhitelist()     { return processWhitelist; }
    public String   getVirusTotalApiKey()     { return virusTotalApiKey; }
    public String   getAbuseIpDbApiKey()      { return abuseIpDbApiKey; }

    public void setServerUrl(String url)                { this.serverUrl = url; }
    public void setAuthToken(String token)              { this.authToken = token; }
    public void setAgentId(int id)                      { this.agentId = id; }
    public void setAgentUuid(String uuid)               { this.agentUuid = uuid; }
    public void setHeartbeatIntervalSec(int sec)        { this.heartbeatIntervalSec = sec; }
    public void setPollIntervalSec(int sec)             { this.pollIntervalSec = sec; }
    public void setOwner(String owner)                  { this.owner = owner; }
    public void setBaselineStart(String start)          { this.baselineStart = start; }
    public void setBaselineComplete(boolean complete)    { this.baselineComplete = complete; }
    public void setWatchDirectories(String[] dirs)      { this.watchDirectories = dirs; }
    public void setProcessWhitelist(String[] procs)     { this.processWhitelist = procs; }

    // Whitelist IP management
    public Set<String> getWhitelistIPs()                 { return whitelistIPs; }
    public void addWhitelistIP(String ip)                { whitelistIPs.add(ip); }
    public void removeWhitelistIP(String ip)             { whitelistIPs.remove(ip); }

    /** Returns the full API URL for a given endpoint path */
    public String apiUrl(String endpoint) {
        String base = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";
        return base + "api/" + endpoint;
    }
}
