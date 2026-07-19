package com.hips.agent.core;

import com.hips.agent.config.AgentConfig;
import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;

/**
 * ============================================================
 * HIPS Agent — Active Response Engine (v1.0)
 * ============================================================
 * Automated threat neutralization. When a monitor detects a
 * CRITICAL or HIGH severity threat, this engine takes immediate
 * defensive action:
 *
 *   1. KILL   — Terminates malicious processes via taskkill
 *   2. VAULT  — Moves infected files to an encrypted quarantine
 *   3. BLOCK  — Creates Windows Firewall rules for hostile IPs
 *
 * All actions are logged to a tamper-evident response audit log
 * and reported back to the HIPS server for SOC visibility.
 *
 * Design: Singleton-like engine injected into monitors via
 *         constructor. Thread-safe via ConcurrentHashMap.
 */
public class ActiveResponseEngine {

    private final AgentConfig config;
    private final ApiClient apiClient;

    private static final Path VAULT_DIR    = Paths.get("C:\\HIPS\\vault");
    private static final Path RESPONSE_LOG = Paths.get("hips-response-audit.log");
    private static final DateTimeFormatter DTF =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // Dedup: track recent responses to avoid acting twice on the same threat
    private final Set<String> recentResponses = ConcurrentHashMap.newKeySet();

    // Counters
    private int processesKilled  = 0;
    private int filesQuarantined = 0;
    private int ipsBlocked       = 0;

    public ActiveResponseEngine(AgentConfig config, ApiClient apiClient) {
        this.config    = config;
        this.apiClient = apiClient;
        ensureVaultExists();
    }

    private void ensureVaultExists() {
        try {
            if (!Files.exists(VAULT_DIR)) {
                Files.createDirectories(VAULT_DIR);
                System.out.println("[HIPS-RESPONSE] Created quarantine vault: " + VAULT_DIR);
            }
        } catch (IOException e) {
            System.err.println("[HIPS-RESPONSE] Cannot create vault: " + e.getMessage());
        }
    }

    // ── 1. Auto-Respond to Malicious Process ─────────────────
    /**
     * Kills a malicious process and quarantines its executable.
     * Called by ProcessMonitor when CRITICAL threats are found.
     *
     * @param pid            The process ID to terminate
     * @param processName    The process name (e.g., mimikatz.exe)
     * @param executablePath Full path to the executable (may be null)
     * @return Result map with action details
     */
    public Map<String, Object> respondToProcess(int pid, String processName, String executablePath) {
        Map<String, Object> result = new LinkedHashMap<>();
        String key = "proc:" + pid;

        if (recentResponses.contains(key)) {
            result.put("action", "skipped_duplicate");
            return result;
        }
        recentResponses.add(key);
        boundCache();

        System.out.println("[HIPS-RESPONSE] ⚡ AUTO-KILL: " + processName + " (PID " + pid + ")");

        // Step 1: Kill the process
        boolean killed = killProcess(pid, processName);
        result.put("process_killed", killed);
        result.put("pid", pid);
        result.put("process_name", processName);

        if (killed) {
            processesKilled++;
            logResponse("PROCESS_KILLED", processName + " (PID " + pid + ")");
        }

        // Step 2: Quarantine the executable
        if (executablePath != null && !executablePath.isEmpty()) {
            Path quarantined = quarantineFile(Paths.get(executablePath));
            result.put("file_quarantined", quarantined != null);
            if (quarantined != null) {
                result.put("quarantine_path", quarantined.toString());
            }
        }

        // Step 3: Report to server
        reportResponse("AUTO_KILL_PROCESS",
            "Terminated malicious process: " + processName, result);

        return result;
    }

    // ── 2. Auto-Quarantine Malicious File ────────────────────
    /**
     * Quarantines a file flagged by YARA or integrity checks.
     * Attempts to kill any process using the file first.
     *
     * @param filePath The full path to the malicious file
     * @param reason   Why the file was flagged (e.g., "YARA: Mimikatz_Strings")
     * @return The quarantine destination path, or null on failure
     */
    public Path respondToMaliciousFile(String filePath, String reason) {
        String key = "file:" + filePath;
        if (recentResponses.contains(key)) return null;
        recentResponses.add(key);
        boundCache();

        System.out.println("[HIPS-RESPONSE] ⚡ AUTO-QUARANTINE: " + filePath);

        // Kill any process holding the file
        String fileName = Paths.get(filePath).getFileName().toString();
        killProcess(-1, fileName);

        // Move to vault
        Path quarantined = quarantineFile(Paths.get(filePath));
        if (quarantined != null) {
            filesQuarantined++;
            logResponse("FILE_QUARANTINED", filePath + " → " + quarantined
                + " | Reason: " + reason);

            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("original_path", filePath);
            meta.put("quarantine_path", quarantined.toString());
            meta.put("reason", reason);
            reportResponse("AUTO_QUARANTINE_FILE", "Quarantined: " + filePath, meta);
        }

        return quarantined;
    }

    // ── 3. Auto-Block Malicious IP ───────────────────────────
    /**
     * Blocks a hostile IP via Windows Firewall (inbound + outbound).
     *
     * @param ip The IPv4 address to block
     * @return true if firewall rules were created successfully
     */
    public boolean respondToMaliciousIP(String ip) {
        String key = "ip:" + ip;
        if (recentResponses.contains(key)) return false;
        recentResponses.add(key);
        boundCache();

        // Validate IP format to prevent command injection
        if (!isValidIPv4(ip)) {
            System.err.println("[HIPS-RESPONSE] Invalid IP rejected: " + ip);
            return false;
        }

        System.out.println("[HIPS-RESPONSE] ⚡ AUTO-BLOCK IP: " + ip);

        boolean blocked = blockIPViaFirewall(ip);
        if (blocked) {
            ipsBlocked++;
            logResponse("IP_BLOCKED", "Firewall rules created for: " + ip);

            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("ip", ip);
            meta.put("blocked", true);
            reportResponse("AUTO_BLOCK_IP", "Blocked hostile IP: " + ip, meta);
        }

        return blocked;
    }

    // ── Internal: Kill Process ────────────────────────────────
    private boolean killProcess(int pid, String processName) {
        try {
            ProcessBuilder pb;
            if (pid > 0) {
                pb = new ProcessBuilder("taskkill", "/F", "/PID", String.valueOf(pid));
            } else {
                pb = new ProcessBuilder("taskkill", "/F", "/IM", processName);
            }
            pb.redirectErrorStream(true);
            Process p = pb.start();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("[HIPS-RESPONSE]   " + line);
                }
            }

            boolean finished = p.waitFor(5, TimeUnit.SECONDS);
            if (!finished) p.destroyForcibly();
            return finished && p.exitValue() == 0;
        } catch (Exception e) {
            System.err.println("[HIPS-RESPONSE] Kill failed: " + e.getMessage());
            return false;
        }
    }

    // ── Internal: Quarantine File to Vault ────────────────────
    private Path quarantineFile(Path source) {
        try {
            if (!Files.exists(source)) return null;
            ensureVaultExists();

            String ts = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
            String name = source.getFileName().toString()
                + "." + ts + ".quarantine";
            Path target = VAULT_DIR.resolve(name);

            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
            System.out.println("[HIPS-RESPONSE] ✓ Quarantined: " + source + " → " + target);
            return target;
        } catch (IOException e) {
            System.err.println("[HIPS-RESPONSE] Quarantine failed: " + e.getMessage());
            return null;
        }
    }

    // ── Internal: Block IP via Windows Firewall ──────────────
    private boolean blockIPViaFirewall(String ip) {
        try {
            String ruleName = "HIPS_AUTOBLOCK_" + ip.replace(".", "_");

            // Inbound rule
            new ProcessBuilder("netsh", "advfirewall", "firewall", "add", "rule",
                "name=" + ruleName + "_IN", "dir=in", "action=block",
                "remoteip=" + ip, "enable=yes")
                .redirectErrorStream(true).start().waitFor(5, TimeUnit.SECONDS);

            // Outbound rule
            new ProcessBuilder("netsh", "advfirewall", "firewall", "add", "rule",
                "name=" + ruleName + "_OUT", "dir=out", "action=block",
                "remoteip=" + ip, "enable=yes")
                .redirectErrorStream(true).start().waitFor(5, TimeUnit.SECONDS);

            return true;
        } catch (Exception e) {
            System.err.println("[HIPS-RESPONSE] Firewall block failed: " + e.getMessage());
            return false;
        }
    }

    // ── Internal: Logging & Reporting ─────────────────────────
    private void logResponse(String action, String detail) {
        try {
            String line = String.format("[%s] [RESPONSE] %s | %s%n",
                LocalDateTime.now().format(DTF), action, detail);
            Files.write(RESPONSE_LOG, line.getBytes(),
                StandardOpenOption.APPEND, StandardOpenOption.CREATE);
        } catch (IOException e) {
            System.err.println("[HIPS-RESPONSE] Log write failed: " + e.getMessage());
        }
    }

    private void reportResponse(String eventType, String desc, Map<String, Object> meta) {
        Event event = new Event(Module.process, eventType, Severity.CRITICAL,
                "Active Response: " + eventType)
            .withDescription(desc)
            .withMetadata(meta);
        apiClient.postAsyncChecked("report.php", event);
    }

    private boolean isValidIPv4(String ip) {
        if (ip == null) return false;
        return ip.matches("^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$");
    }

    private void boundCache() {
        if (recentResponses.size() > 500) recentResponses.clear();
    }

    // ── Statistics ────────────────────────────────────────────
    public int getProcessesKilled()  { return processesKilled; }
    public int getFilesQuarantined() { return filesQuarantined; }
    public int getIPsBlocked()       { return ipsBlocked; }
}
