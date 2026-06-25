package com.hips.agent.network;

import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ============================================================
 * HIPS Agent — DNS Monitor
 * ============================================================
 * Monitors DNS queries made by the host to detect tunneling,
 * DGA (Domain Generation Algorithm) domains, and other
 * DNS-based threats.
 *
 * Uses Windows DNS cache (ipconfig /displaydns) for collection
 * since Java doesn't directly intercept DNS traffic.
 *
 * Functions (2 of 32):
 *   monitorDNSQueries()   — Watches all DNS lookups made by host
 *   detectDNSTunneling()  — Flags abnormally high DNS query rates
 */
public class DnsMonitor {

    private final NetworkAlertHandler alertHandler;

    // Track DNS query counts per minute for rate analysis
    private final List<Integer> queryRateHistory = new ArrayList<>();
    private static final int HISTORY_SIZE = 30;

    // DNS tunneling threshold — more than 100 unique queries/minute is suspicious
    private static final int TUNNELING_THRESHOLD = 100;

    // Track unique domains seen to detect DGA patterns
    private final Map<String, Integer> domainQueryCounts = new ConcurrentHashMap<>();

    // Suspicious TLDs often associated with malware
    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
        ".tk", ".pw", ".cc", ".su", ".top", ".xyz", ".loan",
        ".work", ".click", ".gdn", ".bid", ".win", ".racing"
    );

    public DnsMonitor(NetworkAlertHandler alertHandler) {
        this.alertHandler = alertHandler;
    }

    // Deduplication: track domains already alerted to avoid spamming
    private final Set<String> alreadyAlertedDomains = ConcurrentHashMap.newKeySet();

    // Cooldown for DNS tunneling alerts (5 minutes)
    private static final long TUNNELING_COOLDOWN_MS = 5 * 60 * 1000;
    private long lastTunnelingAlertTime = 0;

    // ── Function 1: monitorDNSQueries() ──────────────────────
    /**
     * Captures current DNS cache entries from the Windows DNS
     * resolver cache. Analyzes query patterns for anomalies
     * including suspicious TLDs and high query rates.
     */
    public void monitorDNSQueries() {
        try {
            // Get DNS cache from Windows
            ProcessBuilder pb = new ProcessBuilder("ipconfig", "/displaydns");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            List<String> domains = new ArrayList<>();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    // Look for "Record Name" lines which contain queried domains
                    if (line.startsWith("Record Name") || line.startsWith("Nombre de registro")) {
                        String[] parts = line.split(":", 2);
                        if (parts.length == 2) {
                            String domain = parts[1].trim().toLowerCase();
                            domains.add(domain);
                            domainQueryCounts.merge(domain, 1, Integer::sum);
                        }
                    }
                }
            }

            process.waitFor();

            // Record query rate
            queryRateHistory.add(domains.size());
            if (queryRateHistory.size() > HISTORY_SIZE) {
                queryRateHistory.remove(0);
            }

            // Check for suspicious TLDs (with deduplication)
            for (String domain : domains) {
                // Skip domains we've already alerted on
                if (alreadyAlertedDomains.contains(domain)) continue;

                for (String tld : SUSPICIOUS_TLDS) {
                    if (domain.endsWith(tld)) {
                        alreadyAlertedDomains.add(domain);
                        Event event = new Event(Module.network, "SUSPICIOUS_DNS", Severity.MEDIUM,
                                "DNS query to suspicious domain: " + domain)
                                .withDescription("DNS query for domain '" + domain +
                                    "' uses a TLD (" + tld + ") commonly associated with " +
                                    "malicious activity including phishing and malware C2.")
                                .withDestination(domain)
                                .withMetadata(Map.of(
                                    "domain", domain,
                                    "tld", tld,
                                    "query_count", domainQueryCounts.getOrDefault(domain, 1)
                                ));

                        alertHandler.logNetworkEvent(event);
                        break;
                    }
                }
            }

            // Check for DNS tunneling
            detectDNSTunneling();

        } catch (Exception e) {
            System.err.println("[HIPS-DNS] DNS monitoring failed: " + e.getMessage());
        }
    }

    // ── Function 2: detectDNSTunneling() ─────────────────────
    /**
     * Detects DNS tunneling by checking if the query rate exceeds
     * the normal threshold. DNS tunneling encodes data in DNS
     * queries/responses to bypass firewalls — it generates an
     * abnormally high volume of unique DNS lookups.
     *
     * Detection: > 100 unique queries in a single scan cycle
     * is flagged as potential tunneling.
     */
    public void detectDNSTunneling() {
        if (queryRateHistory.isEmpty()) return;

        // Cooldown: skip if we recently alerted
        long now = System.currentTimeMillis();
        if ((now - lastTunnelingAlertTime) < TUNNELING_COOLDOWN_MS) return;

        int latestCount = queryRateHistory.get(queryRateHistory.size() - 1);

        if (latestCount > TUNNELING_THRESHOLD) {
            lastTunnelingAlertTime = now;

            // Calculate average for context
            double average = queryRateHistory.stream()
                    .mapToInt(Integer::intValue)
                    .average()
                    .orElse(0);

            Event event = new Event(Module.network, "DNS_TUNNELING", Severity.HIGH,
                    "Possible DNS tunneling detected")
                    .withDescription(String.format(
                        "DNS query rate spiked to %d queries (avg: %.1f, threshold: %d). " +
                        "This volume suggests data may be being exfiltrated via DNS " +
                        "query/response encoding (DNS tunneling).",
                        latestCount, average, TUNNELING_THRESHOLD))
                    .withMetadata(Map.of(
                        "current_query_count", latestCount,
                        "average_query_count", Math.round(average * 10.0) / 10.0,
                        "threshold", TUNNELING_THRESHOLD,
                        "unique_domains_total", domainQueryCounts.size()
                    ));

            alertHandler.triggerNetworkAlert(event);
        }
    }

    // ── Accessors ────────────────────────────────────────────

    public int getUniqueDomainCount() {
        return domainQueryCounts.size();
    }

    public Map<String, Integer> getTopQueriedDomains(int limit) {
        return domainQueryCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(limit)
                .collect(java.util.stream.Collectors.toMap(
                    Map.Entry::getKey, Map.Entry::getValue,
                    (a, b) -> a, LinkedHashMap::new));
    }
}
