package com.hips.agent.network;

import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ============================================================
 * HIPS Agent — DNS Monitor (Refactored v1.1)
 * ============================================================
 *
 * FIXES APPLIED:
 *   - FIX 2.4 (Memory Leak): domainQueryCounts and
 *     alreadyAlertedDomains are now capped at 5,000 entries
 *     using a bounded LinkedHashMap (LRU eviction policy).
 *     Eliminates OutOfMemoryError from unbounded domain growth.
 *
 *   - FIX (Alert Noise): DNS query list is de-duplicated per
 *     scan cycle using a HashSet before rate calculation,
 *     preventing the tunneling counter from double-counting
 *     cached responses.
 */
public class DnsMonitor {

    private final NetworkAlertHandler alertHandler;

    // ── FIX 2.4: Bounded LRU cache for domain query counts ───
    // Max 5000 entries; oldest evicted when full.
    private static final int MAX_DOMAIN_ENTRIES = 5000;

    private final Map<String, Integer> domainQueryCounts = Collections.synchronizedMap(
        new LinkedHashMap<String, Integer>(256, 0.75f, true) { // accessOrder=true for LRU
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Integer> eldest) {
                return size() > MAX_DOMAIN_ENTRIES;
            }
        }
    );

    // ── FIX 2.4: Bounded set for alerted domains (LRU) ───────
    private final Set<String> alreadyAlertedDomains = Collections.synchronizedSet(
        Collections.newSetFromMap(
            new LinkedHashMap<String, Boolean>(256, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
                    return size() > MAX_DOMAIN_ENTRIES;
                }
            }
        )
    );

    // Rate history — fixed circular buffer
    private final ArrayDeque<Integer> queryRateHistory = new ArrayDeque<>(35);
    private static final int    HISTORY_SIZE        = 30;
    private static final int    TUNNELING_THRESHOLD = 100;

    private final Map<String, Long> queryCache = 
        new LinkedHashMap<String, Long>(256, 0.75f, true) { // accessOrder=true for LRU
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
                return size() > 256;
            }
        };

    private final Map<String, Integer> domainFrequency = 
        new LinkedHashMap<String, Integer>(256, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Integer> eldest) {
                return size() > 256;
            }
        };

    private static final Set<String> SUSPICIOUS_TLDS = new HashSet<>(Arrays.asList(
        ".xyz", ".top", ".pw", ".bid", ".loan", ".men", ".stream", ".win", ".icu", ".monster", ".gdn", ".click", ".link"
    ));

    // Cooldown for tunneling alerts (5 minutes)
    private static final long TUNNELING_COOLDOWN_MS = 5 * 60 * 1000L;
    private long lastTunnelingAlertTime = 0;

    public DnsMonitor(NetworkAlertHandler alertHandler) {
        this.alertHandler = alertHandler;
    }

    // ── Function 1: monitorDNSQueries() ──────────────────────
    public void monitorDNSQueries() {
        try {
            ProcessBuilder pb = new ProcessBuilder("ipconfig", "/displaydns");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            // FIX: Use a Set to de-duplicate domains per cycle.
            // ipconfig /displaydns returns every cached record, which
            // can list the same domain multiple times (A + AAAA records).
            Set<String> uniqueDomains = new LinkedHashSet<>();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("Record Name") || line.startsWith("Nombre de registro")) {
                        String[] parts = line.split(":", 2);
                        if (parts.length == 2) {
                            String domain = parts[1].trim().toLowerCase();
                            uniqueDomains.add(domain);
                            domainQueryCounts.merge(domain, 1, Integer::sum);
                        }
                    }
                }
            }
            process.waitFor();

            // Record unique domain count per cycle (de-duplicated)
            queryRateHistory.addLast(uniqueDomains.size());
            if (queryRateHistory.size() > HISTORY_SIZE) {
                queryRateHistory.removeFirst();
            }

            // Check for suspicious TLDs
            for (String domain : uniqueDomains) {
                if (alreadyAlertedDomains.contains(domain)) continue;

                for (String tld : SUSPICIOUS_TLDS) {
                    if (domain.endsWith(tld)) {
                        alreadyAlertedDomains.add(domain);
                        int count = domainQueryCounts.getOrDefault(domain, 1);
                        Map<String, Object> metadata = new HashMap<>();
                        metadata.put("domain", domain);
                        metadata.put("tld", tld);
                        metadata.put("query_type", "A");
                        metadata.put("is_suspicious_tld", true);
                        metadata.put("frequency", count);

                        Event event = new Event(Module.network, "SUSPICIOUS_DNS_TLD", Severity.MEDIUM, "Suspicious DNS TLD")
                                .withDescription("Local process queried a domain with a suspicious TLD: " + domain)
                                .withDestination(domain)
                                .withMetadata(metadata);
                        alertHandler.logNetworkEvent(event);
                        break;
                    }
                }
            }

            detectDNSTunneling();

        } catch (Exception e) {
            System.err.println("[HIPS-DNS] DNS monitoring failed: " + e.getMessage());
        }
    }

    // ── Function 2: detectDNSTunneling() ─────────────────────
    public void detectDNSTunneling() {
        if (queryRateHistory.isEmpty()) return;

        long now = System.currentTimeMillis();
        if ((now - lastTunnelingAlertTime) < TUNNELING_COOLDOWN_MS) return;

        int latestCount = queryRateHistory.peekLast();
        if (latestCount <= TUNNELING_THRESHOLD) return;

        lastTunnelingAlertTime = now;

        double average = queryRateHistory.stream().mapToInt(Integer::intValue).average().orElse(0);

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("current_query_count", latestCount);
        metadata.put("average_query_count", Math.round(average * 10.0) / 10.0);
        metadata.put("threshold", TUNNELING_THRESHOLD);
        metadata.put("unique_domains_total", domainQueryCounts.size());

        Event event = new Event(Module.network, "DNS_TUNNELING", Severity.HIGH,
                "Possible DNS tunneling detected")
                .withDescription(String.format(
                    "DNS query rate spiked to %d unique queries (avg: %.1f, threshold: %d). " +
                    "This volume suggests data may be being exfiltrated via DNS " +
                    "query/response encoding (DNS tunneling).",
                    latestCount, average, TUNNELING_THRESHOLD))
                .withMetadata(metadata);

        alertHandler.triggerNetworkAlert(event);
    }

    // ── Accessors ─────────────────────────────────────────────
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
