package com.hips.agent.intel;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.hips.agent.config.AgentConfig;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * ============================================================
 * HIPS Agent — Threat Intelligence Service
 * ============================================================
 * Integrates with external APIs (VirusTotal, AbuseIPDB) to
 * enrich events with reputation scores.
 */
public class ThreatIntelService {

    private final AgentConfig config;
    private final HttpClient httpClient;
    private final ThreatIntelCache cache;
    private final Gson gson = new Gson();

    public ThreatIntelService(AgentConfig config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        // 24-hour cache TTL
        this.cache = new ThreatIntelCache(24 * 60 * 60 * 1000L);
    }

    /**
     * Checks a file hash against VirusTotal.
     * @return Number of security vendors that flagged it as malicious.
     *         0 if benign, -1 if error or API key missing.
     */
    public int checkFileHash(String sha256) {
        String apiKey = config.getVirusTotalApiKey();
        if (apiKey == null || apiKey.isEmpty()) return -1;

        Object cached = cache.get("vt_" + sha256);
        if (cached != null) return (int) cached;

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://www.virustotal.com/api/v3/files/" + sha256))
                    .header("x-apikey", apiKey)
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonObject root = JsonParser.parseString(response.body()).getAsJsonObject();
                JsonObject stats = root.getAsJsonObject("data").getAsJsonObject("attributes").getAsJsonObject("last_analysis_stats");
                int maliciousCount = stats.get("malicious").getAsInt();
                
                cache.put("vt_" + sha256, maliciousCount);
                return maliciousCount;
            } else if (response.statusCode() == 404) {
                // Not found in VT database = no detections known
                cache.put("vt_" + sha256, 0);
                return 0;
            } else {
                System.err.println("[ThreatIntel] VirusTotal query failed. Code: " + response.statusCode());
                return -1;
            }
        } catch (Exception e) {
            System.err.println("[ThreatIntel] VirusTotal error: " + e.getMessage());
            return -1;
        }
    }

    /**
     * Checks an IP address against AbuseIPDB.
     * @return Abuse confidence score (0-100). -1 if error or API key missing.
     */
    public int checkIpReputation(String ipAddress) {
        String apiKey = config.getAbuseIpDbApiKey();
        if (apiKey == null || apiKey.isEmpty()) return -1;

        Object cached = cache.get("abuse_" + ipAddress);
        if (cached != null) return (int) cached;

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.abuseipdb.com/api/v2/check?ipAddress=" + ipAddress))
                    .header("Key", apiKey)
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonObject root = JsonParser.parseString(response.body()).getAsJsonObject();
                int score = root.getAsJsonObject("data").get("abuseConfidenceScore").getAsInt();
                
                cache.put("abuse_" + ipAddress, score);
                return score;
            } else {
                System.err.println("[ThreatIntel] AbuseIPDB query failed. Code: " + response.statusCode());
                return -1;
            }
        } catch (Exception e) {
            System.err.println("[ThreatIntel] AbuseIPDB error: " + e.getMessage());
            return -1;
        }
    }
}
