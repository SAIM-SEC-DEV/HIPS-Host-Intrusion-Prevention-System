package com.hips.agent.intel;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.hips.agent.config.AgentConfig;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * ============================================================
 * HIPS Agent — Threat Intelligence Service
 * ============================================================
 * Integrates with external APIs (VirusTotal, AbuseIPDB) to
 * enrich events with reputation scores.
 */
public class ThreatIntelService {

    private final AgentConfig config;
    private final ThreatIntelCache cache;
    private final Gson gson = new Gson();

    public ThreatIntelService(AgentConfig config) {
        this.config = config;
        // 24-hour cache TTL
        this.cache = new ThreatIntelCache(24 * 60 * 60 * 1000L);
    }

    private String getRequest(String urlStr, String headerName, String headerValue) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        if (headerName != null && headerValue != null) {
            conn.setRequestProperty(headerName, headerValue);
        }
        
        int responseCode = conn.getResponseCode();
        if (responseCode == 404) return null;
        if (responseCode != 200) {
            throw new Exception("HTTP " + responseCode);
        }

        StringBuilder response = new StringBuilder();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
        }
        return response.toString();
    }

    /**
     * Checks a file hash against VirusTotal.
     * @return Number of security vendors that flagged it as malicious.
     *         0 if benign, -1 if error or API key missing.
     */
    public int checkFileHash(String sha256) throws Exception {
        return checkFileHash(sha256, null);
    }

    public int checkFileHash(String sha256, String customApiKey) throws Exception {
        String apiKey = (customApiKey != null && !customApiKey.isEmpty()) ? customApiKey : config.getVirusTotalApiKey();
        if (apiKey == null || apiKey.isEmpty()) {
            throw new Exception("VirusTotal API Key is missing. Please provide one in the dashboard or hips-agent.properties.");
        }

        Object cached = cache.get("vt_" + sha256);
        if (cached != null) return (int) cached;

        try {
            String responseBody = getRequest("https://www.virustotal.com/api/v3/files/" + sha256, "x-apikey", apiKey);
            
            if (responseBody != null) {
                JsonObject root = JsonParser.parseString(responseBody).getAsJsonObject();
                JsonObject stats = root.getAsJsonObject("data").getAsJsonObject("attributes").getAsJsonObject("last_analysis_stats");
                int maliciousCount = stats.get("malicious").getAsInt();
                
                cache.put("vt_" + sha256, maliciousCount);
                return maliciousCount;
            } else {
                // Not found in VT database = no detections known
                cache.put("vt_" + sha256, 0);
                return 0;
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
            URL url = new URL("https://api.abuseipdb.com/api/v2/check?ipAddress=" + ipAddress);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.setRequestProperty("Key", apiKey);
            conn.setRequestProperty("Accept", "application/json");

            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                System.err.println("[ThreatIntel] AbuseIPDB query failed. Code: " + responseCode);
                return -1;
            }

            StringBuilder response = new StringBuilder();
            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
            }

            JsonObject root = JsonParser.parseString(response.toString()).getAsJsonObject();
            int score = root.getAsJsonObject("data").get("abuseConfidenceScore").getAsInt();
            
            cache.put("abuse_" + ipAddress, score);
            return score;
        } catch (Exception e) {
            System.err.println("[ThreatIntel] AbuseIPDB error: " + e.getMessage());
            return -1;
        }
    }
}
