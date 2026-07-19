package com.hips.agent.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.hips.agent.config.AgentConfig;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * ============================================================
 * HIPS Agent — API Client (Java 8 Compatible)
 * ============================================================
 * Centralized HTTP client for all communication with the HIPS
 * server. Uses HttpURLConnection for Java 8 compatibility.
 */
public class ApiClient {

    private final Gson gson;
    private final AgentConfig config;

    // Connection timeout for all requests
    private static final int TIMEOUT_MS = 15000;

    public ApiClient(AgentConfig config) {
        this.config = config;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
    }

    private JsonObject sendRequest(String method, String endpoint, Object payload, boolean auth) {
        String urlStr = config.apiUrl(endpoint);
        try {
            return executeHttpRequest(method, urlStr, payload, auth);
        } catch (Exception e) {
            // Diagnostic: If 'localhost' failed, try '127.0.0.1' as a fallback on Windows
            if (urlStr.contains("://localhost")) {
                String fallbackUrl = urlStr.replace("://localhost", "://127.0.0.1");
                try {
                    System.err.println("[HIPS] Request to localhost failed, attempting fallback to 127.0.0.1...");
                    return executeHttpRequest(method, fallbackUrl, payload, auth);
                } catch (Exception ex) {
                    System.err.println("[HIPS] Fallback also failed: " + ex.getMessage());
                }
            }
            
            System.err.println("[HIPS] HTTP " + method + " " + endpoint + " failed.");
            System.err.println("[HIPS] URL: " + urlStr);
            System.err.println("[HIPS] Error: " + e.getMessage());
            
            if (e instanceof java.net.ConnectException) {
                System.err.println("[HIPS] HINT: Is the XAMPP Apache server running? Is the URL correct?");
            } else if (e instanceof java.net.SocketTimeoutException) {
                System.err.println("[HIPS] HINT: Connection timed out. Check your firewall or network.");
            }
            
            return null;
        }
    }

    private JsonObject executeHttpRequest(String method, String urlStr, Object payload, boolean auth) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        conn.setConnectTimeout(TIMEOUT_MS);
        conn.setReadTimeout(TIMEOUT_MS);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("User-Agent", "HIPS-Agent/2.0");

        if (auth) {
            String token = config.getAuthToken();
            if (token != null && !token.isEmpty()) {
                conn.setRequestProperty("Authorization", "Bearer " + token);
            }
        }

        if (payload != null) {
            conn.setDoOutput(true);
            String json = gson.toJson(payload);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes("UTF-8"));
            }
        }

        int statusCode = conn.getResponseCode();
        StringBuilder response = new StringBuilder();
        
        // Read response body
        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                statusCode >= 200 && statusCode < 300 ? conn.getInputStream() : conn.getErrorStream(), "UTF-8"))) {
            String line;
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
        }

        return handleResponse(urlStr, statusCode, response.toString());
    }

    public JsonObject post(String endpoint, Object payload) {
        return sendRequest("POST", endpoint, payload, true);
    }

    public CompletableFuture<JsonObject> postAsync(final String endpoint, final Object payload) {
        return CompletableFuture.supplyAsync(() -> post(endpoint, payload));
    }

    public CompletableFuture<Boolean> postAsyncChecked(final String endpoint, final Object payload) {
        return CompletableFuture.supplyAsync(() -> {
            JsonObject response = post(endpoint, payload);

            // Retry once on connection failure (null = request never reached server)
            if (response == null) {
                try { Thread.sleep(2000); } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
                System.err.println("[HIPS] Retrying alert delivery to " + endpoint + "...");
                response = post(endpoint, payload);
            }

            return isSuccessResponse(response);
        });
    }

    public JsonObject postNoAuth(String endpoint, Object payload) {
        return sendRequest("POST", endpoint, payload, false);
    }

    public JsonObject get(String endpoint) {
        return sendRequest("GET", endpoint, null, true);
    }

    public boolean isSuccessResponse(JsonObject response) {
        return response != null
                && response.has("status")
                && "success".equalsIgnoreCase(response.get("status").getAsString());
    }

    private JsonObject handleResponse(String url, int statusCode, String body) {
        if (statusCode >= 200 && statusCode < 300) {
            System.out.println("[HIPS] Response " + statusCode + " OK");
        } else {
            System.err.println("[HIPS] Response " + statusCode + " from " + url);
            System.err.println("[HIPS] Body: " + body);
        }

        try {
            return JsonParser.parseString(body).getAsJsonObject();
        } catch (Exception e) {
            System.err.println("[HIPS] Failed to parse JSON response: " + body);
            return null;
        }
    }

    public void reportCommandResult(int commandId, String status, Map<String, Object> result) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("command_id", commandId);
        payload.put("status", status);
        payload.put("result", result != null ? result : new HashMap<String, Object>());
        post("result.php", payload);
    }
}
