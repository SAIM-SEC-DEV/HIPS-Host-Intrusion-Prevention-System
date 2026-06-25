package com.hips.agent.intel;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * A simple TTL-based cache for Threat Intel queries to avoid
 * exhausting API rate limits on duplicate files or IPs.
 */
public class ThreatIntelCache {

    private static class CacheEntry {
        final Object data;
        final long expiresAt;

        CacheEntry(Object data, long ttlMillis) {
            this.data = data;
            this.expiresAt = System.currentTimeMillis() + ttlMillis;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }

    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final long defaultTtlMillis;

    public ThreatIntelCache(long defaultTtlMillis) {
        this.defaultTtlMillis = defaultTtlMillis;
    }

    public void put(String key, Object value) {
        cache.put(key, new CacheEntry(value, defaultTtlMillis));
        cleanup();
    }

    public Object get(String key) {
        CacheEntry entry = cache.get(key);
        if (entry != null) {
            if (!entry.isExpired()) {
                return entry.data;
            } else {
                cache.remove(key);
            }
        }
        return null;
    }

    private void cleanup() {
        // Run cleanup periodically if map gets too large
        if (cache.size() > 1000) {
            long now = System.currentTimeMillis();
            cache.entrySet().removeIf(e -> e.getValue().expiresAt < now);
        }
    }
}
