package com.hips.agent.file;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ============================================================
 * HIPS Agent — File Integrity Engine
 * ============================================================
 * Manages cryptographic hash computation and comparison for
 * file integrity monitoring. On startup, baseline hashes are
 * computed for all files in watched directories. During
 * monitoring, any file modification is re-hashed and compared
 * against the baseline to detect tampering.
 *
 * Supports: SHA-256 (default), MD5 (fallback)
 *
 * Functions (6 of 25):
 *   computeHash(), storeBaselineHash(), compareHash(),
 *   updateBaseline(), getBaselineCount(), removeBaseline()
 */
public class FileIntegrity {

    // Stores baseline hashes: filePath → SHA-256 hash string
    private final Map<String, String> baselineHashes = new ConcurrentHashMap<>();
    private final Map<String, Long> sizeCache = new ConcurrentHashMap<>();
    private final Map<String, Long> timeCache = new ConcurrentHashMap<>();

    // Default algorithm (SHA-256 is more secure than MD5)
    private static final String HASH_ALGORITHM = "SHA-256";

    // Maximum file size to hash (skip very large files to avoid
    // blocking the monitoring thread for too long)
    private static final long MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB

    // ── Function 1: computeHash() ────────────────────────────
    /**
     * Computes the SHA-256 hash of a file. Reads the file in
     * 8KB chunks to handle large files efficiently without
     * loading them entirely into memory.
     *
     * @param filePath  Path to the file to hash
     * @return          Hex string of the SHA-256 hash, or null on error
     */
    public String computeHash(Path filePath) {
        try {
            long fileSize = Files.size(filePath);
            if (fileSize > MAX_FILE_SIZE) {
                System.out.println("[HIPS-INTEGRITY] Skipping large file (" + fileSize + " bytes): " + filePath);
                return null;
            }

            long lastModified = Files.getLastModifiedTime(filePath).toMillis();
            String absPath = filePath.toAbsolutePath().toString();

            // Optimization: Skip re-hashing if metadata is unchanged
            if (sizeCache.containsKey(absPath) && sizeCache.get(absPath) == fileSize &&
                timeCache.containsKey(absPath) && timeCache.get(absPath) == lastModified) {
                return baselineHashes.get(absPath);
            }

            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);

            // Read file in chunks to avoid memory issues
            try (InputStream is = Files.newInputStream(filePath)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }

            // Convert the hash bytes to a hex string
            byte[] hashBytes = digest.digest();
            String hexHash = bytesToHex(hashBytes);

            // Update metadata caches
            sizeCache.put(absPath, fileSize);
            timeCache.put(absPath, lastModified);

            return hexHash;

        } catch (NoSuchAlgorithmException e) {
            System.err.println("[HIPS-INTEGRITY] Hash algorithm not available: " + HASH_ALGORITHM);
            return null;
        } catch (IOException e) {
            // File may have been deleted between detection and hashing
            System.err.println("[HIPS-INTEGRITY] Cannot read file for hashing: " + filePath);
            return null;
        }
    }

    // ── Function 2: storeBaselineHash() ──────────────────────
    /**
     * Walks a directory recursively and computes + stores the
     * SHA-256 hash of every regular file. This creates the
     * "known good" baseline during startup.
     *
     * @param directory  Root directory to baseline
     */
    public void storeBaselineHash(Path directory) {
        try {
            Files.walkFileTree(directory, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (attrs.isRegularFile() && attrs.size() <= MAX_FILE_SIZE) {
                        String hash = computeHash(file);
                        if (hash != null) {
                            baselineHashes.put(file.toAbsolutePath().toString(), hash);
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    // Skip files we can't access (permission denied, locked, etc.)
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            System.err.println("[HIPS-INTEGRITY] Failed to baseline directory: " + directory);
        }
    }

    // ── Function 3: compareHash() ────────────────────────────
    /**
     * Compares a file's current hash against its stored baseline.
     * Returns true if the hashes DO NOT MATCH (i.e., the file
     * has been tampered with).
     *
     * @param filePath     Path to the file
     * @param currentHash  The just-computed hash of the file
     * @return             true if hash mismatch (tampering), false if OK or no baseline
     */
    public boolean compareHash(Path filePath, String currentHash) {
        if (currentHash == null) return false;

        String absPath = filePath.toAbsolutePath().toString();
        String baselineHash = baselineHashes.get(absPath);

        // If there's no baseline for this file, it's new — not a mismatch
        if (baselineHash == null) return false;

        // Compare hashes (case-insensitive hex comparison)
        boolean mismatch = !baselineHash.equalsIgnoreCase(currentHash);

        if (mismatch) {
            System.err.println("[HIPS-INTEGRITY] MISMATCH for " + filePath);
            System.err.println("[HIPS-INTEGRITY]   Baseline: " + baselineHash);
            System.err.println("[HIPS-INTEGRITY]   Current:  " + currentHash);
        }

        return mismatch;
    }

    // ── Function 4: updateBaseline() ─────────────────────────
    /**
     * Updates the baseline hash for a specific file. Called after
     * an authorized modification is confirmed (e.g., whitelisted
     * process made the change).
     */
    public void updateBaseline(Path filePath) {
        String hash = computeHash(filePath);
        if (hash != null) {
            baselineHashes.put(filePath.toAbsolutePath().toString(), hash);
            System.out.println("[HIPS-INTEGRITY] Baseline updated for: " + filePath);
        }
    }

    // ── Function 5: removeBaseline() ─────────────────────────
    /**
     * Removes a file's baseline entry (e.g., when the file is deleted).
     */
    public void removeBaseline(Path filePath) {
        baselineHashes.remove(filePath.toAbsolutePath().toString());
    }

    // ── Function 6: getBaselineCount() ───────────────────────
    /**
     * Returns the total number of baselined files.
     */
    public int getBaselineCount() {
        return baselineHashes.size();
    }

    /**
     * Returns the baseline hash for a specific file path.
     */
    public String getBaselineHash(Path filePath) {
        return baselineHashes.get(filePath.toAbsolutePath().toString());
    }

    /**
     * Returns an unmodifiable view of all baseline hashes.
     */
    public Map<String, String> getBaselineHashes() {
        return new HashMap<String, String>(baselineHashes);
    }

    // ── Helper: Convert byte array to hex string ─────────────
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
