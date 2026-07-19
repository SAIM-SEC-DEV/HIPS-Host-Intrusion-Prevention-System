<?php
/**
 * ============================================================
 * HIPS — Host Intrusion Prevention System
 * API Endpoint: /api/report.php
 * ============================================================
 *
 * Purpose:
 *   Receives event reports from agents. Each event is logged
 *   into the events table. If the severity is HIGH or CRITICAL,
 *   an alert is also created in the alerts table for the
 *   dashboard's Live Alerts page.
 *
 * HTTP Method: POST
 * Auth: Bearer <token> required
 *
 * Request Body (JSON):
 *   {
 *     "module":       "file",                       // Required: "file" or "network"
 *     "event_type":   "FILE_MODIFIED",              // Required
 *     "severity":     "HIGH",                       // Required: CRITICAL, HIGH, MEDIUM, LOW
 *     "title":        "System file was modified",   // Required
 *     "description":  "C:\\Windows\\System32\\...",  // Optional
 *     "source_path":  "C:\\Windows\\System32\\...",  // Optional
 *     "destination":  "",                           // Optional (for network events)
 *     "hash_value":   "abc123...",                  // Optional (for file events)
 *     "metadata":     { "key": "value" },           // Optional extra data
 *     "is_anomaly":   false                         // Optional: flagged by anomaly engine
 *   }
 *
 * Response (201 Created):
 *   {
 *     "status":    "success",
 *     "event_id":  42,
 *     "alert_id":  7,       // Only present if alert was created
 *     "message":   "Event logged successfully."
 *   }
 *
 * @package HIPS\API
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/db_connect.php';

// ── Only accept POST ─────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(405, ['status' => 'error', 'message' => 'Method not allowed. Use POST.']);
}

// ── Authenticate the agent ───────────────────────────────────
$agent = authenticateAgent($pdo);

// ── Validate required fields ─────────────────────────────────
$data = validateJsonBody(['module', 'event_type', 'severity', 'title']);

// ── Validate enum values ─────────────────────────────────────
$validModules    = ['file', 'network', 'process', 'registry', 'memory', 'asset'];
$validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

$module   = strtolower(trim($data['module']));
$severity = strtoupper(trim($data['severity']));

if (!in_array($module, $validModules, true)) {
    jsonResponse(400, [
        'status'  => 'error',
        'message' => 'Invalid module. Must be one of the registered module types.',
    ]);
}

if (!in_array($severity, $validSeverities, true)) {
    jsonResponse(400, [
        'status'  => 'error',
        'message' => 'Invalid severity. Must be CRITICAL, HIGH, MEDIUM, or LOW.',
    ]);
}

// ── Extract fields ───────────────────────────────────────────
$eventType    = trim($data['event_type']);
$title        = trim($data['title']);
$description  = trim($data['description']  ?? '');
$sourcePath   = trim($data['source_path']  ?? '');
$destination  = trim($data['destination']  ?? '');
$hashValue    = trim($data['hash_value']   ?? '');
$metadataJson = isset($data['metadata']) ? json_encode($data['metadata']) : null;
$isAnomaly    = !empty($data['is_anomaly']) ? 1 : 0;
$mitreId      = trim($data['mitre_technique_id'] ?? '');
$mitreTactic  = trim($data['mitre_tactic'] ?? '');

// ── Begin a database transaction ─────────────────────────────
// We use a transaction to ensure that the event AND its
// corresponding alert (if severity warrants) are both written
// atomically. If either fails, both are rolled back.
try {
    $pdo->beginTransaction();

    // ── INSERT into events table ─────────────────────────────
    $eventStmt = $pdo->prepare(
        'INSERT INTO events (
            agent_id, module, event_type, severity, title,
            description, source_path, destination, hash_value,
            metadata_json, is_anomaly, mitre_technique_id, mitre_tactic
        ) VALUES (
            :agent_id, :module, :event_type, :severity, :title,
            :description, :source_path, :destination, :hash_value,
            :metadata_json, :is_anomaly, :mitre_id, :mitre_tactic
        )'
    );
    $eventStmt->execute([
        ':agent_id'      => $agent['id'],
        ':module'        => $module,
        ':event_type'    => $eventType,
        ':severity'      => $severity,
        ':title'         => $title,
        ':description'   => $description,
        ':source_path'   => $sourcePath,
        ':destination'   => $destination,
        ':hash_value'    => $hashValue,
        ':metadata_json' => $metadataJson,
        ':is_anomaly'    => $isAnomaly,
        ':mitre_id'      => $mitreId === '' ? null : $mitreId,
        ':mitre_tactic'  => $mitreTactic === '' ? null : $mitreTactic,
    ]);

    $eventId = (int) $pdo->lastInsertId();
    $alertId = null;

    // ── Create an alert for HIGH and CRITICAL events ─────────
    // ── Absolute Suppression: Multi-Vector Fuzzy Whitelist ─────
    $isWhitelisted = false;
    
    // 1. Collect only threat-related markers (NOT the reporting agent's identity)
    $threatMarkers = [
        $destination ?? '',
        $sourcePath ?? ''
    ];
    
    // Normalize localhost
    foreach($threatMarkers as &$m) if($m === '::1') $m = '127.0.0.1';
    
    // Filter out empty markers
    $validMarkers = array_filter(array_map('trim', array_map('strtolower', $threatMarkers)));
    
    error_log("[HIPS-DEBUG] Processing event: $title ($severity)");
    error_log("[HIPS-DEBUG] Normalized Markers: " . implode(', ', $validMarkers));
    
    // 2. Perform a fast database query to check if ANY marker exists in the whitelist
    if (!empty($validMarkers)) {
        $inQuery = implode(',', array_fill(0, count($validMarkers), '?'));
        // Using LOWER() handles case-insensitivity, but ideally the column should have case-insensitive collation
        $wlStmt = $pdo->prepare("SELECT 1 FROM ip_whitelist WHERE LOWER(ip_address) IN ($inQuery) LIMIT 1");
        $wlStmt->execute(array_values($validMarkers));
        
        if ($wlStmt->fetchColumn()) {
            $isWhitelisted = true;
            error_log("[HIPS-DEBUG] Alert suppressed: Marker matched whitelist in DB.");
        }
    }
    
    if (!$isWhitelisted) {
        error_log("[HIPS-DEBUG] Alert NOT whitelisted. Proceeding to promote.");
    }

    // Only events with severity >= HIGH warrant immediate admin
    // attention on the Live Alerts page, UNLESS they are whitelisted.
    if (in_array($severity, ['CRITICAL', 'HIGH'], true) && !$isWhitelisted) {
        $alertStmt = $pdo->prepare(
            'INSERT INTO alerts (
                event_id, agent_id, severity, module, title, description, mitre_technique_id, mitre_tactic
            ) VALUES (
                :event_id, :agent_id, :severity, :module, :title, :description, :mitre_id, :mitre_tactic
            )'
        );
        $alertStmt->execute([
            ':event_id'    => $eventId,
            ':agent_id'    => $agent['id'],
            ':severity'    => $severity,
            ':module'      => $module,
            ':title'       => $title,
            ':description' => $description,
            ':mitre_id'    => $mitreId === '' ? null : $mitreId,
            ':mitre_tactic'=> $mitreTactic === '' ? null : $mitreTactic,
        ]);

        $alertId = (int) $pdo->lastInsertId();
    }

    // ── Commit the transaction ───────────────────────────────
    $pdo->commit();

    // ── Return success with IDs ──────────────────────────────
    $response = [
        'status'   => 'success',
        'event_id' => $eventId,
        'message'  => 'Event logged successfully.',
    ];
    if ($alertId !== null) {
        $response['alert_id'] = $alertId;
    }

    jsonResponse(201, $response);

} catch (PDOException $e) {
    // Roll back the transaction so the database stays consistent
    $pdo->rollBack();
    error_log('[HIPS] Event report failed for agent ' . $agent['id'] . ': ' . $e->getMessage());
    jsonResponse(500, ['status' => 'error', 'message' => 'Failed to log event.']);
}
