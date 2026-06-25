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
$validModules    = ['file', 'network', 'process', 'registry'];
$validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

$module   = strtolower(trim($data['module']));
$severity = strtoupper(trim($data['severity']));

if (!in_array($module, $validModules, true)) {
    jsonResponse(400, [
        'status'  => 'error',
        'message' => 'Invalid module. Must be "file" or "network".',
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
    // Only events with severity >= HIGH warrant immediate admin
    // attention on the Live Alerts page.
    if (in_array($severity, ['CRITICAL', 'HIGH'], true)) {
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
