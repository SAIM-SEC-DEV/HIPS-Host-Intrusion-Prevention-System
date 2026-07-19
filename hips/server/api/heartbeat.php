<?php
/**
 * ============================================================
 * HIPS — Host Intrusion Prevention System
 * API Endpoint: /api/heartbeat.php
 * ============================================================
 *
 * Purpose:
 *   Receives a heartbeat (alive ping) from a registered agent
 *   every 30 seconds. Updates the agent's last_heartbeat
 *   timestamp and confirms its online status.
 *
 * HTTP Method: POST
 * Auth: Bearer <token> required
 *
 * Request Body (JSON):
 *   {
 *     "agent_uuid":  "a1b2c3d4-...",
 *     "uptime_sec":  3600,           // Optional: agent uptime in seconds
 *     "cpu_usage":   23.5,           // Optional: current CPU usage %
 *     "ram_usage":   68.2            // Optional: current RAM usage %
 *   }
 *
 * Response (200 OK):
 *   {
 *     "status":  "success",
 *     "message": "Heartbeat acknowledged.",
 *     "server_time": "2026-04-14 19:15:00"
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

// ── Authenticate the agent via Bearer token ──────────────────
// This ensures only registered agents can send heartbeats.
// The authenticateAgent() function returns the agent's full
// database row if the token is valid, or sends a 401 and exits.
$agent = authenticateAgent($pdo);

// ── Parse optional metrics from the request body ─────────────
$rawBody = file_get_contents('php://input');
$data    = json_decode($rawBody, true) ?? [];

$uptimeSec = isset($data['uptime_sec']) ? (int)    $data['uptime_sec'] : null;
$cpuUsage  = isset($data['cpu_usage'])  ? (float)  $data['cpu_usage']  : null;
$ramUsage  = isset($data['ram_usage'])  ? (float)  $data['ram_usage']  : null;

// ── Update the agent's heartbeat timestamp and status ────────
// Setting status to 'online' confirms the agent is alive.
// The dashboard uses heartbeat_timeout_sec from settings to
// determine when to flip an agent to 'offline'.
try {
    $stmt = $pdo->prepare(
        'UPDATE agents SET
            last_heartbeat = NOW(),
            status         = :status
         WHERE id = :id'
    );
    $stmt->execute([
        ':status' => 'online',
        ':id'     => $agent['id'],
    ]);

    jsonResponse(200, [
        'status'      => 'success',
        'message'     => 'Heartbeat acknowledged.',
        'server_time' => date('Y-m-d H:i:s'),
    ]);

} catch (PDOException $e) {
    error_log('[HIPS] Heartbeat update failed for agent ' . $agent['id'] . ': ' . $e->getMessage());
    jsonResponse(500, ['status' => 'error', 'message' => 'Heartbeat processing failed.']);
}
