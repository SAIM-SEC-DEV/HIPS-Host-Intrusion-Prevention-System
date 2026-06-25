<?php
/**
 * ============================================================
 * HIPS — Host Intrusion Prevention System
 * API Endpoint: /api/commands.php
 * ============================================================
 *
 * Purpose:
 *   Returns all pending commands for the authenticated agent.
 *   The Java agent polls this endpoint every 10 seconds. Once
 *   fetched, commands are marked as 'sent' so they aren't
 *   returned again on the next poll.
 *
 * HTTP Method: GET
 * Auth: Bearer <token> required
 *
 * Response (200 OK):
 *   {
 *     "status":   "success",
 *     "commands": [
 *       {
 *         "id":              5,
 *         "command_type":    "BLOCK_IP",
 *         "parameters_json": "{\"ip\": \"192.168.1.100\"}",
 *         "priority":        "high",
 *         "admin_note":      "Suspicious scanning activity",
 *         "issued_at":       "2026-04-14 19:00:00"
 *       }
 *     ]
 *   }
 *
 * @package HIPS\API
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/db_connect.php';

// ── Only accept GET ──────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    jsonResponse(405, ['status' => 'error', 'message' => 'Method not allowed. Use GET.']);
}

// ── Authenticate the agent ───────────────────────────────────
$agent = authenticateAgent($pdo);

try {
    // ── Fetch all pending commands for this agent ────────────
    // Commands are ordered by priority (critical first) then by
    // issue date (oldest first) to ensure urgent commands are
    // executed before routine ones.
    $stmt = $pdo->prepare(
        'SELECT id, command_type, parameters_json, priority, admin_note, issued_at
         FROM commands
         WHERE agent_id = :agent_id AND status = :status
         ORDER BY FIELD(priority, "critical", "high", "normal"), issued_at ASC'
    );
    $stmt->execute([
        ':agent_id' => $agent['id'],
        ':status'   => 'pending',
    ]);

    $commands = $stmt->fetchAll();

    // ── Mark fetched commands as 'sent' ──────────────────────
    // This prevents the same command from being returned on the
    // next poll cycle. The agent will later POST the execution
    // result to /api/result.php which updates the status to
    // 'completed' or 'failed'.
    if (!empty($commands)) {
        $ids = array_column($commands, 'id');
        // Build a parameterized IN clause for safety
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $updateStmt = $pdo->prepare(
            "UPDATE commands SET status = 'sent' WHERE id IN ($placeholders)"
        );
        $updateStmt->execute($ids);
    }

    // ── Decode parameters_json for each command ──────────────
    // The Java agent expects parsed JSON objects, not raw strings.
    foreach ($commands as &$cmd) {
        if (!empty($cmd['parameters_json'])) {
            $cmd['parameters'] = json_decode($cmd['parameters_json'], true);
        } else {
            $cmd['parameters'] = null;
        }
        unset($cmd['parameters_json']);
    }
    unset($cmd);

    jsonResponse(200, [
        'status'   => 'success',
        'commands' => $commands,
    ]);

} catch (PDOException $e) {
    error_log('[HIPS] Command fetch failed for agent ' . $agent['id'] . ': ' . $e->getMessage());
    jsonResponse(500, ['status' => 'error', 'message' => 'Failed to fetch commands.']);
}
