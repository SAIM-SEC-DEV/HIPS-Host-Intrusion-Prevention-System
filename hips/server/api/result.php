<?php
/**
 * ============================================================
 * HIPS — Host Intrusion Prevention System
 * API Endpoint: /api/result.php
 * ============================================================
 *
 * Purpose:
 *   Receives the execution result of a command from the agent.
 *   Updates the command's status to 'completed' or 'failed'
 *   and stores the result JSON payload.
 *
 * HTTP Method: POST
 * Auth: Bearer <token> required
 *
 * Request Body (JSON):
 *   {
 *     "command_id":  5,                          // Required
 *     "status":      "completed",                // Required: "completed" or "failed"
 *     "result":      { "blocked": true, ... }    // Optional: execution result data
 *   }
 *
 * @package HIPS\API
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/db_connect.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(405, ['status' => 'error', 'message' => 'Method not allowed. Use POST.']);
}

// ── Authenticate the agent ───────────────────────────────────
$agent = authenticateAgent($pdo);

// ── Validate required fields ─────────────────────────────────
$data = validateJsonBody(['command_id', 'status']);

$commandId  = (int) $data['command_id'];
$cmdStatus  = strtolower(trim($data['status']));
$resultJson = isset($data['result']) ? json_encode($data['result']) : null;

// ── Validate status enum ─────────────────────────────────────
$validStatuses = ['completed', 'failed'];
if (!in_array($cmdStatus, $validStatuses, true)) {
    jsonResponse(400, [
        'status'  => 'error',
        'message' => 'Invalid status. Must be "completed" or "failed".',
    ]);
}

try {
    // ── Verify the command exists and belongs to this agent ──
    // Security: An agent should only be able to update commands
    // that were assigned to it, not commands for other agents.
    $stmt = $pdo->prepare(
        'SELECT id, status FROM commands
         WHERE id = :cmd_id AND agent_id = :agent_id
         LIMIT 1'
    );
    $stmt->execute([
        ':cmd_id'   => $commandId,
        ':agent_id' => $agent['id'],
    ]);
    $command = $stmt->fetch();

    if (!$command) {
        jsonResponse(404, [
            'status'  => 'error',
            'message' => 'Command not found or does not belong to this agent.',
        ]);
    }

    // ── Update the command with the execution result ─────────
    $updateStmt = $pdo->prepare(
        'UPDATE commands SET
            status       = :status,
            result_json  = :result_json,
            completed_at = NOW()
         WHERE id = :id'
    );
    $updateStmt->execute([
        ':status'      => $cmdStatus,
        ':result_json' => $resultJson,
        ':id'          => $commandId,
    ]);

    jsonResponse(200, [
        'status'  => 'success',
        'message' => 'Command result recorded.',
    ]);

} catch (PDOException $e) {
    error_log('[HIPS] Command result update failed: ' . $e->getMessage());
    jsonResponse(500, ['status' => 'error', 'message' => 'Failed to update command result.']);
}
