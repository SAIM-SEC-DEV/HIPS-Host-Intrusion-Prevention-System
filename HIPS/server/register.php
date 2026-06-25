<?php
/**
 * ============================================================
 * HIPS — Host Intrusion Prevention System
 * API Endpoint: /api/register.php
 * ============================================================
 *
 * Purpose:
 *   Registers a new monitoring agent with the HIPS server.
 *   This is the FIRST call the Java agent makes on startup.
 *
 * HTTP Method: POST
 *
 * Request Headers:
 *   Content-Type: application/json
 *
 * Request Body (JSON):
 *   {
 *     "hostname":      "WORKSTATION-01",         // Required
 *     "ip_address":    "192.168.1.50",            // Required
 *     "os_name":       "Windows 11 Pro",          // Optional
 *     "os_version":    "10.0.22631",              // Optional
 *     "os_arch":       "amd64",                   // Optional
 *     "cpu_info":      "Intel Core i7-12700K",    // Optional
 *     "ram_total_mb":  16384,                     // Optional
 *     "agent_version": "1.0.0",                   // Optional
 *     "owner":         "Endpoint Owner"               // Optional
 *   }
 *
 * Response (201 Created):
 *   {
 *     "status":     "success",
 *     "message":    "Agent registered successfully.",
 *     "agent_id":   1,
 *     "agent_uuid": "a1b2c3d4-...",
 *     "auth_token": "abc123...",
 *     "baseline_start": "2026-04-14 19:00:00"
 *   }
 *
 * Security:
 *   - This endpoint does NOT require an auth token (the agent
 *     doesn't have one yet — this is where it receives one).
 *   - A cryptographically secure token is generated using
 *     random_bytes() and stored in the database.
 *   - The agent must include this token in all future requests.
 *   - If an agent with the same hostname + IP already exists,
 *     the existing record is updated and the same token is
 *     returned (idempotent re-registration).
 *
 * @package HIPS\API
 * @version 1.0
 */

declare(strict_types=1);

// ── Load the database connection and helper functions ────────
require_once __DIR__ . '/../config/db_connect.php';

// ── Only accept POST requests ────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(405, [
        'status'  => 'error',
        'message' => 'Method not allowed. Use POST.',
    ]);
}

// ── Validate and parse the JSON request body ─────────────────
// hostname and ip_address are mandatory; the Java agent MUST
// provide these so the server can identify the machine.
$data = validateJsonBody(['hostname', 'ip_address']);

// ── Extract fields with safe defaults ────────────────────────
$hostname     = trim($data['hostname']);
$ipAddress    = trim($data['ip_address']);
$osName       = trim($data['os_name']       ?? '');
$osVersion    = trim($data['os_version']    ?? '');
$osArch       = trim($data['os_arch']       ?? '');
$cpuInfo      = trim($data['cpu_info']      ?? '');
$ramTotalMb   = isset($data['ram_total_mb']) ? (int) $data['ram_total_mb'] : null;
$agentVersion = trim($data['agent_version'] ?? '1.0.0');
$owner        = trim($data['owner']         ?? '');

// ── Basic input validation ───────────────────────────────────
// Validate IP format (supports both IPv4 and IPv6)
if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
    jsonResponse(400, [
        'status'  => 'error',
        'message' => 'Invalid IP address format.',
    ]);
}

// Hostname must not be empty and should be reasonably sized
if (strlen($hostname) < 1 || strlen($hostname) > 255) {
    jsonResponse(400, [
        'status'  => 'error',
        'message' => 'Hostname must be between 1 and 255 characters.',
    ]);
}

// ── Check if this agent is already registered ────────────────
// We identify agents by the combination of hostname + IP.
// If a match exists, we update the record instead of creating
// a duplicate — this makes re-registration idempotent.
$stmt = $pdo->prepare(
    'SELECT id, agent_uuid, auth_token, baseline_start FROM agents
     WHERE hostname = :hostname AND ip_address = :ip
     LIMIT 1'
);
$stmt->execute([
    ':hostname' => $hostname,
    ':ip'       => $ipAddress,
]);
$existing = $stmt->fetch();

if ($existing) {
    // ── UPDATE existing agent ────────────────────────────────
    // Agent is re-registering (e.g., after a reboot). Update
    // its metadata and mark it as online, but keep the same
    // UUID and auth token for continuity.
    $updateStmt = $pdo->prepare(
        'UPDATE agents SET
            os_name       = :os_name,
            os_version    = :os_version,
            os_arch       = :os_arch,
            cpu_info      = :cpu_info,
            ram_total_mb  = :ram_total_mb,
            agent_version = :agent_version,
            owner         = :owner,
            status        = :status,
            last_heartbeat = NOW()
         WHERE id = :id'
    );
    $updateStmt->execute([
        ':os_name'       => $osName,
        ':os_version'    => $osVersion,
        ':os_arch'       => $osArch,
        ':cpu_info'      => $cpuInfo,
        ':ram_total_mb'  => $ramTotalMb,
        ':agent_version' => $agentVersion,
        ':owner'         => $owner,
        ':status'        => 'online',
        ':id'            => $existing['id'],
    ]);

    // Return the existing credentials to the agent
    jsonResponse(200, [
        'status'         => 'success',
        'message'        => 'Agent re-registered successfully. Welcome back.',
        'agent_id'       => (int) $existing['id'],
        'agent_uuid'     => $existing['agent_uuid'],
        'auth_token'     => $existing['auth_token'],
        'baseline_start' => $existing['baseline_start'],
    ]);
}

// ── Generate secure credentials for a new agent ──────────────

// UUID v4: A universally unique identifier for this agent.
// Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
// We generate it from cryptographically secure random bytes.
$uuidBytes = random_bytes(16);
// Set version to 4 (0100 in binary)
$uuidBytes[6] = chr(ord($uuidBytes[6]) & 0x0f | 0x40);
// Set variant to RFC 4122 (10xx in binary)
$uuidBytes[8] = chr(ord($uuidBytes[8]) & 0x3f | 0x80);
$agentUuid = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($uuidBytes), 4));

// Auth Token: A 64-byte (128 hex character) cryptographically
// secure token. The agent stores this locally and includes it
// in the Authorization header of every subsequent API call.
// Using random_bytes() ensures the token is unpredictable.
$authToken = bin2hex(random_bytes(64));

// Baseline Start: The anomaly detection learning phase begins
// immediately upon registration and lasts for 7 days.
$baselineStart = date('Y-m-d H:i:s');

// ── INSERT the new agent into the database ───────────────────
try {
    $insertStmt = $pdo->prepare(
        'INSERT INTO agents (
            agent_uuid, hostname, ip_address, os_name, os_version,
            os_arch, cpu_info, ram_total_mb, agent_version, owner,
            auth_token, status, last_heartbeat, baseline_start
        ) VALUES (
            :uuid, :hostname, :ip, :os_name, :os_version,
            :os_arch, :cpu_info, :ram_total_mb, :agent_version, :owner,
            :auth_token, :status, NOW(), :baseline_start
        )'
    );
    $insertStmt->execute([
        ':uuid'           => $agentUuid,
        ':hostname'       => $hostname,
        ':ip'             => $ipAddress,
        ':os_name'        => $osName,
        ':os_version'     => $osVersion,
        ':os_arch'        => $osArch,
        ':cpu_info'       => $cpuInfo,
        ':ram_total_mb'   => $ramTotalMb,
        ':agent_version'  => $agentVersion,
        ':owner'          => $owner,
        ':auth_token'     => $authToken,
        ':status'         => 'online',
        ':baseline_start' => $baselineStart,
    ]);

    // Get the auto-generated primary key
    $agentId = (int) $pdo->lastInsertId();

    // ── Success! Return the agent's credentials ──────────────
    // The Java agent MUST store the auth_token securely and
    // include it in all future API calls.
    jsonResponse(201, [
        'status'         => 'success',
        'message'        => 'Agent registered successfully.',
        'agent_id'       => $agentId,
        'agent_uuid'     => $agentUuid,
        'auth_token'     => $authToken,
        'baseline_start' => $baselineStart,
    ]);

} catch (PDOException $e) {
    // Log the detailed error for server-side debugging
    error_log('[HIPS] Agent registration failed: ' . $e->getMessage());

    // Return a generic error to the caller (never expose internals)
    jsonResponse(500, [
        'status'  => 'error',
        'message' => 'Failed to register agent. Please check server logs.',
    ]);
}
