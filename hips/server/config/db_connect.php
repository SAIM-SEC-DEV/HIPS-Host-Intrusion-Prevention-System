<?php
/**
 * ============================================================
 * HIPS — Host Intrusion Prevention System
 * Database Connection Configuration
 * ============================================================
 *
 * This file establishes a secure PDO connection to the MySQL
 * database. PDO is used exclusively to prevent SQL injection
 * via prepared statements. All other PHP files include this
 * file to get a database handle ($pdo).
 *
 * Security Notes:
 *   - PDO::ATTR_EMULATE_PREPARES is set to false so that
 *     MySQL performs real prepared statements (not emulated).
 *   - PDO::ATTR_ERRMODE is set to EXCEPTION so that database
 *     errors are thrown as exceptions and can be caught cleanly.
 *   - The charset is set to utf8mb4 to support full Unicode.
 *
 * @package HIPS\Config
 * @version 1.0
 */

declare(strict_types=1);

// ── Database Credentials ─────────────────────────────────────
// Reads from environment variables with safe XAMPP defaults.
// Set HIPS_DB_USER / HIPS_DB_PASS in your environment or
// .htaccess for production deployments.
define('DB_HOST',    getenv('HIPS_DB_HOST')    ?: '127.0.0.1');
define('DB_PORT',    getenv('HIPS_DB_PORT')    ?: '3306');
define('DB_NAME',    getenv('HIPS_DB_NAME')    ?: 'hips_db');
define('DB_USER',    getenv('HIPS_DB_USER')    ?: 'root');
define('DB_PASS',    getenv('HIPS_DB_PASS')    ?: '');
define('DB_CHARSET', 'utf8mb4');

// ── Build the DSN (Data Source Name) ─────────────────────────
$dsn = sprintf(
    'mysql:host=%s;port=%s;dbname=%s;charset=%s',
    DB_HOST,
    DB_PORT,
    DB_NAME,
    DB_CHARSET
);

// ── PDO Connection Options ───────────────────────────────────
// These options harden the connection against common pitfalls.
$options = [
    // Use real prepared statements (not emulated) — critical for
    // preventing SQL injection. MySQL will parse and plan the
    // query before binding any user-supplied values.
    PDO::ATTR_EMULATE_PREPARES   => false,

    // Throw exceptions on database errors so we can catch them
    // in try/catch blocks instead of silently failing.
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,

    // Return associative arrays by default when fetching rows.
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,

    // Use persistent connections to reduce connection overhead
    // on high-frequency agent polling (every 10 seconds).
    PDO::ATTR_PERSISTENT         => true,
];

// ── Establish the Connection ─────────────────────────────────
try {
    $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
} catch (PDOException $e) {
    // In production, log the error and return a generic message.
    // Never expose raw database errors to external callers.
    error_log('[HIPS] Database connection failed: ' . $e->getMessage());

    // Return a JSON error response (since callers are API agents)
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode([
        'status'  => 'error',
        'message' => 'Internal server error. Database connection failed.',
    ]);
    exit;
}

/**
 * Extracts the true client IP address, handling proxies, load balancers,
 * and local loopbacks.
 *
 * @return string The detected IP address
 */
function getClientIP(): string
{
    $headers = [
        'HTTP_CF_CONNECTING_IP', // Cloudflare
        'HTTP_X_FORWARDED_FOR',  // Standard Proxy
        'HTTP_X_REAL_IP',         // Nginx / FastCGI
        'REMOTE_ADDR'             // Fallback
    ];

    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip = $_SERVER[$header];
            // Handle comma-separated lists from proxies
            if (str_contains($ip, ',')) {
                $ip = trim(explode(',', $ip)[0]);
            }
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip === '::1' ? '127.0.0.1' : $ip;
            }
        }
    }

    return '127.0.0.1';
}

// ── Helper: Send a JSON response and terminate ───────────────
/**
 * Outputs a JSON response with the given HTTP status code and
 * an associative array payload, then terminates the script.
 *
 * @param int   $httpCode  HTTP status code (200, 400, 401, 500, etc.)
 * @param array $payload   Associative array to encode as JSON
 * @return never
 */
function jsonResponse(int $httpCode, array $payload): never
{
    http_response_code($httpCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

// ── Helper: Validate the Authorization Token ─────────────────
/**
 * Extracts the Bearer token from the Authorization header and
 * validates it against the agents table. Returns the agent row
 * if valid, or sends a 401 response and terminates if not.
 *
 * Security Flow:
 *   1. Check that the Authorization header exists.
 *   2. Extract the token after "Bearer ".
 *   3. Query the agents table for a matching auth_token.
 *   4. If not found, return 401 Unauthorized.
 *   5. If found, return the full agent row for downstream use.
 *
 * @param PDO $pdo  The database connection handle
 * @return array    The authenticated agent's database row
 */
function authenticateAgent(PDO $pdo): array
{
    // Get the Authorization header (supports both Apache and CGI)
    $authHeader = $_SERVER['HTTP_AUTHORIZATION']
                  ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION']
                  ?? '';

    // The header must start with "Bearer " followed by the token
    if (!str_starts_with($authHeader, 'Bearer ')) {
        jsonResponse(401, [
            'status'  => 'error',
            'message' => 'Missing or malformed Authorization header. Expected: Bearer <token>',
        ]);
    }

    // Extract the raw token string
    $token = trim(substr($authHeader, 7));

    if (empty($token)) {
        jsonResponse(401, [
            'status'  => 'error',
            'message' => 'Authorization token is empty.',
        ]);
    }

    // Look up the token in the agents table using a prepared statement.
    // This is immune to SQL injection because PDO binds the value
    // separately from the query structure.
    $stmt = $pdo->prepare('SELECT * FROM agents WHERE auth_token = :token LIMIT 1');
    $stmt->execute([':token' => $token]);
    $agent = $stmt->fetch();

    if (!$agent) {
        jsonResponse(401, [
            'status'  => 'error',
            'message' => 'Invalid authentication token. Agent not registered.',
        ]);
    }

    // ── IP Whitelist Enforcement for Agents ──────────────────
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
    if ($clientIp === '::1') $clientIp = '127.0.0.1';

    // Fetch whitelist status
    $wlEnabled = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'ip_whitelist_enabled'")->fetchColumn();

    if ($wlEnabled === '1' && $clientIp !== '127.0.0.1') {
        $wlStmt = $pdo->prepare("SELECT id FROM ip_whitelist WHERE ip_address = :ip LIMIT 1");
        $wlStmt->execute([':ip' => $clientIp]);
        if (!$wlStmt->fetch()) {
            error_log("[HIPS Security] Blocked agent connection from non-whitelisted IP: $clientIp");
            jsonResponse(403, [
                'status'  => 'error',
                'message' => 'Access denied. Agent IP address not whitelisted.',
            ]);
        }
    }

    return $agent;
}

// ── Helper: Validate Required JSON Fields ────────────────────
/**
 * Decodes the raw JSON request body and ensures that all
 * required fields are present. Returns the decoded associative
 * array, or sends a 400 response if validation fails.
 *
 * @param array $requiredFields  List of field names that must exist
 * @return array                 The decoded JSON payload
 */
function validateJsonBody(array $requiredFields): array
{
    // Read the raw POST body
    $rawBody = file_get_contents('php://input');
    $data    = json_decode($rawBody, true);

    // Check if JSON decoding succeeded
    if (!is_array($data)) {
        jsonResponse(400, [
            'status'  => 'error',
            'message' => 'Invalid or missing JSON body.',
        ]);
    }

    // Check each required field
    $missing = [];
    foreach ($requiredFields as $field) {
        if (!array_key_exists($field, $data) || $data[$field] === '' || $data[$field] === null) {
            $missing[] = $field;
        }
    }

    if (!empty($missing)) {
        jsonResponse(400, [
            'status'  => 'error',
            'message' => 'Missing required fields: ' . implode(', ', $missing),
        ]);
    }

    return $data;
}
