<?php
/**
 * ============================================================
 * HIPS — Host Intrusion Prevention System
 * API Endpoint: /api/auth.php
 * ============================================================
 *
 * Purpose:
 *   Authenticates dashboard administrators. The login page
 *   POSTs credentials here. On success, a PHP session is
 *   started and the admin is redirected to the dashboard.
 *
 * HTTP Method: POST
 *
 * Request Body (form-encoded or JSON):
 *   {
 *     "username":  "admin",
 *     "password":  "HipsAdmin@2024",
 *     "api_token": "abc123..."
 *   }
 *
 * @package HIPS\API
 */

declare(strict_types=1);

session_start();

require_once __DIR__ . '/../config/db_connect.php';

// ── IP Whitelist Access Control ──────────────────────────────
// This check blocks unauthorized network sources from even
// attempting to authenticate.
$clientIp = getClientIP();

// Only enforce if the feature is explicitly enabled in settings
$wlEnabled = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'ip_whitelist_enabled'")->fetchColumn();

if ($wlEnabled === '1' && $clientIp !== '127.0.0.1') {
    $wlStmt = $pdo->prepare("SELECT id FROM ip_whitelist WHERE ip_address = :ip LIMIT 1");
    $wlStmt->execute([':ip' => $clientIp]);
    if (!$wlStmt->fetch()) {
        error_log("[HIPS Security] Blocked login attempt from non-whitelisted IP: $clientIp");
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        if (!str_contains($contentType, 'application/json')) {
            header('Location: ../dashboard/index.php?error=ip_blocked');
            exit;
        }
        jsonResponse(403, [
            'status' => 'error',
            'message' => 'Access denied. Your IP address is not whitelisted.'
        ]);
    }
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(405, ['status' => 'error', 'message' => 'Method not allowed. Use POST.']);
}

// ── Extract credentials ──────────────────────────────────────
// Support both form-encoded (from the dashboard login form)
// and JSON request bodies.
$contentType = $_SERVER['CONTENT_TYPE'] ?? '';

if (str_contains($contentType, 'application/json')) {
    $data = validateJsonBody(['username', 'password']);
} else {
    // Form-encoded POST from the login page
    $data = [
        'username'  => $_POST['username']  ?? '',
        'password'  => $_POST['password']  ?? '',
        'api_token' => $_POST['api_token'] ?? '',
    ];
}

$username = trim($data['username']);
$password = $data['password'];
$apiToken = trim($data['api_token'] ?? '');

if (empty($username) || empty($password)) {
    // If form-encoded, redirect back to login with error
    if (!str_contains($contentType, 'application/json')) {
        header('Location: ../dashboard/index.php?error=missing_credentials');
        exit;
    }
    jsonResponse(400, ['status' => 'error', 'message' => 'Username and password are required.']);
}

try {
    // ── Look up the admin account ────────────────────────────
    $stmt = $pdo->prepare(
        'SELECT * FROM dashboard_users WHERE username = :username LIMIT 1'
    );
    $stmt->execute([':username' => $username]);
    $user = $stmt->fetch();

    // ── Verify credentials ───────────────────────────────────
    // password_verify() safely compares the plaintext password
    // against the bcrypt hash stored in the database. It is
    // timing-safe to prevent timing-based attacks.
    if (!$user || !password_verify($password, $user['password_hash'])) {
        if (!str_contains($contentType, 'application/json')) {
            header('Location: ../dashboard/index.php?error=invalid_credentials');
            exit;
        }
        jsonResponse(401, ['status' => 'error', 'message' => 'Invalid username or password.']);
    }

    // ── Verify API token if provided ─────────────────────────
    // The API token adds a second factor of authentication.
    // If the admin provides one, it must match.
    if (!empty($apiToken) && $apiToken !== $user['api_token']) {
        if (!str_contains($contentType, 'application/json')) {
            header('Location: ../dashboard/index.php?error=invalid_token');
            exit;
        }
        jsonResponse(401, ['status' => 'error', 'message' => 'Invalid API token.']);
    }

    // ── Update last login timestamp ──────────────────────────
    $updateStmt = $pdo->prepare(
        'UPDATE dashboard_users SET last_login = NOW() WHERE id = :id'
    );
    $updateStmt->execute([':id' => $user['id']]);

    // ── Create the admin session ─────────────────────────────
    // Regenerate session ID to prevent session fixation attacks.
    session_regenerate_id(true);

    $_SESSION['hips_admin_id']       = $user['id'];
    $_SESSION['hips_admin_username'] = $user['username'];
    $_SESSION['hips_admin_role']     = $user['role'];
    $_SESSION['hips_admin_name']     = $user['display_name'];
    $_SESSION['hips_login_time']     = time();

    // ── Enforce password change for default accounts ─────────
    // If the must_change_password flag is set (e.g., default admin
    // account on first login), redirect to settings page instead
    // of the dashboard to force a password update.
    $mustChangePassword = !empty($user['must_change_password']);
    $_SESSION['hips_must_change_password'] = $mustChangePassword;

    // ── Redirect to dashboard or return JSON ─────────────────
    if (!str_contains($contentType, 'application/json')) {
        if ($mustChangePassword) {
            header('Location: ../dashboard/settings.php?force_password_change=1');
        } else {
            header('Location: ../dashboard/dashboard.php');
        }
        exit;
    }

    jsonResponse(200, [
        'status'  => 'success',
        'message' => 'Login successful.',
        'user'    => [
            'id'       => $user['id'],
            'username' => $user['username'],
            'role'     => $user['role'],
            'name'     => $user['display_name'],
        ],
    ]);

} catch (PDOException $e) {
    error_log('[HIPS] Auth failed: ' . $e->getMessage());
    if (!str_contains($contentType, 'application/json')) {
        header('Location: ../dashboard/index.php?error=server_error');
        exit;
    }
    jsonResponse(500, ['status' => 'error', 'message' => 'Authentication failed. Server error.']);
}
