<?php
/**
 * ============================================================
 * HIPS — First-Time Setup Script
 * ============================================================
 * Run this script ONCE after importing schema.sql to set the
 * default admin password with a proper bcrypt hash.
 *
 * Usage:
 *   1. Open http://localhost/hips/setup.php in your browser
 *   2. The script will create/update the admin account
 *   3. Delete this file after setup for security!
 *
 * Default credentials:
 *   Username: admin
 *   Password: HipsAdmin@2024
 */

declare(strict_types=1);

require_once __DIR__ . '/config/db_connect.php';

// ── Default admin credentials ────────────────────────────────
$username    = 'admin';
$password    = 'HipsAdmin@2024';
$displayName = 'System Administrator';
$role        = 'admin';

// ── Generate bcrypt hash ─────────────────────────────────────
// password_hash() with PASSWORD_BCRYPT generates a 60-character
// hash using a random salt. Cost factor 12 balances security & speed.
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

// ── Generate a secure API token ──────────────────────────────
$apiToken = bin2hex(random_bytes(32));

// ── Insert or update the admin account ───────────────────────
try {
    // Check if admin already exists
    $check = $pdo->prepare("SELECT id FROM dashboard_users WHERE username = :user LIMIT 1");
    $check->execute([':user' => $username]);
    $existing = $check->fetch();

    if ($existing) {
        // Update existing admin with fresh hash and token
        $stmt = $pdo->prepare(
            "UPDATE dashboard_users SET
                password_hash = :hash,
                display_name  = :name,
                role          = :role,
                api_token     = :token
             WHERE username = :user"
        );
        $stmt->execute([
            ':hash'  => $hash,
            ':name'  => $displayName,
            ':role'  => $role,
            ':token' => $apiToken,
            ':user'  => $username,
        ]);
        $action = 'UPDATED';
    } else {
        // Insert new admin
        $stmt = $pdo->prepare(
            "INSERT INTO dashboard_users (username, password_hash, display_name, role, api_token)
             VALUES (:user, :hash, :name, :role, :token)"
        );
        $stmt->execute([
            ':user'  => $username,
            ':hash'  => $hash,
            ':name'  => $displayName,
            ':role'  => $role,
            ':token' => $apiToken,
        ]);
        $action = 'CREATED';
    }

    // Output results
    http_response_code(200);
    header('Content-Type: text/html; charset=utf-8');
    echo "<!DOCTYPE html><html><head><title>HIPS Setup</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #0a0e1a; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
        .box { background: rgba(15,23,42,0.8); border: 1px solid rgba(56,189,248,0.15); border-radius: 16px; padding: 40px; max-width: 500px; width: 100%; }
        h1 { color: #06b6d4; font-size: 22px; margin-bottom: 8px; }
        .success { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); border-radius: 8px; padding: 12px; color: #22c55e; margin: 16px 0; }
        .warn { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); border-radius: 8px; padding: 12px; color: #ef4444; margin: 16px 0; font-size: 13px; }
        table { width: 100%; border-collapse: collapse; margin: 16px 0; }
        td { padding: 8px 12px; border-bottom: 1px solid rgba(56,189,248,0.1); font-size: 14px; }
        td:first-child { color: #94a3b8; font-weight: 600; }
        code { font-family: 'Consolas', monospace; background: rgba(6,182,212,0.1); padding: 2px 6px; border-radius: 4px; font-size: 13px; }
        a { color: #06b6d4; }
    </style></head><body><div class='box'>
    <h1>🛡 HIPS Setup Complete</h1>
    <div class='success'>✓ Admin account {$action} successfully.</div>
    <table>
        <tr><td>Username</td><td><code>{$username}</code></td></tr>
        <tr><td>Password</td><td><code>{$password}</code></td></tr>
        <tr><td>API Token</td><td><code>" . substr($apiToken, 0, 16) . "...</code></td></tr>
        <tr><td>Hash Algorithm</td><td>bcrypt (cost 12)</td></tr>
    </table>
    <div class='warn'>⚠ <strong>Security Warning:</strong> Delete this file (setup.php) immediately after setup. It contains sensitive credential logic.</div>
    <p><a href='dashboard/index.php'>→ Go to Login Page</a></p>
    </div></body></html>";

} catch (PDOException $e) {
    http_response_code(500);
    echo "Setup failed: " . htmlspecialchars($e->getMessage());
}
