<?php
/**
 * HIPS Dashboard — Session Guard
 * Checks if the user is authenticated. If not, redirects to login.
 * Include this at the top of every dashboard page.
 */
session_start();

if (!isset($_SESSION['hips_admin_id'])) {
    header('Location: index.php');
    exit;
}

// Make admin info available to all pages
$adminId       = $_SESSION['hips_admin_id'];
$adminUsername  = $_SESSION['hips_admin_username'];
$adminRole     = $_SESSION['hips_admin_role'];
$adminName     = $_SESSION['hips_admin_name'] ?? $adminUsername;

// Include database connection
require_once __DIR__ . '/../../config/db_connect.php';

// Include CSRF Protection & Audit Logger
require_once __DIR__ . '/CsrfHandler.php';
require_once __DIR__ . '/AuditLogger.php';

// Safe Auto-Setup for Whitelisting
require_once __DIR__ . '/auto_setup.php';

// ── IP Whitelist Session Guard ──────────────────────────────
$clientIp = getClientIP();

$wlEnabled = $pdo->query("SELECT setting_value FROM settings WHERE setting_key = 'ip_whitelist_enabled'")->fetchColumn();

if ($wlEnabled === '1' && $clientIp !== '127.0.0.1') {
    $wlStmt = $pdo->prepare("SELECT id FROM ip_whitelist WHERE ip_address = :ip LIMIT 1");
    $wlStmt->execute([':ip' => $clientIp]);
    if (!$wlStmt->fetch()) {
        session_destroy();
        header('Location: index.php?error=ip_blocked');
        exit;
    }
}

// ── Password Change Enforcement ─────────────────────────────
// If the user is flagged to change their password, block all pages
// except the settings (account tab) and the logout script.
$isSettingsPage = basename($_SERVER['PHP_SELF']) === 'settings.php';
$isAccountTab   = ($_GET['tab'] ?? '') === 'account' || ($_POST['tab'] ?? '') === 'account';

if (!empty($_SESSION['hips_must_change_password'])) {
    if (!$isSettingsPage || !$isAccountTab) {
        header('Location: settings.php?tab=account&force_password_change=1');
        exit;
    }
}
