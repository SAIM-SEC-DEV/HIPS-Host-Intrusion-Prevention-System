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
