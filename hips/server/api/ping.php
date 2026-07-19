<?php
/**
 * ============================================================
 * HIPS — API Ping / Diagnostic Endpoint
 * ============================================================
 * Simple endpoint for agents or users to verify server health.
 */
header('Content-Type: application/json');

$response = [
    'status' => 'ok',
    'timestamp' => date('Y-m-d H:i:s'),
    'server' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
    'php_version' => PHP_VERSION,
    'database' => 'unknown'
];

try {
    require_once __DIR__ . '/../config/db_connect.php';
    if ($pdo) {
        $response['database'] = 'connected';
    }
} catch (Exception $e) {
    $response['database'] = 'error: ' . $e->getMessage();
    http_response_code(500);
}

echo json_encode($response, JSON_PRETTY_PRINT);
