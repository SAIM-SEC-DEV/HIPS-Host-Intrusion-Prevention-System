<?php
require_once 'config/db_connect.php';
// Simulate an agent reporting a HIGH severity event
$data = [
    'module' => 'network',
    'event_type' => 'UNKNOWN_EXTERNAL_CONN',
    'severity' => 'HIGH',
    'title' => 'TEST Unknown External Connection',
    'description' => 'Test connection to 8.8.8.8',
    'destination' => '8.8.8.8',
    'auth_token' => 'test-token'
];

// We need a real agent token to test authenticateAgent
$agent = $pdo->query("SELECT auth_token FROM agents LIMIT 1")->fetchColumn();
if (!$agent) {
    echo "Error: No agent found in DB.";
    exit;
}

// Prepare curl request to report.php
$url = 'http://localhost/hips/api/report.php';
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Content-Type: application/json',
    'Authorization: Bearer ' . $agent
]);

$response = curl_exec($ch);
echo "Response: " . $response;
curl_close($ch);
?>
