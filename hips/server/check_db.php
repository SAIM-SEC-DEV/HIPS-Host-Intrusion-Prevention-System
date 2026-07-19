<?php
require_once __DIR__ . '/config/db_connect.php';

echo "Database connection successful.\n";

$stmt = $pdo->query("SELECT * FROM agents");
$agents = $stmt->fetchAll(PDO::FETCH_ASSOC);

echo "Total agents: " . count($agents) . "\n";
foreach ($agents as $agent) {
    echo "ID: {$agent['id']}, Hostname: {$agent['hostname']}, Status: {$agent['status']}, Last Heartbeat: {$agent['last_heartbeat']}\n";
}

$stmt = $pdo->query("SELECT COUNT(*) FROM events");
echo "Total events: " . $stmt->fetchColumn() . "\n";

$stmt = $pdo->query("SELECT COUNT(*) FROM alerts");
echo "Total alerts: " . $stmt->fetchColumn() . "\n";
