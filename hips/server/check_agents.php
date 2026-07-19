<?php
require_once 'config/db_connect.php';
$stmt = $pdo->query("SELECT id, agent_uuid, hostname, ip_address, status, last_heartbeat FROM agents");
echo json_encode($stmt->fetchAll(), JSON_PRETTY_PRINT);
?>
