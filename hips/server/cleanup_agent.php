<?php
require_once 'config/db_connect.php';
try {
    // Clean up foreign key references first (if they don't cascade)
    $pdo->exec('DELETE FROM alerts WHERE agent_id = 2');
    $pdo->exec('DELETE FROM events WHERE agent_id = 2');
    $pdo->exec('DELETE FROM commands WHERE agent_id = 2');
    // Delete the agent itself
    $deleted = $pdo->exec('DELETE FROM agents WHERE id = 2');
    echo json_encode(["status" => "success", "message" => "Cleaned up Agent 2. Deleted $deleted agents."]);
} catch (Exception $e) {
    echo json_encode(["status" => "error", "message" => $e->getMessage()]);
}
?>
