<?php
$currentPage = 'commands';
require_once 'includes/session.php';

// Handle command dispatch
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $agentId    = (int)($_POST['agent_id'] ?? 0);
    $cmdType    = $_POST['command_type'] ?? '';
    $paramsJson = $_POST['parameters'] ?? '{}';
    $priority   = $_POST['priority'] ?? 'normal';
    $note       = $_POST['admin_note'] ?? '';

    if ($agentId > 0 && $cmdType) {
        // Validate JSON
        $decoded = json_decode($paramsJson, true);
        if ($decoded === null && $paramsJson !== '{}' && $paramsJson !== '') {
            $error = "Invalid JSON parameters.";
        } else {
            $stmt = $pdo->prepare(
                "INSERT INTO commands (agent_id, command_type, parameters_json, priority, admin_note, issued_by)
                 VALUES (:agent_id, :cmd_type, :params, :priority, :note, :user)"
            );
            $stmt->execute([
                ':agent_id' => $agentId,
                ':cmd_type' => $cmdType,
                ':params'   => $paramsJson ?: null,
                ':priority' => $priority,
                ':note'     => $note,
                ':user'     => $adminUsername,
            ]);
            $success = "Command dispatched successfully!";
        }
    }
}

$agents = $pdo->query("SELECT id, hostname, status FROM agents ORDER BY hostname")->fetchAll();
$recentCmds = $pdo->query(
    "SELECT c.*, ag.hostname FROM commands c
     LEFT JOIN agents ag ON c.agent_id = ag.id
     ORDER BY c.issued_at DESC LIMIT 10"
)->fetchAll();

$preselectedAgent = $_GET['agent'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Send Command</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>Send Command</h1><span class="breadcrumb">HIPS / Management / Commands</span></div>
        </div>

        <?php if (isset($success)): ?>
        <div style="background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:var(--radius-sm);padding:12px;margin-bottom:16px;color:var(--severity-low);font-size:13px;">✓ <?= $success ?></div>
        <?php elseif (isset($error)): ?>
        <div class="login-error" style="margin-bottom:16px;"><?= $error ?></div>
        <?php endif; ?>

        <div class="grid-2-1">
            <!-- Command Form -->
            <div class="card animate-fadeIn delay-1">
                <div class="card-title"><span class="icon">⌨</span> Dispatch Command</div>
                <form method="POST">
                    <div class="form-group">
                        <label for="agent_id">Target Agent</label>
                        <select name="agent_id" id="agent_id" class="form-control" required>
                            <option value="">Select an agent...</option>
                            <?php foreach ($agents as $a): ?>
                            <option value="<?= $a['id'] ?>" <?= $preselectedAgent==$a['id']?'selected':'' ?>><?= htmlspecialchars($a['hostname']) ?> (<?= $a['status'] ?>)</option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="command_type">Command Type</label>
                        <select name="command_type" id="command_type" class="form-control" required>
                            <option value="">Select command...</option>
                            <option value="BLOCK_IP">BLOCK_IP — Block a malicious IP</option>
                            <option value="UNBLOCK_IP">UNBLOCK_IP — Remove IP block</option>
                            <option value="SCAN_FILE">SCAN_FILE — Integrity check file</option>
                            <option value="FULL_SCAN">FULL_SCAN — Complete hash scan</option>
                            <option value="RESTART">RESTART — Restart agent</option>
                            <option value="SHUTDOWN">SHUTDOWN — Stop agent</option>
                            <option value="UPDATE_RULES">UPDATE_RULES — Reload rules</option>
                            <option value="WHITELIST_ADD">WHITELIST_ADD — Whitelist a trusted IP</option>
                            <option value="WHITELIST_REMOVE">WHITELIST_REMOVE — Remove IP from whitelist</option>
                            <option value="LIST_PROCESSES">LIST_PROCESSES — Trigger process snapshot</option>
                            <option value="SCAN_REGISTRY">SCAN_REGISTRY — Initiates registry scan</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="parameters">JSON Parameters</label>
                        <textarea name="parameters" id="parameters" class="form-control" placeholder='{"ip": "192.168.1.100"}'>{}</textarea>
                    </div>
                    <div class="form-group">
                        <label for="admin_note">Admin Note</label>
                        <input type="text" name="admin_note" id="admin_note" class="form-control" placeholder="Reason for this command...">
                    </div>
                    <div class="form-group">
                        <label for="priority">Priority</label>
                        <select name="priority" id="priority" class="form-control">
                            <option value="normal">Normal</option>
                            <option value="high">High</option>
                            <option value="critical">Critical</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary" style="width:100%;">🚀 Send Command</button>
                </form>
            </div>

            <!-- Command Reference -->
            <div class="card animate-fadeIn delay-2">
                <div class="card-title"><span class="icon">📖</span> Command Reference</div>
                <div style="font-size:12px;">
                    <?php
                    $cmds = [
                        ['BLOCK_IP', 'Block an IP via Windows Firewall', '{"ip":"x.x.x.x"}'],
                        ['UNBLOCK_IP', 'Remove a firewall block rule', '{"ip":"x.x.x.x"}'],
                        ['SCAN_FILE', 'Hash-check a specific file', '{"path":"C:\\\\..."}'],
                        ['FULL_SCAN', 'Re-hash all monitored files', '{}'],
                        ['RESTART', 'Restart the agent service', '{}'],
                        ['SHUTDOWN', 'Stop the agent gracefully', '{}'],
                        ['UPDATE_RULES', 'Reload detection rules', '{}'],
                        ['WHITELIST_ADD', 'Whitelist a trusted IP', '{"ip":"192.168.1.100"}'],
                        ['WHITELIST_REMOVE', 'Remove IP from whitelist', '{"ip":"192.168.1.100"}'],
                        ['LIST_PROCESSES', 'Take a new process snapshot', '{}'],
                        ['SCAN_REGISTRY', 'Trigger immediate registry scan', '{}'],
                    ];
                    foreach ($cmds as $c):
                    ?>
                    <div style="padding:8px 0;border-bottom:1px solid var(--border-color);">
                        <strong style="color:var(--accent-cyan);font-family:'JetBrains Mono',monospace;"><?= $c[0] ?></strong>
                        <div style="color:var(--text-secondary);margin:2px 0;"><?= $c[1] ?></div>
                        <code style="font-size:11px;color:var(--text-muted);"><?= $c[2] ?></code>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>

        <!-- Recent Commands -->
        <div class="card animate-fadeIn delay-3" style="margin-top:20px;">
            <div class="card-title"><span class="icon">📜</span> Recent Commands</div>
            <table class="data-table">
                <thead><tr><th>ID</th><th>Agent</th><th>Command</th><th>Priority</th><th>Status</th><th>Issued</th><th>By</th></tr></thead>
                <tbody>
                    <?php foreach ($recentCmds as $c): ?>
                    <tr>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;">#<?= $c['id'] ?></td>
                        <td><?= htmlspecialchars($c['hostname'] ?? 'N/A') ?></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent-cyan);"><?= $c['command_type'] ?></td>
                        <td><span class="badge <?= $c['priority']==='critical'?'critical':($c['priority']==='high'?'high':'low') ?>"><?= ucfirst($c['priority']) ?></span></td>
                        <td><span class="badge <?= $c['status']==='completed'?'online':($c['status']==='failed'?'critical':'medium') ?>"><?= ucfirst($c['status']) ?></span></td>
                        <td style="font-size:12px;color:var(--text-muted);"><?= date('M j, H:i', strtotime($c['issued_at'])) ?></td>
                        <td style="font-size:12px;"><?= htmlspecialchars($c['issued_by'] ?? 'System') ?></td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($recentCmds)): ?>
                    <tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:30px;">No commands dispatched yet.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </main>
</div>
</body>
</html>
