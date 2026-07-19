<?php
$currentPage = 'virus-total';
require_once 'includes/session.php';

// Handle VT scan dispatch
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF Protection Check
    if (!CsrfHandler::validate($_POST['csrf_token'] ?? null)) {
        die("Security violation: CSRF token invalid or missing.");
    }

    $action = $_POST['action'] ?? '';
    $agentId = (int)($_POST['agent_id'] ?? 0);
    $filePath = trim($_POST['file_path'] ?? '');

    if ($agentId > 0 && $filePath) {
        if ($action === 'scan') {
            $paramsJson = json_encode(['path' => $filePath]);
            $stmt = $pdo->prepare(
                "INSERT INTO commands (agent_id, command_type, parameters_json, priority, admin_note, issued_by)
                 VALUES (:agent_id, 'VT_SCAN_FILE', :params, 'high', 'Manual VT Triage', :user)"
            );
            $stmt->execute([
                ':agent_id' => $agentId,
                ':params'   => $paramsJson,
                ':user'     => $adminUsername,
            ]);
            $success = "VT Scan command dispatched successfully! The agent will return the result shortly.";
        } elseif ($action === 'quarantine') {
            $paramsJson = json_encode(['path' => $filePath]);
            $stmt = $pdo->prepare(
                "INSERT INTO commands (agent_id, command_type, parameters_json, priority, admin_note, issued_by)
                 VALUES (:agent_id, 'QUARANTINE_FILE', :params, 'critical', 'Manual Quarantine', :user)"
            );
            $stmt->execute([
                ':agent_id' => $agentId,
                ':params'   => $paramsJson,
                ':user'     => $adminUsername,
            ]);
            $success = "Quarantine command dispatched! The agent will kill the process and vault the file.";
        }
    }
}

$agents = $pdo->query("SELECT id, hostname, status FROM agents ORDER BY hostname")->fetchAll();

// Get recent VT scans from commands table
$recentScans = $pdo->query(
    "SELECT c.*, ag.hostname FROM commands c
     LEFT JOIN agents ag ON c.agent_id = ag.id
     WHERE c.command_type IN ('VT_SCAN_FILE', 'QUARANTINE_FILE')
     ORDER BY c.issued_at DESC LIMIT 15"
)->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Intel Analyzer</title>
    <link rel="stylesheet" href="assets/css/style.css?v=5.2">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>Intel Analyzer</h1><span class="breadcrumb">HIPS / Threat Intelligence / VirusTotal</span></div>
        </div>

        <?php if (isset($success)): ?>
        <div style="background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:var(--radius-sm);padding:12px;margin-bottom:16px;color:var(--severity-low);font-size:13px;">✓ <?= $success ?></div>
        <?php elseif (isset($error)): ?>
        <div class="login-error" style="margin-bottom:16px;"><?= $error ?></div>
        <?php endif; ?>

        <div class="grid-2-1">
            <!-- Manual Triage Form -->
            <div class="card animate-fadeIn delay-1">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-microscope"></i></span> Manual File Triage</div>
                <form method="POST">
                    <?php CsrfHandler::insertField(); ?>
                    <input type="hidden" name="action" value="scan">
                    <div class="form-group">
                        <label for="agent_id">Target Agent</label>
                        <select name="agent_id" id="agent_id" class="form-control" required>
                            <option value="">Select an agent...</option>
                            <?php foreach ($agents as $a): ?>
                            <option value="<?= $a['id'] ?>"><?= htmlspecialchars($a['hostname']) ?> (<?= $a['status'] ?>)</option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="file_path">Target File Path (Absolute path on agent machine)</label>
                        <input type="text" name="file_path" id="file_path" class="form-control" placeholder="C:\Users\Public\Downloads\suspicious.exe" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary" style="width:100%;"><i class="fa-solid fa-bolt-lightning"></i> Initiate VirusTotal Scan</button>
                </form>
                
                <div style="margin-top:20px; font-size:12px; color:var(--text-muted); border-top: 1px solid var(--border-color); padding-top:15px;">
                    <p><strong>Note:</strong> Initiating a scan will command the HIPS agent to compute the SHA-256 hash of the target file locally, then query the VirusTotal API using the ThreatIntelService.</p>
                </div>
            </div>

            <!-- Threat Intelligence Overview -->
            <div class="card animate-fadeIn delay-2">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-shield-halved"></i></span> Vendor Intelligence</div>
                <div style="display:flex; justify-content:center; align-items:center; height:150px; flex-direction:column;">
                    <div style="font-size:48px; color:var(--accent-violet);">60+</div>
                    <div style="color:var(--text-secondary); font-size:14px;">Integrated Antivirus Engines</div>
                </div>
                <div style="font-size:12px; color:var(--text-muted); text-align:center;">
                    Powered by VirusTotal API
                </div>
            </div>
        </div>

        <!-- Triage Results & Quarantine -->
        <div class="card animate-fadeIn delay-3" style="margin-top:20px;">
            <div class="card-title"><span class="icon"><i class="fa-solid fa-chart-bar"></i></span> Analysis Results</div>
            <table class="data-table">
                <thead><tr><th>Command ID</th><th>Agent</th><th>Type</th><th>File Path</th><th>Status/Result</th><th>Action</th></tr></thead>
                <tbody>
                    <?php foreach ($recentScans as $s): 
                        $params = json_decode($s['parameters_json'], true);
                        $result = json_decode($s['result_json'] ?? '{}', true);
                        $path = $params['path'] ?? 'N/A';
                    ?>
                    <tr>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;">#<?= $s['id'] ?></td>
                        <td><?= htmlspecialchars($s['hostname'] ?? 'N/A') ?></td>
                        <td style="font-size:12px;color:var(--accent-violet);"><?= $s['command_type'] ?></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:11px;"><?= htmlspecialchars($path) ?></td>
                        <td>
                            <?php if ($s['status'] === 'pending'): ?>
                                <span class="badge medium">Pending</span>
                            <?php elseif ($s['status'] === 'completed'): ?>
                                <?php if ($s['command_type'] === 'VT_SCAN_FILE'): ?>
                                    <?php 
                                        $vtScore = $result['vt_score'] ?? -1;
                                        if ($vtScore > 0) {
                                            echo "<span class='badge critical'>Malicious ({$vtScore}/70)</span>";
                                        } elseif ($vtScore === 0) {
                                            echo "<span class='badge low'>Clean (0/70)</span>";
                                        } else {
                                            echo "<span class='badge medium'>Unknown / Error</span>";
                                        }
                                    ?>
                                <?php else: ?>
                                    <span class="badge low">Quarantined</span>
                                <?php endif; ?>
                            <?php else: ?>
                                <span class="badge critical">Failed</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if ($s['status'] === 'completed' && $s['command_type'] === 'VT_SCAN_FILE' && ($result['vt_score'] ?? 0) > 0): ?>
                                <form method="POST" style="display:inline;">
                                    <?php CsrfHandler::insertField(); ?>
                                    <input type="hidden" name="action" value="quarantine">
                                    <input type="hidden" name="agent_id" value="<?= $s['agent_id'] ?>">
                                    <input type="hidden" name="file_path" value="<?= htmlspecialchars($path) ?>">
                                    <button type="submit" class="btn" style="background-color:var(--severity-critical); color:white; padding:4px 8px; font-size:11px; border:none; border-radius:4px; cursor:pointer;">Kill & Quarantine</button>
                                </form>
                            <?php else: ?>
                                <span style="color:var(--text-muted); font-size:11px;">N/A</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($recentScans)): ?>
                    <tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:30px;">No manual triage scans initiated yet.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </main>
</div>
</body>
</html>
