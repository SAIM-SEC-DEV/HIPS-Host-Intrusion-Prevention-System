<?php
$currentPage = 'registry-monitor';
require_once 'includes/session.php';

$registryEvents = $pdo->query(
    "SELECT e.*, ag.hostname FROM events e
     LEFT JOIN agents ag ON e.agent_id = ag.id
     WHERE e.module = 'registry'
     ORDER BY e.created_at DESC LIMIT 50"
)->fetchAll();

$totalRegEvents = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='registry'")->fetchColumn();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Registry Monitor</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>Registry Monitor</h1><span class="breadcrumb">HIPS / Monitoring / Registry</span></div>
        </div>

        <div class="status-strip animate-fadeIn delay-1">
            <div class="strip-item"><span class="status-dot online"></span><span class="value">Monitor Active</span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Total Events</span><span class="value"><?= $totalRegEvents ?></span></div>
        </div>

        <!-- Recent Registry Events -->
        <div class="card animate-fadeIn delay-2">
            <div class="card-title"><span class="icon">📝</span> Registry Integrity Events</div>
            <div style="overflow-x:auto;">
            <table class="data-table">
                <thead><tr><th>Time</th><th>Agent</th><th>Event Type</th><th>Severity</th><th>Description</th><th>MITRE ATT&CK</th></tr></thead>
                <tbody>
                    <?php if (empty($registryEvents)): ?>
                    <tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:30px;">No registry events recorded yet.</td></tr>
                    <?php else: foreach ($registryEvents as $e): ?>
                    <tr>
                        <td style="font-size:12px;color:var(--text-muted);"><?= date('M j, H:i:s', strtotime($e['created_at'])) ?></td>
                        <td><?= htmlspecialchars($e['hostname'] ?? 'N/A') ?></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($e['event_type']) ?></td>
                        <td><span class="badge <?= strtolower($e['severity']) ?>"><?= $e['severity'] ?></span></td>
                        <td style="font-size:12px;"><?= htmlspecialchars($e['description']) ?></td>
                        <td style="font-size:11px;color:var(--text-secondary);">
                            <?php if ($e['mitre_technique_id']): ?>
                            🛡️ <?= htmlspecialchars($e['mitre_technique_id']) ?>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; endif; ?>
                </tbody>
            </table>
            </div>
        </div>
    </main>
</div>
</body>
</html>
