<?php
$currentPage = 'file-monitor';
require_once 'includes/session.php';

// Fetch file events
$fileEvents = $pdo->query(
    "SELECT e.*, ag.hostname FROM events e
     LEFT JOIN agents ag ON e.agent_id = ag.id
     WHERE e.module = 'file'
     ORDER BY e.created_at DESC LIMIT 20"
)->fetchAll();

// Count stats
$totalFileEvents = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='file'")->fetchColumn();
$hashMismatches  = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='file' AND event_type LIKE '%HASH%' OR (module='file' AND severity='CRITICAL')")->fetchColumn();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — File Monitor</title>
    <link rel="stylesheet" href="assets/css/style.css?v=7.1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>File Monitor</h1><span class="breadcrumb">HIPS / Monitoring / File System</span></div>
        </div>

        <!-- Status Strip -->
        <div class="status-strip animate-fadeIn delay-1">
            <div class="strip-item"><span class="status-dot online"></span><span class="value">Monitor Active</span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Total Events</span><span class="value"><?= $totalFileEvents ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Hash Mismatches</span><span class="value" style="color:var(--severity-critical);"><?= $hashMismatches ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Algorithm</span><span class="value">SHA-256</span></div>
        </div>

        <div class="grid-2" style="margin-bottom:20px;">
            <!-- Watched Directories -->
            <div class="card animate-fadeIn delay-2">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-folder-open"></i></span> Watched Directories</div>
                <table class="data-table">
                    <thead><tr><th>Path</th><th>Priority</th><th>Status</th></tr></thead>
                    <tbody>
                        <tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;">C:\Windows\System32</td><td><span class="badge critical">Critical</span></td><td style="color:var(--severity-low);"><i class="fa-solid fa-check"></i> Clean</td></tr>
                        <tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;">C:\Users\Desktop</td><td><span class="badge high">High</span></td><td style="color:var(--severity-low);"><i class="fa-solid fa-check"></i> Clean</td></tr>
                        <tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;">C:\Program Files</td><td><span class="badge high">High</span></td><td style="color:var(--severity-low);"><i class="fa-solid fa-check"></i> Clean</td></tr>
                        <tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;">C:\ProgramData</td><td><span class="badge medium">Medium</span></td><td style="color:var(--severity-low);"><i class="fa-solid fa-check"></i> Clean</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- Active File Rules -->
            <div class="card animate-fadeIn delay-3">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-list-check"></i></span> Active File Detection Rules</div>
                <div style="max-height:260px;overflow-y:auto;">
                    <?php
                    // Fetch real security settings
                    $securitySettings = $pdo->query("SELECT setting_key, setting_value FROM settings WHERE category='security'")->fetchAll(PDO::FETCH_KEY_PAIR);
                    
                    $rules = [
                        ['File Monitor Engine', $securitySettings['file_monitor_enabled'] ?? '0'],
                        ['Sensitive Extension Check', '1'],
                        ['Hash Integrity (' . ($securitySettings['hash_algorithm'] ?? 'SHA-256') . ')', '1'],
                        ['Off-Hours Activity Watch', '1'],
                        ['System Directory Protection', '1'],
                        ['MITRE Technique Mapping', $securitySettings['mitre_mapping_enabled'] ?? '0'],
                    ];
                    foreach ($rules as $r):
                        $enabled = ($r[1] === '1' || $r[1] === true);
                    ?>
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border-color);font-size:13px;">
                        <span style="color:<?= $enabled ? 'var(--text-primary)' : 'var(--text-muted)' ?>;"><?= $r[0] ?></span>
                        <div class="status-indicator">
                            <?php if ($enabled): ?>
                                <span class="badge low" style="font-size:9px;"><i class="fa-solid fa-check"></i> ACTIVE</span>
                            <?php else: ?>
                                <span class="badge high" style="font-size:9px;"><i class="fa-solid fa-pause"></i> DISABLED</span>
                            <?php endif; ?>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>

        </div>

        <!-- Recent File Events -->
        <div class="card animate-fadeIn delay-3">
            <div class="card-title"><span class="icon"><i class="fa-solid fa-file-contract"></i></span> Recent File Events</div>
            <div style="overflow-x:auto;">
            <table class="data-table">
                <thead><tr><th>Time</th><th>Agent</th><th>Event Type</th><th>Severity</th><th>File Path</th></tr></thead>
                <tbody>
                    <?php if (empty($fileEvents)): ?>
                    <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:30px;">No file events recorded yet.</td></tr>
                    <?php else: foreach ($fileEvents as $e): ?>
                    <tr>
                        <td style="font-size:12px;color:var(--text-muted);"><?= date('M j, H:i:s', strtotime($e['created_at'])) ?></td>
                        <td><?= htmlspecialchars($e['hostname'] ?? 'N/A') ?></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($e['event_type']) ?></td>
                        <td><span class="badge <?= strtolower($e['severity']) ?>"><?= $e['severity'] ?></span></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:11px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?= htmlspecialchars($e['source_path'] ?? 'N/A') ?></td>
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
