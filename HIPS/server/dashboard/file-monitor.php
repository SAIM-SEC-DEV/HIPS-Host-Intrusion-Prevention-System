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
    <link rel="stylesheet" href="assets/css/style.css">
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
                <div class="card-title"><span class="icon">📂</span> Watched Directories</div>
                <table class="data-table">
                    <thead><tr><th>Path</th><th>Priority</th><th>Status</th></tr></thead>
                    <tbody>
                        <tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;">C:\Windows\System32</td><td><span class="badge critical">Critical</span></td><td style="color:var(--severity-low);">✓ Clean</td></tr>
                        <tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;">User Desktop Directory</td><td><span class="badge high">High</span></td><td style="color:var(--severity-low);">✓ Clean</td></tr>
                        <tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;">C:\Program Files</td><td><span class="badge high">High</span></td><td style="color:var(--severity-low);">✓ Clean</td></tr>
                        <tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;">C:\ProgramData</td><td><span class="badge medium">Medium</span></td><td style="color:var(--severity-low);">✓ Clean</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- Active File Rules -->
            <div class="card animate-fadeIn delay-3">
                <div class="card-title"><span class="icon">📋</span> Active File Detection Rules</div>
                <div style="max-height:260px;overflow-y:auto;">
                    <?php
                    $rules = [
                        ['Sensitive Path Detection', true], ['Sensitive Extension Check', true],
                        ['Hash Integrity Verification', true], ['Off-Hours Activity Flag', true],
                        ['Whitelist Bypass Check', true], ['System Directory Protection', true],
                        ['Executable Creation Alert', true], ['DLL Modification Watch', true],
                        ['Script File Detection', true], ['Config File Monitor', true],
                        ['Registry File Watch', true], ['Batch File Execution Alert', true],
                        ['PowerShell Script Detection', true], ['Driver File Modification', true],
                        ['Recursive Directory Watch', true], ['File Deletion in Protected Paths', true],
                        ['Large File Creation Alert', true], ['Rapid File Change Detection', true],
                        ['Hidden File Detection', true], ['Temporary File Monitoring', true],
                        ['Archive Extraction Watch', true], ['Startup Folder Monitoring', true],
                        ['USB Drive File Alert', false], ['Network Share Monitoring', false],
                    ];
                    foreach ($rules as $idx => $r):
                    ?>
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--border-color);font-size:13px;">
                        <span style="color:<?= $r[1] ? 'var(--text-primary)' : 'var(--text-muted)' ?>;"><?= $r[0] ?></span>
                        <label class="toggle-switch"><input type="checkbox" <?= $r[1] ? 'checked' : '' ?>><span class="toggle-slider"></span></label>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>

        <!-- Recent File Events -->
        <div class="card animate-fadeIn delay-3">
            <div class="card-title"><span class="icon">📄</span> Recent File Events</div>
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
