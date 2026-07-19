<?php
$currentPage = 'memory-monitor';
require_once 'includes/session.php';

// Fetch memory events
$memoryEvents = $pdo->query(
    "SELECT e.*, ag.hostname FROM events e
     LEFT JOIN agents ag ON e.agent_id = ag.id
     WHERE e.module = 'memory'
     ORDER BY e.created_at DESC LIMIT 20"
)->fetchAll();

// Count stats
$totalMemoryEvents = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='memory'")->fetchColumn();
$filelessThreats  = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='memory' AND severity='CRITICAL'")->fetchColumn();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Memory Analysis</title>
    <link rel="stylesheet" href="assets/css/style.css?v=7.1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>Memory Analysis</h1><span class="breadcrumb">HIPS / Monitoring / Memory</span></div>
        </div>

        <!-- Status Strip -->
        <div class="status-strip animate-fadeIn delay-1">
            <div class="strip-item"><span class="status-dot online"></span><span class="value">Scanner Active</span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Total Scans Logged</span><span class="value"><?= $totalMemoryEvents ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Fileless Threats</span><span class="value" style="color:var(--severity-critical);"><?= $filelessThreats ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Engine</span><span class="value">YARA Memory</span></div>
        </div>

        <div class="grid-2" style="margin-bottom:20px;">
            <!-- Targeted Processes -->
            <div class="card animate-fadeIn delay-2">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-brain"></i></span> Active Process Scanning Targets</div>
                <table class="data-table">
                    <thead><tr><th>Process Name</th><th>Priority</th><th>Status</th></tr></thead>
                    <tbody>
                        <tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;">powershell.exe</td><td><span class="badge critical">Critical</span></td><td style="color:var(--severity-low);"><i class="fa-solid fa-check"></i> Clean</td></tr>
                        <tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;">cmd.exe</td><td><span class="badge high">High</span></td><td style="color:var(--severity-low);"><i class="fa-solid fa-check"></i> Clean</td></tr>
                        <tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;">wscript.exe</td><td><span class="badge high">High</span></td><td style="color:var(--severity-low);"><i class="fa-solid fa-check"></i> Clean</td></tr>
                        <tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px;">svchost.exe</td><td><span class="badge medium">Medium</span></td><td style="color:var(--severity-low);"><i class="fa-solid fa-check"></i> Clean</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- Active Memory Rules -->
            <div class="card animate-fadeIn delay-3">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-clipboard-list"></i></span> Fileless Malware Detection Rules</div>
                <div style="max-height:260px;overflow-y:auto;">
                    <?php
                    $rules = [
                        ['Reflective DLL Injection', true], ['Process Hollowing Check', true],
                        ['Meterpreter Shellcode Detection', true], ['Cobalt Strike Beacon Hunt', true],
                        ['Suspicious RWX Memory Regions', true], ['PowerShell Obfuscation Watch', true],
                        ['Mimikatz Password Dumper', true], ['Empire Agent Detection', true],
                        ['In-Memory Crypto Miners', true], ['Heap Spray Detection', false],
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

        <!-- Recent Memory Events -->
        <div class="card animate-fadeIn delay-3">
            <div class="card-title"><span class="icon"><i class="fa-solid fa-memory"></i></span> Recent Memory Events</div>
            <div style="overflow-x:auto;">
            <table class="data-table">
                <thead><tr><th>Time</th><th>Agent</th><th>Event Type</th><th>Severity</th><th>Process Info</th></tr></thead>
                <tbody>
                    <?php if (empty($memoryEvents)): ?>
                    <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:30px;">No memory anomalies recorded yet.</td></tr>
                    <?php else: foreach ($memoryEvents as $e): ?>
                    <tr>
                        <td style="font-size:12px;color:var(--text-muted);"><?= date('M j, H:i:s', strtotime($e['created_at'])) ?></td>
                        <td><?= htmlspecialchars($e['hostname'] ?? 'N/A') ?></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($e['event_type']) ?></td>
                        <td><span class="badge <?= strtolower($e['severity']) ?>"><?= $e['severity'] ?></span></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:11px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?= htmlspecialchars($e['description'] ?? 'N/A') ?></td>
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
