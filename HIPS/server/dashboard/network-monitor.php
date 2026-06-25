<?php
$currentPage = 'network-monitor';
require_once 'includes/session.php';

$networkEvents = $pdo->query(
    "SELECT e.*, ag.hostname FROM events e
     LEFT JOIN agents ag ON e.agent_id = ag.id
     WHERE e.module = 'network'
     ORDER BY e.created_at DESC LIMIT 20"
)->fetchAll();

$totalNetEvents = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='network'")->fetchColumn();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Network Monitor</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>Network Monitor</h1><span class="breadcrumb">HIPS / Monitoring / Network</span></div>
        </div>

        <div class="status-strip animate-fadeIn delay-1">
            <div class="strip-item"><span class="status-dot online"></span><span class="value">Monitor Active</span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Total Events</span><span class="value"><?= $totalNetEvents ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Interface</span><span class="value">Ethernet (Primary)</span></div>
        </div>

        <div class="grid-2" style="margin-bottom:20px;">
            <!-- Active Connections -->
            <div class="card animate-fadeIn delay-2">
                <div class="card-title"><span class="icon">🔗</span> Active Connections (Sample)</div>
                <div style="overflow-x:auto;">
                <table class="data-table">
                    <thead><tr><th>Local</th><th>Remote</th><th>Protocol</th><th>Status</th><th>Threat</th></tr></thead>
                    <tbody>
                        <tr><td style="font-size:12px;">0.0.0.0:80</td><td style="font-size:12px;">0.0.0.0:0</td><td>TCP</td><td style="color:var(--severity-low);">LISTENING</td><td><span class="badge low">Low</span></td></tr>
                        <tr><td style="font-size:12px;">0.0.0.0:443</td><td style="font-size:12px;">0.0.0.0:0</td><td>TCP</td><td style="color:var(--severity-low);">LISTENING</td><td><span class="badge low">Low</span></td></tr>
                        <tr><td style="font-size:12px;">0.0.0.0:3306</td><td style="font-size:12px;">0.0.0.0:0</td><td>TCP</td><td style="color:var(--severity-medium);">LISTENING</td><td><span class="badge high">High</span></td></tr>
                    </tbody>
                </table>
                </div>
            </div>

            <!-- Open Ports -->
            <div class="card animate-fadeIn delay-2">
                <div class="card-title"><span class="icon">🚪</span> Open Ports</div>
                <table class="data-table">
                    <thead><tr><th>Port</th><th>Service</th><th>Risk</th></tr></thead>
                    <tbody>
                        <tr><td>80</td><td>HTTP (Apache)</td><td><span class="badge low">Low</span></td></tr>
                        <tr><td>443</td><td>HTTPS</td><td><span class="badge low">Low</span></td></tr>
                        <tr><td>3306</td><td>MySQL</td><td><span class="badge high">High</span></td></tr>
                        <tr><td>3389</td><td>RDP</td><td><span class="badge critical">Critical</span></td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="grid-2" style="margin-bottom:20px;">
            <!-- IP Blacklist -->
            <div class="card animate-fadeIn delay-3">
                <div class="card-title"><span class="icon">🚫</span> IP Blacklist</div>
                <table class="data-table">
                    <thead><tr><th>IP Address</th><th>Reason</th><th>Added</th><th>Action</th></tr></thead>
                    <tbody>
                        <tr><td style="font-family:'JetBrains Mono',monospace;">198.51.100.1</td><td>Known malicious</td><td>Apr 14</td><td><button class="btn btn-danger btn-sm">Remove</button></td></tr>
                        <tr><td style="font-family:'JetBrains Mono',monospace;">203.0.113.50</td><td>C2 server</td><td>Apr 14</td><td><button class="btn btn-danger btn-sm">Remove</button></td></tr>
                    </tbody>
                </table>
                <div style="margin-top:12px;display:flex;gap:8px;">
                    <input type="text" class="form-control" placeholder="Enter IP to block..." style="flex:1;">
                    <button class="btn btn-primary btn-sm">+ Block</button>
                </div>
            </div>

            <!-- Traffic Chart -->
            <div class="card animate-fadeIn delay-3">
                <div class="card-title"><span class="icon">📊</span> Inbound vs Outbound Traffic</div>
                <div class="chart-container">
                    <canvas id="trafficChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Recent Network Events -->
        <div class="card animate-fadeIn delay-4">
            <div class="card-title"><span class="icon">🌐</span> Recent Network Events</div>
            <div style="overflow-x:auto;">
            <table class="data-table">
                <thead><tr><th>Time</th><th>Agent</th><th>Event Type</th><th>Severity</th><th>Destination</th></tr></thead>
                <tbody>
                    <?php if (empty($networkEvents)): ?>
                    <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:30px;">No network events recorded yet.</td></tr>
                    <?php else: foreach ($networkEvents as $e): ?>
                    <tr>
                        <td style="font-size:12px;color:var(--text-muted);"><?= date('M j, H:i:s', strtotime($e['created_at'])) ?></td>
                        <td><?= htmlspecialchars($e['hostname'] ?? 'N/A') ?></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($e['event_type']) ?></td>
                        <td><span class="badge <?= strtolower($e['severity']) ?>"><?= $e['severity'] ?></span></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($e['destination'] ?? 'N/A') ?></td>
                    </tr>
                    <?php endforeach; endif; ?>
                </tbody>
            </table>
            </div>
        </div>
    </main>
</div>

<script>
new Chart(document.getElementById('trafficChart').getContext('2d'), {
    type: 'bar',
    data: {
        labels: ['00:00','04:00','08:00','12:00','16:00','20:00'],
        datasets: [
            { label: 'Inbound', data: [12,8,25,38,42,15], backgroundColor: 'rgba(59,130,246,0.6)', borderRadius: 4 },
            { label: 'Outbound', data: [8,5,20,30,35,12], backgroundColor: 'rgba(6,182,212,0.6)', borderRadius: 4 }
        ]
    },
    options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#94a3b8' } } },
        scales: {
            x: { ticks: { color: '#64748b' }, grid: { color: 'rgba(56,189,248,0.05)' } },
            y: { beginAtZero: true, ticks: { color: '#64748b' }, grid: { color: 'rgba(56,189,248,0.05)' } }
        }
    }
});
</script>
</body>
</html>
