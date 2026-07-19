<?php
$currentPage = 'reports';
require_once 'includes/session.php';

// Fetch analytics data
$totalBlocked   = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE severity IN ('CRITICAL','HIGH')")->fetchColumn();
$totalFileEvt   = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='file'")->fetchColumn();
$totalNetEvt    = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='network'")->fetchColumn();

// Severity distribution
$critCount = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE severity='CRITICAL'")->fetchColumn();
$highCount = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE severity='HIGH'")->fetchColumn();
$medCount  = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE severity='MEDIUM'")->fetchColumn();
$lowCount  = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE severity='LOW'")->fetchColumn();
$totalAll  = max(1, $critCount + $highCount + $medCount + $lowCount);

// Weekly trend (last 7 days)
$weeklyData = $pdo->query(
    "SELECT DATE(created_at) as day, COUNT(*) as count FROM events
     WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
     GROUP BY DATE(created_at) ORDER BY day"
)->fetchAll();

$weekLabels = []; $weekCounts = [];
for ($i = 6; $i >= 0; $i--) {
    $day = date('Y-m-d', strtotime("-$i days"));
    $weekLabels[] = date('D', strtotime($day));
    $found = false;
    foreach ($weeklyData as $w) {
        if ($w['day'] === $day) { $weekCounts[] = (int)$w['count']; $found = true; break; }
    }
    if (!$found) $weekCounts[] = 0;
}

// Top threat types
$topThreats = $pdo->query(
    "SELECT event_type, COUNT(*) as count, severity FROM events
     GROUP BY event_type, severity ORDER BY count DESC LIMIT 8"
)->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Reports & Analytics</title>
    <link rel="stylesheet" href="assets/css/style.css?v=5.1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>Reports & Analytics</h1><span class="breadcrumb">HIPS / Analytics / Reports</span></div>
        </div>

        <div class="stat-grid">
            <div class="stat-card animate-fadeIn delay-1"><div class="stat-icon"><i class="fa-solid fa-shield-halved"></i></div><div class="stat-value"><?= $totalBlocked ?></div><div class="stat-label">Threats Blocked</div></div>
            <div class="stat-card animate-fadeIn delay-2"><div class="stat-icon"><i class="fa-solid fa-file-shield"></i></div><div class="stat-value"><?= $totalFileEvt ?></div><div class="stat-label">File Events</div></div>
            <div class="stat-card animate-fadeIn delay-3"><div class="stat-icon"><i class="fa-solid fa-network-wired"></i></div><div class="stat-value"><?= $totalNetEvt ?></div><div class="stat-label">Network Events</div></div>
            <div class="stat-card animate-fadeIn delay-4"><div class="stat-icon"><i class="fa-solid fa-bolt"></i></div><div class="stat-value">&lt;2s</div><div class="stat-label">Avg Response Time</div></div>
        </div>

        <div class="grid-2" style="margin-bottom:20px;">
            <!-- Threat Distribution -->
            <div class="card animate-fadeIn delay-2">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-chart-pie"></i></span> Threat Distribution</div>
                <div class="chart-container" style="height:220px;">
                    <canvas id="threatChart"></canvas>
                </div>
            </div>

            <!-- Weekly Trend -->
            <div class="card animate-fadeIn delay-3">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-chart-line"></i></span> Weekly Threat Trend</div>
                <div class="chart-container" style="height:220px;">
                    <canvas id="weeklyChart"></canvas>
                </div>
            </div>
        </div>

        <div class="grid-2-1">
            <!-- Top Threat Types -->
            <div class="card animate-fadeIn delay-3">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-trophy"></i></span> Top Threat Types</div>
                <table class="data-table">
                    <thead><tr><th>#</th><th>Threat Type</th><th>Severity</th><th>Count</th><th>%</th></tr></thead>
                    <tbody>
                        <?php foreach ($topThreats as $i => $t): ?>
                        <tr>
                            <td style="color:var(--text-muted);"><?= $i + 1 ?></td>
                            <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($t['event_type']) ?></td>
                            <td><span class="badge <?= strtolower($t['severity']) ?>"><?= $t['severity'] ?></span></td>
                            <td style="font-weight:600;"><?= $t['count'] ?></td>
                            <td style="color:var(--text-muted);"><?= round($t['count'] / $totalAll * 100, 1) ?>%</td>
                        </tr>
                        <?php endforeach; ?>
                        <?php if (empty($topThreats)): ?>
                        <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:30px;">No threat data available yet.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <!-- Export Panel -->
            <div class="card animate-fadeIn delay-4">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-file-export"></i></span> Export Reports</div>
                <div style="margin-bottom:12px;">
                    <label style="font-size:12px;color:var(--text-secondary);margin-bottom:6px;display:block;">Report Period</label>
                    <select id="exportRange" class="form-control" style="font-size:12px;">
                        <option value="7d">Last 7 Days</option>
                        <option value="30d">Last 30 Days</option>
                        <option value="all">All Time</option>
                    </select>
                </div>
                <div style="display:flex;flex-direction:column;gap:10px;">
                    <a href="#" onclick="exportReport('pdf')" class="btn btn-secondary" style="justify-content:flex-start;text-decoration:none;"><i class="fa-solid fa-file-pdf"></i> PDF Summary Report</a>
                    <a href="#" onclick="exportReport('excel')" class="btn btn-secondary" style="justify-content:flex-start;text-decoration:none;"><i class="fa-solid fa-file-excel"></i> Excel Event Log</a>
                    <a href="#" onclick="exportReport('csv')" class="btn btn-secondary" style="justify-content:flex-start;text-decoration:none;"><i class="fa-solid fa-file-csv"></i> CSV Raw Data Export</a>
                    <button class="btn btn-secondary" style="justify-content:flex-start;" onclick="window.print();"><i class="fa-solid fa-print"></i> Print This Page</button>
                </div>
                <div style="margin-top:16px;padding:12px;background:var(--bg-input);border-radius:var(--radius-sm);font-size:12px;color:var(--text-muted);">
                    <strong>Export Notes:</strong><br>
                    PDF opens a printable summary (use "Save as PDF" in print dialog)<br>
                    Excel exports as tab-separated .xls file<br>
                    CSV exports raw event data for analysis
                </div>
            </div>
        </div>
    </main>
</div>

<script>
// Threat Distribution Chart (Doughnut)
new Chart(document.getElementById('threatChart').getContext('2d'), {
    type: 'doughnut',
    data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
            data: [<?= $critCount ?>, <?= $highCount ?>, <?= $medCount ?>, <?= $lowCount ?>],
            backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e'],
            borderColor: '#0a0f1e',
            borderWidth: 3,
        }]
    },
    options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', padding: 16 } } },
        cutout: '65%',
    }
});

// Weekly Trend Chart (Bar)
new Chart(document.getElementById('weeklyChart').getContext('2d'), {
    type: 'bar',
    data: {
        labels: <?= json_encode($weekLabels) ?>,
        datasets: [{
            label: 'Events',
            data: <?= json_encode($weekCounts) ?>,
            backgroundColor: 'rgba(139, 92, 246, 0.6)',
            borderColor: 'rgba(139, 92, 246, 1)',
            borderWidth: 1, borderRadius: 6,
        }]
    },
    options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
            x: { ticks: { color: '#64748b' }, grid: { color: 'rgba(139,92,246,0.05)' } },
            y: { beginAtZero: true, ticks: { color: '#64748b' }, grid: { color: 'rgba(139,92,246,0.05)' } }
        }
    }
});

// ── Export Report Function ───────────────────────────────────
function exportReport(format) {
    var range = document.getElementById('exportRange').value;
    var url = '../api/export.php?format=' + format + '&range=' + range;
    if (format === 'pdf') {
        window.open(url, '_blank');
    } else {
        window.location.href = url;
    }
}
</script>
</body>
</html>
