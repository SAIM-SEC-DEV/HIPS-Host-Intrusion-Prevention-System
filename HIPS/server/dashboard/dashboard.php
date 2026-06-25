<?php
$currentPage = 'dashboard';
require_once 'includes/session.php';

// ── Fetch dashboard statistics ───────────────────────────────
$totalAgents   = (int) $pdo->query("SELECT COUNT(*) FROM agents")->fetchColumn();
$onlineAgents  = (int) $pdo->query("SELECT COUNT(*) FROM agents WHERE status = 'online'")->fetchColumn();
$offlineAgents = $totalAgents - $onlineAgents;
$activeAlerts  = (int) $pdo->query("SELECT COUNT(*) FROM alerts WHERE status = 'new'")->fetchColumn();
$fileEvents    = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module = 'file' AND DATE(created_at) = CURDATE()")->fetchColumn();
$networkEvents = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module = 'network' AND DATE(created_at) = CURDATE()")->fetchColumn();
$processEvents = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module = 'process' AND DATE(created_at) = CURDATE()")->fetchColumn();
$registryEvents= (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module = 'registry' AND DATE(created_at) = CURDATE()")->fetchColumn();
$commandsSent  = (int) $pdo->query("SELECT COUNT(*) FROM commands WHERE DATE(issued_at) = CURDATE()")->fetchColumn();
$totalEvents   = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE DATE(created_at) = CURDATE()")->fetchColumn();

// Severity counts for threat gauge
$criticalCount = (int)$pdo->query("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL' AND status='new'")->fetchColumn();
$highCount     = (int)$pdo->query("SELECT COUNT(*) FROM alerts WHERE severity='HIGH' AND status='new'")->fetchColumn();
$medCount      = (int)$pdo->query("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM' AND status='new'")->fetchColumn();

// Threat score (0-100)
$threatScore = min(100, $criticalCount * 25 + $highCount * 10 + $medCount * 3);
$threatLevel = $threatScore >= 70 ? 'CRITICAL' : ($threatScore >= 40 ? 'HIGH' : ($threatScore >= 15 ? 'MEDIUM' : 'LOW'));
$threatColor = $threatScore >= 70 ? 'var(--severity-critical)' : ($threatScore >= 40 ? 'var(--severity-high)' : ($threatScore >= 15 ? 'var(--severity-medium)' : 'var(--severity-low)'));

// Recent alerts (last 7)
$recentAlerts = $pdo->query(
    "SELECT a.*, ag.hostname FROM alerts a
     LEFT JOIN agents ag ON a.agent_id = ag.id
     ORDER BY a.created_at DESC LIMIT 7"
)->fetchAll();

// Agent statuses
$agents = $pdo->query(
    "SELECT id, hostname, ip_address, status, last_heartbeat, os_name FROM agents ORDER BY status DESC, hostname"
)->fetchAll();

// Hourly event chart data (last 24 hours)
$chartData = $pdo->query(
    "SELECT HOUR(created_at) as hour, module, COUNT(*) as count
     FROM events WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
     GROUP BY HOUR(created_at), module ORDER BY hour"
)->fetchAll();

$fileHours = array_fill(0, 24, 0);
$netHours  = array_fill(0, 24, 0);
$procHours = array_fill(0, 24, 0);
$regHours  = array_fill(0, 24, 0);
foreach ($chartData as $row) {
    $h = (int)$row['hour'];
    if ($row['module'] === 'file')    $fileHours[$h] = (int)$row['count'];
    if ($row['module'] === 'network') $netHours[$h]  = (int)$row['count'];
    if ($row['module'] === 'process') $procHours[$h] = (int)$row['count'];
    if ($row['module'] === 'registry') $regHours[$h] = (int)$row['count'];
}

// Recent activity timeline (last 10 events)
$recentActivity = $pdo->query(
    "SELECT e.module, e.severity, e.description, e.created_at, ag.hostname
     FROM events e LEFT JOIN agents ag ON e.agent_id = ag.id
     ORDER BY e.created_at DESC LIMIT 10"
)->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Dashboard</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
    <style>
        /* Dashboard-specific enhancements */
        .threat-gauge { text-align:center; padding:20px 0; }
        .threat-ring {
            position:relative; width:140px; height:140px; margin:0 auto 12px;
            border-radius:50%;
            background: conic-gradient(
                var(--threat-color, var(--accent-cyan)) calc(var(--threat-pct, 0) * 3.6deg),
                rgba(100,116,139,0.15) 0deg
            );
            display:flex; align-items:center; justify-content:center;
            animation: gaugeReveal 1.5s cubic-bezier(0.25,0.46,0.45,0.94) both;
        }
        .threat-ring::before {
            content:''; position:absolute; inset:10px;
            border-radius:50%; background: var(--bg-primary);
            transition: background 0.5s ease;
        }
        .threat-ring .threat-inner {
            position:relative; z-index:1; text-align:center;
        }
        .threat-ring .threat-score {
            font-size:32px; font-weight:800; line-height:1;
            font-family:'JetBrains Mono',monospace;
        }
        .threat-ring .threat-label {
            font-size:10px; text-transform:uppercase; letter-spacing:2px;
            color:var(--text-muted); margin-top:4px;
        }
        @keyframes gaugeReveal { from { opacity:0; transform:scale(0.7) rotate(-90deg); } to { opacity:1; transform:scale(1) rotate(0); } }

        .timeline { position:relative; padding-left:20px; }
        .timeline::before {
            content:''; position:absolute; left:7px; top:0; bottom:0; width:2px;
            background: linear-gradient(to bottom, var(--accent-cyan), transparent);
        }
        .timeline-item {
            position:relative; padding:8px 0 8px 16px; border:none;
            transition: transform 0.2s ease;
        }
        .timeline-item:hover { transform:translateX(4px); }
        .timeline-item::before {
            content:''; position:absolute; left:-16px; top:14px;
            width:8px; height:8px; border-radius:50%;
            background: var(--accent-cyan); border:2px solid var(--bg-primary);
            transition: background 0.5s ease, border-color 0.5s ease;
        }
        .timeline-item .tl-time {
            font-size:10px; color:var(--text-muted);
            font-family:'JetBrains Mono',monospace;
        }
        .timeline-item .tl-desc {
            font-size:12px; color:var(--text-secondary);
            margin-top:2px; line-height:1.4;
        }
        .timeline-item .tl-meta {
            font-size:10px; color:var(--text-muted); margin-top:2px;
        }

        .system-health { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
        .health-item {
            display:flex; align-items:center; gap:10px;
            padding:10px 12px; border-radius:var(--radius-sm);
            background:var(--bg-table-row); transition:all 0.3s ease;
        }
        .health-item:hover { background:var(--bg-table-hover); transform:translateX(2px); }
        .health-indicator {
            width:10px; height:10px; border-radius:50%;
            animation: healthPulse 2s ease-in-out infinite;
        }
        .health-indicator.green { background:#22c55e; box-shadow:0 0 8px rgba(34,197,94,0.4); }
        .health-indicator.yellow { background:#eab308; box-shadow:0 0 8px rgba(234,179,8,0.4); }
        .health-indicator.red { background:#ef4444; box-shadow:0 0 8px rgba(239,68,68,0.4); }
        @keyframes healthPulse { 0%,100%{opacity:1;} 50%{opacity:0.6;} }
        .health-label { font-size:12px; color:var(--text-secondary); flex:1; }
        .health-value { font-size:11px; font-weight:600; color:var(--text-primary);
            font-family:'JetBrains Mono',monospace; }
    </style>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>

    <main class="main-content">
        <!-- Page Header -->
        <div class="page-header animate-fadeIn">
            <div>
                <h1>Dashboard</h1>
                <span class="breadcrumb">HIPS / Overview</span>
            </div>
            <div class="header-actions" style="display:flex;gap:12px;align-items:center;">
                <div class="refresh-bar active" id="refreshBar">
                    <label class="toggle-switch" style="margin:0;">
                        <input type="checkbox" id="refreshToggle" checked>
                        <span class="toggle-slider"></span>
                    </label>
                    <span>Auto-refresh</span>
                    <span class="refresh-countdown" id="countdown">20</span>
                    <div class="refresh-progress">
                        <div class="refresh-progress-fill" id="progressFill" style="width:100%;"></div>
                    </div>
                </div>
                <span style="font-size:12px; color:var(--text-muted);">
                    <?= date('H:i:s') ?>
                </span>
                <button class="btn btn-secondary btn-sm" onclick="location.reload()">↻ Refresh</button>
            </div>
        </div>

        <!-- Stat Cards -->
        <div class="stat-grid">
            <div class="stat-card cyan animate-fadeIn delay-1">
                <div class="stat-icon">🖥</div>
                <div class="stat-value" data-count="<?= $totalAgents ?>"><?= $totalAgents ?></div>
                <div class="stat-label">Total Agents</div>
                <span class="stat-trend down">↑ <?= $onlineAgents ?> online</span>
            </div>
            <div class="stat-card red animate-fadeIn delay-2">
                <div class="stat-icon">🔔</div>
                <div class="stat-value" data-count="<?= $activeAlerts ?>"><?= $activeAlerts ?></div>
                <div class="stat-label">Active Alerts</div>
                <?php if ($activeAlerts > 0): ?>
                <span class="stat-trend up">⚠ Action needed</span>
                <?php else: ?>
                <span class="stat-trend down">✓ All clear</span>
                <?php endif; ?>
            </div>
            <div class="stat-card blue animate-fadeIn delay-3">
                <div class="stat-icon">📁</div>
                <div class="stat-value" data-count="<?= $fileEvents ?>"><?= $fileEvents ?></div>
                <div class="stat-label">File Events Today</div>
            </div>
            <div class="stat-card amber animate-fadeIn delay-4">
                <div class="stat-icon">🌐</div>
                <div class="stat-value" data-count="<?= $networkEvents ?>"><?= $networkEvents ?></div>
                <div class="stat-label">Network Events Today</div>
            </div>
            <div class="stat-card green animate-fadeIn delay-5">
                <div class="stat-icon">🔄</div>
                <div class="stat-value" data-count="<?= $processEvents ?>"><?= $processEvents ?></div>
                <div class="stat-label">Process Events</div>
            </div>
            <div class="stat-card purple animate-fadeIn delay-6" style="background:var(--glass-card-bg);border:1px solid var(--glass-border);border-radius:var(--radius-md);padding:16px;text-align:center;">
                <div class="stat-icon">📝</div>
                <div class="stat-value" data-count="<?= $registryEvents ?>" style="font-size:28px;font-weight:800;font-family:'JetBrains Mono',monospace;color:#a855f7;"><?= $registryEvents ?></div>
                <div class="stat-label" style="font-size:10px;text-transform:uppercase;color:var(--text-muted);margin-top:6px;">Registry Events</div>
            </div>
        </div>

        <!-- Row 2: Threat Gauge + System Health + Agent Status -->
        <div style="display:grid; grid-template-columns: 1fr 1.5fr 1fr; gap:20px; margin-bottom:24px;">
            <!-- Threat Level Gauge -->
            <div class="card scroll-reveal">
                <div class="card-title"><span class="icon">🎯</span> Threat Level</div>
                <div class="threat-gauge">
                    <div class="threat-ring" style="--threat-pct:<?= $threatScore ?>; --threat-color:<?= $threatColor ?>;">
                        <div class="threat-inner">
                            <div class="threat-score" style="color:<?= $threatColor ?>;"><?= $threatScore ?></div>
                            <div class="threat-label"><?= $threatLevel ?></div>
                        </div>
                    </div>
                    <div style="font-size:11px; color:var(--text-muted); margin-top:8px;">
                        🔴 <?= $criticalCount ?> Critical &nbsp; 🟠 <?= $highCount ?> High &nbsp; 🟡 <?= $medCount ?> Medium
                    </div>
                </div>
            </div>

            <!-- System Health -->
            <div class="card scroll-reveal">
                <div class="card-title"><span class="icon">💊</span> System Health</div>
                <div class="system-health">
                    <div class="health-item">
                        <div class="health-indicator green"></div>
                        <span class="health-label">Apache Server</span>
                        <span class="health-value">Running</span>
                    </div>
                    <div class="health-item">
                        <div class="health-indicator green"></div>
                        <span class="health-label">MySQL Database</span>
                        <span class="health-value">Connected</span>
                    </div>
                    <div class="health-item">
                        <div class="health-indicator <?= $onlineAgents > 0 ? 'green' : 'red' ?>"></div>
                        <span class="health-label">Agent Connectivity</span>
                        <span class="health-value"><?= $onlineAgents ?>/<?= $totalAgents ?> Online</span>
                    </div>
                    <div class="health-item">
                        <div class="health-indicator <?= $criticalCount > 0 ? 'red' : ($highCount > 0 ? 'yellow' : 'green') ?>"></div>
                        <span class="health-label">Security Posture</span>
                        <span class="health-value"><?= $threatLevel ?></span>
                    </div>
                    <div class="health-item">
                        <div class="health-indicator green"></div>
                        <span class="health-label">File Monitoring</span>
                        <span class="health-value"><?= $fileEvents ?> events</span>
                    </div>
                    <div class="health-item">
                        <div class="health-indicator green"></div>
                        <span class="health-label">Network Monitoring</span>
                        <span class="health-value"><?= $networkEvents ?> events</span>
                    </div>
                    <div class="health-item">
                        <div class="health-indicator green"></div>
                        <span class="health-label">Process Monitoring</span>
                        <span class="health-value"><?= $processEvents ?> events</span>
                    </div>
                    <div class="health-item">
                        <div class="health-indicator green"></div>
                        <span class="health-label">Registry Integrity</span>
                        <span class="health-value"><?= $registryEvents ?> events</span>
                    </div>
                </div>
            </div>

            <!-- Agent Status -->
            <div class="card scroll-reveal reveal-right">
                <div class="card-title"><span class="icon">🖥</span> Agent Status</div>
                <?php foreach ($agents as $ag): ?>
                <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border-color);">
                    <div style="display:flex;align-items:center;gap:8px;">
                        <span class="status-dot <?= $ag['status'] ?>"></span>
                        <div>
                            <span style="font-size:13px;font-weight:500;"><?= htmlspecialchars($ag['hostname']) ?></span>
                            <div style="font-size:10px;color:var(--text-muted);"><?= $ag['ip_address'] ?></div>
                        </div>
                    </div>
                    <span class="badge <?= $ag['status'] ?>"><?= ucfirst($ag['status']) ?></span>
                </div>
                <?php endforeach; ?>
                <?php if (empty($agents)): ?>
                <p style="color:var(--text-muted);font-size:13px;text-align:center;padding:20px;">No agents registered yet.</p>
                <?php endif; ?>
            </div>
        </div>

        <!-- Row 3: Recent Alerts + Activity Timeline -->
        <div class="grid-2-1" style="margin-bottom:24px;">
            <!-- Recent Alerts Table -->
            <div class="card scroll-reveal">
                <div class="card-title" style="justify-content:space-between;">
                    <span><span class="icon">🔔</span> Recent Alerts</span>
                    <a href="alerts.php" class="btn btn-secondary btn-sm" style="font-size:10px;">View All →</a>
                </div>
                <div style="overflow-x:auto;">
                <table class="data-table">
                    <thead>
                        <tr><th>Severity</th><th>Title</th><th>Agent</th><th>Module</th><th>Time</th></tr>
                    </thead>
                    <tbody>
                        <?php if (empty($recentAlerts)): ?>
                        <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:30px;">No alerts yet. System is clean. ✓</td></tr>
                        <?php else: foreach ($recentAlerts as $alert): ?>
                        <tr>
                            <td><span class="badge <?= strtolower($alert['severity']) ?>"><?= $alert['severity'] ?></span></td>
                            <td><?= htmlspecialchars($alert['title']) ?></td>
                            <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($alert['hostname'] ?? 'N/A') ?></td>
                            <td><?= ucfirst($alert['module']) ?></td>
                            <td style="color:var(--text-muted);font-size:12px;"><?= date('H:i:s', strtotime($alert['created_at'])) ?></td>
                        </tr>
                        <?php endforeach; endif; ?>
                    </tbody>
                </table>
                </div>
            </div>

            <!-- Activity Timeline + Quick Command -->
            <div style="display:flex;flex-direction:column;gap:20px;">
                <div class="card scroll-reveal reveal-right">
                    <div class="card-title"><span class="icon">📜</span> Activity Timeline</div>
                    <div class="timeline" style="max-height:240px;overflow-y:auto;">
                        <?php if (empty($recentActivity)): ?>
                        <p style="color:var(--text-muted);font-size:12px;text-align:center;padding:20px;">No activity yet.</p>
                        <?php else: foreach ($recentActivity as $act): ?>
                        <div class="timeline-item">
                            <div class="tl-time"><?= date('H:i:s', strtotime($act['created_at'])) ?></div>
                            <div class="tl-desc"><?= htmlspecialchars(substr($act['description'] ?? 'Event recorded', 0, 80)) ?></div>
                            <div class="tl-meta"><?= htmlspecialchars($act['hostname'] ?? 'Unknown') ?> · <?= ucfirst($act['module']) ?></div>
                        </div>
                        <?php endforeach; endif; ?>
                    </div>
                </div>

                <!-- Quick Command -->
                <div class="card scroll-reveal reveal-right">
                    <div class="card-title"><span class="icon">⚡</span> Quick Command</div>
                    <form action="commands.php" method="GET" style="display:flex;gap:8px;">
                        <select class="form-control" name="agent" style="flex:1;">
                            <option value="">Select Agent</option>
                            <?php foreach ($agents as $ag): ?>
                            <option value="<?= $ag['id'] ?>"><?= htmlspecialchars($ag['hostname']) ?></option>
                            <?php endforeach; ?>
                        </select>
                        <button type="submit" class="btn btn-primary btn-sm">→</button>
                    </form>
                </div>
            </div>
        </div>

        <!-- 24-Hour Activity Chart -->
        <div class="card scroll-reveal reveal-scale">
            <div class="card-title"><span class="icon">📊</span> 24-Hour Event Activity</div>
            <div class="chart-container">
                <canvas id="activityChart"></canvas>
            </div>
        </div>
    </main>
</div>

<script>
// ── 24-Hour Activity Chart ───────────────────────────────────
const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
const gridColor = isDark ? 'rgba(56,189,248,0.05)' : 'rgba(15,23,42,0.06)';
const labelColor = isDark ? '#64748b' : '#64748b';
const legendColor = isDark ? '#94a3b8' : '#475569';

const ctx = document.getElementById('activityChart').getContext('2d');
new Chart(ctx, {
    type: 'bar',
    data: {
        labels: <?= json_encode(array_map(fn($h) => str_pad($h, 2, '0', STR_PAD_LEFT) . ':00', range(0, 23))) ?>,
        datasets: [
            {
                label: 'File Events',
                data: <?= json_encode(array_values($fileHours)) ?>,
                backgroundColor: isDark ? 'rgba(59, 130, 246, 0.6)' : 'rgba(37, 99, 235, 0.65)',
                borderColor: isDark ? 'rgba(59, 130, 246, 1)' : 'rgba(37, 99, 235, 1)',
                borderWidth: 1,
                borderRadius: 4,
            },
            {
                label: 'Network Events',
                data: <?= json_encode(array_values($netHours)) ?>,
                backgroundColor: isDark ? 'rgba(6, 182, 212, 0.6)' : 'rgba(8, 145, 178, 0.6)',
                borderColor: isDark ? 'rgba(6, 182, 212, 1)' : 'rgba(8, 145, 178, 1)',
                borderWidth: 1,
                borderRadius: 4,
            },
            {
                label: 'Process Events',
                data: <?= json_encode(array_values($procHours)) ?>,
                backgroundColor: 'rgba(34, 197, 94, 0.6)',
                borderColor: 'rgba(34, 197, 94, 1)',
                borderWidth: 1,
                borderRadius: 4,
            },
            {
                label: 'Registry Events',
                data: <?= json_encode(array_values($regHours)) ?>,
                backgroundColor: 'rgba(168, 85, 247, 0.6)',
                borderColor: 'rgba(168, 85, 247, 1)',
                borderWidth: 1,
                borderRadius: 4,
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { labels: { color: legendColor, font: { family: 'Inter', size: 12 } } }
        },
        scales: {
            x: { ticks: { color: labelColor, font: { size: 10 } }, grid: { color: gridColor } },
            y: { beginAtZero: true, ticks: { color: labelColor }, grid: { color: gridColor } }
        }
    }
});

// ── Auto-Refresh with Toggle ─────────────────────────────────
(function() {
    const INTERVAL = 20;
    let remaining = INTERVAL;
    let timer = null;

    const toggle      = document.getElementById('refreshToggle');
    const countdownEl  = document.getElementById('countdown');
    const progressFill = document.getElementById('progressFill');
    const refreshBar   = document.getElementById('refreshBar');

    function tick() {
        remaining--;
        countdownEl.textContent = remaining;
        progressFill.style.width = ((remaining / INTERVAL) * 100) + '%';
        if (remaining <= 0) location.reload();
    }

    function start() {
        remaining = INTERVAL;
        countdownEl.textContent = remaining;
        progressFill.style.width = '100%';
        timer = setInterval(tick, 1000);
    }

    function stop() {
        clearInterval(timer);
        timer = null;
        countdownEl.textContent = '—';
        progressFill.style.width = '0%';
    }

    toggle.addEventListener('change', function() {
        if (this.checked) { refreshBar.classList.add('active'); start(); }
        else { refreshBar.classList.remove('active'); stop(); }
    });

    start();
})();
</script>
</body>
</html>
