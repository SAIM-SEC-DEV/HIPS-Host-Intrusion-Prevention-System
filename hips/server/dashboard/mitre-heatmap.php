<?php
/**
 * ============================================================
 * HIPS Dashboard — MITRE ATT&CK Heatmap
 * ============================================================
 * Visualizes detected threats mapped to the MITRE ATT&CK
 * framework. Each cell represents a technique, and its color
 * intensity reflects how many times it has been observed.
 *
 * This gives SOC analysts an instant, at-a-glance view of
 * which adversary tactics are actively targeting the network.
 */
$currentPage = 'mitre-heatmap';
require_once 'includes/session.php';

// ── Fetch MITRE data from events ─────────────────────────────
$mitreData = $pdo->query(
    "SELECT mitre_technique_id, mitre_tactic, COUNT(*) as hit_count,
            MAX(severity) as max_severity, MAX(created_at) as last_seen
     FROM events
     WHERE mitre_technique_id IS NOT NULL AND mitre_technique_id != ''
     GROUP BY mitre_technique_id, mitre_tactic
     ORDER BY hit_count DESC"
)->fetchAll();

// Total MITRE-mapped events
$totalMapped = (int) $pdo->query(
    "SELECT COUNT(*) FROM events WHERE mitre_technique_id IS NOT NULL AND mitre_technique_id != ''"
)->fetchColumn();

// Build tactic → techniques map
$tacticMap = [];
$maxHits = 1;
foreach ($mitreData as $row) {
    $tactic = $row['mitre_tactic'] ?: 'Unknown';
    if (!isset($tacticMap[$tactic])) $tacticMap[$tactic] = [];
    $tacticMap[$tactic][] = $row;
    if ((int)$row['hit_count'] > $maxHits) $maxHits = (int)$row['hit_count'];
}

// Define the canonical MITRE ATT&CK tactic order
$tacticOrder = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Command & Control',
    'Exfiltration', 'Impact'
];

// Known technique names for display
$techniqueNames = [
    'T1204.002' => 'User Execution: Malicious File',
    'T1565.001' => 'Stored Data Manipulation',
    'T1485'     => 'Data Destruction',
    'T1036'     => 'Masquerading',
    'T1071.001' => 'Application Layer Protocol',
    'T1571'     => 'Non-Standard Port',
    'T1498'     => 'Network Denial of Service',
    'T1046'     => 'Network Service Scanning',
    'T1572'     => 'Protocol Tunneling',
    'T1055'     => 'Process Injection',
    'T1543.003' => 'Create/Modify System Service',
    'T1059'     => 'Command & Scripting Interpreter',
    'T1547.001' => 'Registry Run Keys',
    'T1562.004' => 'Disable System Firewall',
];

// Recent MITRE-mapped alerts (last 15)
$recentMitre = $pdo->query(
    "SELECT e.mitre_technique_id, e.mitre_tactic, e.severity, e.title,
            e.created_at, ag.hostname
     FROM events e
     LEFT JOIN agents ag ON e.agent_id = ag.id
     WHERE e.mitre_technique_id IS NOT NULL AND e.mitre_technique_id != ''
     ORDER BY e.created_at DESC LIMIT 15"
)->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — MITRE ATT&CK Heatmap</title>
    <link rel="stylesheet" href="assets/css/style.css?v=7.1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
    <style>
        /* ── MITRE Heatmap Styles ──────────────────────────── */
        .mitre-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .tactic-column {
            background: var(--bg-surface-dim);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            overflow: hidden;
            transition: all 0.3s ease;
        }
        .tactic-column:hover {
            border-color: rgba(148, 163, 184, 0.15);
            box-shadow: var(--shadow-md);
            transform: translateY(-2px);
        }
        .tactic-header {
            padding: 12px 14px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: var(--accent-violet);
            border-bottom: 1px solid var(--border-color);
            background: linear-gradient(90deg, rgba(122,34,225,0.06), transparent);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .tactic-header .tactic-count {
            margin-left: auto;
            background: rgba(122, 34, 225, 0.12);
            color: var(--accent-violet);
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 10px;
            font-family: 'JetBrains Mono', monospace;
        }
        .technique-cell {
            padding: 10px 14px;
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            transition: all 0.25s ease;
            position: relative;
            overflow: hidden;
        }
        .technique-cell::before {
            content: '';
            position: absolute;
            left: 0; top: 0; bottom: 0;
            width: 3px;
            transition: all 0.3s ease;
        }
        .technique-cell:hover {
            background: var(--accent-violet-dim);
        }
        .technique-cell.heat-1::before { background: #22c55e; }
        .technique-cell.heat-2::before { background: #eab308; }
        .technique-cell.heat-3::before { background: #f97316; }
        .technique-cell.heat-4::before { background: #ef4444; }
        .technique-cell.heat-5::before { background: #dc2626; box-shadow: 0 0 10px rgba(220,38,38,0.5); }
        .technique-id {
            font-size: 10px;
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            color: var(--text-muted);
        }
        .technique-name {
            font-size: 12px;
            color: var(--text-primary);
            margin-top: 2px;
            font-weight: 500;
        }
        .technique-hits {
            font-size: 10px;
            color: var(--text-muted);
            margin-top: 4px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .hit-bar {
            flex: 1;
            height: 4px;
            background: var(--bg-secondary);
            border-radius: 2px;
            overflow: hidden;
        }
        .hit-bar-fill {
            height: 100%;
            border-radius: 2px;
            transition: width 1s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .heat-1 .hit-bar-fill { background: #22c55e; }
        .heat-2 .hit-bar-fill { background: #eab308; }
        .heat-3 .hit-bar-fill { background: #f97316; }
        .heat-4 .hit-bar-fill { background: #ef4444; }
        .heat-5 .hit-bar-fill { background: #dc2626; box-shadow: 0 0 6px rgba(220,38,38,0.6); }

        /* Empty tactic */
        .tactic-empty {
            padding: 20px 14px;
            text-align: center;
            color: var(--text-muted);
            font-size: 11px;
            font-style: italic;
        }

        /* Legend */
        .heatmap-legend {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 12px 16px;
            background: var(--bg-card);
            border-radius: var(--radius-md);
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
        }
        .legend-label {
            font-size: 11px;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 11px;
            color: var(--text-secondary);
        }
        .legend-dot {
            width: 10px;
            height: 10px;
            border-radius: 2px;
        }

        /* Stats row */
        .mitre-stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }
        .mitre-stat-card {
            padding: 20px;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            text-align: center;
        }
        .mitre-stat-value {
            font-size: 32px;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-violet);
            text-shadow: none;
        }
        .mitre-stat-label {
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 4px;
        }

        /* Pulse animation for active threats */
        @keyframes threatPulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
        }
        .technique-cell.heat-5 { animation: threatPulse 2s ease-in-out infinite; }
    </style>
</head>
<body>

<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>

    <main class="main-content">
        <!-- Page Header -->
        <div class="page-header animate-fadeIn">
            <div>
                <h1>MITRE ATT&CK Heatmap</h1>
                <span class="breadcrumb">HIPS / Analytics / MITRE ATT&CK</span>
            </div>
            <div class="header-actions">
                <span style="font-size:12px; color:var(--text-muted);">
                    <?= date('H:i:s') ?>
                </span>
                <button class="btn btn-secondary btn-sm" onclick="location.reload()">↻ Refresh</button>
            </div>
        </div>

        <!-- Stats Overview -->
        <div class="mitre-stats animate-fadeIn">
            <div class="mitre-stat-card">
                <div class="mitre-stat-value"><?= $totalMapped ?></div>
                <div class="mitre-stat-label">Mapped Events</div>
            </div>
            <div class="mitre-stat-card">
                <div class="mitre-stat-value"><?= count($mitreData) ?></div>
                <div class="mitre-stat-label">Techniques Observed</div>
            </div>
            <div class="mitre-stat-card">
                <div class="mitre-stat-value"><?= count($tacticMap) ?></div>
                <div class="mitre-stat-label">Active Tactics</div>
            </div>
            <div class="mitre-stat-card">
                <div class="mitre-stat-value"><?= $maxHits ?></div>
                <div class="mitre-stat-label">Peak Technique Hits</div>
            </div>
        </div>

        <!-- Heat Legend -->
        <div class="heatmap-legend animate-fadeIn">
            <span class="legend-label">Threat Intensity:</span>
            <div class="legend-item"><div class="legend-dot" style="background:#22c55e;"></div>Low (1-2)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#eab308;"></div>Medium (3-5)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#f97316;"></div>High (6-10)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#ef4444;"></div>Critical (11-20)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#dc2626; box-shadow:0 0 6px rgba(220,38,38,0.6);"></div>Severe (20+)</div>
        </div>

        <!-- MITRE ATT&CK Heatmap Grid -->
        <div class="mitre-grid">
            <?php foreach ($tacticOrder as $tactic):
                $techniques = $tacticMap[$tactic] ?? [];
                $tacticTotal = 0;
                foreach ($techniques as $t) $tacticTotal += (int)$t['hit_count'];
            ?>
            <div class="tactic-column scroll-reveal">
                <div class="tactic-header">
                    <span><?= htmlspecialchars($tactic) ?></span>
                    <?php if ($tacticTotal > 0): ?>
                    <span class="tactic-count"><?= $tacticTotal ?></span>
                    <?php endif; ?>
                </div>

                <?php if (empty($techniques)): ?>
                    <div class="tactic-empty">No detections</div>
                <?php else: ?>
                    <?php foreach ($techniques as $tech):
                        $hits = (int)$tech['hit_count'];
                        $pct  = min(100, round(($hits / $maxHits) * 100));

                        // Calculate heat level (1-5)
                        if ($hits >= 20)     $heat = 5;
                        elseif ($hits >= 11) $heat = 4;
                        elseif ($hits >= 6)  $heat = 3;
                        elseif ($hits >= 3)  $heat = 2;
                        else                 $heat = 1;

                        $techName = $techniqueNames[$tech['mitre_technique_id']] ?? $tech['mitre_technique_id'];
                    ?>
                    <div class="technique-cell heat-<?= $heat ?>" title="<?= htmlspecialchars($techName) ?> — <?= $hits ?> detections">
                        <div class="technique-id"><?= htmlspecialchars($tech['mitre_technique_id']) ?></div>
                        <div class="technique-name"><?= htmlspecialchars($techName) ?></div>
                        <div class="technique-hits">
                            <span><?= $hits ?> hit<?= $hits !== 1 ? 's' : '' ?></span>
                            <div class="hit-bar">
                                <div class="hit-bar-fill" style="width:<?= $pct ?>%;"></div>
                            </div>
                            <span class="badge <?= strtolower($tech['max_severity']) ?>" style="font-size:8px;padding:1px 4px;"><?= $tech['max_severity'] ?></span>
                        </div>
                    </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>

        <!-- Recent MITRE-Mapped Events -->
        <div class="card scroll-reveal" style="margin-top:24px;">
            <div class="card-title"><span class="icon"><i class="fa-solid fa-scroll"></i></span> Recent ATT&CK-Mapped Events</div>
            <div style="overflow-x:auto;">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Technique</th>
                        <th>Tactic</th>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>Agent</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($recentMitre)): ?>
                    <tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:30px;">No MITRE-mapped events yet. <i class="fa-solid fa-check"></i></td></tr>
                    <?php else: foreach ($recentMitre as $evt): ?>
                    <tr>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;"><?= htmlspecialchars($evt['mitre_technique_id']) ?></td>
                        <td><?= htmlspecialchars($evt['mitre_tactic']) ?></td>
                        <td><span class="badge <?= strtolower($evt['severity']) ?>"><?= $evt['severity'] ?></span></td>
                        <td><?= htmlspecialchars($evt['title']) ?></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($evt['hostname'] ?? 'N/A') ?></td>
                        <td style="color:var(--text-muted);font-size:12px;"><?= date('M d, H:i', strtotime($evt['created_at'])) ?></td>
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
