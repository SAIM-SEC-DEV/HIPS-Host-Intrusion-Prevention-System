<?php
/**
 * ============================================================
 * HIPS — Host Intrusion Prevention System
 * Export Reports Endpoint
 * ============================================================
 *
 * Generates downloadable reports in CSV, Excel (TSV), and
 * PDF-printable formats. Called from the Reports dashboard page.
 *
 * GET Parameters:
 *   format  = csv | excel | pdf
 *   range   = 7d | 30d | all  (default: 7d)
 */

session_start();
if (!isset($_SESSION['hips_admin_id'])) {
    http_response_code(401);
    echo "Unauthorized";
    exit;
}

require_once __DIR__ . '/../config/db_connect.php';

$format = $_GET['format'] ?? 'csv';
$range  = $_GET['range'] ?? '7d';

// Build date filter
$dateFilter = '';
switch ($range) {
    case '30d':
        $dateFilter = "WHERE e.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
        break;
    case 'all':
        $dateFilter = '';
        break;
    case '7d':
    default:
        $dateFilter = "WHERE e.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
        break;
}

// Fetch event data
$sql = "SELECT e.id, e.module, e.event_type, e.severity, e.title, e.description,
               e.source_path, e.destination, e.hash_value, e.is_anomaly, e.created_at,
               a.hostname, a.ip_address
        FROM events e
        LEFT JOIN agents a ON e.agent_id = a.id
        $dateFilter
        ORDER BY e.created_at DESC";

$events = $pdo->query($sql)->fetchAll();

// ── CSV Export ──────────────────────────────────────────────
if ($format === 'csv') {
    $filename = 'hips-events-' . date('Y-m-d') . '.csv';
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');

    $output = fopen('php://output', 'w');

    // Header row
    fputcsv($output, [
        'ID', 'Timestamp', 'Module', 'Event Type', 'Severity', 'Title',
        'Description', 'Source Path', 'Destination', 'Hash', 'Anomaly',
        'Agent Hostname', 'Agent IP'
    ]);

    // Data rows
    foreach ($events as $e) {
        fputcsv($output, [
            $e['id'],
            $e['created_at'],
            $e['module'],
            $e['event_type'],
            $e['severity'],
            $e['title'],
            $e['description'],
            $e['source_path'],
            $e['destination'],
            $e['hash_value'],
            $e['is_anomaly'] ? 'Yes' : 'No',
            $e['hostname'] ?? 'N/A',
            $e['ip_address'] ?? 'N/A',
        ]);
    }

    fclose($output);
    exit;
}

// ── Excel Export (Tab-Separated) ────────────────────────────
if ($format === 'excel') {
    $filename = 'hips-events-' . date('Y-m-d') . '.xls';
    header('Content-Type: application/vnd.ms-excel; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');

    // BOM for Excel UTF-8 compatibility
    echo "\xEF\xBB\xBF";

    // Header row
    echo implode("\t", [
        'ID', 'Timestamp', 'Module', 'Event Type', 'Severity', 'Title',
        'Description', 'Source Path', 'Destination', 'Hash', 'Anomaly',
        'Agent Hostname', 'Agent IP'
    ]) . "\n";

    // Data rows
    foreach ($events as $e) {
        echo implode("\t", [
            $e['id'],
            $e['created_at'],
            $e['module'],
            $e['event_type'],
            $e['severity'],
            str_replace(["\t", "\n", "\r"], ' ', $e['title']),
            str_replace(["\t", "\n", "\r"], ' ', $e['description'] ?? ''),
            $e['source_path'] ?? '',
            $e['destination'] ?? '',
            $e['hash_value'] ?? '',
            $e['is_anomaly'] ? 'Yes' : 'No',
            $e['hostname'] ?? 'N/A',
            $e['ip_address'] ?? 'N/A',
        ]) . "\n";
    }

    exit;
}

// ── PDF Export (Printable HTML — triggers browser Print dialog) ──
if ($format === 'pdf') {
    // Fetch summary stats
    $totalEvents = count($events);
    $critCount = 0; $highCount = 0; $medCount = 0; $lowCount = 0;
    $fileCount = 0; $netCount = 0;
    foreach ($events as $e) {
        switch ($e['severity']) {
            case 'CRITICAL': $critCount++; break;
            case 'HIGH': $highCount++; break;
            case 'MEDIUM': $medCount++; break;
            case 'LOW': $lowCount++; break;
        }
        if ($e['module'] === 'file') $fileCount++;
        if ($e['module'] === 'network') $netCount++;
    }

    $rangeLabel = $range === '7d' ? 'Last 7 Days' : ($range === '30d' ? 'Last 30 Days' : 'All Time');
    $reportDate = date('F j, Y — H:i:s');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>HIPS Security Report — <?= $reportDate ?></title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; color: #1e293b; background: #fff; padding: 40px; font-size: 12px; }
        .header { text-align: center; margin-bottom: 30px; border-bottom: 3px solid #0f172a; padding-bottom: 20px; }
        .header h1 { font-size: 24px; color: #0f172a; margin-bottom: 5px; }
        .header .subtitle { color: #64748b; font-size: 13px; }
        .header .meta { margin-top: 8px; font-size: 11px; color: #94a3b8; }
        .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }
        .summary-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; text-align: center; }
        .summary-card .value { font-size: 28px; font-weight: 700; }
        .summary-card .label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
        .summary-card.critical .value { color: #ef4444; }
        .summary-card.high .value { color: #f97316; }
        .summary-card.medium .value { color: #eab308; }
        .summary-card.low .value { color: #22c55e; }
        .section-title { font-size: 16px; font-weight: 600; margin: 25px 0 12px; padding-bottom: 6px; border-bottom: 1px solid #e2e8f0; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 11px; }
        th { background: #f1f5f9; padding: 8px 10px; text-align: left; font-weight: 600; border-bottom: 2px solid #cbd5e1; }
        td { padding: 6px 10px; border-bottom: 1px solid #f1f5f9; }
        tr:nth-child(even) { background: #f8fafc; }
        .badge { padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; display: inline-block; }
        .badge.critical { background: #fef2f2; color: #ef4444; border: 1px solid #fecaca; }
        .badge.high { background: #fff7ed; color: #f97316; border: 1px solid #fed7aa; }
        .badge.medium { background: #fefce8; color: #ca8a04; border: 1px solid #fde68a; }
        .badge.low { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
        .footer { margin-top: 30px; padding-top: 15px; border-top: 1px solid #e2e8f0; color: #94a3b8; font-size: 10px; text-align: center; }
        @media print {
            body { padding: 20px; }
            .no-print { display: none; }
        }
    </style>
</head>
<body>
    <div class="no-print" style="text-align:center;margin-bottom:20px;">
        <button onclick="window.print()" style="padding:10px 30px;font-size:14px;background:#0f172a;color:#fff;border:none;border-radius:6px;cursor:pointer;">🖨 Print / Save as PDF</button>
        <button onclick="window.close()" style="padding:10px 20px;font-size:14px;background:#64748b;color:#fff;border:none;border-radius:6px;cursor:pointer;margin-left:10px;">✕ Close</button>
    </div>

    <div class="header">
        <h1>🛡 HIPS Security Report</h1>
        <div class="subtitle">Host Intrusion Prevention System — Event Summary</div>
        <div class="meta">Report generated: <?= $reportDate ?> | Period: <?= $rangeLabel ?> | Total Events: <?= $totalEvents ?></div>
    </div>

    <div class="summary-grid">
        <div class="summary-card critical"><div class="value"><?= $critCount ?></div><div class="label">Critical</div></div>
        <div class="summary-card high"><div class="value"><?= $highCount ?></div><div class="label">High</div></div>
        <div class="summary-card medium"><div class="value"><?= $medCount ?></div><div class="label">Medium</div></div>
        <div class="summary-card low"><div class="value"><?= $lowCount ?></div><div class="label">Low</div></div>
    </div>

    <div class="summary-grid" style="grid-template-columns: repeat(3, 1fr);">
        <div class="summary-card"><div class="value"><?= $totalEvents ?></div><div class="label">Total Events</div></div>
        <div class="summary-card"><div class="value"><?= $fileCount ?></div><div class="label">File Events</div></div>
        <div class="summary-card"><div class="value"><?= $netCount ?></div><div class="label">Network Events</div></div>
    </div>

    <div class="section-title">Event Log</div>
    <table>
        <thead>
            <tr><th>#</th><th>Timestamp</th><th>Severity</th><th>Module</th><th>Event Type</th><th>Title</th><th>Agent</th></tr>
        </thead>
        <tbody>
        <?php foreach (array_slice($events, 0, 200) as $i => $e): ?>
            <tr>
                <td style="color:#94a3b8;"><?= $i + 1 ?></td>
                <td><?= $e['created_at'] ?></td>
                <td><span class="badge <?= strtolower($e['severity']) ?>"><?= $e['severity'] ?></span></td>
                <td><?= ucfirst($e['module']) ?></td>
                <td style="font-family:monospace;font-size:10px;"><?= htmlspecialchars($e['event_type']) ?></td>
                <td><?= htmlspecialchars(substr($e['title'], 0, 60)) ?></td>
                <td><?= htmlspecialchars($e['hostname'] ?? 'N/A') ?></td>
            </tr>
        <?php endforeach; ?>
        <?php if ($totalEvents > 200): ?>
            <tr><td colspan="7" style="text-align:center;color:#94a3b8;padding:12px;">... and <?= $totalEvents - 200 ?> more events (use CSV for full data)</td></tr>
        <?php endif; ?>
        </tbody>
    </table>

    <div class="footer">
        HIPS — Host Intrusion Prevention System | Confidential Security Report | Generated by HIPS Dashboard v1.0
    </div>

    <script>
        // Auto-trigger print dialog after page loads
        window.addEventListener('load', function() {
            setTimeout(function() { window.print(); }, 500);
        });
    </script>
</body>
</html>
<?php
    exit;
}

// Unknown format
http_response_code(400);
echo json_encode(['error' => 'Invalid format. Use: csv, excel, or pdf']);
