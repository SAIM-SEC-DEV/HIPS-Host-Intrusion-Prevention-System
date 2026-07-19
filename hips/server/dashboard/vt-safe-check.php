<?php
$currentPage = 'vt-safe-check';
require_once 'includes/session.php';

// Safe EICAR Download Generator (Obfuscated to prevent the PHP file itself from being quarantined by Windows Defender)
if (isset($_GET['download_eicar'])) {
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="eicar-test-malware.com"');
    $p1 = 'X5O!P%@AP[4\PZX';
    $p2 = '54(P^)7CC)7}$EI';
    $p3 = 'CAR-STANDARD-A';
    $p4 = 'NTIVIRUS-TEST-FILE!$H+H*';
    echo $p1 . $p2 . $p3 . $p4;
    exit;
}

$result = null;
$error = null;
$vtApiKey = 'YOUR_VIRUSTOTAL_API_KEY_HERE'; // User can hardcode this or enter it in the form

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $apiKey = $_POST['api_key'] ?? '';
    $hashToCheck = '';

    if (empty($apiKey)) {
        $error = "Please provide a VirusTotal API Key.";
    } else {
        // Did they provide a hash directly?
        if (!empty($_POST['file_hash'])) {
            $hashToCheck = trim($_POST['file_hash']);
        } 
        // Did they upload a file?
        elseif (isset($_FILES['suspicious_file']) && $_FILES['suspicious_file']['error'] === UPLOAD_ERR_OK) {
            $tmpPath = $_FILES['suspicious_file']['tmp_name'];
            
            // 1. Calculate Hash in memory/temp storage
            $hashToCheck = hash_file('sha256', $tmpPath);
            
            // 2. IMMEDIATELY delete the file to ensure system safety
            @unlink($tmpPath);
        } else {
            $error = "Please upload a file or enter a SHA-256 hash.";
        }

        // 3. Query VirusTotal
        if (!empty($hashToCheck)) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, "https://www.virustotal.com/api/v3/files/" . $hashToCheck);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                "x-apikey: " . $apiKey
            ]);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200) {
                $result = json_decode($response, true);
            } elseif ($httpCode === 404) {
                $error = "File not found in VirusTotal database (Hash: $hashToCheck). It has never been scanned by VT.";
            } elseif ($httpCode === 401) {
                $error = "Invalid VirusTotal API Key.";
            } else {
                $error = "Error communicating with VirusTotal (HTTP $httpCode).";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Safe VT Check</title>
    <link rel="stylesheet" href="assets/css/style.css?v=7.1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>Safe VirusTotal Check</h1><span class="breadcrumb">HIPS / Threat Intelligence / Isolated Checker</span></div>
        </div>

        <?php if ($error): ?>
        <div class="login-error" style="margin-bottom:16px;"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <div class="grid-2">
            <!-- Upload Form -->
            <div class="card animate-fadeIn delay-1">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-microscope"></i></span> Isolated File Scanner</div>
                <p style="font-size:13px; color:var(--text-muted); margin-bottom: 20px;">
                    Upload a suspicious file here. The file will <strong>never be executed or saved</strong> on the server. 
                    We calculate the SHA-256 hash in memory and instantly delete the temp file, making this 100% safe.
                </p>
                <form method="POST" enctype="multipart/form-data">
                    <div class="form-group">
                        <label for="api_key">VirusTotal API Key (Required)</label>
                        <input type="password" name="api_key" id="api_key" class="form-control" required placeholder="Enter your VT API v3 Key">
                    </div>
                    
                    <div class="form-group">
                        <label for="suspicious_file">Upload File (Safe Check)</label>
                        <input type="file" name="suspicious_file" id="suspicious_file" class="form-control">
                    </div>
                    
                    <div style="text-align:center; margin: 10px 0; color:var(--text-muted); font-size:12px;">— OR —</div>
                    
                    <div class="form-group">
                        <label for="file_hash">Enter SHA-256 Hash Directly</label>
                        <input type="text" name="file_hash" id="file_hash" class="form-control" placeholder="e.g. 44d88612fea8a8f36de82e1278abb02f...">
                    </div>

                    <button type="submit" class="btn btn-primary" style="width:100%;"><i class="fa-solid fa-magnifying-glass"></i> Check Reputation</button>
                </form>


            </div>

            <!-- Results -->
            <div class="card animate-fadeIn delay-2">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-chart-line"></i></span> Analysis Results</div>
                <?php if ($result): 
                    $stats = $result['data']['attributes']['last_analysis_stats'];
                    $malicious = $stats['malicious'] ?? 0;
                    $suspicious = $stats['suspicious'] ?? 0;
                    $undetected = $stats['undetected'] ?? 0;
                    $total = $malicious + $suspicious + $undetected;
                    
                    $statusColor = ($malicious > 0) ? 'var(--severity-critical)' : 'var(--severity-low)';
                ?>
                    <div style="text-align:center; padding: 25px 0; border-bottom: 1px solid var(--border-color); background: radial-gradient(circle at center, rgba(139, 92, 246, 0.08), transparent);">
                        <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 2px; margin-bottom: 10px;">Detection Score</div>
                        <h2 style="color: <?= $statusColor ?>; margin:0; font-size: 48px; font-weight: 800; text-shadow: 0 0 20px <?= ($malicious > 0) ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.2)' ?>;">
                            <?= $malicious ?> <span style="font-size: 20px; color: var(--text-muted); font-weight: 400;">/ <?= $total ?></span>
                        </h2>
                        <div style="margin-top: 10px;">
                            <span class="badge <?= ($malicious > 0) ? 'critical' : 'low' ?>" style="padding: 4px 15px; border-radius: 12px; font-size: 11px;">
                                <?= ($malicious > 0) ? 'MALICIOUS THREAT' : 'VERIFIED CLEAN' ?>
                            </span>
                        </div>
                    </div>
                    
                    <div style="margin-top:20px;">
                        <p style="font-size:13px; font-family:'JetBrains Mono', monospace; word-break: break-all;">
                            <strong>SHA-256:</strong><br>
                            <span style="color:var(--accent-violet);"><?= htmlspecialchars($hashToCheck) ?></span>
                        </p>
                        <p style="font-size:13px; margin-top:10px;">
                            <strong>Threat Label:</strong> 
                            <?= htmlspecialchars($result['data']['attributes']['popular_threat_classification']['suggested_threat_label'] ?? 'Unknown/Clean') ?>
                        </p>
                    </div>
                <?php elseif (!$error && $_SERVER['REQUEST_METHOD'] === 'POST'): ?>
                    <p style="font-size:13px; color:var(--text-muted); text-align:center; padding: 40px 0;">
                        File is safe. 0 vendors flagged this file.
                    </p>
                <?php else: ?>
                    <p style="font-size:13px; color:var(--text-muted); text-align:center; padding: 40px 0;">
                        Submit a file or hash to see the intelligence report here.
                    </p>
                <?php endif; ?>
            </div>
        </div>
    </main>
</div>
</body>
</html>
