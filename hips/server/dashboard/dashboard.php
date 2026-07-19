<?php
$currentPage = 'dashboard';
require_once 'includes/session.php';

// ── Fetch dashboard statistics ───────────────────────────────
// Optimize agent counts
$agentStats = $pdo->query("SELECT COUNT(*) as total, SUM(CASE WHEN TIMESTAMPDIFF(SECOND, last_heartbeat, NOW()) <= 180 THEN 1 ELSE 0 END) as online FROM agents")->fetch();
$totalAgents   = (int) $agentStats['total'];
$onlineAgents  = (int) $agentStats['online'];
$offlineAgents = $totalAgents - $onlineAgents;

// Optimize event counts
$eventStats = $pdo->query("
    SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN module = 'file' THEN 1 ELSE 0 END) as file_events,
        SUM(CASE WHEN module = 'network' THEN 1 ELSE 0 END) as network_events,
        SUM(CASE WHEN module = 'process' THEN 1 ELSE 0 END) as process_events,
        SUM(CASE WHEN module = 'registry' THEN 1 ELSE 0 END) as registry_events,
        SUM(CASE WHEN module = 'memory' THEN 1 ELSE 0 END) as memory_events,
        SUM(CASE WHEN module = 'asset' THEN 1 ELSE 0 END) as asset_events
    FROM events WHERE DATE(created_at) = CURDATE()
")->fetch();

$fileEvents    = (int) $eventStats['file_events'];
$networkEvents = (int) $eventStats['network_events'];
$processEvents = (int) $eventStats['process_events'];
$registryEvents= (int) $eventStats['registry_events'];
$memoryEvents  = (int) $eventStats['memory_events'];
$assetEvents   = (int) $eventStats['asset_events'];
$totalEvents   = (int) $eventStats['total'];

// Commands count
$commandsSent  = (int) $pdo->query("SELECT COUNT(*) FROM commands WHERE DATE(issued_at) = CURDATE()")->fetchColumn();

// Optimize alert severity counts
$alertStats = $pdo->query("
    SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
        SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as med_count
    FROM alerts WHERE status = 'new'
")->fetch();

$activeAlerts  = (int) $alertStats['total'];
$criticalCount = (int) $alertStats['critical_count'];
$highCount     = (int) $alertStats['high_count'];
$medCount      = (int) $alertStats['med_count'];

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
    "SELECT id, hostname, ip_address, IF(TIMESTAMPDIFF(SECOND, last_heartbeat, NOW()) > 180, 'offline', 'online') as status, last_heartbeat, os_name FROM agents ORDER BY IF(TIMESTAMPDIFF(SECOND, last_heartbeat, NOW()) > 180, 'offline', 'online') DESC, hostname"
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
$memHours  = array_fill(0, 24, 0);
$assetHours = array_fill(0, 24, 0);
foreach ($chartData as $row) {
    $h = (int)$row['hour'];
    if ($row['module'] === 'file')    $fileHours[$h] = (int)$row['count'];
    if ($row['module'] === 'network') $netHours[$h]  = (int)$row['count'];
    if ($row['module'] === 'process') $procHours[$h] = (int)$row['count'];
    if ($row['module'] === 'registry') $regHours[$h] = (int)$row['count'];
    if ($row['module'] === 'memory')  $memHours[$h]  = (int)$row['count'];
    if ($row['module'] === 'asset')   $assetHours[$h] = (int)$row['count'];
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
    <link rel="stylesheet" href="assets/css/style.css?v=10.1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
    <style>
        /* Dashboard-specific premium enhancements */
        .threat-gauge { 
            text-align:center; 
            padding:24px 0;
            background: linear-gradient(145deg, rgba(15, 23, 42, 0.5), rgba(8, 12, 28, 0.8));
            border-radius: var(--radius-lg);
            border: 1px solid var(--border-color);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.02), var(--shadow-sm);
        }
        .threat-ring {
            position:relative; width:160px; height:160px; margin:0 auto 16px;
            border-radius:50%;
            background: conic-gradient(
                var(--threat-color, var(--accent-violet)) 0deg,
                var(--threat-color, var(--accent-violet)) calc(var(--threat-pct, 0) * 3.6deg),
                rgba(255,255,255,0.03) 0deg
            );
            display:flex; align-items:center; justify-content:center;
            box-shadow: 0 0 30px rgba(0,0,0,0.4), 0 0 60px rgba(139,92,246,0.05);
            animation: gaugeReveal 1.2s cubic-bezier(0.34, 1.56, 0.64, 1) both;
        }
        .threat-ring::before {
            content:''; position:absolute; inset:12px;
            border-radius:50%; 
            background: linear-gradient(145deg, rgba(15, 23, 42, 0.95), rgba(8, 12, 28, 0.98));
            z-index: 0;
            box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.4), inset 0 -1px 0 rgba(255,255,255,0.03);
        }
        .threat-ring .threat-inner {
            position:relative; z-index:1; text-align:center;
        }
        .threat-ring .threat-score {
            font-size:42px; font-weight:800; line-height:1;
            font-family:'JetBrains Mono',monospace;
            text-shadow: 0 0 20px var(--shadow-glow);
        }
        .threat-ring .threat-label {
            font-size:11px; text-transform:uppercase; letter-spacing:2px;
            color:var(--text-muted); margin-top:6px;
            font-weight: 700;
        }
        @keyframes gaugeReveal { from { opacity:0; transform:scale(0.8) rotate(-180deg); } to { opacity:1; transform:scale(1) rotate(0); } }

        .timeline { position:relative; padding-left:24px; }
        .timeline::before {
            content:''; position:absolute; left:7px; top:0; bottom:0; width:2px;
            background: linear-gradient(to bottom, var(--accent-violet), rgba(139,92,246,0.2), transparent);
            opacity: 0.4;
        }
        .timeline-item {
            position:relative; padding:12px 0 12px 16px; border:none;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            border-radius: var(--radius-sm);
        }
        .timeline-item:hover { 
            background: linear-gradient(90deg, rgba(139,92,246,0.04), transparent);
            transform:translateX(6px); 
        }
        .timeline-item::before {
            content:''; position:absolute; left:-21px; top:18px;
            width:10px; height:10px; border-radius:50%;
            background: linear-gradient(135deg, var(--accent-violet), var(--accent-deep)); 
            border: 2px solid var(--bg-primary);
            box-shadow: 0 0 10px rgba(139, 92, 246, 0.5);
            z-index: 1;
        }
        .timeline-item .tl-time {
            font-size:10px; color:var(--text-muted);
            font-family:'JetBrains Mono',monospace;
            font-weight: 600;
        }
        .timeline-item .tl-desc {
            font-size:13px; color:var(--text-primary);
            margin-top:4px; line-height:1.5;
        }
        .timeline-item .tl-meta {
            font-size:11px; color:var(--text-muted); margin-top:4px;
            display: flex; align-items: center; gap: 6px;
        }
    </style>
</head>
<body>

<!-- ── Epic Dragon Intro (First Visit Only) ──────────────────── -->
<script>
    // Force the animation to replay once for the user upon next refresh
    if (!sessionStorage.getItem('force_replay_done')) {
        localStorage.removeItem('hips_intro_played');
        sessionStorage.setItem('force_replay_done', '1');
    }
</script>
<div id="hipsIntro" style="position:fixed;inset:0;z-index:9999;background:#030508;display:none;overflow:hidden;">
    <canvas id="introCanvas" style="position:absolute;inset:0;width:100%;height:100%;"></canvas>
    <svg id="introDragon" viewBox="0 0 320 280" style="position:absolute;width:340px;height:300px;bottom:-350px;right:-350px;filter:drop-shadow(0 0 30px rgba(220,38,38,0.6));z-index:2;will-change:transform;" xmlns="http://www.w3.org/2000/svg">
        <defs>
            <linearGradient id="dgScale" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#1a0a0a"/><stop offset="100%" stop-color="#0d0d1a"/></linearGradient>
            <linearGradient id="dgVein" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#dc2626"/><stop offset="100%" stop-color="#7f1d1d"/></linearGradient>
            <radialGradient id="dgChest"><stop offset="0%" stop-color="#fff" stop-opacity="0.9"/><stop offset="40%" stop-color="#f97316" stop-opacity="0.6"/><stop offset="100%" stop-color="#dc2626" stop-opacity="0"/></radialGradient>
            <radialGradient id="dgEye"><stop offset="0%" stop-color="#fbbf24"/><stop offset="60%" stop-color="#f59e0b"/><stop offset="100%" stop-color="#dc2626"/></radialGradient>
        </defs>
        <!-- Wing back -->
        <path d="M140,130 L60,30 L90,15 L120,25 L140,8 L155,20 L150,55 L145,90Z" fill="#12001e" stroke="#5b1a1a" stroke-width="0.8" opacity="0.7"/>
        <path d="M140,130 L75,35 M140,130 L105,22 M140,130 L135,15" stroke="#6b2020" stroke-width="0.6" opacity="0.5"/>
        <!-- Wing front -->
        <path d="M155,125 L220,25 L248,12 L270,22 L280,45 L265,80 L235,110Z" fill="#12001e" stroke="#5b1a1a" stroke-width="0.8"/>
        <path d="M155,125 L230,30 M155,125 L255,20 M155,125 L272,38" stroke="url(#dgVein)" stroke-width="0.8" opacity="0.7"/>
        <!-- Torn wing edges -->
        <path d="M60,30 L55,25 L62,28 M90,15 L88,10 L93,14 M270,22 L275,17 L272,24 M280,45 L286,42 L281,48" stroke="#3a1010" stroke-width="0.5" fill="none"/>
        <!-- Body -->
        <path d="M120,120 Q135,100 155,110 Q175,95 180,115 Q190,130 182,155 Q175,180 160,195 Q140,205 125,195 Q110,178 108,155 Q107,135 120,120Z" fill="url(#dgScale)" stroke="#4a1515" stroke-width="1"/>
        <!-- Scales texture -->
        <path d="M130,130 Q140,125 150,130 M125,145 Q138,140 152,145 M128,160 Q142,155 155,160 M133,175 Q145,170 157,175" stroke="#2a0a0a" stroke-width="0.5" fill="none" opacity="0.6"/>
        <!-- Neck -->
        <path d="M125,118 Q110,95 100,75 Q95,60 92,50" fill="none" stroke="url(#dgScale)" stroke-width="18" stroke-linecap="round"/>
        <path d="M125,118 Q110,95 100,75 Q95,60 92,50" fill="none" stroke="#4a1515" stroke-width="0.8"/>
        <!-- Head -->
        <path d="M92,50 Q82,40 70,36 Q58,32 48,38 L32,44 Q38,48 48,50 Q65,55 80,58 Q90,60 92,50Z" fill="url(#dgScale)" stroke="#4a1515" stroke-width="0.8"/>
        <!-- Upper jaw -->
        <path d="M48,38 Q38,34 28,36 L18,42 Q25,46 32,44Z" fill="#0d0a15" stroke="#4a1515" stroke-width="0.6"/>
        <!-- Fangs -->
        <path d="M30,44 L27,54 L32,46 M38,42 L36,50 L40,44 M24,42 L20,52 L26,44" fill="#1a1525" stroke="#6b3030" stroke-width="0.4"/>
        <!-- Lower jaw -->
        <path d="M48,50 Q36,54 25,50 L18,42 Q22,48 30,52 Q42,56 48,50Z" fill="#080510" stroke="#4a1515" stroke-width="0.5"/>
        <!-- Horns -->
        <path d="M72,32 Q82,16 98,6" fill="none" stroke="#2d1045" stroke-width="3.5" stroke-linecap="round"/>
        <path d="M78,38 Q86,24 96,16" fill="none" stroke="#2d1045" stroke-width="2.5" stroke-linecap="round"/>
        <!-- Battle scars on horns -->
        <path d="M80,22 L83,25 M88,14 L91,17" stroke="#1a0830" stroke-width="0.5"/>
        <!-- Eye -->
        <ellipse cx="65" cy="42" rx="5" ry="3.5" fill="url(#dgEye)" id="dragonEyeEl"/>
        <ellipse cx="64" cy="42" rx="1.5" ry="3" fill="#000"/>
        <!-- Spines (dark purple) -->
        <path d="M95,48 L88,32 M100,55 L95,40 M107,65 L103,50 M113,78 L110,62 M120,90 L118,76 M128,102 L127,88 M135,112 L135,100" stroke="#4c1d95" stroke-width="2.5" stroke-linecap="round"/>
        <!-- Tail -->
        <path d="M175,180 Q200,200 225,210 Q250,218 270,212 Q285,205 290,192 Q288,185 280,188 Q268,198 248,200 Q225,200 200,190 Q180,180 175,180Z" fill="url(#dgScale)" stroke="#4a1515" stroke-width="0.6"/>
        <path d="M290,192 L298,186 L292,195 L300,190 L293,198" fill="#2d1045" stroke="#4c1d95" stroke-width="0.5"/>
        <!-- Chest glow (hidden initially, shown during charge) -->
        <ellipse id="chestGlow" cx="150" cy="145" rx="30" ry="40" fill="url(#dgChest)" opacity="0"/>
        <!-- Ember drips from fangs -->
        <circle cx="28" cy="55" r="1.2" fill="#f97316" opacity="0" class="fang-ember"/>
        <circle cx="36" cy="51" r="1" fill="#ef4444" opacity="0" class="fang-ember"/>
    </svg>
    <div id="hipsText" style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-family:'JetBrains Mono',monospace;font-size:18vw;font-weight:900;color:transparent;z-index:3;opacity:0;letter-spacing:0.05em;pointer-events:none;
        background:linear-gradient(180deg,#fff 0%,#f97316 40%,#dc2626 70%,#7f1d1d 100%);
        -webkit-background-clip:text;background-clip:text;
        text-shadow:0 0 80px rgba(220,38,38,0.8),0 0 160px rgba(249,115,22,0.4);
        filter:drop-shadow(0 0 30px rgba(220,38,38,0.6));">HIPS</div>
</div>
<script>
(function(){
    if(localStorage.getItem('hips_intro_played')){var e=document.getElementById('hipsIntro');if(e)e.parentNode.removeChild(e);return;}
    var overlay=document.getElementById('hipsIntro');
    overlay.style.display='block';
    var preloader=document.getElementById('pagePreloader');
    if(preloader)preloader.style.display='none';
    var canvas=document.getElementById('introCanvas'),ctx=canvas.getContext('2d');
    var W,H;function resize(){W=canvas.width=window.innerWidth;H=canvas.height=window.innerHeight;}
    resize();window.addEventListener('resize',resize);
    // Particle system
    var particles=[];
    function Particle(x,y,type){
        this.x=x;this.y=y;this.type=type;
        this.vx=(Math.random()-0.5)*4;this.vy=(Math.random()-0.5)*4-2;
        this.life=1;this.decay=0.008+Math.random()*0.015;
        this.size=type==='ember'?1+Math.random()*3:type==='fire'?4+Math.random()*8:2+Math.random()*4;
        this.color=type==='ember'?'rgba(249,115,22,':'rgba(220,38,38,';
        if(type==='fire'&&Math.random()>0.6)this.color='rgba(255,255,255,';
        if(type==='smoke')this.color='rgba(100,80,80,';
    }
    Particle.prototype.update=function(){
        this.x+=this.vx;this.y+=this.vy;
        if(this.type==='ember'){this.vy-=0.03;this.vx*=0.99;}
        if(this.type==='fire'){this.vy-=0.08;this.size*=0.97;}
        if(this.type==='smoke'){this.vy-=0.02;this.size*=1.005;this.vx*=0.98;}
        this.life-=this.decay;
    };
    Particle.prototype.draw=function(){
        if(this.life<=0)return;
        ctx.beginPath();ctx.arc(this.x,this.y,Math.max(0.5,this.size*this.life),0,Math.PI*2);
        ctx.fillStyle=this.color+(this.life*0.8)+')';ctx.fill();
    };
    // Dragon element
    var dragonEl=document.getElementById('introDragon');
    var hipsText=document.getElementById('hipsText');
    var chestGlow=document.getElementById('chestGlow');
    var phase=0,startTime=null;
    // Screen shake
    function shake(intensity){
        var ox=(Math.random()-0.5)*intensity,oy=(Math.random()-0.5)*intensity;
        overlay.style.transform='translate('+ox+'px,'+oy+'px)';
    }
    // Animation phases
    function getDragonPos(t){
        if(t<600)return{x:W+100-((W*0.6+100)*(t/600)),y:H+100-((H*0.5+100)*(t/600)),s:0.3+0.7*(t/600),r:15*(1-t/600)};
        if(t<1800){var p=(t-600)/1200;return{x:W*0.4-p*W*0.05,y:H*0.5-p*H*0.1,s:1+p*0.15,r:-5*p};}
        if(t<2800){var p=(t-1800)/1000;return{x:W*0.35,y:H*0.4,s:1.15+p*0.05,r:-5};}
        if(t<3600){var p=(t-2800)/800;return{x:W*0.35,y:H*0.4,s:1.2-p*0.1,r:-5+p*3};}
        if(t<5400){var p=(t-4200)/1200;p=Math.max(0,p);return{x:W*0.35+p*W*0.6,y:H*0.4+p*H*0.6,s:1.1-p*0.5,r:-2+p*20};}
        return{x:W+200,y:H+200,s:0.3,r:20};
    }
    var flashAlpha=0,fireActive=false;
    function animate(now){
        if(startTime===null)startTime=now;
        var t=now-startTime;
        ctx.clearRect(0,0,W,H);
        // Background pulse
        var bgAlpha=Math.min(1,t/500);
        ctx.fillStyle='rgba(3,5,8,'+bgAlpha+')';ctx.fillRect(0,0,W,H);
        // Phase: Entry with screen shake (0-600ms)
        if(t<600){shake(8*(1-t/600));}
        else{overlay.style.transform='none';}
        // Dragon position
        var dp=getDragonPos(t);
        dragonEl.style.left=(dp.x-170)+'px';
        dragonEl.style.top=(dp.y-150)+'px';
        dragonEl.style.transform='scale('+dp.s+') rotate('+dp.r+'deg)';
        // Ember trail (0.6-1.8s)
        if(t>300&&t<5400){
            for(var i=0;i<2;i++){
                particles.push(new Particle(dp.x+Math.random()*40-20,dp.y+Math.random()*40+60,'ember'));
            }
        }
        // Chest charge glow (1.8-2.8s)
        if(t>1800&&t<3600){
            var cp=Math.min(1,(t-1800)/1000);
            chestGlow.setAttribute('opacity',cp*0.9);
            // Charge particles
            for(var i=0;i<Math.floor(cp*5);i++){
                var a=Math.random()*Math.PI*2,r=30+Math.random()*20;
                particles.push(new Particle(dp.x+Math.cos(a)*r,dp.y+Math.sin(a)*r,'ember'));
            }
        }
        // Fire blast (2.8-3.6s)
        if(t>2800&&t<3600){
            fireActive=true;
            var fp=(t-2800)/800;
            shake(12*fp);
            // Massive fire particles from dragon toward center
            for(var i=0;i<20;i++){
                var fx=dp.x-40,fy=dp.y-20;
                var p=new Particle(fx,fy,'fire');
                p.vx=(W/2-fx)*0.015+Math.random()*6-3;
                p.vy=(H/2-fy)*0.015+Math.random()*6-3;
                p.size=6+Math.random()*12;
                p.decay=0.012;
                particles.push(p);
            }
            // Flash
            flashAlpha=Math.min(0.7,fp*1.2);
        }else{
            fireActive=false;
            if(flashAlpha>0)flashAlpha*=0.9;
        }
        // HIPS text reveal (3.6-4.2s)
        if(t>3400&&t<6500){
            var tp=Math.min(1,(t-3400)/600);
            hipsText.style.opacity=tp;
            if(t>3600&&t<4200){
                // Residual heat pulse
                var pulse=1+Math.sin((t-3600)*0.01)*0.03;
                hipsText.style.transform='translate(-50%,-50%) scale('+pulse+')';
            }
        }
        // Dragon retreat (4.2-5.4s)
        if(t>4200&&t<5400){
            var rp=(t-4200)/1200;
            dragonEl.style.opacity=1-rp;
            // Smoke
            for(var i=0;i<3;i++){
                particles.push(new Particle(dp.x+Math.random()*60-30,dp.y+Math.random()*40,'smoke'));
            }
        }
        if(t>5400)dragonEl.style.opacity=0;
        // HIPS fade + dashboard fade in (5.4-6.5s)
        if(t>5400){
            var fo=(t-5400)/1100;
            hipsText.style.opacity=Math.max(0,1-fo*1.5);
            overlay.style.opacity=Math.max(0,1-fo);
        }
        // Update and draw particles
        for(var i=particles.length-1;i>=0;i--){
            particles[i].update();particles[i].draw();
            if(particles[i].life<=0)particles.splice(i,1);
        }
        // Flash overlay
        if(flashAlpha>0.01){
            ctx.fillStyle='rgba(255,240,220,'+flashAlpha+')';ctx.fillRect(0,0,W,H);
        }
        // Vignette
        var vg=ctx.createRadialGradient(W/2,H/2,H*0.3,W/2,H/2,H*0.8);
        vg.addColorStop(0,'rgba(0,0,0,0)');vg.addColorStop(1,'rgba(0,0,0,0.7)');
        ctx.fillStyle=vg;ctx.fillRect(0,0,W,H);
        if(t<6600){requestAnimationFrame(animate);}
        else{
            overlay.parentNode.removeChild(overlay);
            localStorage.setItem('hips_intro_played','1');
            var pl=document.getElementById('pagePreloader');
            if(pl){pl.classList.add('hidden');setTimeout(function(){pl.style.display='none';},500);}
        }
    }
    requestAnimationFrame(animate);
})();
</script>

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
                <button class="btn btn-secondary btn-sm" onclick="location.reload()"><i class="fa-solid fa-rotate"></i> Refresh</button>
            </div>
        </div>

        <!-- Stat Cards -->
        <div class="stat-grid">
            <div class="stat-card animate-fadeIn delay-1">
                <div class="stat-icon"><i class="fa-solid fa-desktop"></i></div>
                <div class="stat-value" data-count="<?= $totalAgents ?>"><?= $totalAgents ?></div>
                <div class="stat-label">Total Agents</div>
                <span class="stat-trend down">↑ <?= $onlineAgents ?> online</span>
            </div>
            <div class="stat-card animate-fadeIn delay-2">
                <div class="stat-icon"><i class="fa-solid fa-triangle-exclamation"></i></div>
                <div class="stat-value" data-count="<?= $activeAlerts ?>"><?= $activeAlerts ?></div>
                <div class="stat-label">Active Alerts</div>
                <?php if ($activeAlerts > 0): ?>
                <span class="stat-trend up"><i class="fa-solid fa-triangle-exclamation"></i> Action needed</span>
                <?php else: ?>
                <span class="stat-trend down"><i class="fa-solid fa-check"></i> All clear</span>
                <?php endif; ?>
            </div>
            <div class="stat-card animate-fadeIn delay-3">
                <div class="stat-icon"><i class="fa-solid fa-folder-tree"></i></div>
                <div class="stat-value" data-count="<?= $fileEvents ?>"><?= $fileEvents ?></div>
                <div class="stat-label">File Events Today</div>
            </div>
            <div class="stat-card animate-fadeIn delay-4">
                <div class="stat-icon"><i class="fa-solid fa-network-wired"></i></div>
                <div class="stat-value" data-count="<?= $networkEvents ?>"><?= $networkEvents ?></div>
                <div class="stat-label">Network Events Today</div>
            </div>
            <div class="stat-card animate-fadeIn delay-5">
                <div class="stat-icon"><i class="fa-solid fa-microchip"></i></div>
                <div class="stat-value" data-count="<?= $processEvents ?>"><?= $processEvents ?></div>
                <div class="stat-label">Process Events</div>
            </div>
            <div class="stat-card animate-fadeIn delay-6">
                <div class="stat-icon"><i class="fa-solid fa-database"></i></div>
                <div class="stat-value" data-count="<?= $registryEvents ?>"><?= $registryEvents ?></div>
                <div class="stat-label">Registry Events</div>
            </div>
        </div>

        <!-- Security Status Overview -->
        <div class="card animate-fadeIn" style="margin-bottom:24px; border-left: 4px solid <?= $threatScore > 50 ? 'var(--severity-high)' : 'var(--accent-violet)' ?>;">
            <div style="display:flex; align-items:center; justify-content:space-between; padding:4px 10px;">
                <div style="display:flex; align-items:center; gap:16px;">
                    <div style="font-size:32px; color:var(--accent-violet);"><i class="fa-solid fa-shield-halved"></i></div>
                    <div>
                        <h3 style="margin:0; color:var(--text-heading);">System Security Status: <?= $threatScore > 50 ? 'Attention Required' : 'Protected' ?></h3>
                        <p style="margin:4px 0 0; color:var(--text-muted); font-size:13px;">
                            <?php if ($threatScore > 50): ?>
                                High threat level detected. Please review the critical alerts immediately.
                            <?php else: ?>
                                No critical threats detected. All monitoring modules are active and reporting.
                            <?php endif; ?>
                        </p>
                    </div>
                </div>
                <div style="text-align:right;">
                    <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; letter-spacing:1px;">Last Activity</div>
                    <div style="font-size:14px; color:var(--text-primary); font-weight:600; font-family:'JetBrains Mono',monospace;">
                        <?php 
                        $lastEventTime = $pdo->query("SELECT created_at FROM events ORDER BY created_at DESC LIMIT 1")->fetchColumn();
                        echo $lastEventTime ? date('M d, H:i', strtotime($lastEventTime)) : 'N/A';
                        ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Row 2: Threat Gauge + System Health + Agent Status -->
        <div style="display:grid; grid-template-columns: 1fr 1.5fr 1fr; gap:20px; margin-bottom:24px;">
            <!-- Threat Level Gauge -->
            <div class="card scroll-reveal">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-crosshairs"></i></span> Threat Level</div>
                <div style="padding:10px;">
                    <div class="threat-ring" style="--threat-pct:<?= $threatScore ?>; --threat-color:<?= $threatColor ?>;">
                        <div class="threat-inner">
                            <div class="threat-score" style="color:<?= $threatColor ?>;"><?= $threatScore ?></div>
                            <div class="threat-label"><?= $threatLevel ?></div>
                        </div>
                    </div>
                    <div style="font-size:11px; color:var(--text-muted); margin-top:8px;">
                        <i class="fa-solid fa-circle" style="color:var(--severity-critical); font-size:8px;"></i> <?= $criticalCount ?> Critical &nbsp; <i class="fa-solid fa-circle" style="color:var(--severity-high); font-size:8px;"></i> <?= $highCount ?> High &nbsp; <i class="fa-solid fa-circle" style="color:var(--severity-medium); font-size:8px;"></i> <?= $medCount ?> Medium
                    </div>
                </div>
            </div>

            <!-- System Health -->
            <div class="card scroll-reveal">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-heart-pulse"></i></span> System Health</div>
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
                    <div class="health-item">
                        <div class="health-indicator green"></div>
                        <span class="health-label">Memory Analysis</span>
                        <span class="health-value"><?= $memoryEvents ?> events</span>
                    </div>
                    <div class="health-item">
                        <div class="health-indicator green"></div>
                        <span class="health-label">Hardware Audit</span>
                        <span class="health-value"><?= $assetEvents ?> events</span>
                    </div>
                </div>
            </div>

            <!-- Agent Status -->
            <div class="card scroll-reveal reveal-right">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-microchip"></i></span> Agent Status</div>
                <?php foreach ($agents as $ag): ?>
                <div class="health-grid-item" style="padding:8px 0;border-bottom:1px solid var(--border-color);">
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
                    <span><span class="icon"><i class="fa-solid fa-triangle-exclamation"></i></span> Recent Alerts</span>
                    <a href="alerts.php" class="btn btn-secondary btn-sm" style="font-size:10px;">View All →</a>
                </div>
                <div style="overflow-x:auto;">
                <table class="data-table">
                    <thead>
                        <tr><th>Severity</th><th>Title</th><th>Agent</th><th>Module</th><th>Time</th></tr>
                    </thead>
                    <tbody>
                        <?php if (empty($recentAlerts)): ?>
                        <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:30px;">No alerts yet. System is clean. <i class="fa-solid fa-check"></i></td></tr>
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
                    <div class="card-title"><span class="icon"><i class="fa-solid fa-timeline"></i></span> Activity Timeline</div>
                <div class="timeline" style="max-height:300px;overflow-y:auto;">
                    <?php if (empty($recentActivity)): ?>
                    <p style="color:var(--text-muted);font-size:12px;text-align:center;padding:20px;">No activity yet.</p>
                    <?php else: foreach ($recentActivity as $act): ?>
                    <div class="timeline-item">
                        <div class="tl-time"><?= date('H:i:s', strtotime($act['created_at'])) ?></div>
                        <div class="tl-desc"><?= htmlspecialchars(substr($act['description'] ?? 'Event recorded', 0, 80)) ?></div>
                        <div class="tl-meta">
                            <span><i class="fa-solid fa-location-dot"></i> <?= htmlspecialchars($act['hostname'] ?? 'System') ?></span>
                            <span>•</span>
                            <span class="badge <?= strtolower($act['severity'] ?? 'low') ?>" style="font-size:8px; padding:1px 4px;"><?= $act['severity'] ?></span>
                        </div>
                    </div>
                    <?php endforeach; endif; ?>
                </div>
            </div>

            <!-- Quick Actions Card -->
            <div class="card scroll-reveal reveal-right">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-bolt"></i></span> Quick Actions</div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
                    <a href="commands.php?action=scan" class="action-card">
                        <div class="action-icon"><i class="fa-solid fa-magnifying-glass-plus"></i></div>
                        <div class="action-label">Deep Scan</div>
                    </a>
                    <a href="reports.php" class="action-card">
                        <div class="action-icon"><i class="fa-solid fa-chart-simple"></i></div>
                        <div class="action-label">Report</div>
                    </a>
                    <a href="agents.php" class="action-card">
                        <div class="action-icon"><i class="fa-solid fa-users-gear"></i></div>
                        <div class="action-label">Manage</div>
                    </a>
                    <a href="settings.php" class="action-card">
                        <div class="action-icon"><i class="fa-solid fa-gears"></i></div>
                        <div class="action-label">Settings</div>
                    </a>
                </div>
                <div style="margin-top:16px; padding:12px; background:var(--bg-secondary); border-radius:var(--radius-md); border:1px dashed var(--border-color);">
                    <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">System Integrity</div>
                    <div style="height:6px; background:rgba(255,255,255,0.05); border-radius:3px; overflow:hidden;">
                        <div style="width:94%; height:100%; background:var(--accent-violet); box-shadow:0 0 8px var(--accent-violet);"></div>
                    </div>
                    <div style="display:flex; justify-content:space-between; margin-top:6px; font-size:10px; color:var(--text-muted);">
                        <span>94% Secure</span>
                        <span>v2.4.0</span>
                    </div>
                </div>
            </div>
        </div>
        </div>

        <!-- 24-Hour Activity Chart -->
        <div class="card scroll-reveal reveal-scale">
            <div class="card-title"><span class="icon"><i class="fa-solid fa-chart-area"></i></span> 24-Hour Event Activity</div>
            <div class="chart-container">
                <canvas id="activityChart"></canvas>
            </div>
        </div>
    </main>
</div>

<script>
// ── 24-Hour Activity Chart ───────────────────────────────────
const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
const gridColor = isDark ? 'rgba(139,92,246,0.05)' : 'rgba(15,23,42,0.06)';
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
                backgroundColor: isDark ? 'rgba(139, 92, 246, 0.4)' : 'rgba(109, 40, 217, 0.45)',
                borderColor: isDark ? 'rgba(139, 92, 246, 1)' : 'rgba(109, 40, 217, 1)',
                borderWidth: 1,
                borderRadius: 4,
            },
            {
                label: 'Network Events',
                data: <?= json_encode(array_values($netHours)) ?>,
                backgroundColor: isDark ? 'rgba(139, 92, 246, 0.6)' : 'rgba(109, 40, 217, 0.65)',
                borderColor: isDark ? 'rgba(139, 92, 246, 1)' : 'rgba(109, 40, 217, 1)',
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
            },
            {
                label: 'Memory Events',
                data: <?= json_encode(array_values($memHours)) ?>,
                backgroundColor: 'rgba(239, 68, 68, 0.6)',
                borderColor: 'rgba(239, 68, 68, 1)',
                borderWidth: 1,
                borderRadius: 4,
            },
            {
                label: 'Asset Events',
                data: <?= json_encode(array_values($assetHours)) ?>,
                backgroundColor: 'rgba(234, 179, 8, 0.6)',
                borderColor: 'rgba(234, 179, 8, 1)',
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
