"""HTML/CSS/JS for the WAF dashboard, served as a single self-contained page.

Kept in its own module so ``waf_dashboard.py`` stays focused on routing. No
external CDN / JS library is referenced — charts are drawn on a <canvas> so the
dashboard works on an air-gapped bare-metal box.
"""

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OJS WAF — Live Dashboard</title>
<style>
  :root {
    --bg:#0b0f17; --panel:#141b29; --panel2:#1b2435; --line:#26324a;
    --txt:#e6edf7; --muted:#8a99b3; --accent:#4f9cff; --ok:#34d399;
    --warn:#fbbf24; --bad:#f87171; --pass:#22c55e; --block:#ef4444;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--txt);
    font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
  header { display:flex; align-items:center; gap:14px; padding:16px 24px;
    border-bottom:1px solid var(--line); background:var(--panel); position:sticky; top:0; z-index:5; }
  header h1 { font-size:18px; margin:0; font-weight:600; letter-spacing:.3px; }
  header .badge { font-size:12px; color:var(--muted); }
  .dot { width:9px; height:9px; border-radius:50%; background:var(--ok); display:inline-block;
    box-shadow:0 0 8px var(--ok); animation:pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.35} }
  .wrap { padding:20px 24px; max-width:1400px; margin:0 auto; }
  .grid { display:grid; gap:16px; }
  .cards { grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); margin-bottom:16px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px; }
  .card .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.6px; }
  .card .value { font-size:26px; font-weight:700; margin-top:6px; }
  .card .sub { color:var(--muted); font-size:12px; margin-top:4px; }
  .bar { height:6px; border-radius:4px; background:var(--panel2); margin-top:10px; overflow:hidden; }
  .bar > span { display:block; height:100%; background:var(--accent); transition:width .4s; }
  .cols { grid-template-columns:2fr 1fr; align-items:start; }
  @media(max-width:900px){ .cols{ grid-template-columns:1fr; } }
  .panel { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px; }
  .panel h2 { font-size:13px; text-transform:uppercase; letter-spacing:.6px; color:var(--muted);
    margin:0 0 12px; }
  canvas { width:100%; height:220px; display:block; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--muted); font-weight:500; font-size:11px; text-transform:uppercase; letter-spacing:.5px; }
  td.uri { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px;
    max-width:520px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .tag { display:inline-block; padding:2px 8px; border-radius:20px; font-size:11px; font-weight:600; }
  .tag.BLOCK { background:rgba(239,68,68,.15); color:var(--block); }
  .tag.PASS { background:rgba(34,197,94,.15); color:var(--pass); }
  .atk { font-size:11px; color:var(--warn); }
  .atklist { display:flex; flex-direction:column; gap:8px; }
  .atkrow { display:flex; align-items:center; gap:10px; }
  .atkrow .n { margin-left:auto; font-variant-numeric:tabular-nums; color:var(--muted); }
  .atkbar { flex:1; height:8px; background:var(--panel2); border-radius:5px; overflow:hidden; }
  .atkbar > span { display:block; height:100%; background:linear-gradient(90deg,var(--warn),var(--bad)); }
  .ip { font-family:ui-monospace,monospace; }
  .muted { color:var(--muted); }
  .score { font-variant-numeric:tabular-nums; }
  .toolbar { display:flex; gap:10px; align-items:center; margin-bottom:12px; }
  button { background:var(--panel2); color:var(--txt); border:1px solid var(--line);
    padding:6px 12px; border-radius:8px; cursor:pointer; font-size:12px; }
  button.active { background:var(--accent); border-color:var(--accent); color:#06122a; font-weight:600; }
  footer { color:var(--muted); font-size:12px; text-align:center; padding:18px; }
</style>
</head>
<body>
<header>
  <span class="dot"></span>
  <h1>OJS WAF · Live Dashboard</h1>
  <span class="badge" id="model">model —</span>
  <span class="badge" style="margin-left:auto" id="clock"></span>
</header>

<div class="wrap">
  <div class="grid cards" id="syscards"></div>

  <div class="grid cols">
    <div class="panel">
      <h2>Traffic — requests / minute (last 60m)</h2>
      <canvas id="chart" width="900" height="220"></canvas>
    </div>
    <div class="panel">
      <h2>Attack types detected</h2>
      <div class="atklist" id="attacks"><span class="muted">No attacks recorded.</span></div>
      <h2 style="margin-top:18px">Top blocked source IPs</h2>
      <div class="atklist" id="sources"><span class="muted">—</span></div>
    </div>
  </div>

  <div class="panel" style="margin-top:16px">
    <div class="toolbar">
      <h2 style="margin:0">Recent requests</h2>
      <span style="flex:1"></span>
      <button id="btnAll" class="active" onclick="setFilter(false)">All</button>
      <button id="btnBlk" onclick="setFilter(true)">Blocked only</button>
    </div>
    <table>
      <thead><tr>
        <th>Time</th><th>Decision</th><th>Method</th><th>URI</th>
        <th>Attack</th><th>Score</th><th>Source IP</th>
      </tr></thead>
      <tbody id="events"></tbody>
    </table>
  </div>
</div>
<footer>OJS WAF dashboard · auto-refresh 3s · data from dataset/labeled · metrics from /proc</footer>

<script>
let onlyBlocked = false;
const fmtBytes = b => {
  if (!b) return "0 B";
  const u = ["B","KB","MB","GB","TB"]; let i = 0;
  while (b >= 1024 && i < u.length-1) { b/=1024; i++; }
  return b.toFixed(i?1:0)+" "+u[i];
};
function setFilter(b){ onlyBlocked=b;
  document.getElementById('btnAll').classList.toggle('active',!b);
  document.getElementById('btnBlk').classList.toggle('active',b);
  loadEvents(); }

function card(label,value,sub,pct,color){
  let bar = pct!=null ? `<div class="bar"><span style="width:${Math.min(pct,100)}%;background:${color||'var(--accent)'}"></span></div>` : '';
  return `<div class="card"><div class="label">${label}</div>
    <div class="value">${value}</div><div class="sub">${sub||''}</div>${bar}</div>`;
}

async function loadStats(){
  const s = await (await fetch('api/stats')).json();
  const m = s.system.memory, net = s.system.network;
  const cpu = s.system.cpu_percent, load = s.system.load_average;
  document.getElementById('model').textContent = 'model ' + (s.waf.model_version||'—');
  const cards = [
    card('Total requests', s.waf.total.toLocaleString(), `${s.waf.days_loaded} day(s) loaded`),
    card('Blocked', s.waf.blocked.toLocaleString(), s.waf.block_rate+'% block rate',
         s.waf.block_rate, 'var(--block)'),
    card('Passed', s.waf.passed.toLocaleString(), 'clean traffic'),
    card('CPU', cpu+'%', `${s.system.cpu_count} cores · load ${load[0]}`, cpu, 'var(--accent)'),
    card('Memory', m.percent+'%', `${fmtBytes(m.used)} / ${fmtBytes(m.total)}`, m.percent,
         m.percent>85?'var(--bad)':'var(--ok)'),
    card('Network', '↓'+fmtBytes(net.rx_rate)+'/s', '↑'+fmtBytes(net.tx_rate)+'/s'),
  ];
  document.getElementById('syscards').innerHTML = cards.join('');

  // attack types
  const atk = s.waf.attack_types, max = Math.max(1,...Object.values(atk));
  const ae = document.getElementById('attacks');
  const keys = Object.keys(atk);
  ae.innerHTML = keys.length ? keys.sort((a,b)=>atk[b]-atk[a]).map(k=>
    `<div class="atkrow"><span class="atk">${k}</span>
     <div class="atkbar"><span style="width:${100*atk[k]/max}%"></span></div>
     <span class="n">${atk[k].toLocaleString()}</span></div>`).join('')
    : '<span class="muted">No attacks recorded.</span>';

  const se = document.getElementById('sources');
  se.innerHTML = s.waf.top_sources.length ? s.waf.top_sources.map(x=>
    `<div class="atkrow"><span class="ip">${x.source_ip}</span>
     <span class="n">${x.count.toLocaleString()}</span></div>`).join('')
    : '<span class="muted">—</span>';
}

async function loadEvents(){
  const url = 'api/events?limit=60' + (onlyBlocked?'&blocked=1':'');
  const ev = await (await fetch(url)).json();
  document.getElementById('events').innerHTML = ev.map(e=>{
    const t = (e.timestamp||'').replace(/^[A-Za-z]{3}, /,'').replace(' GMT','');
    const atk = e.attack_type && e.attack_type!=='NONE'
      ? `<span class="atk">${e.attack_type}</span>` : '<span class="muted">—</span>';
    return `<tr>
      <td class="muted">${t}</td>
      <td><span class="tag ${e.decision}">${e.decision}</span></td>
      <td>${e.method}</td>
      <td class="uri" title="${(e.uri||'').replace(/"/g,'&quot;')}">${e.uri||''}</td>
      <td>${atk}</td>
      <td class="score">${e.threat_score.toFixed(3)}</td>
      <td class="ip">${e.source_ip}</td></tr>`;
  }).join('') || '<tr><td colspan="7" class="muted">No events.</td></tr>';
}

let chartData = {buckets:[],total:[],blocked:[]};
async function loadChart(){
  chartData = await (await fetch('api/timeseries')).json();
  drawChart();
}
function drawChart(){
  const c = document.getElementById('chart'), ctx = c.getContext('2d');
  const W = c.width = c.clientWidth, H = c.height;
  ctx.clearRect(0,0,W,H);
  const T = chartData.total, B = chartData.blocked;
  if (!T.length) return;
  const pad = 26, max = Math.max(1,...T);
  const x = i => pad + i*(W-2*pad)/Math.max(1,T.length-1);
  const y = v => H-pad - v*(H-2*pad)/max;
  // grid
  ctx.strokeStyle = '#26324a'; ctx.lineWidth = 1; ctx.fillStyle='#8a99b3'; ctx.font='10px sans-serif';
  for (let g=0; g<=4; g++){ const yy=pad+g*(H-2*pad)/4;
    ctx.beginPath(); ctx.moveTo(pad,yy); ctx.lineTo(W-pad,yy); ctx.stroke();
    ctx.fillText(Math.round(max*(1-g/4)), 2, yy+3); }
  const area = (arr,stroke,fill)=>{
    ctx.beginPath(); arr.forEach((v,i)=> i?ctx.lineTo(x(i),y(v)):ctx.moveTo(x(i),y(v)));
    ctx.strokeStyle=stroke; ctx.lineWidth=2; ctx.stroke();
    ctx.lineTo(x(arr.length-1),H-pad); ctx.lineTo(x(0),H-pad); ctx.closePath();
    ctx.fillStyle=fill; ctx.fill();
  };
  area(T,'#4f9cff','rgba(79,156,255,.12)');
  area(B,'#ef4444','rgba(239,68,68,.14)');
  // x labels (every ~10)
  ctx.fillStyle='#8a99b3';
  for (let i=0;i<chartData.buckets.length;i+=Math.ceil(chartData.buckets.length/6))
    ctx.fillText(chartData.buckets[i], x(i)-12, H-8);
}
window.addEventListener('resize', drawChart);

function tick(){ document.getElementById('clock').textContent = new Date().toLocaleTimeString(); }
async function refresh(){ try{ await Promise.all([loadStats(),loadEvents(),loadChart()]); }catch(e){} }
tick(); refresh();
setInterval(tick,1000);
setInterval(refresh,3000);
</script>
</body>
</html>"""
