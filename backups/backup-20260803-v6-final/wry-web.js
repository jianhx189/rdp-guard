// wry-web.js - RDP Guard Web Dashboard v6 (2026-08-03)
// 在 19888 端口提供状态页；读取 rdp_guard.json（引擎实时写入）
// v6 变更：
//  1. 新增"攻击日志"框：显示当日每次 4625 攻击（时间/IP/被爆破用户名/类型/状态码），仅当日，倒序
//  2. "强制解锁 RDP"按钮常驻显示（RDP 被锁时可一键强制解锁并解封全部）
//  3. 保留 v5：RDP 端口状态卡片、封禁倒计时、unblockRequests/rdpOpenRequest 机制
const http = require('http');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const PORT = 19888;
const HOST = '127.0.0.1'; // 仅本机访问
const STATE_FILE = path.join(__dirname, 'data', 'rdp_guard.json');
const RULE_PREFIX = 'RDP-Guard-Block-';
const LOG_MAX_SHOW = 100; // 日志框最多显示条数

function readState() {
    try {
        if (fs.existsSync(STATE_FILE)) {
            const st = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
            if (!st.rdp) st.rdp = { port: 3389, open: true, blockUntil: null, portListening: null };
            if (!Array.isArray(st.attackLog)) st.attackLog = [];
            return st;
        }
    } catch (e) { /* ignore */ }
    return { version: 6, lastCheck: null, lastEvent: null, totalFailures: 0, blockedIPs: {}, attempts: {}, todayDate: null, todayFailures: 0, todayIPs: {}, attackLog: [], rdp: { port: 3389, open: true, blockUntil: null, portListening: null }, error: '状态文件不存在（引擎可能未运行）' };
}

function isValidIPv4(ip) {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
    return ip.split('.').map(Number).every(n => n >= 0 && n <= 255);
}

const HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RDP Guard 状态</title>
<style>
  body { font-family:"Segoe UI","Microsoft YaHei",sans-serif; background:#f0f2f5; margin:0; padding:20px; }
  .container { max-width:900px; margin:0 auto; }
  h1 { font-size:20px; color:#1f2937; display:flex; align-items:center; gap:10px; }
  h3 { margin:0 0 4px; color:#1f2937; }
  .badge { padding:3px 10px; border-radius:12px; font-size:13px; font-weight:600; }
  .badge.ok { background:#d1fae5; color:#065f46; }
  .badge.bad { background:#fee2e2; color:#991b1b; }
  .badge.warn { background:#fef3c7; color:#92400e; }
  .card { background:#fff; border-radius:10px; padding:16px 20px; margin-top:14px; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  .stat-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:10px; }
  .stat { background:#f9fafb; border-radius:8px; padding:10px 12px; }
  .stat .k { font-size:12px; color:#6b7280; }
  .stat .v { font-size:18px; font-weight:700; color:#111827; }
  table { width:100%; border-collapse:collapse; margin-top:8px; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid #e5e7eb; font-size:14px; }
  th { background:#f9fafb; color:#374151; }
  .ip { font-family:Consolas,monospace; font-weight:600; color:#b91c1c; }
  .btn { background:#fee2e2; color:#991b1b; border:1px solid #fecaca; border-radius:6px; padding:6px 14px; cursor:pointer; font-size:13px; font-weight:600; }
  .btn:hover { background:#fecaca; }
  .btn.green { background:#d1fae5; color:#065f46; border:1px solid #a7f3d0; }
  .btn.green:hover { background:#a7f3d0; }
  .btn.red { background:#fee2e2; color:#991b1b; border:1px solid #fecaca; }
  .muted { color:#9ca3af; font-size:12px; }
  .msg { margin-top:8px; font-size:13px; }
  .logbox { max-height:320px; overflow-y:auto; margin-top:8px; border:1px solid #e5e7eb; border-radius:8px; background:#0f172a; padding:0; }
  .logbox table { margin:0; }
  .logbox th { background:#1e293b; color:#94a3b8; font-size:12px; position:sticky; top:0; }
  .logbox td { border-bottom:1px solid #1e293b; color:#cbd5e1; font-size:12px; font-family:Consolas,monospace; padding:5px 10px; }
  .logbox tr:hover td { background:#1e293b; }
  .user-cell { color:#f59e0b; font-weight:600; }
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ RDP Guard 状态 <span id="badge" class="badge">…</span></h1>
  <div class="card"><div class="stat-grid">
    <div class="stat"><div class="k">今日攻击量 <span class="muted" id="todayDate"></span></div><div class="v" id="today">0</div></div>
    <div class="stat"><div class="k">引擎状态</div><div class="v" id="engine">…</div></div>
    <div class="stat"><div class="k">最近检查</div><div class="v" id="lastCheck">…</div></div>
    <div class="stat"><div class="k">累计失败登录</div><div class="v" id="total">0</div></div>
    <div class="stat"><div class="k">已封禁 IP</div><div class="v" id="blockedCount">0</div></div>
  </div><div class="msg muted" id="hint"></div></div>
  <div class="card"><h3>🖥️ RDP 端口 (3389) <span id="rdp-badge" class="badge">…</span></h3>
    <div class="stat-grid">
      <div class="stat"><div class="k">端口状态</div><div class="v" id="rdp-status">…</div></div>
      <div class="stat"><div class="k">监听状态</div><div class="v" id="rdp-listen">…</div></div>
      <div class="stat"><div class="k">恢复时间</div><div class="v" id="rdp-until">…</div></div>
    </div>
    <div class="msg" id="rdp-actions"></div>
    <div class="msg muted">默认开启；检测到攻击时自动封锁 5 分钟，到期自动恢复。RDP 被锁时可点下方按钮强制解锁。</div>
  </div>
  <div class="card"><h3>🗓️ 今日攻击源（含内网探测，上海时区）</h3>
    <table><thead><tr><th>IP 地址</th><th>类型</th><th>失败次数</th><th>状态</th></tr></thead><tbody id="today-list"></tbody></table></div>
  <div class="card"><h3>🚫 已封禁 IP（5 分钟自动解封）</h3>
    <table><thead><tr><th>IP 地址</th><th>封禁时间</th><th>剩余</th><th></th></tr></thead><tbody id="blocked-list"></tbody></table></div>
  <div class="card"><h3>📜 攻击日志（当日逐条 · 最新在前）<span class="muted" id="log-count"></span></h3>
    <div class="logbox"><table><thead><tr><th style="width:150px">时间</th><th>攻击源 IP</th><th>被爆破用户名</th><th style="width:70px">类型</th><th>状态码</th></tr></thead><tbody id="attack-log"></tbody></table></div>
  </div>
  <div class="card"><h3>📈 今日失败登录（1 天窗口，含内网攻击源）</h3>
    <table><thead><tr><th>IP 地址</th><th>尝试账户</th><th>登录类型</th><th>状态码</th><th>失败次数</th><th>最近时间</th></tr></thead><tbody id="attempts-list"></tbody></table></div>
  <p class="muted" id="foot">RDP Guard v6 · 页面每 5 秒自动刷新 · 仅本机可访问</p>
</div>
<script>
var esc = function(s){ return String(s==null?"":s).replace(/[&<>"']/g, function(c){ return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]; }); };
function fmt(iso){ if(!iso) return "-"; var d=new Date(iso); return d.toLocaleString("zh-CN",{hour12:false}); }
function fmtTime(iso){ if(!iso) return "-"; var d=new Date(iso); return d.toLocaleString("zh-CN",{hour12:false,month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"}); }
function isPrivate(ip){
  if(!ip || ip === "-") return true;
  if(ip.indexOf(":")>=0) return true;
  var p = ip.split(".");
  if(p.length!==4) return true;
  var n = p.map(Number);
  if(n.some(function(x){return isNaN(x)||x<0||x>255;})) return true;
  var a=n[0], b=n[1];
  if(a===10) return true;
  if(a===172 && b>=16 && b<=31) return true;
  if(a===192 && b===168) return true;
  if(a===169 && b===254) return true;
  if(a===100 && b>=64 && b<=127) return true;
  if(a===127||a===0||a>=224) return true;
  return false;
}
function statusText(s){
  if(!s || s === "-" || s === "") return "-";
  var m = {"0xc0000064":"用户名不存在","0xc000006a":"密码错误","0xc000006d":"用户名或密码错误","0xc000006f":"不允许该时段登录","0xc0000070":"不允许该工作站","0xc0000071":"密码过期","0xc0000072":"账户已禁用","0xc000009a":"资源不足","0xc0000193":"账户过期","0xc0000224":"必须改密码后才能登录","0xc0000234":"账户已锁定","0xc0000371":"本地账户不可用"};
  var k = String(s).toLowerCase();
  return m[k] ? m[k] + " (" + s + ")" : s;
}
function remainTxt(until){
  if(!until) return "";
  var ms = new Date(until).getTime() - Date.now();
  if(ms <= 0) return "已到期";
  var s = Math.round(ms/1000);
  if(s >= 60) return Math.floor(s/60)+"分"+(s%60)+"秒 后自动解封";
  return s+"秒 后自动解封";
}
async function unblock(ip){
  if(!confirm("确认解封 "+ip+" ？")) return;
  try {
    var r = await fetch("/api/unblock?ip="+encodeURIComponent(ip), {method:"POST"});
    var j = await r.json();
    alert(j.ok ? "已解封 "+ip : "解封失败: "+(j.error||"未知错误"));
  } catch(e) { alert("请求失败: "+e.message); }
  refresh();
}
async function rdpOpen(){
  if(!confirm("确认强制解锁 RDP 端口并解封全部攻击源？")) return;
  try {
    var r = await fetch("/api/rdp/open", {method:"POST"});
    var j = await r.json();
    alert(j.ok ? "已请求引擎强制解锁，约 20 秒内生效" : "请求失败: "+(j.error||"未知错误"));
  } catch(e) { alert("请求失败: "+e.message); }
  refresh();
}
async function refresh(){
  try {
    var r = await fetch("/api/state?t="+Date.now());
    var d = await r.json();
    var last = d.lastCheck ? new Date(d.lastCheck).getTime() : 0;
    var stale = (Date.now()-last) > 60000;
    var badge = document.getElementById("badge");
    if (d.error) { badge.className="badge bad"; badge.textContent="无数据"; }
    else if (stale) { badge.className="badge bad"; badge.textContent="引擎异常"; }
    else { badge.className="badge ok"; badge.textContent="运行中"; }
    document.getElementById("engine").textContent = d.error ? "未运行" : (stale ? "心跳超时" : "运行中");
    document.getElementById("lastCheck").textContent = fmt(d.lastCheck);
    document.getElementById("total").textContent = d.totalFailures || 0;
    document.getElementById("today").textContent = d.todayFailures || 0;
    document.getElementById("todayDate").textContent = d.todayDate ? "(" + d.todayDate + ")" : "";
    var bips = Object.entries(d.blockedIPs||{});
    document.getElementById("blockedCount").textContent = bips.length;
    document.getElementById("hint").textContent = d.error || (bips.length===0 ? "尚未封禁任何 IP（攻击源达阈值后自动封禁 5 分钟）" : "");
    var bt = document.getElementById("blocked-list");
    if (bips.length===0) bt.innerHTML = '<tr><td colspan="4" class="muted">无</td></tr>';
    else bt.innerHTML = bips.map(function(p){
      var v = p[1];
      var since = (typeof v === 'string') ? v : (v && v.since);
      var until = (typeof v === 'object' && v) ? v.until : null;
      return '<tr><td class="ip">'+esc(p[0])+'</td><td>'+fmt(since)+'</td><td class="muted">'+remainTxt(until)+'</td><td><button class="btn" data-ip="'+esc(p[0])+'">解封</button></td></tr>';
    }).join("");
    // RDP 端口状态卡片
    var rdp = d.rdp || { open: true, portListening: null, blockUntil: null };
    var rb = document.getElementById("rdp-badge");
    var rs = document.getElementById("rdp-status");
    if (!rdp.open) { rb.className="badge bad"; rb.textContent="已封锁(防护中)"; rs.textContent="🔒 已封锁"; }
    else if (rdp.portListening === false) { rb.className="badge warn"; rb.textContent="放行但未监听"; rs.textContent="放行中"; }
    else { rb.className="badge ok"; rb.textContent="开启中"; rs.textContent="✅ 开启(放行)"; }
    document.getElementById("rdp-listen").textContent = rdp.portListening===null ? "检测中…" : (rdp.portListening ? "3389 正在监听" : "3389 未监听");
    document.getElementById("rdp-until").textContent = rdp.blockUntil ? fmt(rdp.blockUntil)+" 恢复" : "-";
    // 强制解锁按钮（常驻）
    var act = document.getElementById("rdp-actions");
    if (!rdp.open) {
      act.innerHTML = '<button class="btn red" id="btn-rdp-open">🔓 强制解锁 RDP 端口（并解封全部）</button>';
    } else {
      act.innerHTML = '<button class="btn green" id="btn-rdp-open">🔓 强制解锁 RDP 端口（当前已开启，可重置）</button>';
    }
    // 攻击日志（当日逐条，倒序）
    var logs = (d.attackLog||[]).slice().reverse();
    document.getElementById("log-count").textContent = "共 " + (d.attackLog||[]).length + " 条";
    var lc = document.getElementById("attack-log");
    if (logs.length===0) lc.innerHTML = '<tr><td colspan="5" class="muted" style="text-align:center;padding:16px;">今日暂无攻击记录</td></tr>';
    else lc.innerHTML = logs.slice(0,100).map(function(x){
      var ip = x.ip || "-";
      var priv = isPrivate(ip);
      var user = x.user && x.user !== "?" ? x.user : "-";
      return '<tr><td>'+fmtTime(x.t)+'</td><td class="ip">'+esc(ip)+'</td><td class="user-cell">'+esc(user)+'</td><td>'+(x.logonType&&x.logonType!=="?"?esc(x.logonType):"-")+'</td><td>'+esc(statusText(x.status))+'</td></tr>';
    }).join("");
    var at = document.getElementById("attempts-list");
    var att = Object.entries(d.attempts||{}).sort(function(a,b){ return b[1].length-a[1].length; });
    if (att.length===0) at.innerHTML = '<tr><td colspan="6" class="muted">无</td></tr>';
    else at.innerHTML = att.map(function(p){
      var recs = p[1];
      var last = recs[recs.length-1];
      var lastT = (typeof last === 'string') ? last : last.t;
      var users = {}, types = {}, stats = {};
      recs.forEach(function(r){
        var u = (typeof r === 'string') ? null : r.user; if (u && u !== "?") users[u] = 1;
        var lt = (typeof r === 'string') ? null : r.logonType; if (lt && lt !== "?") types[lt] = 1;
        var s = (typeof r === 'string') ? null : r.status; if (s) stats[s] = 1;
      });
      var userStr = Object.keys(users).join(", ") || "-";
      var typeStr = Object.keys(types).join(", ") || "-";
      var statStr = Object.keys(stats).map(statusText).join(", ") || "-";
      return '<tr><td class="ip">'+esc(p[0])+'</td><td>'+esc(userStr)+'</td><td>'+esc(typeStr)+'</td><td>'+esc(statStr)+'</td><td>'+recs.length+'</td><td>'+fmt(lastT)+'</td></tr>';
    }).join("");
    var tl = document.getElementById("today-list");
    var tip = Object.entries(d.todayIPs||{}).sort(function(a,b){ return b[1]-a[1]; });
    if (tip.length===0) tl.innerHTML = '<tr><td colspan="4" class="muted">今日暂无攻击记录</td></tr>';
    else tl.innerHTML = tip.map(function(p){ var ip=p[0]; var priv=isPrivate(ip); var blk=d.blockedIPs&&d.blockedIPs[ip]; return '<tr><td class="ip">'+esc(ip)+'</td><td>'+(priv?(ip==="(未知)"?"未知":"内网"):"公网")+'</td><td>'+p[1]+'</td><td>'+(blk?"✅ 已封禁":(priv?"⏭ 忽略(内网)":"👁 观察中"))+'</td></tr>'; }).join("");
    document.getElementById("foot").textContent = "RDP Guard v6 · 引擎心跳 "+(d.lastCheck? fmt(d.lastCheck)+" 更新":"暂无")+" · 页面每 5 秒自动刷新";
  } catch(e) {
    document.getElementById("badge").className="badge bad"; document.getElementById("badge").textContent="连接失败";
  }
}
document.addEventListener("click", function(e){
  var btn = e.target && e.target.closest ? e.target.closest("button[data-ip]") : null;
  if (btn) unblock(btn.getAttribute("data-ip"));
  var ro = e.target && e.target.closest ? e.target.closest("#btn-rdp-open") : null;
  if (ro) rdpOpen();
});
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>`;

function sendJSON(res, obj, code){
    res.writeHead(code || 200, {'Content-Type':'application/json; charset=utf-8'});
    res.end(JSON.stringify(obj));
}

const server = http.createServer((req, res) => {
    let u;
    try { u = new URL(req.url, 'http://x'); } catch (e) { return sendJSON(res, {ok:false, error:'bad url'}, 400); }
    if (u.pathname === '/api/state') {
        sendJSON(res, readState());
    } else if (u.pathname === '/api/unblock' && req.method === 'POST') {
        const ip = (u.searchParams.get('ip')||'').trim();
        if (!isValidIPv4(ip)) return sendJSON(res, {ok:false, error:'无效 IP'}, 400);
        const rule = RULE_PREFIX + ip.replace(/\./g,'-');
        exec('netsh advfirewall firewall delete rule name="' + rule + '"', {windowsHide:true}, (err) => {
            if (err) return sendJSON(res, {ok:false, error:'删除防火墙规则失败: '+err.message}, 500);
            try {
                const st = readState();
                st.unblockRequests = st.unblockRequests || {};
                st.unblockRequests[ip] = new Date().toISOString();
                if (st.blockedIPs && st.blockedIPs[ip]) delete st.blockedIPs[ip];
                if (st.attempts && st.attempts[ip]) delete st.attempts[ip];
                const tmp = STATE_FILE + '.web.tmp';
                fs.writeFileSync(tmp, JSON.stringify(st, null, 2));
                fs.renameSync(tmp, STATE_FILE);
            } catch(e) {
                return sendJSON(res, {ok:false, error:'更新状态文件失败: '+e.message}, 500);
            }
            sendJSON(res, {ok:true});
        });
    } else if (u.pathname === '/api/rdp/open' && req.method === 'POST') {
        try {
            const st = readState();
            st.rdpOpenRequest = new Date().toISOString();
            const tmp = STATE_FILE + '.web.tmp';
            fs.writeFileSync(tmp, JSON.stringify(st, null, 2));
            fs.renameSync(tmp, STATE_FILE);
            sendJSON(res, {ok:true, note:'已请求引擎强制解锁 RDP 端口并解封全部（约 20 秒内生效）'});
        } catch(e) {
            sendJSON(res, {ok:false, error:'更新状态文件失败: '+e.message}, 500);
        }
    } else {
        res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
        res.end(HTML);
    }
});

server.listen(PORT, HOST, () => {
    console.log('RDP Guard Dashboard v6 running at http://' + HOST + ':' + PORT);
});
