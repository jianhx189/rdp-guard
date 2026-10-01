// send-report-html.js - RDP Guard 每日安全报告 v3 (2026-08-03)
// v3 变更：与 Web 面板 100% 同源 —— 数据全部取自 rdp_guard.json（todayFailures/todayIPs/attackLog/blockedIPs/rdp），
// 不再自查 wevtutil、不再按半天窗口统计，改为"今日全天"报告。每天 8:00/20:00 各发一次，内容均为截至发送时的今日累计。
// 兼容旧计划任务：不传 --period 参数时同样发送今日报告（参数仅保留兼容，不改变行为）。
// 去 QClaw 化：不依赖任何 QClaw 组件/路径/旧版数据文件。
const nodemailer = require('nodemailer');
const fs = require('fs');
const os = require('os');
const path = require('path');

const STATE_FILE = path.join(__dirname, 'data', 'rdp_guard.json');
const LOG_FILE = path.join(__dirname, 'data', 'rdp_guard.log');
const ATTACK_LOG_MAX_SHOW = 50; // 邮件里逐条显示的当日攻击日志上限（最新在前）

// ============= 邮件配置（环境变量优先，其次 mail-config.json）=============
function loadMailConfig() {
    let cfg = {};
    try {
        const cfgFile = path.join(__dirname, 'mail-config.json');
        if (fs.existsSync(cfgFile)) cfg = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
    } catch (e) {}
    return {
        host: cfg.host || 'smtp.yeah.net',
        port: cfg.port || 465,
        secure: cfg.secure !== false,
        user: process.env.SMTP_USER || cfg.user || '',
        pass: process.env.SMTP_PASS || cfg.pass || '',
        to: process.env.REPORT_TO_EMAIL || cfg.to || '',
        fromName: cfg.fromName || 'wry合金防护',
    };
}
const MAIL = loadMailConfig();

// ============= 时间工具（Asia/Shanghai = UTC+8，中国无夏令时）=============
function toShanghai(d) { return new Date(d.getTime() + 8 * 3600 * 1000); }
function shanghaiDateStr(ts) {
    const sh = toShanghai(new Date(ts));
    return sh.getUTCFullYear() + '-' + String(sh.getUTCMonth() + 1).padStart(2, '0') + '-' + String(sh.getUTCDate()).padStart(2, '0');
}
function fmtCN(d) { return d.toLocaleString('zh-CN', { timeZone: 'UTC', hour12: false }); }
// ISO 时间 -> 本地 HH:MM:SS（与 Web 面板显示一致）
function fmtTime(iso) {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso || '');
    const sh = toShanghai(d);
    return String(sh.getUTCHours()).padStart(2, '0') + ':' + String(sh.getUTCMinutes()).padStart(2, '0') + ':' + String(sh.getUTCSeconds()).padStart(2, '0');
}

// ============ 数据源：引擎状态 rdp_guard.json（唯一数据源，与 Web 100% 同源）============
function getGuardState() {
    try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); }
    catch { return null; }
}

// ============ 工具函数 ============
function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function isValidIPv4(ip) {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
    return ip.split('.').map(Number).every(n => n >= 0 && n <= 255);
}
function riskLevel(count) {
    if (count >= 100) return { color: '#e74c3c', label: '高危', icon: '🔴' };
    if (count >= 50) return { color: '#e67e22', label: '中危', icon: '🟠' };
    if (count >= 10) return { color: '#f39c12', label: '低危', icon: '🟡' };
    return { color: '#27ae60', label: '观察', icon: '🟢' };
}
const KNOWN_USERS = ['administrator', 'admin', 'wry', 'pro', 'guest'];
const STATUS_MAP = {
    '0xC0000064': '未知用户名', '0xC000006A': '密码错误', '0xC0000234': '账户锁定',
    '0xC0000072': '账户禁用', '0xC000006F': '登录时间外', '0xC0000070': '工作站限制',
    '0xC000006E': '账户不存在', '0xC000006D': '用户名/密码错误'
};
function getRecentLogs() {
    try {
        const content = fs.readFileSync(LOG_FILE, 'utf8');
        const lines = content.split('\n').filter(l => l.trim());
        return lines.slice(-15);
    } catch { return []; }
}

// ============ 主流程：从引擎状态采集（与 Web 同源）===========
const guardState = getGuardState();
if (!guardState) {
    console.error('❌ 无法读取引擎状态文件: ' + STATE_FILE);
    process.exit(1);
}

const now = new Date();
const dateStr = shanghaiDateStr(Date.now());
const hostname = os.hostname();
const nowStr = fmtCN(now);

const todayFailures = guardState.todayFailures || 0;
const todayIPs = guardState.todayIPs || {};
const attackLog = Array.isArray(guardState.attackLog) ? guardState.attackLog : [];
const blockedIPs = Object.keys((guardState.blockedIPs) || {}).filter(isValidIPv4);
const rdp = guardState.rdp || { open: true, port: 3389, blockUntil: null, portListening: null };
const totalFailures = guardState.totalFailures || 0;
const lastCheck = guardState.lastCheck ? fmtTime(guardState.lastCheck) : '—';

// ---- 今日 IP 统计（todayIPs 与 Web 卡片同源）----
const ipEntries = Object.entries(todayIPs).sort((a, b) => b[1] - a[1]);

// ---- 今日被爆破用户名 / 状态码（由 attackLog 聚合，与 Web 日志框同源）----
const userCount = {}; const statusCount = {}; const typeCount = {};
for (const a of attackLog) {
    const u = (a.user && a.user !== '?' && a.user.trim()) ? a.user.trim() : '(未知)';
    userCount[u] = (userCount[u] || 0) + 1;
    const s = (a.status && a.status !== '') ? a.status : null;
    if (s) statusCount[s] = (statusCount[s] || 0) + 1;
    const t = (a.logonType && a.logonType !== '?' && a.logonType !== '') ? a.logonType : null;
    if (t) typeCount[t] = (typeCount[t] || 0) + 1;
}
const userEntries = Object.entries(userCount).sort((a, b) => b[1] - a[1]);
const statusEntries = Object.entries(statusCount).sort((a, b) => b[1] - a[1]);

// ---- 今日逐条攻击日志（最新在前，最多 ATTACK_LOG_MAX_SHOW 条）----
const recentAttacks = attackLog.slice(-ATTACK_LOG_MAX_SHOW).reverse();

// ============ 组装 HTML ============
let failRows = '';
if (ipEntries.length === 0) {
    failRows = '<tr><td colspan="4" style="text-align:center;color:#94a0b8;padding:30px 16px;font-size:14px;">今日无失败登录记录 🛡️</td></tr>';
} else {
    for (const [ip, count] of ipEntries) {
        const rl = riskLevel(count);
        const blocked = blockedIPs.includes(ip);
        failRows += '<tr>' +
            '<td style="padding:12px 16px;border-bottom:1px solid #eef1f5;font-family:monospace;font-size:13px;color:#2c3e50;">' + escapeHtml(ip) + '</td>' +
            '<td style="padding:12px 16px;border-bottom:1px solid #eef1f5;font-weight:700;color:' + rl.color + ';font-size:15px;">' + count + '</td>' +
            '<td style="padding:12px 16px;border-bottom:1px solid #eef1f5;"><span style="background:' + rl.color + ';color:white;padding:3px 12px;border-radius:10px;font-size:11px;font-weight:600;">' + rl.icon + ' ' + rl.label + '</span></td>' +
            '<td style="padding:12px 16px;border-bottom:1px solid #eef1f5;">' +
                (blocked ? '<span style="color:#e74c3c;font-weight:600;">● 已封禁</span>' : '<span style="color:#bdc3c7;">—</span>') +
            '</td></tr>';
    }
}

let userRows = '';
if (userEntries.length === 0) {
    userRows = '<div style="text-align:center;color:#94a0b8;padding:20px;font-size:13px;">无记录</div>';
} else {
    userRows = '<table style="width:100%;border-collapse:collapse;font-size:13px;"><thead><tr style="background:#f8f9fb;">' +
        '<th style="padding:8px 12px;text-align:left;color:#94a0b8;font-weight:600;font-size:11px;">用户名</th>' +
        '<th style="padding:8px 12px;text-align:left;color:#94a0b8;font-weight:600;font-size:11px;">次数</th>' +
        '<th style="padding:8px 12px;text-align:left;color:#94a0b8;font-weight:600;font-size:11px;">类型</th></tr></thead><tbody>';
    for (const [u, c] of userEntries.slice(0, 15)) {
        const isKnown = KNOWN_USERS.includes(u.toLowerCase());
        userRows += '<tr>' +
            '<td style="padding:8px 12px;border-bottom:1px solid #eef1f5;font-family:monospace;' + (isKnown ? 'color:#e74c3c;font-weight:700;' : 'color:#2c3e50;') + '">' + escapeHtml(u) + (isKnown ? ' ⚠' : '') + '</td>' +
            '<td style="padding:8px 12px;border-bottom:1px solid #eef1f5;font-weight:700;">' + c + '</td>' +
            '<td style="padding:8px 12px;border-bottom:1px solid #eef1f5;">' + (isKnown ? '<span style="color:#e74c3c;font-size:12px;">真实账户</span>' : '<span style="color:#95a5a6;font-size:12px;">字典猜测</span>') + '</td></tr>';
    }
    userRows += '</tbody></table>';
    if (userEntries.length > 15) {
        userRows += '<div style="text-align:center;color:#94a0b8;font-size:12px;padding:8px;">还有 ' + (userEntries.length - 15) + ' 个用户名未显示...</div>';
    }
}

let statusRows = '';
if (statusEntries.length === 0) {
    statusRows = '<div style="text-align:center;color:#94a0b8;padding:12px;font-size:13px;">无数据</div>';
} else {
    statusRows = '<table style="width:100%;font-size:13px;">';
    for (const [s, c] of statusEntries) {
        statusRows += '<tr>' +
            '<td style="padding:6px 12px;font-family:monospace;color:#2c3e50;">' + s + '</td>' +
            '<td style="padding:6px 12px;font-weight:700;color:#2c3e50;">' + c + '</td>' +
            '<td style="padding:6px 12px;color:#7f8c8d;font-size:12px;">' + (STATUS_MAP[s.toUpperCase()] || '—') + '</td></tr>';
    }
    statusRows += '</table>';
}

let attackLogRows = '';
if (recentAttacks.length === 0) {
    attackLogRows = '<div style="text-align:center;color:#27ae60;padding:16px;font-size:13px;">🛡️ 今日暂无逐条攻击记录</div>';
} else {
    attackLogRows = '<table style="width:100%;border-collapse:collapse;font-size:12px;">' +
        '<thead><tr style="background:#0f1e3d;"><th style="padding:8px 10px;text-align:left;color:#9fb3d1;font-weight:600;font-size:11px;">时间</th>' +
        '<th style="padding:8px 10px;text-align:left;color:#9fb3d1;font-weight:600;font-size:11px;">攻击源 IP</th>' +
        '<th style="padding:8px 10px;text-align:left;color:#9fb3d1;font-weight:600;font-size:11px;">被爆破用户名</th>' +
        '<th style="padding:8px 10px;text-align:left;color:#9fb3d1;font-weight:600;font-size:11px;">类型</th>' +
        '<th style="padding:8px 10px;text-align:left;color:#9fb3d1;font-weight:600;font-size:11px;">状态</th></tr></thead><tbody>';
    for (const a of recentAttacks) {
        attackLogRows += '<tr>' +
            '<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-family:monospace;color:#5a6c7d;">' + fmtTime(a.t) + '</td>' +
            '<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-family:monospace;color:#2c3e50;font-weight:600;">' + escapeHtml(a.ip || '—') + '</td>' +
            '<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-family:monospace;color:#e74c3c;font-weight:600;">' + escapeHtml(a.user || '?') + '</td>' +
            '<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#7f8c8d;">' + escapeHtml(a.logonType || '—') + '</td>' +
            '<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-family:monospace;color:#7f8c8d;">' + escapeHtml(a.status || '—') + '</td></tr>';
    }
    attackLogRows += '</tbody></table>';
    if (attackLog.length > recentAttacks.length) {
        attackLogRows += '<div style="color:#94a0b8;font-size:11px;padding:8px 0 0;">共 ' + attackLog.length + ' 条，邮件仅展示最近 ' + recentAttacks.length + ' 条，完整请查看 Web 面板</div>';
    }
}

let blockRows = '';
if (blockedIPs.length === 0) {
    blockRows = '<div style="text-align:center;color:#27ae60;padding:16px;font-size:13px;">🛡️ 当前无封禁 IP，系统正常运行</div>';
} else {
    blockRows = '<div style="display:flex;flex-wrap:wrap;gap:8px;padding:4px 0;">';
    for (const ip of blockedIPs) {
        blockRows += '<span style="background:#fff5f5;color:#e74c3c;border:1px solid #f5c6cb;padding:5px 14px;border-radius:20px;font-family:monospace;font-size:13px;font-weight:600;">🚫 ' + escapeHtml(ip) + '</span>';
    }
    blockRows += '</div><div style="color:#94a0b8;font-size:12px;padding:8px 0;">共 ' + blockedIPs.length + ' 个 IP 被封禁</div>';
}

let logRows = '';
{
    const recentLogs = getRecentLogs();
    if (recentLogs.length === 0) {
        logRows = '<div style="text-align:center;color:#94a0b8;padding:16px;font-size:13px;">暂无操作日志</div>';
    } else {
        for (const log of recentLogs) {
            const isAlert = /触发防护|告警|封禁|封锁|攻击/.test(log);
            const isRecover = /恢复|清除|解封|放行/.test(log);
            const color = isAlert ? '#e74c3c' : isRecover ? '#27ae60' : '#7f8c8d';
            logRows += '<div style="font-family:monospace;font-size:11px;color:' + color + ';padding:4px 0;border-bottom:1px solid #f5f7fa;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + escapeHtml(log.trim()) + '</div>';
        }
    }
}

// ---- RDP 端口状态横幅 ----
const rdpOpen = !!rdp.open;
const rdpBlocked = !!rdp.blockUntil;
const guardHtml = rdpBlocked
    ? '<div style="background:linear-gradient(135deg,#fff5f5,#ffe8e8);border-left:4px solid #e74c3c;border-radius:8px;padding:16px 20px;margin:0 0 20px 0;">' +
        '<div style="display:flex;align-items:center;gap:8px;"><span style="font-size:18px;">🚨</span>' +
        '<span style="color:#e74c3c;font-weight:700;font-size:15px;">RDP 端口已被封锁（攻击防护中），预计 ' + fmtTime(rdp.blockUntil) + ' 自动恢复</span></div>' +
        '<div style="margin-top:8px;font-size:13px;color:#7f3545;">当前封禁 IP: ' + escapeHtml(blockedIPs.join(', ') || '无') + '</div></div>'
    : '<div style="background:linear-gradient(135deg,#f0fff4,#e8ffe8);border-left:4px solid #27ae60;border-radius:8px;padding:16px 20px;margin:0 0 20px 0;">' +
        '<div style="display:flex;align-items:center;gap:8px;"><span style="font-size:18px;">✅</span>' +
        '<span style="color:#27ae60;font-weight:700;font-size:15px;">防护待命 — RDP 端口正常开放</span></div>' +
        '<div style="margin-top:8px;font-size:13px;color:#2a6b3a;">今日失败 ' + todayFailures + ' 次 · 封禁 ' + blockedIPs.length + ' 个 · 规则: 5次/天触发 · 封禁5分钟自动解封</div></div>';

const threatLevel = todayFailures > 100 ? 'high' : todayFailures > 20 ? 'mid' : 'low';
const threatColor = threatLevel === 'high' ? '#e74c3c' : threatLevel === 'mid' ? '#f39c12' : '#27ae60';
const threatLabel = threatLevel === 'high' ? '高危' : threatLevel === 'mid' ? '中危' : '低危';

const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>wry合金防护 — 每日安全报告</title>
</head>
<body style="margin:0;padding:0;background:#e9ecf1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;">
<div style="max-width:640px;margin:0 auto;padding:24px 12px;">

<div style="background:linear-gradient(135deg,#0f1e3d 0%,#1a3a6e 50%,#234e8a 100%);border-radius:20px 20px 0 0;padding:36px 40px 28px;position:relative;overflow:hidden;">
<div style="position:absolute;top:-30px;right:-20px;font-size:120px;opacity:0.06;">🛡️</div>
<div style="display:flex;align-items:center;gap:14px;margin-bottom:6px;">
<span style="font-size:30px;">🛡️</span>
<span style="font-size:22px;font-weight:800;color:white;letter-spacing:1px;">wry合金防护</span>
</div>
<div style="color:rgba(255,255,255,0.65);font-size:13px;font-weight:400;">RDP 安全监控系统 · ${escapeHtml(hostname)}</div>
<div style="margin-top:14px;display:inline-block;background:rgba(255,255,255,0.15);border-radius:8px;padding:4px 14px;">
<span style="color:white;font-size:13px;font-weight:600;">${dateStr} · 今日全天报告</span>
</div>
</div>

<div style="background:white;padding:16px 40px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #eef1f5;">
<div>
<div style="color:#94a0b8;font-size:11px;text-transform:uppercase;letter-spacing:1px;">统计口径</div>
<div style="color:#2c3e50;font-size:13px;font-weight:600;margin-top:2px;">今日 00:00 → 截至 ${nowStr.split(' ')[1]}</div>
</div>
<div style="text-align:right;">
<div style="color:#94a0b8;font-size:11px;text-transform:uppercase;letter-spacing:1px;">威胁等级</div>
<div style="margin-top:2px;"><span style="background:${threatColor};color:white;padding:3px 14px;border-radius:12px;font-size:13px;font-weight:700;">${threatLabel}</span></div>
</div>
</div>

${guardHtml}

<div style="background:white;padding:24px 40px;border-bottom:1px solid #eef1f5;">
<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px;">
<div style="background:linear-gradient(135deg,#f8f9fb,#eef1f6);border-radius:14px;padding:18px;text-align:center;border:1px solid #eef1f5;">
<div style="font-size:32px;font-weight:800;color:${todayFailures > 50 ? '#e74c3c' : todayFailures > 10 ? '#f39c12' : '#27ae60'};">${todayFailures}</div>
<div style="color:#94a0b8;font-size:12px;margin-top:4px;font-weight:500;">今日失败次数</div>
</div>
<div style="background:linear-gradient(135deg,#f8f9fb,#eef1f6);border-radius:14px;padding:18px;text-align:center;border:1px solid #eef1f5;">
<div style="font-size:32px;font-weight:800;color:#234e8a;">${ipEntries.length}</div>
<div style="color:#94a0b8;font-size:12px;margin-top:4px;font-weight:500;">今日攻击源 IP</div>
</div>
<div style="background:linear-gradient(135deg,#f8f9fb,#eef1f6);border-radius:14px;padding:18px;text-align:center;border:1px solid #eef1f5;">
<div style="font-size:32px;font-weight:800;color:${blockedIPs.length > 0 ? '#e74c3c' : '#27ae60'};">${blockedIPs.length}</div>
<div style="color:#94a0b8;font-size:12px;margin-top:4px;font-weight:500;">当前封禁 IP</div>
</div>
<div style="background:linear-gradient(135deg,#f8f9fb,#eef1f6);border-radius:14px;padding:18px;text-align:center;border:1px solid #eef1f5;">
<div style="font-size:32px;font-weight:800;color:${rdpOpen ? '#27ae60' : '#e74c3c'};">${rdpOpen ? '开放' : '封锁'}</div>
<div style="color:#94a0b8;font-size:12px;margin-top:4px;font-weight:500;">RDP 端口(3389)${rdpOpen && rdp.portListening ? ' · 监听中' : ''}</div>
</div>
</div>
</div>

<div style="background:white;padding:24px 40px;border-bottom:1px solid #eef1f5;">
<div style="font-size:15px;font-weight:700;color:#2c3e50;margin-bottom:16px;">🔍 今日失败登录 IP 统计（与 Web 面板同源）</div>
<table style="width:100%;border-collapse:collapse;font-size:14px;">
<thead><tr style="background:#f8f9fb;">
<th style="padding:10px 16px;text-align:left;color:#94a0b8;font-weight:600;font-size:11px;">IP 地址</th>
<th style="padding:10px 16px;text-align:left;color:#94a0b8;font-weight:600;font-size:11px;">次数</th>
<th style="padding:10px 16px;text-align:left;color:#94a0b8;font-weight:600;font-size:11px;">风险</th>
<th style="padding:10px 16px;text-align:left;color:#94a0b8;font-weight:600;font-size:11px;">状态</th>
</tr></thead>
<tbody>${failRows}</tbody>
</table>
</div>

<div style="background:white;padding:24px 40px;border-bottom:1px solid #eef1f5;">
<div style="font-size:15px;font-weight:700;color:#2c3e50;margin-bottom:16px;">👤 今日被爆破的用户名</div>
${userRows}
</div>

<div style="background:white;padding:24px 40px;border-bottom:1px solid #eef1f5;">
<div style="font-size:15px;font-weight:700;color:#2c3e50;margin-bottom:12px;">📋 状态码分布</div>
${statusRows}
</div>

<div style="background:#0f1e3d;padding:24px 40px;border-bottom:1px solid #16305c;">
<div style="font-size:15px;font-weight:700;color:white;margin-bottom:16px;">📜 今日攻击事件明细（最新在前）</div>
${attackLogRows}
</div>

<div style="background:white;padding:24px 40px;border-bottom:1px solid #eef1f5;">
<div style="font-size:15px;font-weight:700;color:#2c3e50;margin-bottom:16px;">🚫 当前封禁状态</div>
${blockRows}
</div>

<div style="background:white;padding:24px 40px;border-bottom:1px solid #eef1f5;">
<div style="font-size:15px;font-weight:700;color:#2c3e50;margin-bottom:12px;">📜 最近操作日志</div>
${logRows}
</div>

<div style="background:#0f1e3d;padding:24px 40px;border-radius:0 0 20px 20px;">
<div style="display:flex;justify-content:space-between;align-items:center;">
<div>
<div style="color:rgba(255,255,255,0.9);font-size:14px;font-weight:700;">🛡️ wry合金防护</div>
<div style="color:rgba(255,255,255,0.5);font-size:11px;margin-top:4px;">每10秒检测 · 5次/天触发封禁 · 封禁5分钟自动解封 · 攻击时封锁RDP端口</div>
</div>
<div style="text-align:right;">
<div style="color:rgba(255,255,255,0.4);font-size:11px;">${nowStr}</div>
<div style="color:rgba(255,255,255,0.3);font-size:10px;margin-top:2px;">${escapeHtml(hostname)} · 引擎心跳 ${lastCheck}</div>
</div>
</div>
</div>

</div>
</body></html>`;

async function sendEmail(htmlBody) {
    if (!MAIL.pass) {
        console.error('❌ SMTP_PASS 未配置（环境变量 SMTP_PASS 或 mail-config.json 的 pass 字段），无法发送邮件');
        process.exit(1);
    }
    if (!MAIL.to) {
        console.error('❌ 收件人未配置（环境变量 REPORT_TO_EMAIL 或 mail-config.json 的 to 字段）');
        process.exit(1);
    }
    const transporter = nodemailer.createTransport({
        host: MAIL.host, port: MAIL.port, secure: MAIL.secure,
        auth: { user: MAIL.user, pass: MAIL.pass }
    });
    return await transporter.sendMail({
        from: '"' + MAIL.fromName + '" <' + MAIL.user + '>',
        to: MAIL.to,
        subject: '🛡️ ' + MAIL.fromName + ' ' + dateStr + ' 今日防护报告 — 累计 ' + todayFailures + ' 次失败 · ' + threatLabel,
        html: htmlBody
    });
}

(async () => {
    try {
        if (todayFailures === 0 && blockedIPs.length === 0 && attackLog.length === 0) {
            console.log('✅ 今日无失败登录记录，跳过邮件发送（' + dateStr + '）');
            process.exit(0);
        }
        const info = await sendEmail(html);
        console.log('✅ 报告邮件发送成功！MessageId:', info.messageId);
        console.log('日期:', dateStr, '| 今日失败:', todayFailures, '| 攻击源:', ipEntries.length, '| 封禁:', blockedIPs.length, '| RDP:', rdpOpen ? '开放' : '封锁');
        console.log('数据源: rdp_guard.json（与 Web 面板同源）');
    } catch (err) {
        console.error('❌ 发送失败:', err.message);
        process.exit(1);
    }
})();
