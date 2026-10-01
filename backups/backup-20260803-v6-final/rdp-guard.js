// rdp-guard.js - RDP Guard Engine v6 (2026-08-03)
// 监控 Windows 安全日志 (Event 4625 登录失败)，统计攻击源，达到阈值封禁 IP 5 分钟，
// 同时自动封锁 RDP 端口(3389) 5 分钟，到期自动恢复（默认开启，除非有攻击）。
//
// v6 变更（2026-08-03 用户要求）：
//  1. 新增 attackLog：当日每次 4625 事件逐条记录（时间/IP/被爆破用户名/登录类型/状态码），
//     供 Web 面板日志框与邮件报告使用（与网页同源，保证数据一致）；跨天自动清空，上限 500 条
//  2. 其余保留 v5：5 分钟封禁/端口封锁自动恢复、RDP 端口管控、手动打开请求机制
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const CONFIG = {
    stateFile: path.join(__dirname, 'data', 'rdp_guard.json'),
    logFile: path.join(__dirname, 'data', 'rdp_guard.log'),
    threshold: 5,                    // 窗口内失败次数达到该值即封禁
    windowMs: 24 * 60 * 60 * 1000,   // 统计窗口：1 天
    banMs: 5 * 60 * 1000,            // 封禁持续：5 分钟
    checkIntervalMs: 10000,          // 轮询间隔 10 秒
    firewallRulePrefix: "RDP-Guard-Block-",
    rdpPort: 3389,
    rdpAllowRule: "RDP-Guard-Allow-RDP-3389",
    rdpBlockRule: "RDP-Guard-Block-Port-3389",
    wevtutilMaxEvents: 1000,
    attackLogMax: 500,               // 当日攻击日志上限（防状态文件膨胀）
    blockPrivateIPs: ['192.168.3.88'], // 内网但视为攻击源的 IP（192.168.3.88 跑内网穿透，是唯一攻击源），照常统计并封禁
    version: 6,
};

function log(msg) {
    const line = `[${new Date().toISOString()}] ${msg}`;
    console.log(line);
    try { fs.appendFileSync(CONFIG.logFile, line + "\n"); } catch (e) { /* ignore */ }
}

// ---------- 状态 ----------
let state = {
    version: CONFIG.version, engineStart: new Date().toISOString(),
    lastCheck: null, lastEvent: null, totalFailures: 0,
    blockedIPs: {}, attempts: {}, lastSeenRecordId: 0,
    todayDate: null, todayFailures: 0, todayIPs: {}, attackLog: [],
    rdp: { port: CONFIG.rdpPort, open: true, blockUntil: null, portListening: null }
};
try {
    if (fs.existsSync(CONFIG.stateFile)) {
        const loaded = JSON.parse(fs.readFileSync(CONFIG.stateFile, 'utf8'));
        state = Object.assign(state, loaded);
        if (state.attempts) {
            for (const ip of Object.keys(state.attempts)) {
                state.attempts[ip] = state.attempts[ip].map(r => (typeof r === 'string') ? { t: r, user: '?', logonType: '?', status: '' } : r);
            }
        }
        if (state.blockedIPs) {
            for (const ip of Object.keys(state.blockedIPs)) {
                const v = state.blockedIPs[ip];
                if (typeof v === 'string') {
                    const since = Date.parse(v) || Date.now();
                    state.blockedIPs[ip] = { since: new Date(since).toISOString(), until: new Date(since + CONFIG.banMs).toISOString() };
                }
            }
        }
        if (!Array.isArray(state.attackLog)) state.attackLog = [];
        if (!state.rdp) state.rdp = { port: CONFIG.rdpPort, open: true, blockUntil: null, portListening: null };
        state.version = CONFIG.version;
        state.engineStart = new Date().toISOString();
    }
} catch (e) {
    log(`状态文件加载失败: ${e.message}`);
}

function saveState() {
    try {
        let pending = {};
        let rdpReq = null;
        try {
            if (fs.existsSync(CONFIG.stateFile)) {
                const onDisk = JSON.parse(fs.readFileSync(CONFIG.stateFile, 'utf8'));
                if (onDisk && onDisk.unblockRequests && typeof onDisk.unblockRequests === 'object') pending = onDisk.unblockRequests;
                if (onDisk && onDisk.rdpOpenRequest) rdpReq = onDisk.rdpOpenRequest;
            }
        } catch (e) { /* ignore */ }
        const keys = Object.keys(pending);
        if (keys.length) {
            state.unblockRequests = pending;
            for (const ip of keys) {
                if (state.blockedIPs && state.blockedIPs[ip]) delete state.blockedIPs[ip];
                if (state.attempts && state.attempts[ip]) delete state.attempts[ip];
            }
        } else {
            delete state.unblockRequests;
        }
        if (rdpReq) state.rdpOpenRequest = rdpReq; else delete state.rdpOpenRequest;

        const tmp = CONFIG.stateFile + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
        fs.renameSync(tmp, CONFIG.stateFile);
    } catch (e) {
        log(`保存状态失败: ${e.message}`);
    }
}

// ---------- 工具函数 ----------
function run(cmd, cb) {
    exec(cmd, { maxBuffer: 16 * 1024 * 1024, windowsHide: true }, cb);
}
function ruleNameFor(ip) { return CONFIG.firewallRulePrefix + ip.replace(/\./g, '-'); }
function ruleExists(name, cb) {
    run(`netsh advfirewall firewall show rule name="${name}"`, (err, stdout) => {
        cb(!!(stdout && stdout.includes(name)));
    });
}

function isPrivateIP(ip) {
    if (!ip || ip === '-' || ip === '' ) return true;
    ip = ip.toLowerCase();
    if (ip === 'localhost' || ip === '::1' || ip.startsWith('fe80')) return true;
    if (ip.includes(':')) return true;
    const parts = ip.split('.');
    if (parts.length !== 4) return true;
    const n = parts.map(x => Number(x));
    if (n.some(x => isNaN(x) || x < 0 || x > 255)) return true;
    const [a, b] = n;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a >= 224) return true;
    return false;
}

// ---------- 今日攻击统计（含内网/未知，按上海时区 UTC+8）----------
function shanghaiDateStr(ms) {
    return new Date(ms + 8 * 3600 * 1000).toISOString().slice(0, 10);
}

// 跨天/首次启动时重置并从事件日志重建当天数据（todayFailures/todayIPs/attackLog）
// 从安全事件日志重建当天数据（todayFailures/todayIPs/attackLog）
// reset=true: 跨天/首次启动，重置统计并重建；reset=false: 同天重启且日志为空时，仅回填逐条日志（不覆盖统计）
let rebuildingToday = false;
function rebuildTodayFromEvents(today, reset) {
    if (rebuildingToday) { log('今日统计重建已在进行，跳过本次请求'); return; }
    rebuildingToday = true;
    if (reset) { state.todayFailures = 0; state.todayIPs = {}; state.attackLog = []; }
    const cmd = `wevtutil qe Security /q:"*[System[EventID=4625]]" /c:${CONFIG.wevtutilMaxEvents} /rd:true /f:xml`;
    exec(cmd, { maxBuffer: 64 * 1024 * 1024, windowsHide: true }, (err, stdout) => {
        rebuildingToday = false;
        if (err) { log(`今日统计重建失败: ${err.message}`); return; }
        const events = parseEvents(stdout);
        let failures = 0; const ips = {};
        for (const e of events) {
            if (!e.time) continue;
            const t = new Date(e.time);
            if (isNaN(t.getTime())) continue;
            if (shanghaiDateStr(t.getTime()) !== today) continue;
            const ip = (e.ip && e.ip !== '-') ? e.ip : '(未知)';
            ips[ip] = (ips[ip] || 0) + 1;
            failures++;
            state.attackLog.push({ t: e.time, ip, user: e.user || '?', logonType: e.logonType || '?', status: e.status || '' });
        }
        if (reset) { state.todayFailures = failures; state.todayIPs = ips; }
        state.attackLog.sort((a, b) => new Date(a.t) - new Date(b.t));
        if (state.attackLog.length > CONFIG.attackLogMax) state.attackLog = state.attackLog.slice(-CONFIG.attackLogMax);
        log(`今日攻击统计: 失败 ${failures} 次, 攻击源 ${Object.keys(ips).length} 个, 日志 ${state.attackLog.length} 条`);
        saveState();
    });
}

function ensureTodayStats() {
    const today = shanghaiDateStr(Date.now());
    if (state.todayDate !== today) {
        state.todayDate = today;
        rebuildTodayFromEvents(today, true);
        return;
    }
    // 同一天：当天已有攻击但 attackLog 为空（v6 升级/引擎重启后），回填补齐当日逐条日志
    if (state.attackLog.length === 0 && (state.todayFailures > 0 || Object.keys(state.todayIPs).length > 0)) {
        rebuildTodayFromEvents(today, false);
    }
}

function isValidIPv4(ip) {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
    const parts = ip.split('.').map(Number);
    return parts.every(n => n >= 0 && n <= 255);
}

function parseEvents(xml) {
    const blocks = xml.match(/<Event[^>]*>[\s\S]*?<\/Event>/g) || [];
    return blocks.map(b => {
        const rec = (b.match(/<EventRecordID>(\d+)<\/EventRecordID>/) || [])[1];
        const time = (b.match(/TimeCreated SystemTime='([^']+)'/) || [])[1];
        const logonType = (b.match(/<Data Name='LogonType'>([^<]*)<\/Data>/) || [])[1];
        const ip = (b.match(/<Data Name='IpAddress'>([^<]*)<\/Data>/) || [])[1];
        const user = (b.match(/<Data Name='TargetUserName'>([^<]*)<\/Data>/) || [])[1];
        const status = (b.match(/<Data Name='SubStatus'>([^<]*)<\/Data>/) || [])[1];
        const workstation = (b.match(/<Data Name='WorkstationName'>([^<]*)<\/Data>/) || [])[1];
        return { recordId: Number(rec) || 0, time, logonType, ip, user, status, workstation };
    }).filter(e => e.recordId > 0);
}

// ---------- RDP 端口管控（默认开启，除非有攻击）----------
function ensureRdpAllow(cb) {
    ruleExists(CONFIG.rdpAllowRule, exists => {
        if (exists) { if (cb) cb(null, true); return; }
        const cmd = `netsh advfirewall firewall add rule name="${CONFIG.rdpAllowRule}" dir=in action=allow protocol=TCP localport=${CONFIG.rdpPort}`;
        run(cmd, err => {
            if (err) log(`RDP 放行规则创建失败: ${err.message} (引擎需要管理员权限)`);
            else log(`RDP 端口放行规则已就绪 (${CONFIG.rdpAllowRule})`);
            if (cb) cb(err, !err);
        });
    });
}

function closeRdpPort(reason, cb) {
    const cmd = `netsh advfirewall firewall add rule name="${CONFIG.rdpBlockRule}" dir=in action=block protocol=TCP localport=${CONFIG.rdpPort}`;
    run(cmd, err => {
        if (err) { log(`封锁 RDP 端口失败: ${err.message}`); if (cb) cb(err); return; }
        state.rdp.open = false;
        state.rdp.blockUntil = new Date(Date.now() + CONFIG.banMs).toISOString();
        log(`RDP 端口(${CONFIG.rdpPort}) 已封锁（${reason}），${CONFIG.banMs / 1000} 秒后自动恢复`);
        saveState();
        if (cb) cb(null);
    });
}

function openRdpPort(reason, cb) {
    run(`netsh advfirewall firewall delete rule name="${CONFIG.rdpBlockRule}"`, () => {
        ensureRdpAllow(() => {
            state.rdp.open = true;
            state.rdp.blockUntil = null;
            log(`RDP 端口(${CONFIG.rdpPort}) 已恢复开放（${reason}）`);
            saveState();
            if (cb) cb(null);
        });
    });
}

function checkRdpListening() {
    run(`netstat -ano | findstr :${CONFIG.rdpPort}`, (err, stdout) => {
        const listening = !err && /LISTENING/i.test(stdout);
        if (listening !== state.rdp.portListening) {
            state.rdp.portListening = listening;
            log(`RDP 端口监听状态: ${listening ? '3389 正在监听' : '3389 未监听'}`);
            saveState();
        }
    });
}

// ---------- 封禁 ----------
function ensureRule(ip, cb) {
    if (!isValidIPv4(ip)) {
        log(`跳过非法 IP（不入 netsh）: ${ip}`);
        return cb(new Error('bad ip'), false);
    }
    const ruleName = ruleNameFor(ip);
    ruleExists(ruleName, exists => {
        if (exists) return cb(null, true);
        const cmd = `netsh advfirewall firewall add rule name="${ruleName}" dir=in interface=any action=block remoteip=${ip}`;
        run(cmd, err2 => {
            if (!err2) {
                log(`已封禁公网 IP: ${ip} (规则 ${ruleName})`);
                cb(null, true);
            } else {
                log(`封禁失败 ${ip}: ${err2.message} (引擎需要管理员权限运行)`);
                cb(err2, false);
            }
        });
    });
}

function expireBans() {
    const now = Date.now();
    const expired = Object.keys(state.blockedIPs).filter(ip => {
        const v = state.blockedIPs[ip];
        const until = (v && typeof v === 'object' && v.until) ? Date.parse(v.until) : NaN;
        return !isNaN(until) && until <= now;
    });
    if (!expired.length) return;
    let pending = expired.length;
    expired.forEach(ip => {
        const rule = ruleNameFor(ip);
        run(`netsh advfirewall firewall delete rule name="${rule}"`, err => {
            if (err) log(`自动解封 ${ip} 删除规则失败: ${err.message}`);
            else log(`自动解封 ${ip}（5 分钟封禁到期，规则 ${rule} 已删除）`);
            delete state.blockedIPs[ip];
            if (state.attempts && state.attempts[ip]) delete state.attempts[ip];
            if (--pending === 0) saveState();
        });
    });
}

function expireRdpBlock() {
    if (state.rdp.open || !state.rdp.blockUntil) return;
    if (Date.now() >= Date.parse(state.rdp.blockUntil)) {
        openRdpPort('5 分钟封锁到期自动恢复');
    }
}

function unbanAllIPs(cb) {
    const ips = Object.keys(state.blockedIPs);
    if (!ips.length) return cb();
    let pending = ips.length;
    ips.forEach(ip => {
        const rule = ruleNameFor(ip);
        run(`netsh advfirewall firewall delete rule name="${rule}"`, () => {
            log(`手动解封全部: 移除 ${ip}`);
            delete state.blockedIPs[ip];
            if (state.attempts && state.attempts[ip]) delete state.attempts[ip];
            if (--pending === 0) cb();
        });
    });
}

function consumeRdpOpenRequest() {
    if (!state.rdpOpenRequest) return;
    log('Web 面板请求手动打开 RDP 端口并解封全部攻击源');
    openRdpPort('Web 面板手动打开', () => {
        unbanAllIPs(() => {
            delete state.rdpOpenRequest;
            try {
                if (fs.existsSync(CONFIG.stateFile)) {
                    const onDisk = JSON.parse(fs.readFileSync(CONFIG.stateFile, 'utf8'));
                    delete onDisk.rdpOpenRequest;
                    const tmp = CONFIG.stateFile + '.tmp';
                    fs.writeFileSync(tmp, JSON.stringify(onDisk, null, 2));
                    fs.renameSync(tmp, CONFIG.stateFile);
                }
            } catch (e) { /* ignore */ }
            log('手动打开完成：RDP 端口已开放，全部攻击源已解封');
            saveState();
        });
    });
}

function processUnblocks() {
    const reqs = state.unblockRequests || {};
    const ips = Object.keys(reqs);
    if (!ips.length) return;
    ips.forEach(ip => {
        if (state.blockedIPs[ip]) {
            delete state.blockedIPs[ip];
            log(`Web 面板手动解封 ${ip}（引擎已同步，防火墙规则由 Web 删除）`);
        }
        delete state.attempts[ip];
        delete reqs[ip];
    });
    if (!Object.keys(reqs).length) delete state.unblockRequests;
}

function reconcileRules() {
    const ips = Object.keys(state.blockedIPs).filter(ip => {
        const v = state.blockedIPs[ip];
        const until = (v && typeof v === 'object' && v.until) ? Date.parse(v.until) : NaN;
        return isNaN(until) || until > Date.now();
    });
    if (!ips.length) return;
    log(`启动对账: 检查 ${ips.length} 个未过期封禁 IP 的防火墙规则...`);
    ips.forEach(ip => ensureRule(ip, () => {}));
}

// ---------- 事件轮询 ----------
function pollEvents() {
    const q = `*[System[EventID=4625]]`;
    const cmd = `wevtutil qe Security /q:"${q}" /c:${CONFIG.wevtutilMaxEvents} /rd:true /f:xml`;
    exec(cmd, { maxBuffer: 64 * 1024 * 1024, windowsHide: true }, (err, stdout) => {
        let newFailures = 0;
        try {
            if (err) {
                log(`wevtutil 查询失败: ${err.message}`);
                return;
            }
            const events = parseEvents(stdout);
            const now = Date.now();
            ensureTodayStats();
            consumeRdpOpenRequest();
            expireBans();
            expireRdpBlock();
            checkRdpListening();
            processUnblocks();
            const oldLastSeen = state.lastSeenRecordId;
            for (const e of events) {
                if (e.recordId > state.lastSeenRecordId) state.lastSeenRecordId = e.recordId;
            }
            for (const e of events) {
                if (e.recordId <= oldLastSeen) continue;
                if (state.todayDate === shanghaiDateStr(now)) {
                    const ipk = (e.ip && e.ip !== '-') ? e.ip : '(未知)';
                    state.todayIPs[ipk] = (state.todayIPs[ipk] || 0) + 1;
                    state.todayFailures++;
                    state.attackLog.push({ t: e.time || new Date(now).toISOString(), ip: ipk, user: e.user || '?', logonType: e.logonType || '?', status: e.status || '' });
                    if (state.attackLog.length > CONFIG.attackLogMax) state.attackLog = state.attackLog.slice(-CONFIG.attackLogMax);
                }
                if (isPrivateIP(e.ip) && CONFIG.blockPrivateIPs.indexOf(e.ip) === -1) continue;
                if (!state.blockedIPs[e.ip]) {
                    if (!state.attempts[e.ip]) state.attempts[e.ip] = [];
                    state.attempts[e.ip].push({
                        t: e.time || new Date(now).toISOString(),
                        user: e.user || '?',
                        logonType: e.logonType || '?',
                        status: e.status || '',
                        workstation: e.workstation || ''
                    });
                    state.totalFailures++;
                    newFailures++;
                    state.lastEvent = e.time || new Date(now).toISOString();
                    log(`尝试登录失败 from ${e.ip} (user=${e.user || '?'}, type=${e.logonType}, rec=${e.recordId})`);
                }
            }
            for (const ip of Object.keys(state.attempts)) {
                const cutoff = now - CONFIG.windowMs;
                state.attempts[ip] = state.attempts[ip].filter(r => {
                    const ts = (typeof r === 'string') ? r : r.t;
                    const tms = Date.parse(ts);
                    return !isNaN(tms) && tms >= cutoff;
                });
                if (!state.attempts[ip].length) delete state.attempts[ip];
            }
            for (const ip of Object.keys(state.attempts)) {
                if (!state.blockedIPs[ip] && state.attempts[ip].length >= CONFIG.threshold) {
                    log(`${ip} 在窗口内失败 ${state.attempts[ip].length} 次 >= ${CONFIG.threshold}，触发封禁`);
                    const banUntil = now + CONFIG.banMs;
                    ensureRule(ip, (e2, ok) => {
                        if (ok) {
                            state.blockedIPs[ip] = { since: new Date(now).toISOString(), until: new Date(banUntil).toISOString() };
                            delete state.attempts[ip];
                            saveState();
                            if (state.rdp.open) closeRdpPort(`检测到攻击源 ${ip} 达到阈值`);
                        }
                    });
                }
            }
            if (newFailures > 0) log(`本次轮询新增 ${newFailures} 条公网失败登录`);
        } catch (e) {
            log(`轮询异常: ${e.message}`);
        } finally {
            state.lastCheck = new Date().toISOString();
            saveState();
        }
    });
}

// ---------- 启动 ----------
log(`RDP Guard Engine v${CONFIG.version} 启动 (state=${CONFIG.stateFile})`);
ensureRdpAllow();
consumeRdpOpenRequest();
reconcileRules();
processUnblocks();
ensureTodayStats();
pollEvents();
setInterval(pollEvents, CONFIG.checkIntervalMs);

process.on('SIGINT', () => { log('引擎退出'); process.exit(0); });
process.on('uncaughtException', (e) => { log(`未捕获异常: ${e.message}`); });
