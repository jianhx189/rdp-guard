// wry-selfheal.js - RDP Guard 自愈看门狗（Node 版，2026-08-03）
// 替代 PowerShell 版看门狗：PowerShell/AMSI 在本机偶发崩溃（AccessViolationException），
// 导致引擎/Web 失联时无法自动拉起。Node 版完全绕开 PowerShell/AMSI，后台静默运行。
// 由计划任务 wry-rdp-guard 每分钟调用一次，检查后退出。
const { exec, spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const path = require('path');

const DIR = __dirname;
const NODE = 'D:/app/nodejs/node.exe';
const DATA = path.join(DIR, 'data');
const STATE_FILE = path.join(DATA, 'rdp_guard.json');
const LOG_FILE = path.join(DATA, 'rdp_guard_selfheal.log');
const FORCE_FLAG = path.join(DATA, 'selfheal_force.flag');
const ENGINE_SCRIPT = path.join(DIR, 'rdp-guard.js');
const WEB_SCRIPT = path.join(DIR, 'wry-web.js');
const WEB_PORT = 19888;
const HB_TIMEOUT_MS = 65 * 1000;    // 心跳超过 65s 视为失联（引擎每 10s 写一次心跳，65s 足够安全且失联恢复更快）
const START_WAIT_MS = 8000;         // 启动后等待引擎首次写心跳

function log(msg) {
    const line = '[' + new Date().toLocaleString('zh-CN', { hour12: false }) + '] ' + msg;
    console.log(line);
    try { fs.appendFileSync(LOG_FILE, line + '\r\n'); } catch (e) {}
}

// ---- 进程查找：wmic 获取 node 进程命令行 ----
function findProcs(pattern) {
    return new Promise((resolve) => {
        exec('wmic process where "name=\'node.exe\'" get ProcessId,CommandLine /format:list', { windowsHide: true, maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => {
            if (err) { log('WARN wmic 查询失败: ' + err.message); return resolve([]); }
            const pids = [];
            const blocks = String(stdout).split(/\r?\n\s*\r?\n/);
            for (const b of blocks) {
                if (b.indexOf('CommandLine=') >= 0 && b.indexOf(pattern) >= 0) {
                    const m = b.match(/ProcessId=(\d+)/);
                    if (m) pids.push(Number(m[1]));
                }
            }
            resolve(pids);
        });
    });
}

function killPids(pids) {
    for (const pid of pids) {
        try { process.kill(pid, 'SIGKILL'); log('已结束进程 PID=' + pid); }
        catch (e) { log('结束 PID=' + pid + ' 失败: ' + e.message); }
    }
}

function startProc(script, tag) {
    const child = spawn(NODE, [script], { cwd: DIR, windowsHide: true, stdio: 'ignore', detached: true });
    log(tag + ' 已启动 PID=' + child.pid + ' (' + script + ')');
    child.on('error', (e) => log('ERROR ' + tag + ' 启动失败: ' + e.message));
}

function checkPort(port, timeout) {
    return new Promise((resolve) => {
        const s = net.connect({ host: '127.0.0.1', port: port });
        let done = false;
        const fin = (ok) => { if (!done) { done = true; try { s.destroy(); } catch (e) {} resolve(ok); } };
        s.on('connect', () => fin(true));
        s.on('error', () => fin(false));
        s.setTimeout(timeout || 3000, () => fin(false));
    });
}

function readHeartbeat() {
    try {
        if (!fs.existsSync(STATE_FILE)) return null;
        const st = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
        if (!st.lastCheck) return null;
        const t = Date.parse(st.lastCheck);
        return isNaN(t) ? null : t;
    } catch (e) { return null; }
}

async function main() {
    log('========== 看门狗检查开始 ==========');
    // 数据目录放 selfheal_force.flag 即强制杀掉引擎/Web 并用当前代码重启（运维钩子）
    if (fs.existsSync(FORCE_FLAG)) {
        try { fs.unlinkSync(FORCE_FLAG); } catch (e) {}
        log('FORCE 标记存在，强制重启引擎与 Web');
        const enginePids = await findProcs('rdp-guard.js');
        if (enginePids.length) killPids(enginePids);
        const webPids = await findProcs('wry-web.js');
        if (webPids.length) killPids(webPids);
        await new Promise(r => setTimeout(r, 1500));
        startProc(ENGINE_SCRIPT, '引擎');
        startProc(WEB_SCRIPT, 'Web');
        log('DONE');
        process.exit(0);
    }
    // ---- 引擎检查：心跳 ----
    const hb = readHeartbeat();
    const hbOk = hb !== null && (Date.now() - hb) <= HB_TIMEOUT_MS;
    if (hbOk) {
        log('ENGINE_OK 心跳正常');
    } else {
        const age = hb ? Math.round((Date.now() - hb) / 1000) + 's' : '无记录';
        log('WARN 引擎心跳异常: ' + age);
        const pids = await findProcs('rdp-guard.js');
        if (pids.length) { log('杀掉失联引擎进程: ' + pids.join(',')); killPids(pids); }
        else { log('引擎进程不存在，直接启动'); }
        await new Promise(r => setTimeout(r, 2000));
        startProc(ENGINE_SCRIPT, '引擎');
    }
    // ---- Web 检查：端口 ----
    const webOk = await checkPort(WEB_PORT);
    if (webOk) {
        log('WEB_OK');
    } else {
        const pids = await findProcs('wry-web.js');
        if (pids.length) { log('杀掉残留 Web 进程: ' + pids.join(',')); killPids(pids); }
        await new Promise(r => setTimeout(r, 1000));
        startProc(WEB_SCRIPT, 'Web');
    }
    // ---- 如果刚启动过，等待并确认 ----
    log('DONE');
    process.exit(0);
}

main();
