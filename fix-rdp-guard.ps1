# fix-rdp-guard.ps1 - 一键修复 RDP Guard（需要管理员权限）
# 用法：右键"以管理员身份运行"，或：powershell -ExecutionPolicy Bypass -File fix-rdp-guard.ps1
# 步骤：
#   1) 若未提权则自动请求 UAC 提权（参数使用数组形式，避免引号被破坏）
#   2) 杀掉旧的引擎/Web 进程（旧引擎每 10 秒触发 PowerShell 崩溃，且检测不到事件）
#   3) 用新引擎 v4 + 新仪表盘 v4 启动服务（去 QClaw 化，目录取 $PSScriptRoot）
#   4) 注册计划任务（登录 + 每 1 分钟自愈看门狗 + 邮件报告，最高权限）
#   5) 验证 19888 与引擎心跳
$ErrorActionPreference = "Continue"
$dir = $PSScriptRoot
$node = "D:/app/nodejs/node.exe"
if (-not (Test-Path $node)) { $node = "node" }
$dataDir = Join-Path $dir "data"
$logFile = Join-Path $dataDir "rdp_guard_fix.log"

function Log($m) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $m"
    Write-Output $line
    try { Add-Content -Path $logFile -Value $line -Encoding UTF8 } catch {}
}

# ---- 提权 ----
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Output "需要管理员权限，正在请求 UAC 提权..."
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath) -Verb RunAs -Wait -WindowStyle Hidden
        Write-Output "提权实例已执行完毕，结果见 $logFile"
        exit 0
    } catch {
        Write-Output "UAC 提权失败或被拒绝：$($_.Exception.Message)"
        exit 1
    }
}
Log "===== RDP Guard 修复开始 $(Get-Date) ====="

# ---- 1) 杀旧进程 ----
Log "-- 步骤1: 清理旧进程（命令行匹配 rdp-guard|wry-web）"
$procs = Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -and $_.CommandLine -match "rdp-guard|wry-web"
}
foreach ($p in $procs) {
    Log "  杀掉 node PID=$($p.ProcessId)  $($p.CommandLine)"
    try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop } catch { Log "    失败: $($_.Exception.Message)" }
}
Start-Sleep -Seconds 2
$conn = Get-NetTCPConnection -LocalPort 19888 -State Listen -ErrorAction SilentlyContinue
if ($conn) {
    foreach ($c in $conn) {
        Log "  19888 仍被 PID=$($c.OwningProcess) 占用，强制结束"
        try { Stop-Process -Id $c.OwningProcess -Force -ErrorAction Stop } catch { Log "    失败: $($_.Exception.Message)" }
    }
    Start-Sleep -Seconds 2
}

# ---- 2) 启动新引擎 + 新 Web ----
Log "-- 步骤2: 启动新引擎 v4 与仪表盘 v4（$node）"
$engineScript = Join-Path $dir "rdp-guard.js"
$webScript = Join-Path $dir "wry-web.js"
$engine = Start-Process -FilePath $node -ArgumentList @($engineScript) -WorkingDirectory $dir -WindowStyle Hidden -PassThru
Log "  引擎已启动 PID=$($engine.Id)"
$web = Start-Process -FilePath $node -ArgumentList @($webScript) -WorkingDirectory $dir -WindowStyle Hidden -PassThru
Log "  Web 已启动 PID=$($web.Id)"

# ---- 3) 注册计划任务 ----
Log "-- 步骤3: 注册计划任务"
$reg = Join-Path $dir "register-tasks.ps1"
if (Test-Path $reg) {
    & $reg 2>&1 | ForEach-Object { Log "  $_" }
} else {
    Log "  WARN 未找到 register-tasks.ps1，跳过任务注册"
}

# ---- 4) 验证 ----
Log "-- 步骤4: 验证（等待引擎首次轮询）"
Start-Sleep -Seconds 15
try {
    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:19888/" -UseBasicParsing -TimeoutSec 5
    Log "  19888 响应: HTTP $($resp.StatusCode)，页面长度 $($resp.Content.Length)"
} catch { Log "  ERROR 19888 无响应: $($_.Exception.Message)" }

$statePath = Join-Path $dataDir "rdp_guard.json"
if (Test-Path $statePath) {
    $st = Get-Content $statePath -Raw | ConvertFrom-Json
    if ($st.lastCheck) {
        $age = [math]::Round(([DateTimeOffset]::Now - [DateTimeOffset]::Parse($st.lastCheck)).TotalSeconds, 1)
        Log "  引擎心跳: lastCheck=$($st.lastCheck) 距今 ${age}s  totalFailures=$($st.totalFailures)"
    } else { Log "  WARN 状态文件存在但无 lastCheck" }
} else { Log "  WARN 状态文件不存在" }

Log "===== 修复结束 $(Get-Date) ====="
Write-Output ""
Write-Output "修复完成！请打开 http://localhost:19888 查看新仪表盘。"
Write-Output "详细日志: $logFile"