# RDP Guard self-heal watchdog v4 (2026-08-02)
# 修复点：
#  - 不再只看"进程是否存在"，改为检查引擎心跳（rdp_guard.json 的 lastCheck），
#    引擎进程活着但失联（如旧版每 10 秒触发 PowerShell 崩溃）也会被杀掉重启
#  - 使用 D:/app/nodejs/node.exe 绝对路径，避免 PATH 问题
#  - Start-Process 参数使用数组形式，避免路径含空格时引号被破坏（v4）
#  - 去 QClaw 化：目录取 $PSScriptRoot
$ErrorActionPreference = "Continue"
$dir = $PSScriptRoot
$node = "D:/app/nodejs/node.exe"
if (-not (Test-Path $node)) { $node = "node" }
$webScript = Join-Path $dir "wry-web.js"
$ws = New-Object -ComObject WScript.Shell  # 隐藏窗口启动器（后台静默运行）
$engineScript = Join-Path $dir "rdp-guard.js"
$dataDir = Join-Path $dir "data"
$stateFile = Join-Path $dataDir "rdp_guard.json"
$logFile = Join-Path $dataDir "rdp_guard_selfheal.log"

function Log($m) {
    $line = "[$(Get-Date -Format o)] $m"
    Write-Output $line
    try { Add-Content -Path $logFile -Value $line -Encoding UTF8 } catch {}
}

function Test-Port {
    param([int]$Port)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect("127.0.0.1", $Port)
        $tcp.Close()
        return $true
    } catch { return $false }
}

function Get-EngineProc {
    Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -match "rdp-guard\.js" }
}

# ---- 引擎心跳检查 ----
$hbOk = $false
if (Test-Path $stateFile) {
    try {
        $st = Get-Content $stateFile -Raw | ConvertFrom-Json
        if ($st.lastCheck) {
            # 统一转 UTC 计算，兼容 ConvertFrom-Json 返回 string / DateTime 两种类型，
            # 避免 [DateTimeOffset]::Parse(DateTime) 在部分环境把 UTC 误当本地时间(+8h)
            if ($st.lastCheck -is [DateTime]) {
                $lc = [DateTimeOffset]::new([DateTime]::SpecifyKind($st.lastCheck, [DateTimeKind]::Utc))
            } else {
                $lc = [DateTimeOffset]::Parse([string]$st.lastCheck).ToUniversalTime()
            }
            $ageSec = ([DateTimeOffset]::Now.ToUniversalTime() - $lc).TotalSeconds
            $hbOk = $ageSec -le 120
            if (-not $hbOk) { Log "WARN 引擎心跳过期: $([math]::Round($ageSec))s" }
        } else { Log "WARN 状态文件无 lastCheck 字段" }
    } catch { Log "WARN 状态文件解析失败: $($_.Exception.Message)" }
} else { Log "INFO 状态文件不存在（引擎可能从未成功运行）" }

$engine = Get-EngineProc
if ($hbOk) {
    Log "ENGINE_OK 心跳正常"
} else {
    if ($engine) {
        Log "ACTION 引擎进程存在但失联，杀掉重启: $($engine.ProcessId -join ',')"
        foreach ($p in $engine) { try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop } catch {} }
        Start-Sleep -Seconds 2
    } else {
        Log "ACTION 引擎进程不存在，直接启动"
    }
    $ws.Run('"' + $node + '" "' + $engineScript + '"', 0, $false)  # 隐藏窗口静默启动引擎
    Log "ENGINE_RESTARTED"
}

# ---- Web 检查 ----
if (Test-Port -Port 19888) {
    Log "WEB_OK"
} else {
    $ws.Run('"' + $node + '" "' + $webScript + '"', 0, $false)  # 隐藏窗口静默启动 Web
    Log "WEB_RESTARTED"
}
Log "DONE"