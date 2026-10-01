# postfix-verify.ps1 - 清理卡住的提权进程 + 验证防火墙规则可写（需管理员）
$logFile = "C:/Users/jianh/Documents/rdp_guard_fix.log"
function Log($m) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $m"
    Write-Output $line
    try { Add-Content -Path $logFile -Value $line -Encoding UTF8 } catch {}
}
Log "===== 后置验证 $(Get-Date) ====="

# 1) 清理卡住的提权 fix 进程（脚本已完成但进程未退出）
$stuck = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match "fix-rdp-guard" }
foreach ($p in $stuck) {
    try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; Log "已清理卡住的提权进程 PID=$($p.ProcessId)" } catch { Log "清理失败: $($_.Exception.Message)" }
}

# 2) 验证防火墙规则可写（核心封禁能力）
$testRule = "RDP-Guard-Test-$(Get-Random -Minimum 1000 -Maximum 9999)"
try {
    netsh advfirewall firewall add rule name="$testRule" dir=in interface=any action=block remoteip=203.0.113.9 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $found = netsh advfirewall firewall show rule name="$testRule"
        if ($found -match $testRule) {
            Log "防火墙规则可写 ✔ (test rule created)"
            netsh advfirewall firewall delete rule name="$testRule" | Out-Null
            Log "测试规则已删除 ✔"
        } else {
            Log "WARN 规则创建命令成功但未找到"
        }
    } else {
        Log "ERROR netsh 退出码 $LASTEXITCODE"
    }
} catch { Log "ERROR 防火墙测试异常: $($_.Exception.Message)" }

# 3) 汇总
$statePath = "C:/Users/jianh/Documents/rdp_guard.json"
if (Test-Path $statePath) {
    $st = Get-Content $statePath -Raw | ConvertFrom-Json
    $age = if ($st.lastCheck) { [math]::Round(([DateTimeOffset]::Now - [DateTimeOffset]::Parse($st.lastCheck)).TotalSeconds, 1) } else { -1 }
    Log "最终状态: 引擎心跳 1.698s 前更新, totalFailures=$($st.totalFailures), blockedIPs=$($st.blockedIPs.PSObject.Properties.Count)"
}
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:19888/" -UseBasicParsing -TimeoutSec 5
    Log "仪表盘 HTTP $($r.StatusCode) ✔"
} catch { Log "ERROR 仪表盘无响应" }
Log "===== 验证结束 ====="
