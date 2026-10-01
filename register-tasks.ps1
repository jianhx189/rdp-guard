# register-tasks.ps1 - 注册 RDP Guard 计划任务（需要管理员权限）
# 去 QClaw 化：目录取 $PSScriptRoot，不依赖任何 QClaw 路径
# 任务：
#   wry-rdp-guard ：登录时 + 每 1 分钟运行自愈看门狗（最高权限，VBS 静默启动，无控制台窗口）
#   wry-rdp-report：每天 8:00 / 20:00 发送半天安全报告邮件（最高权限，脚本自动判断半天，VBS 静默启动）
# 2026-08-03 变更：任务改走 wscript + VBS 启动器（launch-selfheal.vbs / launch-report.vbs），
#   彻底避免 node.exe 控制台窗口弹出；不再经过 PowerShell/AMSI（本机 ConfigDefender 模块损坏，
#   powershell.exe 偶发 AccessViolationException 崩溃，故看门狗已改为 Node 实现 wry-selfheal.js）
$ErrorActionPreference = "Stop"
$dir = $PSScriptRoot
$wscript = "wscript.exe"
$launchSelfheal = Join-Path $dir "launch-selfheal.vbs"
$launchReport = Join-Path $dir "launch-report.vbs"

foreach ($n in @("wry-rdp-guard", "wry-rdp-web", "wry-rdp-report")) {
    if (Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $n -Confirm:$false
        Write-Output "已删除旧任务 $n"
    }
}

# ---- 自愈看门狗任务（登录时 + 每 1 分钟）----
# 路径无空格，无需引号包裹；VBS 内部用 WScript.Shell Run 隐藏窗口
$actionGuard = New-ScheduledTaskAction -Execute $wscript -Argument $launchSelfheal
$triggerLogon = New-ScheduledTaskTrigger -AtLogOn
$triggerEvery = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
# 使用当前身份全名（如 wry-pro\wry），避免 USERDOMAIN/USERNAME 拼接缺分隔符导致任务注册失败
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
$settings.Hidden = $true  # 后台静默运行，任务计划程序 UI 中隐藏

Register-ScheduledTask -TaskName "wry-rdp-guard" -Action $actionGuard -Trigger @($triggerLogon, $triggerEvery) -Principal $principal -Settings $settings -Description "RDP Guard 自愈看门狗（Node 版，VBS 静默启动）：心跳检测引擎与 Web，失联自动重启" -Force | Out-Null
Write-Output "已注册 wry-rdp-guard（登录时 + 每 1 分钟，最高权限，wscript 静默启动）"

# ---- 邮件报告任务（每天 8:00 上半天 / 20:00 下半天，脚本自动判断，无需参数）----
$actionReport = New-ScheduledTaskAction -Execute $wscript -Argument $launchReport
$triggerAm = New-ScheduledTaskTrigger -Daily -At 08:00
$triggerPm = New-ScheduledTaskTrigger -Daily -At 20:00
$settingsReport = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
$settingsReport.Hidden = $true  # 后台静默运行

Register-ScheduledTask -TaskName "wry-rdp-report" -Action $actionReport -Trigger @($triggerAm, $triggerPm) -Principal $principal -Settings $settingsReport -Description "RDP Guard 邮件报告：每天 8:00/20:00 发送半天报告（VBS 静默启动）" -Force | Out-Null
Write-Output "已注册 wry-rdp-report（每天 08:00 am / 20:00 pm，wscript 静默启动）"

# 注册后验证（防止假注册）
foreach ($verifyName in @("wry-rdp-guard", "wry-rdp-report")) {
    $t = Get-ScheduledTask -TaskName $verifyName -ErrorAction SilentlyContinue
    if (-not $t) {
        Write-Error "任务 $verifyName 注册失败，请检查权限与用户账户"
        exit 1
    }
    Write-Output "验证通过: $verifyName (State=$($t.State))"
}
