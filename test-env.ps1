# 诊断：提权环境变量 + Principal 测试
$log = "C:/Users/jianh/Documents/rdp_guard_fix.log"
function Log($m) { $l = "[$(Get-Date -Format 'HH:mm:ss')] [diag] $m"; Add-Content -Path $log -Value $l -Encoding UTF8 }
Log "USERDOMAIN=$env:USERDOMAIN USERNAME=$env:USERNAME COMPUTERNAME=$env:COMPUTERNAME"
Log "GetCurrent=$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log "IsAdmin=$isAdmin"
try {
  $p1 = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
  Log "Principal1 OK: $($p1.UserId) Logon=$($p1.LogonType) Run=$($p1.RunLevel)"
} catch { Log "Principal1 FAIL: $($_.Exception.Message)" }
try {
  $p2 = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
  Log "Principal2 OK: $($p2.UserId)"
} catch { Log "Principal2 FAIL: $($_.Exception.Message)" }
try {
  $p3 = New-ScheduledTaskPrincipal -LogonType Interactive -RunLevel Highest
  Log "Principal3 OK: $($p3.UserId)"
} catch { Log "Principal3 FAIL: $($_.Exception.Message)" }
Log "DIAG_DONE"