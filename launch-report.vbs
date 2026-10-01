' RDP Guard 邮件报告 静默启动器 (2026-08-03)
' 用途：计划任务 wry-rdp-report 每天 8:00/20:00 调用本文件，隐藏窗口启动邮件报告脚本
Set sh = CreateObject("WScript.Shell")
sh.Run """D:\app\nodejs\node.exe"" ""E:\RDP-Guard\send-report-html.js""", 0, False
