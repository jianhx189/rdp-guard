' RDP Guard 自愈看门狗 静默启动器 (2026-08-03)
' 用途：计划任务 wry-rdp-guard 每分钟调用本文件，用 wscript 隐藏窗口启动 Node 看门狗
' 为什么用 VBS：node.exe 是控制台程序，直接从计划任务启动会闪黑框；
' wscript.exe 是 GUI 宿主，Run 的窗口样式 0 = 完全隐藏，不经过 PowerShell/AMSI（本机该模块损坏易崩溃）
Set sh = CreateObject("WScript.Shell")
sh.Run """D:\app\nodejs\node.exe"" ""E:\RDP-Guard\wry-selfheal.js""", 0, False
