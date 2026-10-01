// launch-hidden.cs - RDP Guard 静默启动器 (2026-08-03)
// 编译: csc.exe /nologo /target:winexe /out:E:\RDP-Guard\launch-hidden.exe E:\RDP-Guard\launch-hidden.cs
// 用途: 以完全无窗口方式启动任意程序(如 node.exe)，供计划任务使用，避免控制台窗口闪烁。
//       原生编译的 EXE，不经过 PowerShell/WScript/AMSI（本机这些脚本宿主因 AMSI 栈损坏会崩溃）。
using System;
using System.Diagnostics;

class LaunchHidden
{
    [STAThread]
    static void Main(string[] args)
    {
        if (args.Length == 0) return;
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = args[0];
            if (args.Length > 1)
            {
                for (int i = 1; i < args.Length; i++)
                {
                    if (psi.Arguments.Length > 0) psi.Arguments += " ";
                    psi.Arguments += "\"" + args[i] + "\"";
                }
            }
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            Process.Start(psi);
        }
        catch { }
    }
}
