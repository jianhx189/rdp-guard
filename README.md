# RDP-Guard 远程桌面防护系统

> 独立运行在 E 盘（E:\RDP-Guard），完全脱离 QClaw，仅依赖系统自带 wevtutil + netsh + Node.js。
> 监控 Windows 安全日志 (Event 4625 登录失败)，统计攻击源，达到阈值自动封禁 IP **5 分钟**；
> 唯一攻击源为 192.168.3.88（内网穿透跳板，虽属内网但视为攻击源，照常统计并封禁）。

## 目录结构

| 路径 | 说明 |
|---|---|
| `E:\RDP-Guard\` | 系统根目录（程序本体） |
| `E:\RDP-Guard\data\` | 运行数据：状态文件 + 日志（唯一需要持久化的目录） |
| `E:\RDP-Guard\backups\` | 历史版本备份（按日期命名） |
| `E:\RDP-Guard\tasks\` | 计划任务 XML 模板（改配置就改这里，然后重跑 register-tasks.cmd） |
| `E:\RDP-Guard\node_modules\` | 唯一第三方依赖 nodemailer（邮件发送） |

## 文件备注表

| 文件名 | 作用 | 备注 |
|---|---|---|
| `rdp-guard.js` | **核心引擎**：轮询 4625 事件、统计攻击、封禁 IP、管控 RDP 端口 | 10 秒轮询；1 天窗口内失败 ≥5 次 → 封禁 IP + 封锁 RDP 端口(3389) **5 分钟**，到期自动恢复；需管理员权限 |
| `wry-web.js` | **Web 面板**：19888 端口仪表盘，实时显示 RDP 端口状态/今日攻击量/封禁倒计时/**当日攻击逐条日志框**，常驻**强制解锁**按钮（RDP 被锁时可一键解封全部） | 仅监听 127.0.0.1；页面 5 秒自动刷新 |
| `wry-selfheal.js` | **自愈看门狗（Node 版）**：每分钟检查引擎心跳(<65s)与 19888 端口，失联自动重启 | 由计划任务 `wry-rdp-guard` 驱动（登录时 + 每 1 分钟）；spawn 用 detached:true 防连带杀子进程 |
| `launch-hidden.exe` | **静默启动器**（C# 编译，winexe 无窗口、不走 AMSI） | 计划任务入口；源码见 `launch-hidden.cs` |
| `launch-hidden.cs` | 静默启动器源码 | 编译命令在文件头注释 |
| `send-report-html.js` | **邮件报告**：每天 8:00/20:00 发送**今日全天**报告（数据与 Web 面板 100% 同源，同读 rdp_guard.json，不再自查事件日志） | 由计划任务 `wry-rdp-report` 驱动；SMTP 配置见 `mail-config.json` |
| `fix-rdp-guard.ps1` | 一键修复脚本 | 需管理员（自动弹 UAC） |
| `register-tasks.cmd` | **任务注册脚本（schtasks 原生命令）** | 需提权运行；导入 tasks\*.xml；批处理必须 CRLF + 纯 ASCII |
| `mail-config.json` | SMTP 邮件配置 | ⚠️ 含明文密码，勿外传 |
| `postfix-verify.ps1` | 邮件发送测试脚本 | 辅助工具 |
| `test-env.ps1` | 环境检查（node/防火墙/wevtutil） | 辅助工具 |
| `package.json` / `package-lock.json` | Node 依赖声明 | 依赖仅 nodemailer |
| `launch-selfheal.vbs` / `launch-report.vbs` | **已废弃**（wscript 在本机 ntdll 崩溃） | 保留作历史备注 |
| `wry-selfheal.ps1` / `register-tasks.ps1` | **已废弃**（本机 AMSI 栈损坏，PowerShell 脚本会崩溃） | 保留作历史备注 |

## 运行机制

1. 开机登录 → 计划任务 `wry-rdp-guard` 触发静默启动器 → Node 看门狗
2. 看门狗发现引擎/Web 未运行 → 静默启动 `rdp-guard.js` + `wry-web.js`（无 cmd 窗口）
3. 引擎每 10 秒查询 Security 日志，**1 天窗口**内失败 ≥5 次 → 封禁该 IP + 封锁 RDP 端口
4. **封禁/封锁持续 5 分钟**，到期自动解封、自动恢复端口（默认开启，除非有攻击）
5. `192.168.3.88` 列入 `blockPrivateIPs`：虽为内网但跑内网穿透，是唯一攻击源，照常统计并封禁
6. Web 面板可**手动打开 RDP 端口**（按钮 → 写入请求 → 引擎 20 秒内执行：恢复放行 + 解封全部）
7. 今日攻击量按上海时区统计（含内网/未知 IP），跨天自动重建；引擎维护当日**逐条攻击日志 attackLog**（时间/攻击源IP/被爆破用户名/登录类型/状态码，跨天清空、上限 500 条，同天重启自动回填）
8. 每天 8:00/20:00 邮件报告（经 launch-hidden.exe 静默触发）：内容为**截至发送时的今日累计**，与 Web 面板同源，杜绝两边数字不一致

## 防火墙规则（引擎管理）

| 规则名 | 动作 | 说明 |
|---|---|---|
| `RDP-Guard-Allow-RDP-3389` | 放行 TCP 3389 | 默认开启（RDP 端口可用） |
| `RDP-Guard-Block-Port-3389` | 阻断 TCP 3389 | 攻击时创建，5 分钟到期删除 |
| `RDP-Guard-Block-<IP>` | 阻断该 IP 全部入站 | 攻击源封禁，5 分钟到期删除 |

## 数据文件说明（data\ 目录）

| 文件 | 说明 |
|---|---|
| `rdp_guard.json` | 引擎实时状态（心跳 lastCheck、今日攻击量、当日逐条攻击日志 attackLog、1 天窗口 attempts、封禁列表、rdp 端口状态） |
| `rdp_guard.log` | 引擎运行日志 |
| `rdp_guard_selfheal.log` | 看门狗运行日志 |

## 排障速查

- 引擎是否活着看**心跳**：`(Get-Content 'E:\RDP-Guard\data\rdp_guard.json' -Raw | ConvertFrom-Json).lastCheck`，10 秒内新鲜 = 正常
- 提权进程对非提权 WMI 查询会显示空命令行，是正常现象，别据此误判引擎未启动
- 看门狗以心跳(<65s)为准；刚杀进程后心跳仍在 65s 窗口内，下一分钟才拉起，属正常
- 本机 AMSI/PowerShell 栈损坏（wscript/ps1 偶发崩溃）→ 不要用 .vbs/.ps1 做常驻任务，一律走 launch-hidden.exe + .js

## 迁移记录

- 2026-08-03 从 `C:\Users\jianh\rdp-firewall` 整体迁移至 `E:\RDP-Guard`；旧位置已清理无残留
- 2026-08-03 看门狗 Node 化 + launch-hidden.exe 静默启动（废弃 PowerShell/VBS，AMSI 崩溃）
- 2026-08-03 **v5**：封禁时长 10 分钟窗口 → 改为封禁/端口封锁 **5 分钟自动解封**；新增 RDP 端口(3389)实时状态显示与手动打开按钮；引擎检测 3389 监听状态
- 2026-08-03 **v6**：Web 面板新增**当日攻击逐条日志框**（时间/攻击源IP/被爆破用户名/类型/状态码）与**常驻强制解锁按钮**；邮件报告改为与 Web 面板同源的**今日全天报告**（同读 rdp_guard.json），修复邮件与网页数据不一致；引擎同天重启自动回填当日 attackLog
