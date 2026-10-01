const fs = require('fs');
const path = require('path');
const root = 'E:\\RDP-Guard\\backups';
const targets = ['backup-20260802-174509','backup-20260802-1806','backup-20260803-0006','backup-20260803-pre-daily','backup-20260803-v5','backup-20260803-v5-final','backup-20260803-v5-rdp-port','backup-20260803-watchdog-final','backup-20260803-watchdog-node'];
for (const t of targets) {
  const full = path.resolve(root, t);
  if (!full.startsWith(path.resolve(root) + path.sep)) throw new Error('越界: ' + full);
  fs.rmSync(full, { recursive: true, force: true });
  console.log('已删除: ' + full);
}
for (const f of ['E:\\RDP-Guard\\_dryrun-test.js', 'E:\\RDP-Guard\\_patch-readme.js']) {
  if (fs.existsSync(f)) { fs.rmSync(f, { force: true }); console.log('已删除: ' + f); }
}
console.log('---- 剩余备份 ----');
console.log(fs.readdirSync(root).join('\n'));
