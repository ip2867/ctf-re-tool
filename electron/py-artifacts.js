'use strict';
// run_python 的工作目录选择与产物扫描（纯函数，零 Electron 依赖）。
//
// 背景：旧实现 spawn('python',[tempFile]) 不设 cwd，脚本里的相对路径
// （open('out.bin','wb')）会写到进程当前目录——实测把 rk.bin/tabs.json/sbox.json
// 写到了仓库根目录，既污染仓库也不可追溯。
//
// 现在固定落在 cases/<题>/scripts/，执行后扫描新增/修改文件并登记为 evidence。

const fs = require('fs');
const path = require('path');
const os = require('os');

// 优先级：explicit > caseDir/scripts > workDir > temp
function pickPythonCwd(input) {
  const i = input || {};
  const usable = (p) => {
    if (!p) return '';
    const s = String(p).trim();
    if (!s) return '';
    try { return fs.existsSync(s) && fs.statSync(s).isDirectory() ? s : ''; } catch (e) { return ''; }
  };

  const explicit = usable(i.explicitCwd);
  if (explicit) return explicit;

  const caseDir = String(i.caseDir || '').trim();
  if (caseDir) {
    const scripts = path.join(caseDir, 'scripts');
    return usable(scripts) || caseDir;
  }

  const work = usable(i.workDir);
  if (work) return work;

  return os.tmpdir();
}

// 目录快照：{relpath: {mtimeMs, size}}
function snapshotDir(dir) {
  const out = new Map();
  if (!dir) return out;
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return out; }
  for (const e of entries) {
    if (!e.isFile()) continue;
    const p = path.join(dir, e.name);
    try {
      const st = fs.statSync(p);
      out.set(e.name, { mtimeMs: st.mtimeMs, size: st.size });
    } catch (err) { /* 并发删除 */ }
  }
  return out;
}

// 只返回"新增或 mtime/size 变化"的文件。sinceMs 可选：再按 mtime 兜底过滤。
function scanNewArtifacts(dir, sinceMs, before) {
  if (!dir) return [];
  const prev = before instanceof Map ? before : snapshotDir(dir);
  const now = snapshotDir(dir);
  const out = [];
  for (const [name, st] of now) {
    const old = prev.get(name);
    const changed = !old || old.mtimeMs !== st.mtimeMs || old.size !== st.size;
    if (!changed) continue;
    if (sinceMs && st.mtimeMs < sinceMs - 1000) continue;
    out.push({ name, path: path.join(dir, name), size: st.size, mtimeMs: st.mtimeMs });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

module.exports = { pickPythonCwd, snapshotDir, scanNewArtifacts };
