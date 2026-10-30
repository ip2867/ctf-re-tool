'use strict';
// 从自然语言消息里提取文件/目录路径（纯函数，零依赖）
//
// ── 为什么需要（NaughtyBoy / 驱动逆向 实测）──────────────────────
// 用户最自然的交互是把路径直接写在聊天里：
//     E:\ctf\pratice\ai\[ByteCTF2019]驱动逆向\attachment_x\驱动逆向 这个有两个文件是一道ctf逆向题目，你打开后求解flag
// 但旧实现只认"文件对话框选中的那个"（state.currentFile）。消息里含"求解flag"会命中
// 快捷命令 → autoAnalyze() → 发现没有 currentFile → 打印「请先选择文件」→ 什么都不做。
// 用户看到的就是"他不理我"。
//
// 这里的职责：把消息里提到的路径识别出来，交给上层去打开/分析。
// 只做**识别**，不判断文件是否存在（存在性要问 fs，属于上层）。

// Windows 路径：盘符 + 反斜杠/正斜杠；或 UNC（\\server\share）
// 允许空格与中文，但要在明显的分隔符处停下。
const WIN_ABS = /(?:^|[\s（(【\["'`：:，,、;；])([A-Za-z]:[\\/][^\r\n"'`|<>*?]*?)(?=[\s"'`|<>*?]|$)/g;
const UNC_ABS = /(?:^|[\s（(【\["'`：:，,、;；])(\\\\[^\\/\s]+[\\/][^\r\n"'`|<>*?]*?)(?=[\s"'`|<>*?]|$)/g;
// POSIX 绝对路径（Kali 上常见）；至少要两级，避免把 "/" "//" 当路径
const POSIX_ABS = /(?:^|[\s（(【\["'`：:，,、;；])(\/(?:[^\s/]+\/)+[^\s"'`|<>*?]*)/g;

function decodeLoose(v) {
  if (typeof v !== 'string') return null;
  let s = v.trim();
  if (!s) return null;
  // 去掉末尾的标点（中文句号/逗号/括号），它们常被误粘进路径
  s = s.replace(/[，,。.；;：:、）)】\]》>]+$/, '');
  if (!s) return null;
  return s;
}

/**
 * 从一段文本里提取候选路径（按出现顺序去重）。
 *
 * @param {string} text
 * @param {{os?:'win'|'posix'}} [opts] 主要影响返回顺序（当前系统的一类排前面）
 * @returns {string[]}
 */
function extractPaths(text, opts) {
  const s = String(text == null ? '' : text);
  const found = [];

  const collect = (re) => {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(s)) !== null) {
      const p = decodeLoose(m[1]);
      if (p) found.push({ path: p, index: m.index });
    }
  };
  // 先收 Windows/UNC，再收 POSIX；POSIX 收完要把"已被 Windows 路径覆盖的区间"去掉，
  // 否则 `E:/ctf/a/b.exe` 会被 POSIX 正则再从 `/ctf/...` 处匹配一次（实测重复）。
  const winHits = [];
  WIN_ABS.lastIndex = 0;
  { let m; while ((m = WIN_ABS.exec(s)) !== null) { const p = decodeLoose(m[1]); if (p) winHits.push({ path: p, index: m.index, len: m[1].length }); } }
  UNC_ABS.lastIndex = 0;
  { let m; while ((m = UNC_ABS.exec(s)) !== null) { const p = decodeLoose(m[1]); if (p) winHits.push({ path: p, index: m.index, len: m[1].length }); } }
  found.push(...winHits);

  const coveredByWin = (idx) => winHits.some(w => idx >= w.index && idx < w.index + w.len);
  POSIX_ABS.lastIndex = 0;
  let pm;
  while ((pm = POSIX_ABS.exec(s)) !== null) {
    if (coveredByWin(pm.index)) continue;
    const p = decodeLoose(pm[1]);
    if (p) found.push({ path: p, index: pm.index });
  }

  // 按出现顺序，去重（Windows 路径大小写不敏感，POSIX 敏感）
  const seen = new Set();
  const out = [];
  for (const f of found.sort((a, b) => a.index - b.index)) {
    const key = /^[A-Za-z]:/.test(f.path) ? f.path.toLowerCase() : f.path;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f.path);
  }
  return out;
}

/**
 * 判断一句话是否"在要求打开/分析某个路径"。
 * 用来决定要不要因为消息里出现路径而改变动作——避免把随口提到的路径也当指令。
 */
function looksLikeOpenRequest(text) {
  const s = String(text == null ? '' : text);
  if (!s) return false;
  // 明确的开/分析动词
  if (/(打开|载入|加载|分析|看看|跑一下|求解|解一下|解出|reverse|analyze|open)/i.test(s)) return true;
  return false;
}

/**
 * 一步到位：从消息里挑出"该打开哪个路径"。
 *
 * 规则（保守，宁可返回 null 也不要乱开文件）：
 *   1. 消息里没有绝对路径 → null
 *   2. 有多个路径时，优先选**看起来是文件**的（带扩展名），其次选最后一个
 *      （用户常先说目录再说文件，或反之；带扩展名的最明确）
 *   3. 若只给了目录（无扩展名且以分隔符结尾/或无扩展名），也返回——
 *      上层可以据此展开目录挑主文件
 *
 * @returns {{path:string, kind:'file'|'dir'|'unknown', all:string[]} | null}
 */
function pickPathFromMessage(text) {
  const all = extractPaths(text);
  if (!all.length) return null;

  const kindOf = (p) => {
    const base = p.replace(/[\\/]+$/, '').split(/[\\/]/).pop() || '';
    if (!base) return 'dir';
    // 有扩展名（1-10 位字母数字）→ 当文件
    if (/\.[A-Za-z0-9]{1,10}$/.test(base)) return 'file';
    // 末尾有分隔符 → 目录
    if (/[\\/]$/.test(p)) return 'dir';
    return 'unknown';
  };

  const files = all.filter(p => kindOf(p) === 'file');
  const chosen = files.length ? files[files.length - 1] : all[all.length - 1];
  return { path: chosen, kind: kindOf(chosen), all };
}

module.exports = { extractPaths, looksLikeOpenRequest, pickPathFromMessage };
