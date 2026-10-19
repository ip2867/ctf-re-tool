'use strict';
// 去重闸的"地址目标指纹"层（rank 1）。
//
// 背景：旧判据只用「归一化脚本的二元组相似度 > 0.88」。而 normalizeScript 会把
// `0x...` 与所有数字折叠成 ` N `，于是"反汇编另一个函数区间"这类**语义全新的查询**
// 相似度算出来是 1.000（实测 CrackMe2 的 0x4012f0 / 0x42f038 / 0x42fcd9 / 0x401000
// 四个脚本全判为同一思路），第 3 次起永久拦截，AI 只能放弃静态分析。
//
// 这里补一层：抽取脚本的**观测地址集合**，只有"结构相似 + 观测目标也重叠"才算同一实验。
// 判据完全来自输入的结构（地址常量、文件路径），不针对任何题目。

// 小于这个值的常量不当作"观测目标"：它们几乎全是长度/索引/循环上限/小偏移，
// 在任意两个脚本之间都近似相等，纳入目标集合会把不同实验判成相同。
const MIN_TARGET_ADDR = 0x1000n;

// 文件路径：Windows 盘符路径、POSIX 绝对路径、以及带常见扩展名的相对名。
const PATH_PATTERNS = [
  /[A-Za-z]:[\\/][^\s"'`)]+/g,
  /(?:^|[\s"'(])((?:\/[\w.\-]+){2,})/g,
  /[\w.\-]+\.(?:exe|dll|sys|bin|elf|so|apk|dex|py|pyc|js|lua|zip|rar|7z|pcap|txt|json|xml|dat)\b/gi,
];

function normalizePath(p) {
  return String(p || '').trim().replace(/\\/g, '/').toLowerCase();
}

// 十六进制常量：0x... 与长度 >= 8 的纯 hex 字面量（后者常被当作密文/地址表使用）。
// 用 BigInt 规范化，避免前导零/大小写造成"看起来不同、实际同一个地址"。
function hexTargetsIn(text) {
  const out = new Set();
  const push = (raw) => {
    let h = String(raw).replace(/^0[xX]/, '').toLowerCase();
    if (!h || !/^[0-9a-f]+$/.test(h)) return;
    try {
      const v = BigInt('0x' + h);
      if (v < MIN_TARGET_ADDR) return;          // 小常量不是观测目标
      out.add(v.toString(16));
    } catch (e) { /* 非法数字，忽略 */ }
  };
  const s = String(text || '');
  // 0x 前缀形式
  const re0x = /\b0[xX]([0-9a-fA-F]+)\b/g;
  let m;
  while ((m = re0x.exec(s)) !== null) push(m[1]);
  // 纯 hex 字符串字面量（>=8 位，成对出现才像地址/密文；奇数位也接受，按数值处理）
  const reStr = /["']([0-9a-fA-F]{8,})["']/g;
  while ((m = reStr.exec(s)) !== null) push(m[1]);
  return out;
}

function firstPathIn(text) {
  const s = String(text || '');
  for (const re of PATH_PATTERNS) {
    re.lastIndex = 0;
    const m = re.exec(s);
    if (m) {
      const v = m[1] || m[0];
      if (v && v.length >= 3) return normalizePath(v);
    }
  }
  return '';
}

// 抽取一个脚本的"观测目标指纹"。
// addrs：要观测的地址集合（已规范化、已剔除小常量）
// path ：脚本操作的第一个文件（用于"不同文件不可能是同一实验"的前置判断）
function scriptTargets(input) {
  const raw = typeof input === 'string'
    ? input
    : String((input && (input.script || input.command || input.code)) || '');
  return { addrs: hexTargetsIn(raw), path: firstPathIn(raw) };
}

// 重叠度 = 交集 / 较小集合大小（containment）。
// 为什么不用 Jaccard：单侧集合变大（例如脚本多读了一个地址）不该因此判成"不同实验"，
// 只要"较小的那组观测点全部被覆盖"，就说明它们在看同一批东西。
function targetsOverlap(a, b) {
  const A = a || { addrs: new Set(), path: '' };
  const B = b || { addrs: new Set(), path: '' };
  // 不同文件不可能是同一实验（路径都存在且不同才判，避免误伤"未写路径"的脚本）
  if (A.path && B.path && A.path !== B.path) return 0;
  const sa = A.addrs || new Set();
  const sb = B.addrs || new Set();
  const minSize = Math.min(sa.size, sb.size);
  if (!minSize) return 0;
  let inter = 0;
  for (const x of sa) if (sb.has(x)) inter++;
  return inter / minSize;
}

// ---------- 去重状态机 ----------
// 两层，顺序固定（计划 §rank1 改法 4）：
//   cleared → A（逐字节相同）→ B（结构相似 + 目标重叠）
// A/B 各自独立计数：A 命中不改 B 计数，B 命中不改 A 计数。

const SIMILARITY_THRESHOLD = 0.88;
const TARGET_OVERLAP_THRESHOLD = 0.5;
const A_LIMIT_SCRIPT = 2;    // 脚本类：逐字节相同第 2 次即拦
const A_LIMIT_OTHER = 4;
const B_LIMIT = 3;           // 同一目标第 3 次起拦

function createDedupState() {
  return {
    // 逐字节签名 → 次数
    sigCounts: new Map(),
    // 已清空签名的集合（允许重取一次）
    clearedSigs: new Set(),
    // 结构池：{ norm, targets, count, sigs:Set }
    pool: [],
  };
}

/**
 * 判断这次调用是否属于又一轮"同一实验"。
 * @param {object} state    createDedupState() 的返回值（会被就地更新）
 * @param {object} entry    { name, sig, script, isScriptTool, cleared }
 * @returns {{blocked:boolean, layer:'cleared'|'A'|'B'|null, count:number, reason:string}}
 */
function checkDedup(state, entry) {
  const e = entry || {};
  const st = state || createDedupState();
  const sig = String(e.sig || '');
  const isScriptTool = !!e.isScriptTool;
  const limit = isScriptTool ? A_LIMIT_SCRIPT : A_LIMIT_OTHER;

  // 1) 上一轮结果被 microcompact 清空 → 允许重取一次（清空计数）
  if (e.cleared) {
    st.clearedSigs.add(sig);
    st.sigCounts.set(sig, 0);
    for (const p of st.pool) p.count = 0;
    return { blocked: false, layer: 'cleared', count: 0, reason: '上一轮结果已被清空，允许重取一次' };
  }

  // 2) A 层：参数逐字节相同
  const cnt = (st.sigCounts.get(sig) || 0) + 1;
  st.sigCounts.set(sig, cnt);
  if (cnt >= limit) {
    return {
      blocked: true, layer: 'A', count: cnt,
      reason: `A/逐字节相同：同一参数已第 ${cnt} 次提交（阈值 ${limit}）`,
    };
  }

  if (!isScriptTool) {
    return { blocked: false, layer: null, count: cnt, reason: '' };
  }

  // 3) B 层：结构相似 + 观测目标重叠
  const targets = e.targets || scriptTargets(e.script);
  const norm = String(e.norm || '');
  if (!norm || norm.length < 40) {
    return { blocked: false, layer: null, count: cnt, reason: '' };
  }
  // 没有地址指纹 → 不判（宁放行，避免把新实验锁死）
  if (!targets.addrs || !targets.addrs.size) {
    return { blocked: false, layer: null, count: cnt, reason: '无地址目标指纹，B 层不判定（仅 A 层生效）' };
  }

  let hit = null;
  for (const p of st.pool) {
    // 逐字节相同的调用已由 A 层处理过，这里按**签名**跳过而不是按归一化文本：
    // 归一化会把变量名统一改写，"只换变量名"的脚本 norm 完全相同，
    // 若按 norm 跳过，它们就永远进不了 B 层（实测 bug）。
    if (p.sig === sig) continue;
    if (scriptSimilarityFn(norm, p.norm) <= SIMILARITY_THRESHOLD) continue;
    if (targetsOverlap(targets, p.targets) < TARGET_OVERLAP_THRESHOLD) continue;
    hit = p;
    break;
  }

  if (!hit) {
    st.pool.push({ sig, norm, targets, count: 1 });
    // 同时保留"结构相似但目标不同"的说明，便于日志取证
    const nearMiss = st.pool.some(p => p.sig !== sig
      && scriptSimilarityFn(norm, p.norm) > SIMILARITY_THRESHOLD
      && targetsOverlap(targets, p.targets) < TARGET_OVERLAP_THRESHOLD);
    return {
      blocked: false, layer: null, count: 1,
      reason: nearMiss ? '目标集合不同，按新实验放行' : '',
      nearMiss,
    };
  }

  hit.count++;
  if (hit.count >= B_LIMIT) {
    const a = [...(hit.targets.addrs || [])].sort().slice(0, 6).join(',');
    const b = [...(targets.addrs || [])].sort().slice(0, 6).join(',');
    return {
      blocked: true, layer: 'B', count: hit.count,
      reason: `B/同目标：结构相似度 >${SIMILARITY_THRESHOLD} 且观测地址重叠 `
        + `${Math.round(targetsOverlap(targets, hit.targets) * 100)}%（第 ${hit.count} 次；`
        + `历史目标 {${a}}，本次 {${b}}）`,
    };
  }
  return { blocked: false, layer: null, count: hit.count, reason: '' };
}

// 注入点：main.js 用自己那份（含关键字表）；这里给单测/独立使用留一个默认实现。
let scriptSimilarityFn = (a, b) => {
  if (!a || !b) return 0;
  if (a === b) return 1;
  const grams = (s) => {
    const set = new Set();
    for (let i = 0; i + 1 < s.length; i++) set.add(s.slice(i, i + 2));
    return set;
  };
  const A = grams(a), B = grams(b);
  if (!A.size || !B.size) return 0;
  let inter = 0;
  for (const g of A) if (B.has(g)) inter++;
  return inter / (A.size + B.size - inter);
};

function setScriptSimilarity(fn) {
  if (typeof fn === 'function') scriptSimilarityFn = fn;
}

module.exports = {
  MIN_TARGET_ADDR,
  SIMILARITY_THRESHOLD,
  TARGET_OVERLAP_THRESHOLD,
  scriptTargets,
  targetsOverlap,
  normalizePath,
  hexTargetsIn,
  createDedupState,
  checkDedup,
  setScriptSimilarity,
};
