'use strict';
// 从机器码里提取"逐字节立即数比较"形成的字符串（纯函数，零依赖）
//
// ── 为什么需要（NaughtyBoy 实测）────────────────────────────────
// 反汇编里这类校验长这样：
//     cmp byte ptr [rbx+0], 0x62   ; 'b'
//     cmp byte ptr [rbx+1], 0x79   ; 'y'
//     ...
// 伪代码里它被折叠成字符串常量 `"bytectf{"`，但 AI/人读伪代码时极易抄成
// `"bytecf{"`（少一个 t）。一字之差，所有输入在第一步就被拒，
// 而日志里只会看到"校验失败"，完全看不出是前缀抄错了。
//
// 这类"逐字节比较"的模式是**确定性的**：把立即数按偏移排好就是原文。
// 与其让模型去猜，不如直接抽出来。
//
// ── 识别规则（按可靠性排序）────────────────────────────────────
//   ① cmp/mov 到 [reg+disp] 的 imm8，disp 连续递增 → 按 disp 拼成字符串
//   ② 一串连续地址上的 imm8 常量（数据段里的 char 数组）
//   ③ 已知 token（flag/ctf/bytectf…）的相似度提示（防抄错）

// x86/x64 的 `cmp byte ptr [reg+disp], imm8` 常见编码：
//   80 /7 ib            cmp r/m8, imm8
//   41 80 /7 ib         cmp r/m8, imm8（REX.B）
// 我们只做**字节模式扫描 + 相邻指令聚合**，不追求完整解码器；
// 真正的解码由调用方用 capstone（或已有 decodeInsn）提供。

/**
 * 从"逐字节比较"序列还原字符串。
 *
 * @param {Array<{offset:number, value:number}>} pairs
 *        每条比较：offset 是相对基址的偏移，value 是立即数
 * @returns {{ok:boolean, text:string, bytes:number[], gaps:number[], reason?:string}}
 */
function assembleByteComparisons(pairs) {
  const list = (Array.isArray(pairs) ? pairs : [])
    .filter(p => p && Number.isFinite(p.offset) && Number.isFinite(p.value))
    .map(p => ({ offset: Math.trunc(p.offset), value: p.value & 0xff }))
    .sort((a, b) => a.offset - b.offset);
  if (!list.length) return { ok: false, text: '', bytes: [], gaps: [], reason: '没有输入' };

  const base = list[0].offset;
  const bytes = [];
  const gaps = [];
  // 空洞用 -1 占位（不是 0）：0 会被下面的"截到第一个 NUL"误当成字符串结尾，
  // 把 [0x41, <洞>, 0x44] 截成 "A"。实测踩过。
  const HOLE = -1;
  let expect = base;
  for (const p of list) {
    if (p.offset < base) continue;
    const idx = p.offset - base;
    if (idx > bytes.length) {
      gaps.push({ from: bytes.length, to: idx });
      while (bytes.length < idx) bytes.push(HOLE);
    }
    if (idx === bytes.length) bytes.push(p.value);
    else bytes[idx] = p.value;   // 同一偏移重复比较：取最后一次
  }

  // 截到第一个真实 0（C 字符串语义）；空洞不算结尾
  const nul = bytes.indexOf(0);
  const raw = nul >= 0 ? bytes.slice(0, nul) : bytes;
  // 可打印性判断：只看**真实比较过的字节**（空洞不是内容，不该拉低比例）
  const real = raw.filter(b => b !== HOLE);
  const printable = real.filter(b => b >= 0x20 && b < 0x7f).length;
  const ratio = real.length ? printable / real.length : 0;
  const text = raw.map(b => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');

  return {
    ok: raw.length > 0 && ratio >= 0.8,
    text,
    bytes: raw,
    rawBytes: bytes,
    gaps,
    printableRatio: +ratio.toFixed(3),
    reason: ratio >= 0.8 ? '可打印比例达标' : `可打印比例只有 ${(ratio * 100).toFixed(0)}%`,
  };
}

/**
 * 解析一个立即数/偏移字面量，支持多种真实反汇编格式：
 *   0x62 / 62h（IDA 常用后缀 h）/ 98 / 3Ch
 */
function parseNumLit(s) {
  if (s == null) return null;
  const t = String(s).trim();
  if (!t) return null;
  if (/^0x[0-9a-f]+$/i.test(t)) return parseInt(t.slice(2), 16);
  if (/^[0-9a-f]+h$/i.test(t)) return parseInt(t.slice(0, -1), 16);
  if (/^\d+$/.test(t)) return parseInt(t, 10);
  return null;
}

/**
 * 从一段反汇编文本里抓 `cmp byte ptr [reg+disp], imm` 与 `mov byte ptr [reg+disp], imm`。
 * 这是给"只有 IDA 反汇编文本、没有原始字节"的场景用的兜底。
 *
 * 接受的形态（IDA / objdump / capstone 都能命中）：
 *   cmp     byte ptr [rbx+5], 0x74
 *   cmp     byte ptr [rbx+5], 74h          ← IDA 默认格式（后缀 h），实测最常见
 *   cmp     BYTE PTR [rax+2], 79h
 *   cmpb    $0x74,0x5(%rbx)
 *   cmp     byte ptr [rbx], 62h            ← 无 disp，视为 0
 *
 * @returns {Array<{offset:number, value:number, line:number}>}
 */
function extractByteCompares(disasmText) {
  const out = [];
  const lines = String(disasmText || '').split(/\r?\n/);
  const NUM = '(0x[0-9a-fA-F]+|[0-9a-fA-F]+h|\\d+)';
  const reIntel = new RegExp(
    '(?:cmp|mov)\\s+byte\\s+ptr\\s+\\[\\s*[a-z][a-z0-9]*\\s*(?:\\+\\s*' + NUM + ')?\\s*\\]\\s*,\\s*' + NUM,
    'i');
  const reAtt = new RegExp(
    '(?:cmpb|movb)\\s+\\$' + NUM + '\\s*,\\s*(?:' + NUM + ')?\\(%[a-z0-9]+\\)',
    'i');
  for (let i = 0; i < lines.length; i++) {
    const s = lines[i];
    let m = reIntel.exec(s);
    if (m) {
      const off = m[1] ? parseNumLit(m[1]) : 0;
      const val = parseNumLit(m[2]);
      if (off !== null && val !== null) out.push({ offset: off, value: val, line: i + 1 });
      continue;
    }
    m = reAtt.exec(s);
    if (m) {
      const val = parseNumLit(m[1]);
      const off = m[2] ? parseNumLit(m[2]) : 0;
      if (off !== null && val !== null) out.push({ offset: off, value: val, line: i + 1 });
      continue;
    }
  }
  return out;
}

// 常见 flag 前缀（用于"你是不是抄错了"的提示，不参与判定）
//
// ⚠ 不要往里放**易混淆的错误拼写**（如 'bytecf{'）。放了就等于承认它合法：
//   `t === k` 会直接 return []，警告失效。实测踩过这个坑。
const KNOWN_PREFIXES = [
  'flag{', 'ctf{', 'CTF{', 'bytectf{', 'htb{', 'picoCTF{',
  'DASCTF{', 'NSSCTF{', 'SCTF{', 'SYC{', 'moectf{', 'nssctf{',
  'ByteCTF{', 'BCTF{', '0CTF{', 'TCTF{',
];

/**
 * 前缀相似度提示：把提取到的 text 与已知前缀比对，
 * 若有"只差 1-2 个字符"的已知前缀，明确提醒"你可能抄错了"。
 */
function prefixWarnings(text) {
  const t = String(text || '');
  if (!t) return [];
  const out = [];
  for (const k of KNOWN_PREFIXES) {
    if (t === k) return [];           // 完全一致，无警告
    const d = editDistance(t, k);
    if (d > 0 && d <= 2) {
      out.push({
        extracted: t,
        known: k,
        distance: d,
        hint: `提取到 "${t}"，与已知前缀 "${k}" 只差 ${d} 个字符 —— 若你的伪代码/笔记里写的是另一个，以**提取结果**为准。`,
      });
    }
  }
  return out.sort((a, b) => a.distance - b.distance).slice(0, 3);
}

function editDistance(a, b) {
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}

/**
 * 一步到位：从反汇编文本还原被逐字节比较的字符串。
 */
function recoverComparedString(disasmText) {
  const pairs = extractByteCompares(disasmText);
  if (!pairs.length) {
    return { ok: false, text: '', pairs: [], reason: '没找到 cmp/mov byte ptr 形式的逐字节比较' };
  }
  const asm = assembleByteComparisons(pairs);
  return {
    ok: asm.ok,
    text: asm.text,
    bytes: asm.bytes,
    pairs: pairs.length,
    gaps: asm.gaps,
    printableRatio: asm.printableRatio,
    warnings: prefixWarnings(asm.text),
    reason: asm.reason,
  };
}

module.exports = {
  assembleByteComparisons,
  extractByteCompares,
  recoverComparedString,
  prefixWarnings,
  KNOWN_PREFIXES,
};
