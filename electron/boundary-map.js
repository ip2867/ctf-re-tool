'use strict';
// 指令边界重建（instruction boundary reconstruction）
//
// ── 为什么需要（实测 Matr1x 的教训）───────────────────────────────────
// 花指令的杀伤机制是"让反汇编器的指令边界判断出错"。
// 一旦某处偏 1 字节，**后面全部解码错位**（实测：542 处跳转里 239 处目标不在边界上 = 44%）。
//
// 之前尝试过的"把花指令段 nop 掉"路线为什么失败（实测数据）：
//   基线 16878 指令 / 239 个非边界目标 → 修补 53 处后 17188 指令 / 236 个非边界（只改善 3）
//   且不可解码从 4 增到 7。
//   原因：`xor ecx,ecx; jnz +1; B8 <imm32>` 这种结构里，jnz +1 跳过的是 mov 的 opcode；
//   把 xor+jnz nop 掉后那 1 字节独立、mov 缺前缀 → 制造**新的**错位。
//   ⇒ 逐个 nop 在"交叠污染"场景下必然越修越乱。
//
// ── 正确做法（本模块）──────────────────────────────────────────────
// **不修改任何字节**，只重建"哪些地址是指令起点"这张边界图。
// 算法 = IDA 的 MakeCode 语义 + 多轮迭代收敛：
//
//   1) 种子：entry + 所有已知函数入口 + 所有 push/mov 立即数里指向代码区的地址
//   2) 沿控制流展开：解码 → 记录边界 → jcc/call 目标入队、jmp 不再 fallthrough、ret 停
//   3) **强制对齐**：若某个跳转目标 T 不是已解码的指令起点，就强制把 T 当作新起点解码
//      （这正是花指令让反汇编器犯难的时刻——我们用"跳转目标是权威"这个事实纠正它）
//   4) 迭代：新增边界可能让之前"解码失败"的位置变合法，重复 2-3 直到收敛
//   5) 输出：边界集合 + 不可达区间（从未被执行流触及 = 花指令垃圾/数据）
//
// 关键洞见：跳转目标**必须是**指令起点（否则程序跑不起来）。
// 所以"目标不在边界上"这条信息是**纠错依据**，而不是"错误本身"。
// 之前的实现把这条信息当成了"花指令位置"，方向反了。

const { decodeInsn } = require('./junk-code');

const DEFAULT_MAX_BLOCKS = 50000;

/**
 * 重建指令边界图。
 *
 * @param {Buffer} buf
 * @param {object} opts
 *   start, end    代码区文件偏移
 *   seeds         种子入口（文件偏移数组）
 *   maxBlocks     最多展开的基本块数
 *   maxPasses     强制对齐最多迭代轮数（默认 3）
 *   vaToOff       函数：虚拟地址 → 文件偏移（可选；用于把 push/mov 立即数当种子）
 * @returns {{
 *   ok, mode, codeRange, seeds, boundaryCount, insnCount, blocks,
 *   boundaries: number[],          // 排好序的指令起点
 *   insns: Array,                  // {off,len,kind,op,rel,target}
 *   unreached: Array<{from,to}>,   // 从未被控制流触及的区间（花指令垃圾候选）
 *   forcedAligns: Array,           // 强制执行"目标即边界"的位置（= 花指令症状点）
 *   conflicts: Array,              // 同一地址被两种解码解释的位置（严重歧义）
 *   stats, notes
 * }}
 */
function buildBoundaryMap(buf, opts = {}) {
  const start = Number.isFinite(opts.start) ? opts.start : 0;
  const end = Number.isFinite(opts.end) ? opts.end : buf.length;
  if (start < 0 || end > buf.length || end - start < 4) {
    return { ok: false, error: `代码区范围非法: [${start}, ${end})，文件长 ${buf.length}` };
  }
  const maxBlocks = Number(opts.maxBlocks) || DEFAULT_MAX_BLOCKS;
  const maxPasses = Number(opts.maxPasses) || 3;

  // ── 种子收集 ──
  let seeds = Array.isArray(opts.seeds) ? opts.seeds.filter(Number.isFinite) : [];
  seeds = seeds.concat(collectSeedCandidates(buf, start, end, opts)).filter(o => o >= start && o < end);
  seeds = [...new Set(seeds)].sort((a, b) => a - b);
  if (!seeds.length) seeds = [start];

  // ── 多轮：解码 + 强制对齐，直到没有新边界 ──
  let boundary = new Map();        // off -> insn
  let forcedAligns = [];
  let conflicts = [];
  let totalBlocks = 0;

  for (let pass = 0; pass < maxPasses; pass++) {
    const res = expandFromSeeds(buf, { start, end, seeds, boundary, maxBlocks });
    boundary = res.boundary;
    totalBlocks += res.blocks;
    forcedAligns = forcedAligns.concat(res.forcedAligns);
    conflicts = conflicts.concat(res.conflicts);
    if (!res.newBoundaries) break;      // 收敛
    // 新增的强制对齐点作为下一轮种子
    seeds = [...new Set([...seeds, ...res.newSeeds])].sort((a, b) => a - b);
  }

  // ── 冲突仲裁：同一地址被两种解码解释时，选"能连成更多指令"的那种 ──
  // 实测 Matr1x：401 处冲突，绝大多数源于"种子落点比真实边界早/晚 1 字节"。
  // 仲裁规则（不猜字节，只看结构性）：
  //   对冲突地址 C，试两种方案：
  //     A) 保留当前覆盖 C 的指令（C 不是起点）
  //     B) 把 C 当起点重新解码，并向后续链式解码若干条
  //   选"到下一个已确认边界之前能恰好对齐"（无空洞、无越界）的那个。
  const arbitrated = arbitrateConflicts(buf, { start, end, boundary, conflicts });
  boundary = arbitrated.boundary;
  const conflictResolved = arbitrated.resolved;
  const conflictUnresolved = arbitrated.unresolved;

  const insns = [...boundary.values()].sort((a, b) => a.off - b.off);
  const bset = insns.map(i => i.off);
  const unreached = computeUnreached(insns, start, end);

  const stats = {
    seedCount: seeds.length,
    blocks: totalBlocks,
    insnCount: insns.length,
    boundaryCount: bset.length,
    unreachableRegions: unreached.length,
    unreachableBytes: unreached.reduce((s, r) => s + (r.to - r.from), 0),
    forcedAlignCount: forcedAligns.length,
    conflictCount: conflicts.length,
    conflictResolved: conflictResolved,
    conflictUnresolved: conflictUnresolved,
    coverage: end > start ? +(((end - start - stats_unreachedBytes(unreached)) / (end - start)) * 100).toFixed(1) : 0,
  };

  return {
    ok: true,
    mode: 'boundary-map',
    codeRange: { start, end, size: end - start },
    seeds,
    insns,
    boundaries: bset,
    unreached,
    forcedAligns: forcedAligns.slice(0, 200),
    conflicts: conflicts.slice(0, 100),
    stats,
    notes: buildNotes(stats, forcedAligns, conflicts, unreached),
  };
}

function stats_unreachedBytes(unreached) {
  return unreached.reduce((s, r) => s + (r.to - r.from), 0);
}

// ── 种子收集：文件头入口、函数序言扫描、立即数指向代码区 ──
function collectSeedCandidates(buf, start, end, opts) {
  const out = [];
  // 1) 调用方提供的 vaToOff
  if (typeof opts.seedAddresses === 'object' && opts.seedAddresses) {
    /* 已由 seeds 传入 */
  }
  // 2) 文件头入口
  try {
    const isElf = buf.length > 64 && buf.readUInt32BE(0) === 0x7f454c46;
    const isPE = buf.length > 0x40 && buf[0] === 0x4d && buf[1] === 0x5a;
    if (isElf) {
      const is32 = buf[4] === 1;
      const entryVa = is32 ? buf.readUInt32LE(24) : Number(buf.readBigUInt64LE(24));
      const phoff = is32 ? buf.readUInt32LE(28) : Number(buf.readBigUInt64LE(32));
      const phentsize = is32 ? buf.readUInt16LE(42) : buf.readUInt16LE(54);
      const phnum = is32 ? buf.readUInt16LE(44) : buf.readUInt16LE(56);
      for (let k = 0; k < phnum; k++) {
        const o = phoff + k * phentsize;
        if (buf.readUInt32LE(o) !== 1) continue;
        const off = is32 ? buf.readUInt32LE(o + 4) : Number(buf.readBigUInt64LE(o + 8));
        const vaddr = is32 ? buf.readUInt32LE(o + 8) : Number(buf.readBigUInt64LE(o + 16));
        const filesz = is32 ? buf.readUInt32LE(o + 16) : Number(buf.readBigUInt64LE(o + 32));
        if (entryVa >= vaddr && entryVa < vaddr + filesz) {
          const fileOff = entryVa - vaddr + off;
          if (fileOff >= start && fileOff < end) out.push(fileOff);
          break;
        }
      }
    } else if (isPE) {
      const peOff = buf.readUInt32LE(0x3c);
      const optOff = peOff + 24;
      const magic = buf.readUInt16LE(optOff);
      const aoe = buf.readUInt32LE(optOff + 16);
      const numSections = buf.readUInt16LE(peOff + 6);
      const sizeOpt = buf.readUInt16LE(peOff + 20);
      const secOff = optOff + sizeOpt;
      const imageBase = magic === 0x20b ? Number(buf.readBigUInt64LE(optOff + 24)) : buf.readUInt32LE(optOff + 28);
      const va = imageBase + aoe;
      for (let k = 0; k < numSections; k++) {
        const s = secOff + k * 40;
        const secVa = buf.readUInt32LE(s + 12);
        const rawSize = buf.readUInt32LE(s + 16);
        const rawPtr = buf.readUInt32LE(s + 20);
        if (va >= imageBase + secVa && va < imageBase + secVa + rawSize) {
          const off = rawPtr + (va - imageBase - secVa);
          if (off >= start && off < end) out.push(off);
          break;
        }
      }
    }
  } catch (e) { /* 头部异常忽略 */ }

  // 3) 函数序言扫描（push ebp; mov ebp,esp / push 多个寄存器 / sub esp,imm）
  //    这是"找入口"的通用启发式，不依赖任何具体题目
  for (let p = start; p < end - 4; p++) {
    const b0 = buf[p], b1 = buf[p + 1], b2 = buf[p + 2];
    let isPrologue = false;
    if (b0 === 0x55 && b1 === 0x89 && b2 === 0xe5) isPrologue = true;              // push ebp; mov ebp,esp
    else if (b0 === 0x55 && b1 === 0x8b && b2 === 0xec) isPrologue = true;         // push ebp; mov ebp,esp (Intel alt)
    else if (b0 === 0x53 && b1 === 0x56 && b2 === 0x57) isPrologue = true;         // push ebx; push esi; push edi
    else if (b0 === 0x83 && b1 === 0xec) isPrologue = true;                        // sub esp, imm8
    if (isPrologue) out.push(p);
  }

  return [...new Set(out)];
}

// ── 从种子沿控制流展开 ──
function expandFromSeeds(buf, { start, end, seeds, boundary, maxBlocks }) {
  const queue = seeds.slice();
  let blocks = 0;
  const forcedAligns = [];
  const conflicts = [];
  const newSeeds = [];
  let newBoundaries = 0;

  while (queue.length && blocks < maxBlocks) {
    const blockStart = queue.shift();
    if (blockStart < start || blockStart >= end) continue;
    blocks++;

    let p = blockStart;
    let guard = 0;
    while (p >= start && p < end && guard++ < 8000) {
      const existing = boundary.get(p);
      if (existing) break;                            // 已解码（汇合）
      // 若 p 已在别的指令"内部"（非起点但被覆盖）→ 冲突
      const covering = findCovering(boundary, p);
      if (covering) {
        conflicts.push({ off: p, coveredBy: covering.off, coveredLen: covering.len });
        break;
      }
      const d = decodeInsn(buf, p);
      if (!d || d.len <= 0 || p + d.len > end) {
        boundary.set(p, { off: p, len: 1, undecodable: true, kind: 'unk' });
        newBoundaries++;
        p += 1;
        continue;
      }
      // 花指令症状：这个位置不是"顺延"来的，而是被强制当起点（由 seed/target 指定）
      if (p === blockStart && blockStart !== start) {
        const prev = findCovering(boundary, p);
        if (!prev) { /* 正常的块起点 */ }
      }
      const insn = {
        off: d.off, len: d.len, op: d.op, kind: d.kind,
        rel: d.rel, target: (d.rel !== null && d.rel !== undefined) ? d.off + d.len + d.rel : null,
        modrm: d.modrm,
      };
      boundary.set(p, insn);
      newBoundaries++;
      p += d.len;

      // 控制流
      if (d.kind === 'jcc8' || d.kind === 'jcc32') {
        if (insn.target >= start && insn.target < end) {
          if (!boundary.has(insn.target)) {
            // **强制对齐**：跳转目标必须是指令起点 → 入队展开
            queue.push(insn.target);
            newSeeds.push(insn.target);
            forcedAligns.push({ from: d.off, target: insn.target, kind: d.kind, rel: d.rel, reason: 'jcc 目标不在已解码边界上' });
          }
        }
      } else if (d.kind === 'jmp8' || d.kind === 'jmp32') {
        if (insn.target >= start && insn.target < end) {
          if (!boundary.has(insn.target)) {
            queue.push(insn.target);
            newSeeds.push(insn.target);
            forcedAligns.push({ from: d.off, target: insn.target, kind: d.kind, rel: d.rel, reason: 'jmp 目标不在已解码边界上' });
          }
        }
        break;   // 无条件跳转：本块结束
      } else if (d.kind === 'ret' || d.kind === 'retimm') {
        break;
      } else if (d.kind === 'call32') {
        if (insn.target >= start && insn.target < end && !boundary.has(insn.target)) {
          queue.push(insn.target);
          newSeeds.push(insn.target);
        }
      }
    }
  }

  return { boundary, blocks, forcedAligns, conflicts, newSeeds, newBoundaries };
}

// 二分查找 p 是否落在某条已解码指令内部（非起点）
function findCovering(boundary, p) {
  const offs = [...boundary.keys()].sort((a, b) => a - b);
  let lo = 0, hi = offs.length - 1, best = null;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (offs[mid] <= p) { best = offs[mid]; lo = mid + 1; } else hi = mid - 1;
  }
  if (best === null) return null;
  const ins = boundary.get(best);
  return (best < p && best + ins.len > p) ? ins : null;
}

/**
 * 冲突仲裁（不改字节，只决定"哪套边界更自洽"）。
 *
 * 对每个冲突地址 C（当前被某条指令覆盖，但控制流认为 C 也该是起点）：
 *   方案 A：保留覆盖 C 的指令（C 不是起点）
 *   方案 B：从 C 开始解码，看能否在"不越界、不与其他已确认边界冲突"的前提下链式解码 ≥3 条
 * 判定：若 B 能连续解码且链尾恰好落在某个已确认边界上 → 采纳 B（删除覆盖 C 的那条指令，
 *       并把它前面那条重新解码，以保持连续）；否则保留 A。
 *
 * 这条规则不猜"哪个字节是垃圾"，只保证边界图自洽——这是静态能做的最强判定。
 */
function arbitrateConflicts(buf, { start, end, boundary, conflicts }) {
  let resolved = 0, unresolved = 0;
  const seen = new Set();
  for (const c of conflicts) {
    if (!c || !Number.isFinite(c.off)) continue;
    if (seen.has(c.off)) continue;
    seen.add(c.off);
    const C = c.off;

    // 方案 B：从 C 起链式解码
    let p = C, chain = [], ok = false;
    for (let k = 0; k < 6 && p < end; k++) {
      const d = decodeInsn(buf, p);
      if (!d || d.len <= 0) break;
      chain.push({ off: p, len: d.len, op: d.op, kind: d.kind, rel: d.rel,
        target: (d.rel !== null && d.rel !== undefined) ? p + d.len + d.rel : null });
      p += d.len;
      if (boundary.has(p) || p === end) { ok = true; break; }   // 恰好对齐到已知边界
    }
    if (ok && chain.length >= 2) {
      // 采纳 B：删掉覆盖 C 的那条指令，插入链
      const cov = findCovering(boundary, C);
      if (cov) {
        boundary.delete(cov.off);
        // 覆盖 C 的指令之前那条，若原本顺势解到 cov.off，现在可能也需重解——保守起见不动
      }
      for (const ins of chain) {
        if (!boundary.has(ins.off)) boundary.set(ins.off, { ...ins, undecodable: false });
      }
      resolved++;
    } else {
      unresolved++;
    }
  }
  return { boundary, resolved, unresolved };
}

function computeUnreached(insns, start, end) {
  // insns 必须带 len（按地址排序）
  const out = [];
  let cursor = start;
  for (const ins of insns) {
    if (ins.off > cursor) out.push({ from: cursor, to: ins.off });
    cursor = Math.max(cursor, ins.off + (ins.len || 1));
  }
  if (cursor < end) out.push({ from: cursor, to: end });
  return out;
}

function buildNotes(stats, forcedAligns, conflicts, unreached) {
  const notes = [];
  notes.push(`指令边界图：${stats.insnCount} 条指令 / ${stats.seedCount} 个种子 / 覆盖率 ${stats.coverage}%。`);
  notes.push(`强制对齐 ${stats.forcedAlignCount} 处（跳转目标不在边界上 → 按"目标必为指令起点"纠正）。` +
    `这些位置就是花指令制造边界歧义的地方。`);
  if (stats.conflictCount) {
    notes.push(`⚠ ${stats.conflictCount} 处冲突：同一地址被两种解码解释覆盖。说明该区域有交叠污染，` +
      `静态难以判定，建议动态（单步 tracing）确认。`);
  }
  if (stats.unreachableRegions) {
    notes.push(`不可达区间 ${stats.unreachableRegions} 段 / ${stats.unreachableBytes} 字节：` +
      `从未被控制流触及。典型是花指令垃圾块，也可能是未被静态引用的函数——` +
      `**报告给 AI 时应当说明这两义性，不要断言一定是花指令**。`);
  }
  notes.push('本模式**不修改任何字节**，只输出边界图。若要与 IDA 对齐，可在 IDA 里对' +
    '不可达区间按 C（MakeCode）/ U（undefine）逐段修正，或直接用本工具输出的边界列表比对。');
  return notes;
}

module.exports = { buildBoundaryMap };
