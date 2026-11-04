'use strict';
// ELF 结构级异常检测（纯函数，无外部依赖）。
//
// 为什么需要：实测（elfstudy）真实校验逻辑被加密后藏在 **LOAD 段的页尾缝隙**
// （segment slack）里，并靠精心构造的 Rela/COPY/IFUNC 在 ld.so 重定位阶段自解密。
// 旧的 `scan_crypto` 只看「已知算法常量」和「256 项双射表」，于是对这类样本
// 报「未发现算法指纹」——正确但无用，因为它看不见「有东西藏在映射区却没被任何
// 段/节覆盖」这件事。
//
// 本模块不猜算法、不猜语义，只回答三类**可确定的元数据矛盾**：
//   1) 段尾缝隙（slack）里有没有非零数据 —— 内核按页映射，文件字节超过 p_filesz 也会进内存
//   2) 重定位表有没有自相矛盾 —— RELASZ 与 .rela.dyn/.rela.plt 之和不符、COPY 打到代码段、
//      RELATIVE 指向 dynsym 内部、IFUNC 出现在非预期符号上
//   3) 段/节覆盖缺口 —— 文件里有大块数据不被任何 section 覆盖
//
// 判据全部来自 ELF 规范与「正常编译器不会这么干」的事实，与题目内容无关。
// 输出是**线索**（带精确偏移与理由），最终判断交给 AI。

const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const PF_X = 1;
const PF_W = 2;

const DT = {
  NULL: 0, PLTRELSZ: 2, PLTGOT: 3, HASH: 4, STRTAB: 5, SYMTAB: 6, RELA: 7,
  RELASZ: 8, RELAENT: 9, STRSZ: 10, SYMENT: 11, INIT: 12, FINI: 13,
  SONAME: 14, RPATH: 15, SYMBOLIC: 16, REL: 17, RELSZ: 18, RELENT: 19,
  PLTREL: 20, DEBUG: 21, TEXTREL: 22, JMPREL: 23, BIND_NOW: 24,
  FLAGS: 30, RELACOUNT: 0x6ffffff9, RELCOUNT: 0x6ffffffa, FLAGS_1: 0x6ffffffb,
  RELR: 36, RELRSZ: 35, RELRENT: 37,
};

const R_X86_64 = {
  0: 'NONE', 1: '64', 2: 'PC32', 3: 'GOT32', 4: 'PLT32', 5: 'COPY',
  6: 'GLOB_DAT', 7: 'JUMP_SLOT', 8: 'RELATIVE', 9: 'GOTPCREL',
  16: 'TPOFF64', 18: 'TPOFF32', 37: 'IRELATIVE', 41: 'GOTPCRELX', 42: 'REX_GOTPCRELX',
  0x21: 'SIZE64',
};
const R_RISCV = {
  0: 'NONE', 1: '32', 2: '64', 3: 'RELATIVE', 5: 'JUMP_SLOT', 6: 'GLOB_DAT',
  7: 'TLS_DTPMOD32', 8: 'TLS_DTPMOD64',
};
// 各架构下 "改写代码段" / "加载期可执行" 的危险重定位
const DANGEROUS_TEXT_RELOC = new Set([1, 2, 4, 5, 8, 16, 18, 0x21]); // 64/PC32/PLT32/COPY/RELATIVE/TPOFF/SIZE64

function readEhdr(buf) {
  if (!buf || buf.length < 64) return null;
  if (buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) return null;
  const cls = buf[4];               // 1=32, 2=64
  const le = buf[5] === 1;          // 1=LE
  const is64 = cls === 2;
  const r = {
    is64, le, machine: 0, type: 0,
    e_phoff: 0, e_shoff: 0, e_phnum: 0, e_shnum: 0, e_shstrndx: 0, e_entry: 0,
  };
  if (is64) {
    r.type = le ? buf.readUInt16LE(16) : buf.readUInt16BE(16);
    r.machine = le ? buf.readUInt16LE(18) : buf.readUInt16BE(18);
    r.e_entry = Number(le ? buf.readBigUInt64LE(24) : buf.readBigUInt64BE(24));
    r.e_phoff = Number(le ? buf.readBigUInt64LE(32) : buf.readBigUInt64BE(32));
    r.e_shoff = Number(le ? buf.readBigUInt64LE(40) : buf.readBigUInt64BE(40));
    r.e_phnum = le ? buf.readUInt16LE(56) : buf.readUInt16BE(56);
    r.e_shnum = le ? buf.readUInt16LE(60) : buf.readUInt16BE(60);
    r.e_shstrndx = le ? buf.readUInt16LE(62) : buf.readUInt16BE(62);
  } else {
    r.type = le ? buf.readUInt16LE(16) : buf.readUInt16BE(16);
    r.machine = le ? buf.readUInt16LE(18) : buf.readUInt16BE(18);
    r.e_entry = le ? buf.readUInt32LE(24) : buf.readUInt32BE(24);
    r.e_phoff = le ? buf.readUInt32LE(28) : buf.readUInt32BE(28);
    r.e_shoff = le ? buf.readUInt32LE(32) : buf.readUInt32BE(32);
    r.e_phnum = le ? buf.readUInt16LE(44) : buf.readUInt16BE(44);
    r.e_shnum = le ? buf.readUInt16LE(48) : buf.readUInt16BE(48);
    r.e_shstrndx = le ? buf.readUInt16LE(50) : buf.readUInt16BE(50);
  }
  return r;
}

function readPhdrs(buf, eh) {
  const out = [];
  const ent = eh.is64 ? 56 : 32;
  for (let i = 0; i < eh.e_phnum; i++) {
    const o = eh.e_phoff + i * ent;
    if (o + ent > buf.length) break;
    let p = { index: i };
    if (eh.is64) {
      p.type = buf.readUInt32LE(o);
      p.flags = buf.readUInt32LE(o + 4);
      p.offset = Number(buf.readBigUInt64LE(o + 8));
      p.vaddr = Number(buf.readBigUInt64LE(o + 16));
      p.paddr = Number(buf.readBigUInt64LE(o + 24));
      p.filesz = Number(buf.readBigUInt64LE(o + 32));
      p.memsz = Number(buf.readBigUInt64LE(o + 40));
      p.align = Number(buf.readBigUInt64LE(o + 48));
    } else {
      p.type = buf.readUInt32LE(o);
      p.offset = buf.readUInt32LE(o + 4);
      p.vaddr = buf.readUInt32LE(o + 8);
      p.paddr = buf.readUInt32LE(o + 12);
      p.filesz = buf.readUInt32LE(o + 16);
      p.memsz = buf.readUInt32LE(o + 20);
      p.flags = buf.readUInt32LE(o + 24);
      p.align = buf.readUInt32LE(o + 28);
    }
    out.push(p);
  }
  return out;
}

function readShdrs(buf, eh) {
  const out = [];
  const ent = eh.is64 ? 64 : 40;
  for (let i = 0; i < eh.e_shnum; i++) {
    const o = eh.e_shoff + i * ent;
    if (o + ent > buf.length) break;
    let s = { index: i };
    if (eh.is64) {
      s.nameOff = buf.readUInt32LE(o);
      s.type = buf.readUInt32LE(o + 4);
      s.flags = Number(buf.readBigUInt64LE(o + 8));
      s.addr = Number(buf.readBigUInt64LE(o + 16));
      s.offset = Number(buf.readBigUInt64LE(o + 24));
      s.size = Number(buf.readBigUInt64LE(o + 32));
      s.link = buf.readUInt32LE(o + 40);
      s.entsize = Number(buf.readBigUInt64LE(o + 56));
    } else {
      s.nameOff = buf.readUInt32LE(o);
      s.type = buf.readUInt32LE(o + 4);
      s.flags = buf.readUInt32LE(o + 8);
      s.addr = buf.readUInt32LE(o + 12);
      s.offset = buf.readUInt32LE(o + 16);
      s.size = buf.readUInt32LE(o + 20);
      s.link = buf.readUInt32LE(o + 24);
      s.entsize = buf.readUInt32LE(o + 36);
    }
    out.push(s);
  }
  return out;
}

function shstrtabName(buf, shdrs, idx) {
  if (idx < 0 || idx >= shdrs.length) return '';
  const s = shdrs[idx];
  if (!s || s.offset + s.size > buf.length) return '';
  return buf.slice(s.offset, s.offset + s.size).toString('latin1');
}

/** 熵（Shannon，按字节） */
function entropy(buf) {
  if (!buf || !buf.length) return 0;
  const cnt = new Array(256).fill(0);
  for (let i = 0; i < buf.length; i++) cnt[buf[i]]++;
  let h = 0;
  for (const c of cnt) {
    if (!c) continue;
    const p = c / buf.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** 统计"非零字节"与"高熵"（>=7.0）判定 */
function looksLikeData(buf) {
  if (!buf || !buf.length) return { nonzero: 0, ratio: 0, entropy: 0, dataLike: false };
  let nz = 0;
  for (let i = 0; i < buf.length; i++) if (buf[i]) nz++;
  const e = entropy(buf);
  return {
    nonzero: nz,
    ratio: nz / buf.length,
    entropy: Number(e.toFixed(3)),
    // 判定：非零比例 > 30% 或熵 > 6.5 —— 空白页尾通常是全 0，填充通常是低熵重复
    dataLike: (nz / buf.length) > 0.30 || e > 6.5,
  };
}

/**
 * 在页尾缝隙里**按滑窗找连续数据块**。
 *
 * 为什么不能看整体：实测 elfstudy 的 slack 里"大部分是零填充 + 中间夹几块真数据"
 * （0x1988 起 912 字节隐藏重定位表、0x7396 起 816 字节高熵密文），
 * 对整段求非零比例只有 13%/29%，会被判成"没有东西"。
 * 正确做法：滑窗（窗口 128 字节、步长 32）找连续的数据段，再合并相邻窗口。
 *
 * @returns {Array<{start:number,end:number,entropy:number,nonzeroRatio:number}>}
 *          区间是**相对 slack 起点**的偏移
 */
function findDataBlocks(slack) {
  const WIN = 128, STEP = 32;
  if (!slack || slack.length < WIN) {
    if (!slack || !slack.length) return [];
    const info = looksLikeData(slack);
    return info.dataLike ? [{ start: 0, end: slack.length, entropy: info.entropy, nonzeroRatio: info.ratio }] : [];
  }
  const hot = [];
  for (let o = 0; o + WIN <= slack.length; o += STEP) {
    const w = slack.slice(o, o + WIN);
    let nz = 0;
    for (let i = 0; i < w.length; i++) if (w[i]) nz++;
    const e = entropy(w);
    // 窗口判据：非零 > 15% 或熵 > 4.0 —— 比整段宽松，因为真数据块可能夹在零里
    if (nz / WIN > 0.15 || e > 4.0) hot.push([o, o + WIN]);
  }
  if (!hot.length) return [];
  // 合并重叠/相邻窗口
  hot.sort((a, b) => a[0] - b[0]);
  const merged = [hot[0].slice()];
  for (const [s, e] of hot.slice(1)) {
    const last = merged[merged.length - 1];
    if (s <= last[1] + STEP) last[1] = Math.max(last[1], e);
    else merged.push([s, e]);
  }
  // 把窗口边界还原成"真实数据边界"：在块内向前/向后找最后一个非零字节
  return merged.map(([s, e]) => {
    let rs = s, re = e;
    while (rs < e && slack[rs] === 0) rs++;
    while (re > rs && slack[re - 1] === 0) re--;
    const seg = slack.slice(rs, re);
    const info = looksLikeData(seg);
    return { start: rs, end: re, entropy: info.entropy, nonzeroRatio: Number(info.ratio.toFixed(3)) };
  }).filter((b) => b.end - b.start >= 64);   // 小于 64 字节的多为对齐残留
}

/**
 * 主入口：分析 ELF 的结构级异常。
 * @param {Buffer} buf
 * @returns {object|null} 非 ELF 返回 null
 */
function analyzeElfAnomalies(buf) {
  const eh = readEhdr(buf);
  if (!eh) return null;
  const phdrs = readPhdrs(buf, eh);
  const shdrs = readShdrs(buf, eh);
  const strs = shstrtabName(buf, shdrs, eh.e_shstrndx);
  for (const s of shdrs) {
    const end = strs.indexOf('\0', s.nameOff);
    s.name = s.nameOff < strs.length ? strs.slice(s.nameOff, end < 0 ? undefined : end) : '';
  }

  const findings = [];
  const lines = [];

  // ── 1) 段尾缝隙（segment slack）里有数据 ──
  // ⚠️ 必须排除"该区间已被某个 section 覆盖"的情况：正常 ELF 的 .shstrtab/.symtab
  // 等节常位于某个 LOAD 的页尾之后，那是有名有姓的正当数据，不是隐藏物。
  // 实测（elfstudy）不加这条过滤会在 0xa018 附近报 3 条误报。
  const loadSegs = phdrs.filter((p) => p.type === PT_LOAD);
  // ⚠️ 必须排除 SHT_NOBITS（.bss 等）：它们在文件里**不占字节**，s.offset 只是个
  // "映射目标"，把它算进覆盖会让覆盖率超过 100%（实测 elfstudy 踩过）。
  // ⚠️ 还必须把**节表本体**（e_shoff..e_shoff+e_shnum*entsize）算作已覆盖：
  // 它是合法结构数据，但不属于任何 section。实测 0xa168 处的节表被误报成隐藏数据。
  const shEnt = eh.is64 ? 64 : 40;
  const secRangesEarly = shdrs.filter((s) => s.type !== 8 && s.size > 0).map((s) => [s.offset, s.offset + s.size]);
  if (eh.e_shoff > 0 && eh.e_shnum > 0) {
    secRangesEarly.push([eh.e_shoff, eh.e_shoff + eh.e_shnum * shEnt]);
  }
  if (eh.e_phoff > 0 && eh.e_phnum > 0) {
    secRangesEarly.push([eh.e_phoff, eh.e_phoff + eh.e_phnum * (eh.is64 ? 56 : 32)]);
  }
  // 判据：该区间**有实质重叠**的节覆盖（>=50%）就算正当数据，不是隐藏物。
  // 用"重叠比例"而不是"完全包含"：页尾块常跨 .dynamic/.dynstr 等多个相邻节。
  const coveredBySection = (off, len) => {
    if (!len) return false;
    let covered = 0;
    for (const [s, e] of secRangesEarly) {
      const lo = Math.max(off, s), hi = Math.min(off + len, e);
      if (hi > lo) covered += hi - lo;
    }
    return covered / len >= 0.5;
  };
  const slackHits = [];
  for (const p of loadSegs) {
    if (!p.filesz) continue;
    const slackStart = p.offset + p.filesz;
    const slackEnd = Math.min(p.offset + Math.ceil(p.filesz / 0x1000) * 0x1000, buf.length);
    if (slackEnd <= slackStart) continue;
    const slack = buf.slice(slackStart, slackEnd);
    // 滑窗找连续数据块：页尾常是「零填充 + 中间夹真数据」，看整段平均会漏判
    const blocks = findDataBlocks(slack).filter((b) => !coveredBySection(slackStart + b.start, b.end - b.start));
    if (blocks.length) {
      slackHits.push({ seg: p, slackStart, slackEnd, blocks });
    }
  }
  if (slackHits.length) {
    findings.push({
      kind: 'segment-slack-data',
      severity: 'high',
      summary: `${slackHits.length} 个 LOAD 段的页尾缝隙里藏有数据块`,
      detail: slackHits.flatMap((h) => h.blocks.map((b) => ({
        fileOffset: '0x' + (h.slackStart + b.start).toString(16),
        vaddr: '0x' + (h.seg.vaddr + h.seg.filesz + b.start).toString(16),
        length: b.end - b.start,
        entropy: b.entropy,
        nonzeroRatio: b.nonzeroRatio,
        note: '该区间不被任何 section 覆盖，但内核按页映射 → 运行期可读（可执行段还可执行）',
      }))),
    });
    lines.push('## 段尾缝隙（segment slack）里的隐藏数据');
    for (const h of slackHits) {
      for (const b of h.blocks) {
        const fo = h.slackStart + b.start;
        lines.push(`- 文件偏移 **0x${fo.toString(16)}** 起 ${b.end - b.start} 字节（熵 ${b.entropy}，非零 ${(b.nonzeroRatio * 100).toFixed(0)}%）`);
        lines.push(`  · 落在 LOAD#${h.seg.index} 的页尾：p_filesz=0x${h.seg.filesz.toString(16)}，页对齐到 0x${(Math.ceil(h.seg.filesz / 0x1000) * 0x1000).toString(16)}`);
        lines.push('  · readelf/objdump 按段/节看会认为这里"没有东西"，但内核对整页都做了映射');
        lines.push(`  · 建议：\`ida_get_bytes\` 按 VA 0x${(h.seg.vaddr + h.seg.filesz + b.start).toString(16)} 读取，或直接对本文件 0x${fo.toString(16)} 切片分析`);
      }
    }
  }

  // ── 2) 段/节覆盖缺口：文件中有大块数据不被任何 section 覆盖 ──
  const secRanges = shdrs.filter((s) => s.type !== 8 /* NOBITS */ && s.size > 0)
    .map((s) => [s.offset, s.offset + s.size]);
  const gaps = [];
  const sorted = secRanges.slice().sort((a, b) => a[0] - b[0]);
  let cursor = 0;
  for (const [s, e] of sorted) {
    if (s > cursor) gaps.push([cursor, Math.min(s, buf.length)]);
    cursor = Math.max(cursor, e);
  }
  if (cursor < buf.length) gaps.push([cursor, buf.length]);
  const bigGaps = [];
  for (const [s, e] of gaps) {
    if (e - s < 0x100) continue;                  // 小于 256 字节的多为对齐填充
    const info = looksLikeData(buf.slice(s, e));
    if (info.dataLike) bigGaps.push({ start: s, end: e, info });
  }
  if (bigGaps.length) {
    findings.push({
      kind: 'uncovered-file-region',
      severity: bigGaps.some((g) => g.end - g.start >= 0x200) ? 'high' : 'medium',
      summary: `${bigGaps.length} 段文件区域不被任何 section 覆盖且含数据`,
      detail: bigGaps.map((g) => ({
        fileOffset: '0x' + g.start.toString(16),
        length: g.end - g.start,
        nonzeroRatio: Number(g.info.ratio.toFixed(3)),
        entropy: g.info.entropy,
      })),
    });
    lines.push('## 未被任何 section 覆盖的数据区');
    for (const g of bigGaps) {
      lines.push(`- 0x${g.start.toString(16)} ~ 0x${g.end.toString(16)}（${g.end - g.start} 字节，熵 ${g.info.entropy}）`);
    }
  }

  // ── 3) 动态表与重定位的一致性 ──
  const dyn = phdrs.find((p) => p.type === PT_DYNAMIC);
  let relacountDyn = 0, relaszDyn = 0, relaOff = -1, jmprelOff = -1, pltrelsz = 0;
  let flagsTextrel = false, bindNow = false, flags1 = 0;
  if (dyn && dyn.offset + dyn.filesz <= buf.length) {
    const ent = eh.is64 ? 16 : 8;
    for (let o = dyn.offset; o + ent <= dyn.offset + dyn.filesz; o += ent) {
      let tag, val;
      if (eh.is64) {
        tag = Number(buf.readBigInt64LE(o));
        val = Number(buf.readBigUInt64LE(o + 8));
      } else {
        tag = buf.readInt32LE(o);
        val = buf.readUInt32LE(o + 4);
      }
      if (tag === DT.NULL) break;
      if (tag === DT.RELASZ) relaszDyn = val;
      if (tag === DT.RELA) relaOff = val;
      if (tag === DT.JMPREL) jmprelOff = val;
      if (tag === DT.PLTRELSZ) pltrelsz = val;
      if (tag === DT.TEXTREL) flagsTextrel = true;
      if (tag === DT.BIND_NOW) bindNow = true;
      if (tag === DT.FLAGS_1) flags1 = val;
      if (tag === DT.FLAGS && (val & 0x4)) flagsTextrel = true;  // DF_TEXTREL
    }
  }

  // 重定位条数对账：RELASZ 应 >= (RELA 段 + JMPREL 段)
  const relaSec = shdrs.find((s) => s.name === '.rela.dyn');
  const pltSec = shdrs.find((s) => s.name === '.rela.plt');
  const nRelaDyn = relaSec ? Math.floor(relaSec.size / (eh.is64 ? 24 : 12)) : 0;
  const nRelaPlt = pltSec ? Math.floor(pltSec.size / (eh.is64 ? 24 : 12)) : 0;
  const nRelasz = relaszDyn > 0 ? Math.floor(relaszDyn / (eh.is64 ? 24 : 12)) : 0;
  if (flagsTextrel) {
    findings.push({
      kind: 'df-textrel',
      severity: 'high',
      summary: '动态表声明 TEXTREL：程序会在运行期对代码段做重定位',
      detail: { note: '正常编译器不会给 .text 生成重定位；TEXTREL 几乎总意味着作者要改写代码（自解密/自修改）' },
    });
    lines.push('## TEXTREL');
    lines.push('- 动态段含 DF_TEXTREL → **运行期会写代码段**。这是一条强线索：去找"哪条重定位落在可执行段"。');
  }
  if (nRelaDyn + nRelaPlt > 0 && nRelasz > 0 && nRelasz !== nRelaDyn + nRelaPlt) {
    findings.push({
      kind: 'rela-count-mismatch',
      severity: nRelasz < nRelaDyn + nRelaPlt ? 'high' : 'medium',
      summary: `RELASZ=${nRelasz} 条，但 .rela.dyn(${nRelaDyn}) + .rela.plt(${nRelaPlt}) = ${nRelaDyn + nRelaPlt} 条`,
      detail: {
        delta: (nRelaDyn + nRelaPlt) - nRelasz,
        note: nRelasz < nRelaDyn + nRelaPlt
          ? 'RELASZ 比两段之和**少**：ld.so 的 RELA 遍历终点被挪动了，末尾若干条 .rela.plt 不会按原表执行'
          : 'RELASZ 比两段之和**多**：遍历会读到表尾之外，那块内存可能是被覆盖进去的隐藏表',
      },
    });
    lines.push('## 重定位条数矛盾');
    lines.push(`- RELASZ=${nRelasz} 条 vs .rela.dyn(${nRelaDyn}) + .rela.plt(${nRelaPlt}) = ${nRelaDyn + nRelaPlt} 条`);
    lines.push(`- 差值 ${(nRelaDyn + nRelaPlt) - nRelasz}：重定位遍历的**终点被人为挪动过**，这是能改写任意表的入口`);
  }

  // ── 4) 逐条检查 .rela.dyn：COPY/RELATIVE 打到可疑目标 ──
  const execRanges = loadSegs.filter((p) => p.flags & PF_X).map((p) => [p.vaddr, p.vaddr + p.memsz]);
  const inExec = (v) => execRanges.some(([s, e]) => v >= s && v < e);
  const secOf = (v) => {
    for (const s of shdrs) if (s.size && v >= s.addr && v < s.addr + s.size) return s.name;
    return null;
  };
  const symTab = shdrs.find((s) => s.name === '.dynsym');
  const symCount = symTab ? Math.floor(symTab.size / (eh.is64 ? 24 : 16)) : 0;
  const symRange = symTab ? [symTab.addr, symTab.addr + symTab.size] : [0, 0];
  const symNames = [];
  if (symTab) {
    const st = shdrs.find((s) => s.name === '.dynstr');
    const strBuf = st ? buf.slice(st.offset, st.offset + st.size) : Buffer.alloc(0);
    const ent = eh.is64 ? 24 : 16;
    for (let i = 0; i < symCount; i++) {
      const o = symTab.offset + i * ent;
      if (o + ent > buf.length) break;
      const nameOff = buf.readUInt32LE(o);
      const info = buf[o + (eh.is64 ? 4 : 12)];
      const shndx = eh.is64 ? buf.readUInt16LE(o + 6) : buf.readUInt16LE(o + 14);
      const value = eh.is64 ? Number(buf.readBigUInt64LE(o + 8)) : buf.readUInt32LE(o + 4);
      const size = eh.is64 ? Number(buf.readBigUInt64LE(o + 16)) : buf.readUInt32LE(o + 8);
      const e2 = strBuf.indexOf(0, nameOff);
      symNames.push({
        idx: i,
        name: strBuf.slice(nameOff, e2 < 0 ? undefined : e2).toString('latin1'),
        type: info & 0xf,
        bind: info >> 4,
        shndx, value, size,
        fieldOffsets: {
          st_info: (eh.is64 ? 4 : 12) + o,
          st_shndx: (eh.is64 ? 6 : 14) + o,
          st_value: (eh.is64 ? 8 : 4) + o,
          st_size: (eh.is64 ? 16 : 8) + o,
        },
      });
    }
  }

  const suspicious = [];
  if (relaOff > 0 && nRelasz > 0) {
    const ent = eh.is64 ? 24 : 12;
    for (let i = 0; i < nRelasz; i++) {
      const o = relaOff + i * ent;
      if (o + ent > buf.length) break;
      let r_offset, r_info, r_addend = 0, sym, type;
      if (eh.is64) {
        r_offset = Number(buf.readBigUInt64LE(o));
        r_info = buf.readBigUInt64LE(o + 8);          // BigInt，必须整体用 BigInt 运算
        r_addend = Number(buf.readBigInt64LE(o + 16));
        sym = Number(r_info >> 32n);
        type = Number(r_info & 0xffffffffn);
      } else {
        r_offset = buf.readUInt32LE(o);
        r_info = buf.readUInt32LE(o + 4);
        r_addend = buf.readInt32LE(o + 8);
        sym = r_info >>> 8;
        type = r_info & 0xff;
      }
      const table = (eh.machine === 243 ? R_RISCV : R_X86_64);
      const typeName = table[type] || ('TYPE_' + type);
      const tgtSec = secOf(r_offset);
      const hitsExec = inExec(r_offset);
      const inSymTab = r_offset >= symRange[0] && r_offset < symRange[1];
      const symRec = symNames[sym];

      let why = null;
      if (type === 5 /* COPY */ && hitsExec) why = 'COPY 重定位直接写可执行段（正常应为 .bss/.data）';
      else if (type === 5 && inSymTab) why = 'COPY 重定位的 r_offset 落在 .dynsym 内部 —— 在用重定位改写符号表项本身';
      else if (type === 8 /* RELATIVE */ && inSymTab) why = 'RELATIVE 重定位的 r_offset 落在 .dynsym 内部 —— 用加载器写符号表字段（可伪造 st_value/st_shndx）';
      else if (DANGEROUS_TEXT_RELOC.has(type) && hitsExec && type !== 8) why = `${typeName} 重定位写可执行段`;
      else if (symRec && (symRec.type === 10 /* IFUNC */) && symRec.shndx === 0xfff1 /* SHN_ABS */) {
        why = `符号 ${symRec.name || ('#' + symRec.idx)} 是 STT_GNU_IFUNC + SHN_ABS：ld.so 会在加载期**直接调用** st_value 处的 resolver`;
      }
      if (why) {
        suspicious.push({
          idx: i,
          r_offset: '0x' + r_offset.toString(16),
          type: typeName,
          sym,
          symName: symRec ? symRec.name : '',
          addend: '0x' + (r_addend >>> 0).toString(16),
          targetSection: tgtSec,
          why,
        });
      }
    }
  }
  if (suspicious.length) {
    findings.push({
      kind: 'suspicious-relocations',
      severity: 'high',
      summary: `${suspicious.length} 条重定位命中"正常编译器不会这么干"的形态`,
      detail: suspicious,
    });
    lines.push('## 可疑重定位');
    for (const s of suspicious) {
      lines.push(`- #${s.idx} ${s.type} r_offset=${s.r_offset} sym=${s.sym}${s.symName ? '(' + s.symName.slice(0, 48) + ')' : ''} addend=${s.addend}`);
      lines.push(`  · ${s.why}`);
      if (s.targetSection) lines.push(`  · 落在 section ${s.targetSection}`);
    }
  }

  // ── 5) IFUNC 符号清单（无论有无可疑重定位都报） ──
  const ifuncs = symNames.filter((s) => s.type === 10);
  if (ifuncs.length) {
    findings.push({
      kind: 'ifunc-symbols',
      severity: 'medium',
      summary: `${ifuncs.length} 个 STT_GNU_IFUNC 符号（ld.so 会在加载期调用其 resolver）`,
      detail: ifuncs.map((s) => ({
        idx: s.idx, name: s.name, st_value: '0x' + s.value.toString(16),
        st_shndx: s.shndx === 0xfff1 ? 'SHN_ABS' : String(s.shndx),
        note: s.shndx === 0xfff1 ? 'SHN_ABS 的 IFUNC 极不寻常（正常 IFUNC 定义在代码段）' : '',
      })),
    });
    lines.push('## STT_GNU_IFUNC 符号');
    for (const s of ifuncs) {
      lines.push(`- #${s.idx} ${s.name || '(无名)'} st_value=0x${s.value.toString(16)} st_shndx=${s.shndx === 0xfff1 ? 'SHN_ABS' : s.shndx}`);
    }
  }

  // ── 6) 入口/可执行段里的"疑似被补丁的空函数"（endbr64; nop×N; ret） ──
  const patches = [];
  for (const p of loadSegs) {
    if (!(p.flags & PF_X)) continue;
    const seg = buf.slice(p.offset, p.offset + p.filesz);
    for (let i = 0; i + 12 <= seg.length; i++) {
      if (seg[i] === 0xf3 && seg[i + 1] === 0x0f && seg[i + 2] === 0x1e && seg[i + 3] === 0xfa) {
        let j = i + 4;
        let nops = 0;
        while (j < seg.length && seg[j] === 0x90) { j++; nops++; }
        if (nops >= 6 && j < seg.length && seg[j] === 0xc3) {
          patches.push({
            fileOffset: '0x' + (p.offset + i).toString(16),
            vaddr: '0x' + (p.vaddr + i).toString(16),
            pattern: `endbr64 + ${nops}×nop + ret`,
            note: '看起来是"被掏空"的函数；若它被调用，可能有人打算在运行期把 nop 区改成跳板',
          });
        }
      }
    }
  }
  if (patches.length) {
    findings.push({
      kind: 'hollow-functions',
      severity: 'medium',
      summary: `${patches.length} 处 endbr64+nop×N+ret 的空函数`,
      detail: patches.slice(0, 10),
    });
    lines.push('## 疑似"被掏空"的函数');
    for (const q of patches.slice(0, 10)) {
      lines.push(`- ${q.vaddr}（文件 0x${q.fileOffset.slice(2)}）${q.pattern}`);
    }
  }

  // ── 7) 重定位的 addend 指向"未被任何 section 覆盖"的地址 ──
  // elfstudy 的链条正是靠这个起手：一条 RELATIVE 把某符号的 st_value 写成
  // base+0x1d30，而 0x1d30 正是隐藏的假符号定义块；随后 COPY 从 0x1988 拷隐藏表。
  // 正常 ELF 的 addend 指向的是 .data/.rodata 里的符号，绝不会指向段尾缝隙。
  const uncoveredHits = [];
  if (relaOff > 0 && nRelasz > 0) {
    const ent2 = eh.is64 ? 24 : 12;
    for (let i = 0; i < nRelasz; i++) {
      const o = relaOff + i * ent2;
      if (o + ent2 > buf.length) break;
      // ⚠️ 只有 RELATIVE(8) 的 addend 才当"文件偏移/base-relative 地址"看。
      // PC32(2)/PLT32(4)/GOTPCREL(9) 等类型的 addend 是**指令内的位移常量**
      // （常见值 0x10/0x18/0x4），按文件偏移解释会产生大量误报（实测 #7/#8）。
      let rtype, rinfo;
      if (eh.is64) {
        rinfo = buf.readBigUInt64LE(o + 8);
        rtype = Number(rinfo & 0xffffffffn);
      } else {
        rtype = buf.readUInt32LE(o + 4) & 0xff;
      }
      if (rtype !== 8 && rtype !== 5) continue;
      const add = eh.is64 ? Number(buf.readBigInt64LE(o + 16)) : buf.readInt32LE(o + 8);
      if (add <= 0 || add >= buf.length) continue;
      if (coveredBySection(add, 16)) continue;
      const peek = buf.slice(add, add + 16);
      // ⚠️ 这里**不能**用 looksLikeData（熵/非零比）：elfstudy 的 0x1d30 是个 14 字节的
      // 结构化符号定义块（00 00 01 00 88 19 00 00 ...），熵只有 0.577，含大量零
      // 会被误判成"不是数据"。判据改为「该处 16 字节不全是 0」——未被任何 section
      // 覆盖且非零，本身就已经很可疑了。
      if (peek.every((b) => b === 0)) continue;
      uncoveredHits.push({
        relaIndex: i,
        type: rtype === 8 ? 'RELATIVE' : 'COPY',
        addend: '0x' + add.toString(16),
        peekHex: peek.toString('hex'),
        note: '该重定位的 addend 指向文件里一段**不被任何 section 覆盖**的非零数据'
              + '（正常应为 .data/.rodata 中的真实符号）；很可能是被引用进来的隐藏块',
      });
    }
  }
  if (uncoveredHits.length) {
    findings.push({
      kind: 'reloc-addend-to-uncovered',
      severity: 'high',
      summary: `${uncoveredHits.length} 条重定位的 addend 指向未被 section 覆盖的数据区`,
      detail: uncoveredHits,
    });
    lines.push('## 重定位 addend 指向隐藏数据');
    for (const h of uncoveredHits) {
      lines.push(`- .rela #${h.relaIndex} addend=${h.addend}，该处首 16 字节 \`${h.peekHex}\``);
      lines.push(`  · ${h.note}`);
    }
  }

  return {
    ok: true,
    arch: eh.machine === 62 ? 'x86-64' : (eh.machine === 243 ? 'riscv' : ('machine' + eh.machine)),
    is64: eh.is64,
    elfType: eh.type === 3 ? 'DYN(PIE)' : (eh.type === 2 ? 'EXEC' : 'type' + eh.type),
    entry: '0x' + eh.e_entry.toString(16),
    flags: { TEXTREL: flagsTextrel, BIND_NOW: bindNow, FLAGS_1: '0x' + flags1.toString(16) },
    relacount: { relasz: nRelasz, relaDyn: nRelaDyn, relaPlt: nRelaPlt },
    findings,
    text: lines.length ? lines.join('\n') : '',
  };
}

module.exports = { analyzeElfAnomalies, entropy, looksLikeData, findDataBlocks, readEhdr, readPhdrs, readShdrs };
