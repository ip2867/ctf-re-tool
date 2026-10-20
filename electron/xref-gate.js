'use strict';
// 指纹表的 xref 闸门（纯函数）。
//
// 目的：scanCryptoFingerprints 找到的表不一定被代码引用（可能是库数据/无关常量）。
// 但"没找到引用"≠"没被引用"：
//   · 32 位 PE 里表地址常以绝对 imm32 出现，可以直接搜；
//   · x64 PE / ELF 用 RIP-relative，绝对地址为 0 次，按绝对搜索会造成**假阴性**
//     （把真实算法表降级）——比假阳性更糟。
// 因此三种结论：
//   referenced   → 保留
//   unreferenced → 降级（仅 32 位 PE 的绝对搜索为零、且 IDA 未连接时才能断言）
//   unverified   → 保留原置信度，只标注"xref 未验证"
//
// 负面断言反证只接受 referenced 证据。

function toBuf(b) {
  return Buffer.isBuffer(b) ? b : Buffer.from(b || []);
}

// 代码节/段（X 且 !W）。附带 fileOff→VA 换算参数：
// RIP-relative 的位移是相对**指令的虚拟地址**，而扫描拿到的是文件偏移，
// 两者差一个节基准（rawPtr ↔ va / p_offset ↔ p_vaddr）。
function codeRegions(img) {
  const out = [];
  const push = (s, start, size) => {
    if (!(Number.isFinite(start) && Number.isFinite(size) && size > 0)) return;
    const secVa = Number(s.va) + (img.vaIsAbsolute ? 0 : (Number(img.imageBase) || 0));
    const delta = Number.isFinite(secVa) ? secVa - start : 0;
    out.push({ start, end: start + size, vaDelta: delta });
  };
  for (const s of ((img && img.sections) || [])) {
    if (img.format === 'pe') {
      if (s.executable !== true || s.writable === true) continue;
      push(s, Number(s.rawPtr), Number(s.rawSize));
    } else if (img.format === 'elf') {
      if (s.executable !== true || s.writable === true) continue;
      push(s, Number(s.rawPtr), Number(s.fileSize != null ? s.fileSize : s.rawSize));
    }
  }
  return out;
}

function parseVa(v) {
  if (typeof v === 'number') return v;
  const s = String(v == null ? '' : v).trim();
  if (!/^(0x)?[0-9a-fA-F]+$/.test(s)) return NaN;
  return parseInt(s.replace(/^0x/i, ''), 16);
}

// idaXrefs: [{addr, xrefs:[...]}] 或 {[addr]:[...]} —— 有结果就以 code xref 为准
function idaXrefCountFor(idaXrefs, tableVa) {
  if (!idaXrefs) return null;
  const want = Number(tableVa);
  if (!Number.isFinite(want)) return null;
  if (Array.isArray(idaXrefs)) {
    for (const item of idaXrefs) {
      const a = parseVa(item && (item.addr != null ? item.addr : item.address));
      if (a === want) {
        const xs = Array.isArray(item.xrefs) ? item.xrefs : [];
        return xs.length;
      }
    }
    return 0;
  }
  if (typeof idaXrefs === 'object') {
    for (const k of Object.keys(idaXrefs)) {
      if (parseVa(k) === want) {
        const v = idaXrefs[k];
        return Array.isArray(v) ? v.length : Number(v) || 0;
      }
    }
    return 0;
  }
  return null;
}

// 32 位 PE：在代码节里搜 LE32(tableVa)
function countImm32Refs(buf, img, va) {
  let n = 0;
  const needle = Buffer.alloc(4);
  needle.writeUInt32LE(va >>> 0, 0);
  for (const r of codeRegions(img)) {
    const end = Math.min(r.end, buf.length);
    for (let off = r.start; off + 4 <= end; off++) {
      if (buf[off] === needle[0] && buf[off + 1] === needle[1]
        && buf[off + 2] === needle[2] && buf[off + 3] === needle[3]) n++;
    }
  }
  return n;
}

// x64：解析 RIP-relative（48 8D 05/0D/15/1D/25/2D/35/3D + rel32）与 FF 15
function countRipRelativeRefs(buf, img, va) {
  let n = 0;
  const mods = [0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d];
  for (const r of codeRegions(img)) {
    const end = Math.min(r.end, buf.length);
    for (let off = r.start; off + 7 <= end; off++) {
      if (buf[off] === 0x48 && buf[off + 1] === 0x8d && mods.includes(buf[off + 2])) {
        const rel = buf.readInt32LE(off + 3);
        // 指令末的虚拟地址 = 文件偏移 + 节基准 + 7
        const target = ((off + r.vaDelta + 7 + rel) >>> 0);
        if (target === (va >>> 0)) n++;
      } else if (buf[off] === 0xff && buf[off + 1] === 0x15) {
        const rel = buf.readInt32LE(off + 2);
        const target = ((off + r.vaDelta + 6 + rel) >>> 0);
        if (target === (va >>> 0)) n++;
      }
    }
  }
  return n;
}

// 返回 {status:'referenced'|'unreferenced'|'unverified', refs, evidence, log}
function assessTableRefs(input) {
  const i = input || {};
  const buf = toBuf(i.buf);
  const img = i.imageMap || null;
  const va = parseVa(i.tableVa);
  const algo = String(i.algo || 'table');

  if (!Number.isFinite(va) || !img || !img.sections || !img.sections.length) {
    return {
      status: 'unverified', refs: 0,
      evidence: `${algo} 表 0x${Number.isFinite(va) ? va.toString(16) : '?'} 无节表/地址信息，xref 未验证`,
      log: `[指纹闸] ${algo} xref 未验证`,
    };
  }

  // ① IDA 已连接且拿到 xrefs_to 结果 → 直接以它为准
  const idaCount = idaXrefCountFor(i.idaXrefs, va);
  if (idaCount != null) {
    if (idaCount > 0) {
      return {
        status: 'referenced', refs: idaCount,
        evidence: `${algo} 表 0x${va.toString(16)} 被代码引用 ${idaCount} 次（IDA xrefs_to）`,
        log: `[指纹闸] ${algo} 已被引用（${idaCount} 处）`,
      };
    }
    return {
      status: 'unreferenced', refs: 0,
      evidence: `${algo} 表 0x${va.toString(16)} 在 IDA 中无代码 xref → 可能是未引用/库数据`,
      log: `[指纹闸] ${algo} 表未引用 → 降级`,
    };
  }

  // ② 未连接 IDA
  if (img.format === 'pe' && Number(img.bits) === 32) {
    const n = countImm32Refs(buf, img, va);
    if (n > 0) {
      return {
        status: 'referenced', refs: n,
        evidence: `${algo} 表 0x${va.toString(16)} 在代码节以绝对地址被引用 ${n} 次`,
        log: `[指纹闸] ${algo} 已被引用（${n} 处 imm32）`,
      };
    }
    return {
      status: 'unreferenced', refs: 0,
      evidence: `${algo} 表 0x${va.toString(16)} 在代码节无绝对引用 → 可能是未引用/库数据`,
      log: `[指纹闸] ${algo} 表未引用 → 降级`,
    };
  }

  // ③ x64 PE / ELF：RIP-relative
  const n = countRipRelativeRefs(buf, img, va);
  if (n > 0) {
    return {
      status: 'referenced', refs: n,
      evidence: `${algo} 表 0x${va.toString(16)} 被 RIP-relative 指令引用 ${n} 次`,
      log: `[指纹闸] ${algo} 已被引用（${n} 处 rip-rel）`,
    };
  }
  return {
    status: 'unverified', refs: 0,
    evidence: `${algo} 表 0x${va.toString(16)} 未解析到引用（x64/ELF 用 RIP-relative，绝对搜索不适用）`,
    log: `[指纹闸] ${algo} xref 未验证 → 保留`,
  };
}

// 负面断言反证只接受 referenced 证据
function isRefutedByRefs(entry) {
  return !!entry && entry.status === 'referenced';
}

module.exports = { assessTableRefs, isRefutedByRefs, countImm32Refs, countRipRelativeRefs };
