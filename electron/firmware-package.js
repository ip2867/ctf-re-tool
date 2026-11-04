'use strict';
// 固件 / OTA 包的结构解包与材料提取（纯函数）。
//
// 为什么需要（实测 qwb2026_firmware）：题目的信任链是「主机验证器 fw_a + 目标固件
// fw_b.bin + OTA 升级包」，flag 藏在 OTA 包尾、用派生密钥加密。工具原本没有
// 任何「OTA 包结构」概念，AI 只能靠肉眼数偏移。
//
// 本模块**不绑定某个厂商格式**，而是做两件事：
//   1) 通用分诊：识别魔数、版本、描述符表、摘要区、尾部标记块
//   2) 结构化解包：按描述符把分散的片段拼回连续镜像（多段 OTA 的常见形态），
//      并对拼回的镜像做完整性校验（若头部有摘要）
//
// 判据全部来自"数据自身的一致性"（魔数 + 长度自洽 + 摘要匹配），不猜语义。

const crypto = require('crypto');

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest(); }

// ── 常见固件/OTA 魔数 ──
const MAGICS = [
  { magic: Buffer.from('QWBP', 'latin1'), name: 'QWBP', note: '题目自定义 OTA 容器' },
  { magic: Buffer.from('QWBPFLAG', 'latin1'), name: 'QWBPFLAG', note: '题目自定义 flag 段标记' },
  { magic: Buffer.from('ANDROID!', 'latin1'), name: 'ANDROID!', note: 'Android boot image' },
  { magic: Buffer.from('hsqs', 'latin1'), name: 'squashfs', note: 'SquashFS (LE)' },
  { magic: Buffer.from('sqsh', 'latin1'), name: 'squashfs-be', note: 'SquashFS (BE)' },
  { magic: Buffer.from('UBI#', 'latin1'), name: 'UBI', note: 'UBIFS' },
  { magic: Buffer.from('_CPI', 'latin1'), name: 'CPIO', note: 'initramfs (newc)' },
  { magic: Buffer.from('27051956', 'hex'), name: 'uImage', note: 'U-Boot legacy' },
  { magic: Buffer.from('d00dfeed', 'hex'), name: 'FDT/DTB', note: '设备树 blob' },
  { magic: Buffer.from('0f0d0d0a', 'hex'), name: 'TRX', note: 'Broadcom/Netgear TRX' },
  { magic: Buffer.from('CSYS', 'latin1'), name: 'CSYS', note: 'Cisco' },
  { magic: Buffer.from('\x1f\x8b', 'latin1'), name: 'gzip', note: 'gzip 压缩' },
  { magic: Buffer.from('BZh', 'latin1'), name: 'bzip2', note: '' },
  { magic: Buffer.from('FD7zXZ', 'latin1'), name: 'xz', note: '' },
  { magic: Buffer.from('PK\x03\x04', 'latin1'), name: 'zip', note: 'ZIP 容器' },
];

/**
 * 通用分诊：找出所有已知魔数的出现位置。
 * 注意：只报**文件内实际出现**的，不猜。
 */
function findMagics(buf) {
  const hits = [];
  for (const m of MAGICS) {
    let from = 0, at;
    while ((at = buf.indexOf(m.magic, from)) !== -1) {
      hits.push({ offset: at, name: m.name, note: m.note });
      from = at + 1;
      if (hits.length > 200) return hits;
    }
  }
  return hits.sort((a, b) => a.offset - b.offset);
}

// ── 通用"描述符表"探测 ──
// 判据：从某个起点开始，若干个连续的 u32 字段组满足
//   · 前两个 u32 是 (off, len)：0 < off < fileSize 且 len > 0 且 off+len <= fileSize
//   · 至少 2 组
//
// ⚠️ **步长不能只试 8**（实测踩过）：qwb2026 的 OTA 是 `(off, len, crc)` 三元组，
// 步长 **12 字节**。只试 8 会完全检不出描述符表，进而漏掉整个多段结构。
// 常见步长：8（off,len）/ 12（off,len,crc32）/ 16（off,len,crc,flags）/ 20 / 24（含 16B 摘要）。
const DESC_STRIDES = [8, 12, 16, 20, 24, 32];

/**
 * 评估一个候选：越多的段"首尾相接"（off[i] == off[i-1]+len[i-1]）越可信，
 * 因为多段 OTA 通常把镜像连续切分后分散存放。
 * 若候选里带 crc 字段且能与段内容的 CRC32 对上，额外加分。
 */
function scoreDescriptor(cand, buf, stride) {
  let contiguous = 0;
  for (let i = 1; i < cand.entries.length; i++) {
    const prev = cand.entries[i - 1];
    if (cand.entries[i].off === prev.off + prev.len) contiguous++;
  }
  let crcHits = 0;
  if (stride >= 12) {
    for (const e of cand.entries) {
      if (e.crc == null) continue;
      const seg = buf.slice(e.off, e.off + e.len);
      if ((crc32(seg) >>> 0) === (e.crc >>> 0)) crcHits++;
    }
  }
  cand.contiguous = contiguous;
  cand.crcHits = crcHits;
  cand.score = contiguous * 10 + crcHits * 20 + cand.entries.length;
  return cand;
}

/** 标准 CRC32（IEEE 802.3，与 zlib 一致） */
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function findDescriptorTable(buf, opts) {
  const o = opts || {};
  const maxDesc = o.maxDesc || 16;
  const strides = o.strides || DESC_STRIDES;
  const results = [];
  for (const stride of strides) {
    const pairsPerEntry = Math.floor(stride / 4);
    if (pairsPerEntry < 2) continue;
    for (let start = 0; start + stride * 2 <= buf.length; start += 4) {
      for (let n = 2; n <= maxDesc; n++) {
        let ok = true;
        const descs = [];
        for (let i = 0; i < n; i++) {
          const base = start + i * stride;
          if (base + stride > buf.length) { ok = false; break; }
          const off = buf.readUInt32LE(base);
          const len = buf.readUInt32LE(base + 4);
          if (!(off > 0 && off < buf.length && len > 0 && off + len <= buf.length)) { ok = false; break; }
          const e = { off, len };
          if (pairsPerEntry >= 3) e.crc = buf.readUInt32LE(base + 8);
          descs.push(e);
        }
        if (!ok) continue;
        const total = descs.reduce((s, d) => s + d.len, 0);
        if (total >= buf.length) continue;          // 拒绝"整段就是文件本身"
        results.push({ tableOffset: start, count: n, stride, entries: descs, totalLen: total });
      }
    }
  }
  // 按可信度排序：段首尾相接 + CRC 命中 > 段数 > 起止位置
  for (const r of results) scoreDescriptor(r, buf, r.stride);
  results.sort((a, b) => (b.score - a.score) || (b.count - a.count) || (a.tableOffset - b.tableOffset));
  return results.slice(0, 3);
}

/**
 * 按描述符把分散片段拼回连续镜像（多段 OTA 的标准形态）。
 * @returns {Buffer}
 */
function assembleByDescriptors(buf, descs) {
  const parts = [];
  for (const d of descs) parts.push(buf.slice(d.off, d.off + d.len));
  return Buffer.concat(parts);
}

/**
 * OTA / 固件包结构化解包。
 *
 * @param {Buffer} buf
 * @returns {object}
 */
function analyzePackage(buf) {
  const out = {
    ok: true,
    size: buf.length,
    magics: findMagics(buf),
    descriptors: [],
    segments: [],
    trailers: [],
    notes: [],
  };
  const lines = [];

  lines.push(`## 包结构（${buf.length} 字节）`);
  if (out.magics.length) {
    lines.push('- 魔数命中：');
    for (const m of out.magics.slice(0, 12)) {
      lines.push(`  · 0x${m.offset.toString(16)} **${m.name}**${m.note ? '（' + m.note + '）' : ''}`);
    }
  } else {
    lines.push('- 未命中已知固件/OTA 魔数（可能是自定义格式或裸数据）');
  }

  // ── 描述符表 ──
  const tables = findDescriptorTable(buf);
  if (tables.length) {
    const best = tables[0];
    out.descriptors = best.entries;
    out.descriptorStride = best.stride;
    lines.push('');
    lines.push(`## 描述符表 @0x${best.tableOffset.toString(16)}（${best.count} 段，步长 ${best.stride} 字节）`);
    for (let i = 0; i < best.entries.length; i++) {
      const e = best.entries[i];
      // CRC 字段若存在，说明它是校验和；标出「校验的是明文还是密文」
      let crcNote = '';
      if (e.crc != null) {
        const seg = buf.slice(e.off, e.off + e.len);
        const ok = (crc32(seg) >>> 0) === (e.crc >>> 0);
        crcNote = ok
          ? `，CRC32=0x${e.crc.toString(16).padStart(8, '0')} ✓ 与**当前段内容**匹配`
          : `，CRC32=0x${e.crc.toString(16).padStart(8, '0')} ✗ 与当前段内容不匹配`
            + `（可能校验的是**解密后的明文**，或算法不是标准 CRC32）`;
      }
      lines.push(`- #${i} 源偏移 0x${e.off.toString(16)} 长度 ${e.len}（0x${e.len.toString(16)}）`
        + ` → 结束 0x${(e.off + e.len).toString(16)}${crcNote}`);
    }
    // 段间是否首尾相接
    if (best.contiguous != null) {
      lines.push(`- 相邻段连续性：${best.contiguous}/${best.count - 1} 处首尾相接`
        + (best.contiguous === best.count - 1 ? '（镜像被连续切分后分散存放）' : ''));
    }
    if (best.crcHits > 0) {
      lines.push(`- **${best.crcHits} 个段的 CRC 与字段一致** → 描述符解读正确`);
    } else if (best.stride >= 12 && best.entries.some((e) => e.crc != null)) {
      lines.push('- ⚠️ 所有 CRC 都对不上当前段内容 → 该段很可能**是密文**，'
        + 'CRC 校验的是解密后的明文（实测 qwb2026 即此形态，说明解密在验证方内部完成）');
    }
    // 拼回
    const asm = assembleByDescriptors(buf, best.entries);
    out.segments.push({ from: best.tableOffset, assembledLength: asm.length, hex: asm.slice(0, 64).toString('hex') });
    lines.push(`- **按描述符拼回的镜像**：${asm.length} 字节，首 64 字节 \`${asm.slice(0, 64).toString('hex')}\``);
    lines.push('  · 注意：多段 OTA 的片段在文件里不连续，**直接对原始字节做哈希会得到错误结果**；必须先拼。');
    out.assembled = asm;
  }

  // ── 尾部标记块 ──
  // 形态：<8 字节标记><u32 LE 长度><密文>
  const MARKER_RE = /[A-Z][A-Z0-9_]{6,15}/g;
  const text = buf.toString('latin1');
  let m;
  while ((m = MARKER_RE.exec(text)) !== null) {
    const at = m.index;
    if (at + 8 + 4 > buf.length) continue;
    const len = buf.readUInt32LE(at + 8);
    if (!(len > 0 && len <= 4096)) continue;
    if (at + 12 + len > buf.length) continue;
    const body = buf.slice(at + 12, at + 12 + len);
    out.trailers.push({
      marker: m[0], offset: at, length: len,
      bodyOffset: at + 12,
      bodyHex: body.slice(0, 64).toString('hex'),
      bodyEntropy: entropy(body),
    });
  }
  if (out.trailers.length) {
    lines.push('');
    lines.push('## 尾部标记块（形如 `<标记><u32 LE 长度><数据>`）');
    for (const t of out.trailers) {
      lines.push(`- **${t.marker}** @0x${t.offset.toString(16)}，长度 ${t.length}，数据 @0x${t.bodyOffset.toString(16)}（熵 ${t.bodyEntropy}）`);
      lines.push(`  · 首 64 字节 \`${t.bodyHex}\``);
      if (t.bodyEntropy > 6.5) lines.push('  · 熵高 → 极可能是**加密/压缩**的数据，不是明文');
    }
  }

  // ── 摘要区探测：找形如"某段数据的 SHA256/SM3 == 头部某 32 字节"的关系 ──
  const digests = findDigestMatches(buf, out.assembled);
  if (digests.length) {
    out.digests = digests;
    lines.push('');
    lines.push('## 摘要校验（自动匹配）');
    for (const d of digests) {
      lines.push(`- 0x${d.digestOffset.toString(16)} 处 32 字节 == **${d.algo}**(0x${d.dataOffset.toString(16)} 起 ${d.dataLen} 字节) ✓`);
      lines.push(`  · 这把"哪些数据属于被保护的部分"钉死了`);
    }
  }

  return { ...out, text: lines.join('\n') };
}

function entropy(buf) {
  if (!buf.length) return 0;
  const cnt = new Array(256).fill(0);
  for (const b of buf) cnt[b]++;
  let h = 0;
  for (const c of cnt) { if (c) { const p = c / buf.length; h -= p * Math.log2(p); } }
  return Number(h.toFixed(3));
}

/**
 * 找"文件里某 32 字节 == 某段数据的 SHA256 或 SM3"。
 * 这是判定"被保护区域"最硬的证据：摘要对上了，说明这段数据就是作者要护住的东西。
 */
function findDigestMatches(buf, assembled) {
  const out = [];
  const candidates = [];
  if (assembled && assembled.length) candidates.push({ name: 'assembled', data: assembled, offset: -1 });
  // 也试"从文件某处到某处"的常见区间
  for (const [s, e, name] of [[0, buf.length, 'whole-file']]) {
    if (e - s > 0) candidates.push({ name, data: buf.slice(s, e), offset: s });
  }
  // 试所有 32 字节窗口作"数据段"太慢；改为：对每个候选数据段算摘要，再在文件里搜
  for (const c of candidates) {
    const h256 = sha256(c.data);
    const at = buf.indexOf(h256);
    if (at >= 0) out.push({ algo: 'SHA256', digestOffset: at, dataOffset: c.offset < 0 ? '(拼装镜像)' : c.offset, dataLen: c.data.length });
  }
  // SM3：用 python 算（node 无内置）
  try {
    const { execFileSync } = require('child_process');
    for (const c of candidates) {
      const b64 = c.data.toString('base64');
      const py = `import sys,hashlib,base64,json
try:
    d = hashlib.new("sm3", base64.b64decode("${b64}")).digest()
    print(d.hex())
except Exception as e:
    print("")
`;
      const hex = execFileSync('python', ['-I', '-c', py], { encoding: 'utf8', timeout: 60000 }).trim();
      if (!hex) continue;
      const at = buf.indexOf(Buffer.from(hex, 'hex'));
      if (at >= 0) out.push({ algo: 'SM3', digestOffset: at, dataOffset: c.offset < 0 ? '(拼装镜像)' : c.offset, dataLen: c.data.length });
    }
  } catch (e) { /* python/sm3 不可用则跳过 */ }
  return out;
}

module.exports = { analyzePackage, findMagics, findDescriptorTable, assembleByDescriptors, entropy, findDigestMatches, crc32, MAGICS };
