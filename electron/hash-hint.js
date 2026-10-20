'use strict';
// MD5 摘要目标的"存在性"闸门（纯函数）。
//
// 为什么需要：当文件里根本没有 32 位 hex 摘要目标时，让 AI 去"MD5(候选)==目标"爆破
// 是纯浪费预算——MD5 更可能用于 KDF/掩码派生。判据必须校准过：
//   · 旧的 looksHighEntropy（零占比+重复率）在真样本上命中上万次，无法作为"目标存在"证据；
//   · 改用 16 字节对齐窗口 + Shannon>=7.5，并排除 .rsrc/.reloc 与非可执行节。
//
// 只做"目标存在性"，不臆测 flag 形态（不把所有 32-hex 一律当摘要目标）。

function shannonEntropy(buf) {
  if (!buf || !buf.length) return 0;
  const cnt = new Array(256).fill(0);
  for (const b of buf) cnt[b]++;
  let h = 0;
  for (const c of cnt) {
    if (!c) continue;
    const p = c / buf.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// 非可执行、且不是资源/重定位节的文件区间。
// PE：section.va 是 RVA，文件偏移用 rawPtr/rawSize；ELF：rawPtr 是 p_offset。
function scanRegions(buf, imageMap) {
  const out = [];
  if (!imageMap || !Array.isArray(imageMap.sections) || !imageMap.sections.length) {
    // 无节表信息时退化为全文件（调用方已明确只要"存在性"）
    out.push({ start: 0, end: buf.length, name: '(whole)' });
    return out;
  }
  for (const s of imageMap.sections) {
    const name = String(s.name || '');
    if (imageMap.format === 'pe') {
      if (s.executable === true) continue;
      if (/^\.(rsrc|reloc)$/i.test(name)) continue;
      const start = Number(s.rawPtr);
      const size = Number(s.rawSize);
      if (!Number.isFinite(start) || !Number.isFinite(size) || size <= 0) continue;
      out.push({ start, end: Math.min(start + size, buf.length), name });
    } else if (imageMap.format === 'elf') {
      if (s.executable === true) continue;
      const start = Number(s.rawPtr);
      const size = Number(s.fileSize != null ? s.fileSize : s.rawSize);
      if (!Number.isFinite(start) || !Number.isFinite(size) || size <= 0) continue;
      out.push({ start, end: Math.min(start + size, buf.length), name });
    }
  }
  return out;
}

// 全文件 ASCII 32 位 hex 字面量（前后不能紧邻字母数字，避免把 64-hex 切成两段）
function countHexLiterals(buf) {
  const s = buf.toString('latin1');
  const re = /(^|[^0-9A-Za-z])([0-9a-fA-F]{32})(?![0-9A-Za-z])/g;
  let n = 0, m;
  while ((m = re.exec(s)) !== null) {
    n++;
    re.lastIndex = m.index + m[0].length;
  }
  return n;
}

function assessHashTarget(buf, imageMap) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || '');
  const hexLiterals = countHexLiterals(b);

  let highEntropy16 = 0;
  const regions = scanRegions(b, imageMap);
  // 按 16 字节对齐扫描。窗口取 min(256, 区域长度)：
  //   · Shannon 熵的上限是 log2(窗口字节数)——16 字节窗口最大只有 4 bit，
  //     "entropy>=7.5" 在 16 字节窗口上恒不成立；7.5 只在 >=256 字节窗口有区分力。
  //   · 区域本身不足 128 字节时（例如单独存放的 16 字节密钥/摘要），改用
  //     "无零字节 + 16 字节互不相同" 等价判据（随机数据的整块熵接近上限）。
  for (const r of regions) {
    const regionLen = r.end - r.start;
    if (regionLen < 16) continue;
    const W = Math.min(256, regionLen);
    for (let off = r.start; off + W <= r.end; off += 16) {
      const win = b.slice(off, off + W);
      if (W >= 128) {
        if (shannonEntropy(win) >= 7.5) highEntropy16++;
      } else {
        const seen = new Set();
        let zeros = 0;
        for (const x of win) { if (x === 0) zeros++; seen.add(x); }
        if (zeros === 0 && seen.size === win.length) highEntropy16++;
      }
    }
  }

  const hasTarget = hexLiterals > 0 || highEntropy16 > 0;
  return { hexLiterals, highEntropy16, hasTarget };
}

function buildMd5Note(assessment, callSites) {
  const a = assessment || {};
  if (a.hasTarget) {
    return '确认是本层内联的 MD5。哈希不可逆：按 `MD5(候选)==目标` 爆破（字典/规则/长度扩展）；'
      + '若被截断比较，比对长度与比较点。';
  }
  const sites = (callSites || []).length
    ? `\n工具从反编译中抽到的摘要调用点与长度实参：\n` + callSites.map(s => '  · ' + s).join('\n')
    : '';
  return '文件内无 32 位 hex 摘要目标 → MD5 可能用于 KDF/掩码派生，不要做 MD5(候选) == 目标 的爆破。'
    + '优先在反编译里确认 MD5 的输出被谁消费（取字节/取低 32 位/异或进掩码），再决定构造什么。'
    + sites;
}

// 从反编译文本抽 MD5_Update/MD5_Final 邻近行（含长度实参）。
// 输入可以是单个字符串或字符串数组；输出带上下文行，便于 AI 直接判断长度/掩码。
function extractDigestCallSites(decompileTexts) {
  const texts = Array.isArray(decompileTexts) ? decompileTexts : [decompileTexts];
  const out = [];
  const seen = new Set();
  for (const t of texts) {
    const lines = String(t == null ? '' : t).split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      if (!/(MD5_?Update|MD5_?Final|md5_update|md5_final|sub_4016B0)/i.test(lines[i])) continue;
      const ctx = lines.slice(Math.max(0, i - 1), Math.min(lines.length, i + 2))
        .map(s => s.trim()).filter(Boolean).join(' || ');
      if (!ctx || seen.has(ctx)) continue;
      seen.add(ctx);
      out.push(ctx);
      if (out.length >= 8) return out;
    }
  }
  return out;
}

module.exports = { assessHashTarget, buildMd5Note, extractDigestCallSites, shannonEntropy };
