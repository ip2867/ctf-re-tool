'use strict';
// 自修改代码（SMC）特征判定（纯函数，零 Electron 依赖）。
//
// 目的不是"要不要动态调试"，而是"有没有值得走动态的客观信号"：
//   · W+X 节 / 可写代码段（PE 0x80000000|0x20000000；ELF PF_W|PF_X）
//   · 文本节本身可写
//   · 反调试/内存改写的导入（VirtualProtect/VirtualAlloc/WriteProcessMemory/
//     FlushInstructionCache/IsDebuggerPresent/CheckRemoteDebuggerPresent/OutputDebugString）
//
// ⚠️ W+X ≠ 必须动态调试：CrackMe2 有一个 .WProtec(W,X) 节，但算法是静态可判的 MD5。
// 因此输出是"特征"，不是"结论"；提示词必须给双向出口（先静态/离线，再动态）。

const API_CANDIDATES = [
  'VirtualProtect', 'VirtualAlloc', 'VirtualAllocEx', 'WriteProcessMemory',
  'FlushInstructionCache', 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
  'OutputDebugStringA', 'OutputDebugStringW', 'OutputDebugString',
];

// 最小 PE 导入目录解析：DataDirectory[1] → IMAGE_IMPORT_DESCRIPTOR →
// OriginalFirstThunk/FirstThunk → IMAGE_IMPORT_BY_NAME。只取名字，不解析绑定。
function parsePEImports(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || []);
  const names = [];
  if (b.length < 0x40 || b[0] !== 0x4d || b[1] !== 0x5a) return names;
  try {
    const peOff = b.readUInt32LE(0x3c);
    if (peOff <= 0 || peOff + 24 > b.length) return names;
    if (b.readUInt32LE(peOff) !== 0x00004550) return names;
    const coffOff = peOff + 4;
    const numberOfSections = b.readUInt16LE(coffOff + 2);
    const optSize = b.readUInt16LE(coffOff + 16);
    const optOff = coffOff + 20;
    if (optOff + 2 > b.length) return names;
    const magic = b.readUInt16LE(optOff);
    const is64 = magic === 0x20b;
    if (!is64 && magic !== 0x10b) return names;
    // DataDirectory 起点：PE32 +96，PE32+ +112；导入表是第 2 项（index 1）
    const ddOff = optOff + (is64 ? 112 : 96);
    if (ddOff + 8 * 2 > b.length) return names;
    const impRva = b.readUInt32LE(ddOff + 8);
    if (!impRva) return names;

    // RVA -> 文件偏移：查节表
    const secOff = optOff + optSize;
    const rvaToOff = (rva) => {
      for (let i = 0; i < numberOfSections; i++) {
        const o = secOff + i * 40;
        if (o + 40 > b.length) break;
        const va = b.readUInt32LE(o + 12);
        const rawSize = b.readUInt32LE(o + 16);
        const rawPtr = b.readUInt32LE(o + 20);
        if (rva >= va && rva < va + Math.max(rawSize, 1)) return rawPtr + (rva - va);
      }
      return -1;
    };

    let descOff = rvaToOff(impRva);
    if (descOff < 0) return names;
    const thunkSize = is64 ? 8 : 4;
    for (let d = 0; d < 128; d++) {
      const o = descOff + d * 20;
      if (o + 20 > b.length) break;
      const oft = b.readUInt32LE(o);
      const ft = b.readUInt32LE(o + 16);
      const nameRva = b.readUInt32LE(o + 12);
      if (!oft && !ft && !nameRva) break;
      let thunkRva = oft || ft;
      let tOff = rvaToOff(thunkRva);
      if (tOff < 0) continue;
      for (let k = 0; k < 512; k++) {
        const p = tOff + k * thunkSize;
        if (p + thunkSize > b.length) break;
        const val = is64 ? Number(b.readBigUInt64LE(p)) : b.readUInt32LE(p);
        if (!val) break;
        // 高位为 1 表示按序号导入，没有名字
        const isOrdinal = is64 ? (val & 0x8000000000000000) !== 0 : (val & 0x80000000) !== 0;
        if (isOrdinal) continue;
        const hintOff = rvaToOff(val & 0x7fffffff);
        if (hintOff < 0 || hintOff + 2 >= b.length) continue;
        let end = hintOff + 2;
        while (end < b.length && b[end] !== 0 && end - (hintOff + 2) < 256) end++;
        const nm = b.toString('latin1', hintOff + 2, end);
        if (nm) names.push(nm);
      }
    }
  } catch (e) { /* 畸形导入表：返回已解析到的部分 */ }
  return [...new Set(names)];
}

function detectSmcSignals(buf, imageMap) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || []);
  const map = imageMap || null;
  const wxSections = [];
  const evidence = [];
  let textWritable = false;

  for (const s of ((map && map.sections) || [])) {
    const name = String(s.name || '');
    let writable = false;
    let executable = false;
    if (map && map.format === 'pe') {
      const ch = s.characteristics;
      if (typeof ch === 'number') {
        writable = (ch & 0x80000000) !== 0;
        executable = (ch & 0x20000000) !== 0;
      } else if (typeof s.writable === 'boolean' || typeof s.executable === 'boolean') {
        writable = !!s.writable;
        executable = !!s.executable;
      }
    } else if (map && map.format === 'elf') {
      const fl = s.flags;
      if (typeof fl === 'number') {
        writable = (fl & 2) !== 0;      // PF_W
        executable = (fl & 1) !== 0;    // PF_X
      }
    }
    if (writable && executable) wxSections.push(name || s.name || '?');
    if (/^\.text$/i.test(name) && writable) textWritable = true;
  }

  const imports = map && map.format === 'pe' ? parsePEImports(b) : [];
  const suspiciousImports = imports.filter(n => API_CANDIDATES.some(a => n === a || n.startsWith(a)));

  const hasSignal = wxSections.length > 0 || textWritable || suspiciousImports.length > 0;
  if (wxSections.length) evidence.push(`W+X 节: ${wxSections.join(', ')}`);
  if (textWritable) evidence.push('代码节 .text 可写');
  if (suspiciousImports.length) evidence.push(`可疑导入: ${suspiciousImports.join(', ')}`);

  const summary = hasSignal
    ? `发现自修改特征：${evidence.join('；')}`
    : '未发现自修改特征';

  return { wxSections, textWritable, suspiciousImports, hasSignal, evidence, summary };
}

module.exports = { detectSmcSignals, parsePEImports, API_CANDIDATES };
