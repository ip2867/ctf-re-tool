// 自修改（SMC）特征判定单测（合成 PE/ELF，不依赖真样本）。
//
// 关键：W+X ≠ 必须动态调试。提示词必须给双向出口：
//   有 W+X/可写代码节 → 先静态/离线；只有在静态拿不到解包后字节时才动态。
const fs = require('fs');
const path = require('path');
const { detectSmcSignals, parsePEImports } = require('../electron/smc-detect.js');
const { parseImageMap } = require('../electron/binary-map.js');

const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

function buildPE(opts) {
  const o = opts || {};
  const secs = o.sections || [
    { name: '.text', va: 0x1000, vsize: 0x400, rawPtr: 0x400, ch: 0x60000020 },
    { name: '.WProtec', va: 0x2000, vsize: 0x400, rawPtr: 0x800, ch: 0xE0000020 },
  ];
  const impCount = (o.imports && o.imports.length) ? 1 : 0;
  const buf = Buffer.alloc(0x2000 + (impCount ? 0x400 : 0));
  buf.writeUInt16LE(0x5a4d, 0);
  buf.writeUInt32LE(0x80, 0x3c);
  buf.writeUInt32LE(0x00004550, 0x80);
  const coff = 0x84;
  buf.writeUInt16LE(0x14c, coff);
  buf.writeUInt16LE(secs.length + (impCount ? 1 : 0), coff + 2);
  buf.writeUInt16LE(0xe0, coff + 16);
  const opt = coff + 20;
  buf.writeUInt16LE(0x10b, opt);
  buf.writeUInt32LE(0x400000, opt + 28);
  buf.writeUInt32LE(0x10000, opt + 56);
  const ddOff = opt + 96;
  if (impCount) buf.writeUInt32LE(0x3000, ddOff + 8 * 1);   // 导入表 RVA
  const sec = opt + 0xe0;
  const putSec = (i, s) => {
    const p = sec + i * 40;
    buf.write(s.name, p, 8, 'latin1');
    buf.writeUInt32LE(s.vsize, p + 8);
    buf.writeUInt32LE(s.va, p + 12);
    buf.writeUInt32LE(s.vsize, p + 16);
    buf.writeUInt32LE(s.rawPtr, p + 20);
    buf.writeUInt32LE(s.ch, p + 36);
  };
  secs.forEach((s, i) => putSec(i, s));
  if (impCount) {
    putSec(secs.length, { name: '.idata', va: 0x3000, vsize: 0x400, rawPtr: 0x1000, ch: 0xC0000040 });
    // 导入描述符：OriginalFirstThunk=0x3100, Name=0x3200, FirstThunk=0x3300
    const d = 0x1000;                                     // .idata 文件偏移
    buf.writeUInt32LE(0x3100, d);
    buf.writeUInt32LE(0x3200, d + 12);
    buf.writeUInt32LE(0x3300, d + 16);
    buf.write('KERNEL32.dll', 0x1200, 'latin1');          // RVA 0x3200
    // thunk 数组（RVA 0x3100 → offset 0x1100）：每项 4 字节，指向 IMAGE_IMPORT_BY_NAME (RVA 0x3280)
    let nameRva = 0x3280;
    o.imports.forEach((nm, i) => {
      buf.writeUInt32LE(nameRva, 0x1100 + i * 4);
      const off = 0x1000 + (nameRva - 0x3000);
      buf.writeUInt16LE(0, off);
      buf.write(nm, off + 2, 'latin1');
      nameRva += 2 + nm.length + 1 + (nm.length % 2);
    });
  }
  return buf;
}

console.log('[1] PE：.text(X,!W) 与 .WProtec(X,W)');
{
  const buf = buildPE({});
  const map = parseImageMap(buf);
  ok(!!map && map.sections.length === 2, '节表解析');
  const r = detectSmcSignals(buf, map);
  ok(JSON.stringify(r.wxSections) === JSON.stringify(['.WProtec']), `wxSections=['.WProtec']（${JSON.stringify(r.wxSections)}）`);
  ok(r.textWritable === false, 'textWritable=false');
  ok(r.hasSignal === true, 'hasSignal=true');
  ok(/W\+X/.test(r.summary), 'summary 含 W+X');
}

console.log('\n[2] PE：导入表含 IsDebuggerPresent → suspiciousImports 命中');
{
  const buf = buildPE({ imports: ['IsDebuggerPresent', 'GetProcAddress', 'VirtualAlloc'] });
  const imports = parsePEImports(buf);
  ok(imports.includes('IsDebuggerPresent'), `解析出 IsDebuggerPresent（${imports.join(',')}）`);
  const map = parseImageMap(buf);
  const r = detectSmcSignals(buf, map);
  ok(r.suspiciousImports.includes('IsDebuggerPresent'), `suspiciousImports 命中（${r.suspiciousImports.join(',')}）`);
  ok(r.suspiciousImports.includes('VirtualAlloc'), 'VirtualAlloc 也命中');
  ok(!r.suspiciousImports.includes('GetProcAddress'), '无害导入不误报');
}

console.log('\n[3] ELF：PF_W|PF_X 段按 p_flags 分类');
{
  const buf = Buffer.alloc(0x400);
  buf[0] = 0x7f; buf[1] = 0x45; buf[2] = 0x4c; buf[3] = 0x46;
  buf[4] = 1;   // 32 位
  buf[5] = 1;   // 小端
  buf.writeUInt32LE(52, 0x1c);   // phoff
  buf.writeUInt16LE(32, 0x2a);   // phentsize
  buf.writeUInt16LE(2, 0x2c);    // phnum
  // 段1：R+X (PF_X=1, PF_R=4) → flags=5
  buf.writeUInt32LE(1, 52);
  buf.writeUInt32LE(0, 52 + 4);
  buf.writeUInt32LE(0x8048000, 52 + 8);
  buf.writeUInt32LE(0x100, 52 + 16);
  buf.writeUInt32LE(0x100, 52 + 20);
  buf.writeUInt32LE(5, 52 + 24);
  // 段2：R+W+X (flags=7)
  const p2 = 52 + 32;
  buf.writeUInt32LE(1, p2);
  buf.writeUInt32LE(0x200, p2 + 4);
  buf.writeUInt32LE(0x8048100, p2 + 8);
  buf.writeUInt32LE(0x100, p2 + 16);
  buf.writeUInt32LE(0x100, p2 + 20);
  buf.writeUInt32LE(7, p2 + 24);
  const map = parseImageMap(buf);
  ok(map && map.format === 'elf', '解析为 ELF');
  ok(map.sections.some(s => s.flags === 7), 'p_flags 已读出');
  const r = detectSmcSignals(buf, map);
  ok(r.wxSections.length === 1, `W+X 段 1 个（${r.wxSections.length}）`);
}

console.log('\n[4] 无信号样本 → "未发现自修改特征"');
{
  const buf = buildPE({ sections: [
    { name: '.text', va: 0x1000, vsize: 0x400, rawPtr: 0x400, ch: 0x60000020 },
    { name: '.data', va: 0x2000, vsize: 0x400, rawPtr: 0x800, ch: 0xC0000040 },
  ] });
  const map = parseImageMap(buf);
  const r = detectSmcSignals(buf, map);
  ok(r.hasSignal === false, 'hasSignal=false');
  ok(r.summary === '未发现自修改特征', `summary="${r.summary}"`);
}

console.log('\n[5] 提示词双向出口');
{
  ok(appSrc.includes('## SMC/自修改特征'), '提示词含固定块');
  ok(/优先静态\/离线路线/.test(appSrc) || /先走静态\/离线路线/.test(appSrc), '含"优先静态/离线"');
  ok(/\*\*W\+X ≠ 必须动态调试\*\*/.test(appSrc), '含"W+X ≠ 必须动态调试"');
  ok(/未发现自修改特征/.test(appSrc), '无信号时输出"未发现自修改特征"');
  ok(/若 ret 目标不是调用方压入的返回地址/.test(appSrc), '含间接分支/不得判定返回的说明');
  ok(mainSrc.includes("ipcMain.handle('analyze-smc'"), '主进程提供 analyze-smc');
  ok(/detectSmcSignals\(buf, imageMap\)/.test(mainSrc), 'main.js 调用 detectSmcSignals');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
