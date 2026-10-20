// 指纹表 xref 闸门单测。
//
// 结论三态：
//   referenced   → 保留
//   unreferenced → 降级（仅 32 位 PE 的绝对搜索为零、且 IDA 未连接时才能断言）
//   unverified   → 保留原置信度，只标注"xref 未验证"
// x64 PE / ELF 用 RIP-relative，绝对地址为 0 次；按绝对搜索会造成假阴性。
const fs = require('fs');
const path = require('path');
const {
  assessTableRefs, countImm32Refs, countRipRelativeRefs,
} = require('../electron/xref-gate.js');
const { parseImageMap } = require('../electron/binary-map.js');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

// 构造 PE32 / PE32+：.text(X,!W) 与 .data(W,!X)
function buildPE(opts) {
  const o = opts || {};
  const is64 = !!o.is64;
  const buf = Buffer.alloc(0x1000);
  buf.writeUInt16LE(0x5a4d, 0);
  buf.writeUInt32LE(0x80, 0x3c);
  buf.writeUInt32LE(0x00004550, 0x80);
  const coff = 0x84;
  buf.writeUInt16LE(is64 ? 0x8664 : 0x14c, coff);
  buf.writeUInt16LE(2, coff + 2);
  buf.writeUInt16LE(0xe0, coff + 16);
  const opt = coff + 20;
  buf.writeUInt16LE(is64 ? 0x20b : 0x10b, opt);
  if (is64) buf.writeBigUInt64LE(0x140000000n, opt + 24);
  else buf.writeUInt32LE(0x400000, opt + 28);
  buf.writeUInt32LE(0x10000, opt + 56);
  const sec = opt + 0xe0;
  const putSec = (i, name, va, vsize, rawPtr, ch) => {
    const p = sec + i * 40;
    buf.write(name, p, 8, 'latin1');
    buf.writeUInt32LE(vsize, p + 8);
    buf.writeUInt32LE(va, p + 12);
    buf.writeUInt32LE(vsize, p + 16);
    buf.writeUInt32LE(rawPtr, p + 20);
    buf.writeUInt32LE(ch, p + 36);
  };
  putSec(0, '.text', 0x1000, 0x400, 0x400, 0x60000020);
  putSec(1, '.data', 0x2000, 0x400, 0x800, 0xC0000040);
  return buf;
}

const tableVa32 = 0x402000;      // .data 绝对地址（imageBase 0x400000 + 0x2000）

console.log('[1] 32 位 PE：表地址在代码节出现 3 次 → referenced');
{
  const buf = buildPE({});
  // .text 文件偏移 0x400..0x800；写入 3 处 LE32(tableVa)
  [0x420, 0x480, 0x500].forEach(off => buf.writeUInt32LE(tableVa32, off));
  const map = parseImageMap(buf);
  const r = assessTableRefs({ buf, imageMap: map, tableVa: tableVa32, algo: 'AES' });
  ok(r.status === 'referenced', `referenced（实际 ${r.status}）`);
  ok(r.refs === 3, `3 处引用（实际 ${r.refs}）`);
  ok(/引用/.test(r.evidence), '证据含"引用"');
}

console.log('\n[2] 32 位 PE：出现 0 次 → unreferenced 且日志含降级');
{
  const buf = buildPE({});
  const map = parseImageMap(buf);
  const r = assessTableRefs({ buf, imageMap: map, tableVa: tableVa32, algo: 'AES' });
  ok(r.status === 'unreferenced', `unreferenced（实际 ${r.status}）`);
  ok(/表未引用 → 降级/.test(r.log), `日志含「表未引用 → 降级」（${r.log}）`);
}

console.log('\n[3] x64 PE：48 8D 05 <rel32> 指向表 → referenced（不得因无绝对地址降级）');
{
  const buf = buildPE({ is64: true });
  const imageBase = 0x140000000;
  const tableVa = imageBase + 0x2000;
  const instrOff = 0x420;
  const instrVa = imageBase + 0x1000 + (instrOff - 0x400);
  const rel = tableVa - (instrVa + 7);
  buf[instrOff] = 0x48; buf[instrOff + 1] = 0x8d; buf[instrOff + 2] = 0x05;
  buf.writeInt32LE(rel, instrOff + 3);
  const map = parseImageMap(buf);
  ok(map && map.bits === 64, '解析为 PE32+');
  ok(countImm32Refs(buf, map, tableVa) === 0, '绝对 imm32 搜索为 0（x64 正常）');
  const r = assessTableRefs({ buf, imageMap: map, tableVa, algo: 'AES' });
  ok(r.status === 'referenced', `referenced（实际 ${r.status}）`);
  ok(r.refs === 1, `1 处 rip-rel（实际 ${r.refs}）`);
}

console.log('\n[4] x64 无法解析到引用 → unverified，不得降级');
{
  const buf = buildPE({ is64: true });
  const tableVa = 0x140000000 + 0x2000;
  const map = parseImageMap(buf);
  const r = assessTableRefs({ buf, imageMap: map, tableVa, algo: 'AES' });
  ok(r.status === 'unverified', `unverified（实际 ${r.status}）`);
  ok(/xref 未验证/.test(r.log), `日志含「xref 未验证 → 保留」（${r.log}）`);
  ok(!/未引用 → 降级/.test(r.log), '不降级');
}

console.log('\n[5] IDA 已连接时以 xrefs_to 为准');
{
  const buf = buildPE({});
  const map = parseImageMap(buf);
  const r0 = assessTableRefs({ buf, imageMap: map, tableVa: tableVa32, idaXrefs: [{ addr: '0x402000', xrefs: ['0x401234'] }], algo: 'AES' });
  ok(r0.status === 'referenced', `IDA 有 xref → referenced（${r0.status}）`);
  const r1 = assessTableRefs({ buf, imageMap: map, tableVa: tableVa32, idaXrefs: [{ addr: '0x402000', xrefs: [] }], algo: 'AES' });
  ok(r1.status === 'unreferenced', `IDA 明确 0 xref → unreferenced（${r1.status}）`);
}

console.log('\n[6] 源码静态断言：负面断言反证只消费 referenced');
{
  const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
  const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
  ok(!/status === 'unverified'[\s\S]{0,80}refut/i.test(appSrc), 'app.js 不把 unverified 当反证依据');
  ok(/ctx2\.refutedTables = [\s\S]{0,200}status === 'referenced'/.test(appSrc),
    'checkNegativeAssertions 只把 referenced 放进 refutedTables');
  ok(/`unverified`[^\n]{0,80}不得用于反证/.test(appSrc.replace(/\r\n/g, '\n')),
    'unverified 明确不得用于反证');
  ok(/isRefutedByRefs/.test(mainSrc), 'main.js 提供 isRefutedByRefs（只认 referenced）');
  const gate = fs.readFileSync(path.join(__dirname, '..', 'electron', 'xref-gate.js'), 'utf8');
  ok(/function isRefutedByRefs\(entry\) \{\s*\r?\n\s*return !!entry && entry\.status === 'referenced';/.test(gate),
    'isRefutedByRefs 仅接受 referenced');
  // main.js 的扫描器把 xref 三态挂到命中条目上，并在 summary 里三态区分
  ok(/xref: \{ status: xref\.status/.test(mainSrc), '扫描器把 xref 状态挂到命中条目');
  ok(/'（表未引用\/库数据）'/.test(mainSrc) && /'（xref 未验证）'/.test(mainSrc),
    'summary 三态标注（未引用/未验证）');
  ok(/\[指纹闸\]/.test(fs.readFileSync(path.join(__dirname, '..', 'electron', 'xref-gate.js'), 'utf8')),
    '日志前缀 [指纹闸]');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
