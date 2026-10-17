// 载荷自动提取脚本生成单测（Phase 4.1）
// 核心验证：生成的 Python 真的能按扫描器给的参数解码出正确文件（端到端跑 Python）。
const fs = require('fs'), os = require('os'), p = require('path');
const { spawnSync } = require('child_process');
const { buildPayloadExtractPython } = require('./payload_extract_loader.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };
const tmp = os.tmpdir();

function makePE(sectionSize = 0x400) {
  const peOff = 0x80, optSize = 224, secTbl = peOff + 24 + optSize, rawPtr = 0x200;
  const b = Buffer.alloc(rawPtr + sectionSize, 0x90);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(peOff, 0x3c);
  b.write('PE\0\0', peOff, 'latin1');
  b.writeUInt16LE(1, peOff + 6);
  b.writeUInt16LE(optSize, peOff + 20);
  b.write('.text\0\0\0', secTbl, 'latin1');
  b.writeUInt32LE(sectionSize, secTbl + 8);
  b.writeUInt32LE(0x1000, secTbl + 12);
  b.writeUInt32LE(sectionSize, secTbl + 16);
  b.writeUInt32LE(rawPtr, secTbl + 20);
  return b;
}

// 用真实 Python 跑生成的脚本，验证解码结果
function runExtract(script, hostBuf, expectBuf, label) {
  const src = p.join(tmp, `ex_src_${label}.bin`);
  const dst = p.join(tmp, `ex_dst_${label}.bin`);
  const py = p.join(tmp, `ex_${label}.py`);
  fs.writeFileSync(src, hostBuf);
  fs.writeFileSync(py, script);
  const r = spawnSync('python', [py, src, dst], { encoding: 'utf8' });
  const out = (r.stdout || '') + (r.stderr || '');
  if (!/^OK\b/m.test(out)) {
    ok(false, `${label}: 脚本执行失败 → ${out.slice(0, 200)}`);
    return;
  }
  const got = fs.readFileSync(dst);
  const same = got.length === expectBuf.length && got.equals(expectBuf);
  ok(same, `${label}: 解码结果与原始载荷逐字节一致（${got.length}B）`);
}

console.log('A) 单字节 XOR（Disguise 形态：dword 数组 + 低字节 XOR 0x07）');
{
  const pe = makePE();
  const stride = 4, key = 7, off = 0x100;
  const host = Buffer.alloc(off + pe.length * stride + 0x40, 0);
  for (let i = 0; i < pe.length; i++) host[off + i * stride] = pe[i] ^ key;
  const script = buildPayloadExtractPython({ type: 'pe', offset: off, length: pe.length, encode: { kind: 'xor', key, stride } });
  ok(!!script, '生成脚本');
  runExtract(script, host, pe, 'xor_stride4');
}

console.log('\nB) 单字节 ADD');
{
  const pe = makePE();
  const key = 0x33, off = 0x80;
  const host = Buffer.alloc(off + pe.length + 0x40, 0);
  for (let i = 0; i < pe.length; i++) host[off + i] = (pe[i] + key) & 0xff;
  const script = buildPayloadExtractPython({ type: 'pe', offset: off, length: pe.length, encode: { kind: 'add', key, stride: 1 } });
  runExtract(script, host, pe, 'add');
}

console.log('\nC) 周期 XOR（3 字节）');
{
  const pe = makePE();
  const keys = [0x11, 0x22, 0x33], off = 0x60;
  const host = Buffer.alloc(off + pe.length + 0x40, 0xcc);
  for (let i = 0; i < pe.length; i++) host[off + i] = pe[i] ^ keys[i % 3];
  const script = buildPayloadExtractPython({ type: 'pe', offset: off, length: pe.length, encode: { kind: 'periodic-xor', key: keys, period: 3 } });
  runExtract(script, host, pe, 'periodic3');
}

console.log('\nD) 滚动 XOR');
{
  const pe = makePE();
  const off = 0x40;
  const host = Buffer.alloc(off + pe.length + 0x40, 0xcc);
  let prev = 0;
  for (let i = 0; i < pe.length; i++) { host[off + i] = prev ^ pe[i]; prev = pe[i]; }
  const script = buildPayloadExtractPython({ type: 'pe', offset: off, length: pe.length, encode: { kind: 'rolling-xor' } });
  runExtract(script, host, pe, 'rolling_xor');
}

console.log('\nE) Base64 文本');
{
  const pe = makePE();
  const off = 0x30;
  const b64 = Buffer.from(pe.toString('base64'), 'latin1');
  const host = Buffer.concat([Buffer.alloc(off, 0x41), b64, Buffer.alloc(0x20, 0x0a)]);
  const script = buildPayloadExtractPython({ type: 'pe', offset: off, length: pe.length, encode: { kind: 'base64' } });
  runExtract(script, host, pe, 'base64');
}

console.log('\nF) Hex 文本');
{
  const pe = makePE();
  const off = 0x20;
  const hex = Buffer.from(pe.toString('hex'), 'latin1');
  const host = Buffer.concat([Buffer.alloc(off, 0x20), hex, Buffer.alloc(0x20, 0x0a)]);
  const script = buildPayloadExtractPython({ type: 'pe', offset: off, length: pe.length, encode: { kind: 'hex' } });
  runExtract(script, host, pe, 'hex');
}

console.log('\nG) 明文（none）');
{
  const pe = makePE();
  const off = 0x100;
  const host = Buffer.concat([Buffer.alloc(off, 0xcc), pe]);
  const script = buildPayloadExtractPython({ type: 'pe', offset: off, length: pe.length, encode: { kind: 'none' } });
  runExtract(script, host, pe, 'none');
}

console.log('\nH) 未知编码 → 不生成脚本（交回 AI）');
{
  const s = buildPayloadExtractPython({ type: 'pe', offset: 0, length: 10, encode: { kind: 'weird-cipher' } });
  ok(s === null, '未知编码返回 null');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
