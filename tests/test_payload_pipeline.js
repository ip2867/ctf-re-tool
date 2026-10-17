// 载荷检测流水线单测（Phase 1.2）：覆盖 v1.5.3 之后的**新增形态**
// 目标：证明这些能力不是"针对某道题"，而是对任意同类样本都成立。
const fs = require('fs'), os = require('os'), p = require('path');
const { scanCryptoFingerprints } = require('./scanner_loader.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };
const tmp = os.tmpdir();
const write = (name, buf) => { const f = p.join(tmp, name); fs.writeFileSync(f, buf); return f; };
const first = (r) => (r.payloads || [])[0];

// 构造最小 PE（1 节）。DOS stub 用**真实链接器标准 stub**——周期 3/4/8 的多字节 key
// 依赖"已知明文"(0x40..0x74)，stub 不标准时检测器会（正确地）跳过，因此测试样本必须真实。
function makePE(sectionSize = 0x400) {
  const peOff = 0x80, optSize = 224, secTbl = peOff + 24 + optSize, rawPtr = 0x200;
  const b = Buffer.alloc(rawPtr + sectionSize, 0x90);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(peOff, 0x3c);
  // 标准 DOS stub：0x40 起为机器码，0x4e 起为提示串
  const code = [0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21];
  code.forEach((v, i) => { b[0x40 + i] = v; });
  b.write('This program cannot be run in DOS mode.\r\r\n$', 0x4e, 'latin1');
  b.write('PE\0\0', peOff, 'latin1');
  b.writeUInt16LE(0x14c, peOff + 4);
  b.writeUInt16LE(1, peOff + 6);
  b.writeUInt16LE(optSize, peOff + 20);
  b.writeUInt16LE(0x10b, peOff + 24);
  b.writeUInt32LE(0x1000, peOff + 24 + 28);
  b.write('.text\0\0\0', secTbl, 'latin1');
  b.writeUInt32LE(sectionSize, secTbl + 8);
  b.writeUInt32LE(0x1000, secTbl + 12);
  b.writeUInt32LE(sectionSize, secTbl + 16);
  b.writeUInt32LE(rawPtr, secTbl + 20);
  return b;
}

// 构造最小 ELF32 LE（1 节头）
function makeELF() {
  const b = Buffer.alloc(0x400, 0x00);
  b[0] = 0x7f; b[1] = 0x45; b[2] = 0x4c; b[3] = 0x46;   // ELF
  b[4] = 1;   // 32-bit
  b[5] = 1;   // little-endian
  b[6] = 1;   // version
  const shoff = 0x200, shentsize = 0x28, shnum = 1;
  b.writeUInt32LE(shoff, 0x20);
  b.writeUInt16LE(shentsize, 0x2e);
  b.writeUInt16LE(shnum, 0x30);
  return b;
}

// 构造最小 DEX
function makeDEX() {
  const b = Buffer.alloc(0x300, 0x00);
  b.write('dex\n035\0', 0, 'latin1');
  b.writeUInt32LE(b.length, 0x20);   // file_size
  return b;
}

// 周期 XOR 编码
function periodicXor(pe, keys) {
  const out = Buffer.alloc(pe.length);
  for (let i = 0; i < pe.length; i++) out[i] = pe[i] ^ keys[i % keys.length];
  return out;
}
// 滚动 XOR 编码：out[i] = prev ^ in[i]，prev 初值 0
function rollingXor(pe) {
  const out = Buffer.alloc(pe.length);
  let prev = 0;
  for (let i = 0; i < pe.length; i++) { out[i] = prev ^ pe[i]; prev = pe[i]; }
  return out;
}
// 滚动 ADD 编码
function rollingAdd(pe) {
  const out = Buffer.alloc(pe.length);
  let prev = 0;
  for (let i = 0; i < pe.length; i++) { out[i] = (prev + pe[i]) & 0xff; prev = pe[i]; }
  return out;
}
const mount = (payload, off = 0x200, pad = 0x100) => {
  const host = Buffer.alloc(off + payload.length + pad, 0xcc);
  payload.copy(host, off);
  return host;
};

console.log('A) 周期 XOR（2/3/4/8 字节密钥）');
for (const keys of [[0x5a, 0xa5], [0x11, 0x22, 0x33], [0x01, 0x02, 0x03, 0x04], [9, 8, 7, 6, 5, 4, 3, 2]]) {
  const pe = makePE();
  const enc = periodicXor(pe, keys);
  const f = write(`ctf_periodic_${keys.length}.bin`, mount(enc, 0x200));
  const r = scanCryptoFingerprints(f);
  const h = first(r);
  const e = h && h.encode;
  ok(!!h && h.offset === 0x200 && e && e.kind === 'periodic-xor' && e.period === keys.length
    && JSON.stringify(e.key) === JSON.stringify(keys),
    `周期=${keys.length} → offset=0x200, key=[${e ? e.key.map(k => '0x' + k.toString(16)).join(',') : ''}]`);
}

console.log('\nB) 滚动 XOR / 滚动 ADD');
{
  const pe = makePE();
  const f = write('ctf_rolling_xor.bin', mount(rollingXor(pe), 0x180));
  const h = first(scanCryptoFingerprints(f));
  ok(!!h && h.offset === 0x180 && h.encode && h.encode.kind === 'rolling-xor', `滚动 XOR → offset=0x180/${h && h.encode && h.encode.kind}`);
}
{
  const pe = makePE();
  const f = write('ctf_rolling_add.bin', mount(rollingAdd(pe), 0x180));
  const h = first(scanCryptoFingerprints(f));
  ok(!!h && h.offset === 0x180 && h.encode && h.encode.kind === 'rolling-add', `滚动 ADD → offset=0x180/${h && h.encode && h.encode.kind}`);
}

console.log('\nC) Base64 / Hex 文本存储');
{
  const pe = makePE();
  const b64 = Buffer.from(pe.toString('base64') + '\n', 'latin1');
  const host = Buffer.concat([Buffer.alloc(0x100, 0x41), b64, Buffer.alloc(0x40, 0x0a)]);
  const f = write('ctf_b64_pe.txt', host);
  const h = first(scanCryptoFingerprints(f));
  ok(!!h && h.encode && h.encode.kind === 'base64', `Base64 文本 → ${h && h.encode && h.encode.kind} @0x${h ? h.offset.toString(16) : ''}`);
}
{
  const pe = makePE();
  const hex = Buffer.from(pe.toString('hex') + '\n', 'latin1');
  const host = Buffer.concat([Buffer.alloc(0x100, 0x20), hex, Buffer.alloc(0x40, 0x0a)]);
  const f = write('ctf_hex_pe.txt', host);
  const h = first(scanCryptoFingerprints(f));
  ok(!!h && h.encode && h.encode.kind === 'hex', `Hex 文本 → ${h && h.encode && h.encode.kind} @0x${h ? h.offset.toString(16) : ''}`);
}

console.log('\nD) 其它容器：ELF / DEX（明文 + 单字节 XOR）');
{
  const elf = makeELF();
  const f = write('ctf_plain.elf', mount(elf, 0x100));
  const h = first(scanCryptoFingerprints(f));
  ok(!!h && h.type === 'elf' && h.offset === 0x100, `明文 ELF → ${h && h.type} @0x${h ? h.offset.toString(16) : '(none)'}`);
}
{
  const elf = makeELF();
  const key = 0x5a;
  const enc = Buffer.from(elf.map(b => b ^ key));
  const f = write('ctf_xor.elf.bin', mount(enc, 0x140));
  const h = first(scanCryptoFingerprints(f));
  ok(!!h && h.type === 'elf' && h.encode && h.encode.kind === 'xor' && h.encode.key === key,
    `XOR 编码 ELF → ${h && h.type}/${h && h.encode && h.encode.kind}`);
}
{
  const dex = makeDEX();
  const f = write('ctf_plain.dex.bin', mount(dex, 0x100));
  const h = first(scanCryptoFingerprints(f));
  ok(!!h && h.type === 'dex' && h.offset === 0x100, `明文 DEX → ${h && h.type} @0x${h ? h.offset.toString(16) : '(none)'}`);
}
{
  const dex = makeDEX();
  const key = 0x33;
  const enc = Buffer.from(dex.map(b => b ^ key));
  const f = write('ctf_xor.dex.bin', mount(enc, 0x120));
  const h = first(scanCryptoFingerprints(f));
  ok(!!h && h.type === 'dex' && h.encode && h.encode.kind === 'xor' && h.encode.key === key,
    `XOR 编码 DEX → ${h && h.type}/${h && h.encode && h.encode.kind}`);
}

console.log('\nE) shellcode 序言（low 置信度兜底）');
{
  const host = Buffer.alloc(0x400, 0x90);
  Buffer.from('fce882000000', 'hex').copy(host, 0x100);
  const f = write('ctf_shellcode.bin', host);
  const r = scanCryptoFingerprints(f);
  const h = first(r);
  ok(!!h && h.type === 'shellcode' && h.confidence === 'low', `shellcode 序言 → ${h && h.type}/${h && h.confidence}`);
}

console.log('\nF) 优先级：真实容器存在时不报 shellcode 噪声');
{
  const pe = makePE();
  const host = mount(pe, 0x200, 0x200);
  Buffer.from('fce882000000', 'hex').copy(host, host.length - 0x100);
  const f = write('ctf_pe_plus_shellcode.bin', host);
  const r = scanCryptoFingerprints(f);
  ok((r.payloads || []).every(x => x.type !== 'shellcode'), 'PE 与 shellcode 序言共存时，只报 PE');
}

console.log('\nG) 误报安全（大文件/随机数据不产生容器误报）');
{
  const rnd = Buffer.alloc(300000);
  let s = 987654321;
  for (let i = 0; i < rnd.length; i++) { s = (s * 1103515245 + 12345) & 0x7fffffff; rnd[i] = s & 0xff; }
  const f = write('ctf_random2.bin', rnd);
  const r = scanCryptoFingerprints(f);
  ok((r.payloads || []).filter(x => x.type !== 'shellcode').length === 0, '随机数据不误报容器载荷');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
