// 通用性单测：编码存储的内嵌 PE 检测（不针对某一道题）
// 覆盖：XOR/ADD × stride 1/2/4，任意密钥；并确认不误报（正常 PE、随机数据、明文 PE）
const fs = require('fs'), os = require('os'), p = require('path');
const { scanCryptoFingerprints } = require('./scanner_loader.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };

// 构造一个最小可用 PE（含 1 个节），返回 Buffer
function makePE(sectionSize = 0x400) {
  const peOff = 0x80;
  const optSize = 224;
  const secTbl = peOff + 24 + optSize;
  const rawPtr = 0x200;
  const total = rawPtr + sectionSize;
  const b = Buffer.alloc(total, 0x90);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(peOff, 0x3c);
  b.write('PE\0\0', peOff, 'latin1');
  b.writeUInt16LE(0x14c, peOff + 4);            // Machine i386
  b.writeUInt16LE(1, peOff + 6);                // NumberOfSections
  b.writeUInt16LE(optSize, peOff + 20);
  b.writeUInt16LE(0x10b, peOff + 24);           // Magic PE32
  b.writeUInt32LE(0x1000, peOff + 24 + 28);     // ImageBase
  // 节表
  b.write('.text\0\0\0', secTbl, 'latin1');
  b.writeUInt32LE(sectionSize, secTbl + 8);     // VirtualSize
  b.writeUInt32LE(0x1000, secTbl + 12);         // VirtualAddress
  b.writeUInt32LE(sectionSize, secTbl + 16);    // SizeOfRawData
  b.writeUInt32LE(rawPtr, secTbl + 20);         // PointerToRawData
  return b;
}

// 把 pe 编码进载体（宿主用 0x00 填充，模拟 .data）
function embed(pe, { stride, key, mode, off }) {
  const host = Buffer.alloc(off + pe.length * stride + 64, 0x00);
  for (let i = 0; i < pe.length; i++) {
    const v = mode === 'add' ? (pe[i] + key) & 0xff : (pe[i] ^ key);
    host[off + i * stride] = v;                 // 高字节留 0（dword/word 数组形态）
  }
  return host;
}

const tmp = os.tmpdir();
const write = (name, buf) => { const f = p.join(tmp, name); fs.writeFileSync(f, buf); return f; };

console.log('A) XOR 编码 × 各步长（宿主 0x00 填充）');
for (const stride of [1, 2, 4]) {
  for (const key of [0x07, 0x5a, 0xff]) {
    if (key === 0 && stride === 1) continue;
    const pe = makePE();
    const f = write(`ctf_emb_${stride}_${key}.bin`, embed(pe, { stride, key, mode: 'xor', off: 0x40 }));
    const r = scanCryptoFingerprints(f);
    const hit = (r.payloads || [])[0];
    const e = hit && hit.encode;
    ok(!!hit && hit.offset === 0x40 && e && e.stride === stride && e.key === key && e.kind === 'xor',
      `stride=${stride} key=0x${key.toString(16)} → 定位 offset=0x40/${e && e.stride}/${e && e.kind}`);
  }
}

console.log('\nB) ADD 编码 × 各步长（另一类混淆）');
for (const stride of [1, 4]) {
  for (const key of [0x11, 0x80]) {
    const pe = makePE();
    const f = write(`ctf_emb_add_${stride}_${key}.bin`, embed(pe, { stride, key, mode: 'add', off: 0x80 }));
    const r = scanCryptoFingerprints(f);
    const hit = (r.payloads || [])[0];
    const e = hit && hit.encode;
    // key=0x80 时 ADD 与 XOR 恒等（加/减 128 == 翻转 bit7），两种 kind 都正确 → 只校验 key/offset
    const kindOk = key === 0x80 ? (e && (e.kind === 'add' || e.kind === 'xor')) : (e && e.kind === 'add');
    ok(!!hit && hit.offset === 0x80 && e && e.stride === stride && kindOk && e.key === key,
      `stride=${stride} key=0x${key.toString(16)} → offset=0x80/${e && e.kind}/${e && ('0x' + e.key.toString(16))}`);
  }
}

console.log('\nC) 提取配方可用性（按扫描器报的参数解码应得到合法 PE）');
{
  const pe = makePE();
  const key = 0x3c, stride = 4;
  const f = write('ctf_emb_recipe.bin', embed(pe, { stride, key, mode: 'xor', off: 0x120 }));
  const host = fs.readFileSync(f);
  const hit = (scanCryptoFingerprints(f).payloads || [])[0];
  ok(!!hit, '命中内嵌 PE');
  const dec = Buffer.alloc(pe.length);
  for (let i = 0; i < pe.length; i++) dec[i] = host[hit.offset + i * hit.encode.stride] ^ hit.encode.key;
  ok(dec[0] === 0x4d && dec[1] === 0x5a && dec.readUInt32LE(dec.readUInt32LE(0x3c)) === 0x00004550,
    '按扫描器给的 offset/stride/key 解码 → 合法 PE');
  ok(hit.length === pe.length, `报出的长度 ${hit.length} == 真实 ${pe.length}`);
}

console.log('\nD) 误报安全（不应把正常文件当内嵌 PE）');
{
  const f = write('ctf_plain_pe.exe', makePE());
  const r = scanCryptoFingerprints(f);
  ok((r.payloads || []).length === 0, '正常 PE 文件自身不误报为"内嵌 PE"');
}
{
  // 随机数据（固定种子，可复现）
  const rnd = Buffer.alloc(200000);
  let s = 12345;
  for (let i = 0; i < rnd.length; i++) { s = (s * 1103515245 + 12345) & 0x7fffffff; rnd[i] = s & 0xff; }
  const f = write('ctf_random.bin', rnd);
  ok((scanCryptoFingerprints(f).payloads || []).length === 0, '随机数据不误报');
}
{
  // 明文（未编码）内嵌 PE：MZ 相邻差 0x17？4d^5a=0x17 成立 → 但 key = 0x4d^0x4d = 0
  // 这种情况理论上会被当作"key=0 的 XOR"命中，属于可接受（它确实是一个内嵌 PE）
  const host = Buffer.alloc(0x200 + 0x600, 0);
  makePE().copy(host, 0x200);
  const f = write('ctf_plain_embedded.bin', host);
  const r = scanCryptoFingerprints(f);
  // 明文内嵌属"真内嵌"，命中也合理；此处只断言不崩且 offset 正确指向明文 PE
  const hit = (r.payloads || [])[0];
  ok(!hit || hit.offset === 0x200, '明文内嵌 PE：若命中，偏移必须正确 (0x200)');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
