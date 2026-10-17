// 能力边界单测：工具**不得在非 SM4 结构上假装能解**。
//
// 背景（用户提出的审查点）：自动解密脚本只实现 SM4 骨架（32 轮 + X^X^X^rk + 自定义 S 盒）。
// 如果换成 AES 变体或其它分组密码，工具必须**明确不生成脚本**，而不是给出一个注定失败的脚本
// 让 AI 误以为"已经是确定解了"。
//
// 本测试锁定三条边界：
//   A. 有自定义 S 盒但**没有 SM4 形态的轮常量表** → 不生成脚本
//   B. 有 AES 形态的轮常量（Rcon 只有 10 字节） → 不生成脚本
//   C. 标准 AES S 盒 → 识别为 AES，不做 SM4 常量分析
//   D. 完整 SM4 形态（S 盒 + 32 项 CK + 密文）→ **必须**生成脚本（正例，防"过度保守"）
const fs = require('fs'), os = require('os'), p = require('path');
const { scanCryptoFingerprints } = require('./scanner_loader.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };
const tmp = os.tmpdir();

function randomSbox(seed) {
  const a = Array.from({ length: 256 }, (_, i) => i);
  let s = seed;
  for (let i = 255; i > 0; i--) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    const j = s % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}
const sboxBytes = (sbox) => {
  const b = Buffer.alloc(256 * 4);
  for (let i = 0; i < 256; i++) b.writeUInt32LE(sbox[i], i * 4);
  return b;
};
const aesRcon = () => Buffer.from([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);

// SM4 标准 CK 每字节 +delta → 仍是 SM4 形态
function sm4CK(delta) {
  const addPb = (x, d) => {
    const b = [0, 1, 2, 3].map(k => (((x >>> (k * 8)) & 0xff) + d) & 0xff);
    return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
  };
  const out = Buffer.alloc(128);
  for (let i = 0; i < 32; i++) {
    const bb = [0, 1, 2, 3].map(j => ((4 * i + j) * 7) & 0xff);
    const std = ((bb[0] << 24) | (bb[1] << 16) | (bb[2] << 8) | bb[3]) >>> 0;
    out.writeUInt32LE(addPb(std, delta), i * 4);
  }
  return out;
}
function randomBlob(len, seed) {
  const b = Buffer.alloc(len);
  let s = seed;
  for (let i = 0; i < len; i++) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    b[i] = ((s >>> 8) & 0xff) || 0x5a;   // 真实密文几乎无零字节
  }
  return b;
}
const build = (parts, name) => {
  const f = p.join(tmp, `boundary_${name}.bin`);
  fs.writeFileSync(f, Buffer.concat(parts));
  return f;
};
const analyze = (f) => {
  const r = scanCryptoFingerprints(f);
  const an = (r.fingerprints || []).map(x => x.constantAnalysis).filter(Boolean);
  const scripts = an.filter(x => x.decryptScript);
  return { r, an, scripts };
};

console.log('A) 自定义 S 盒 + AES 的 Rcon（无 SM4 轮常量）→ 不得生成脚本');
{
  const f = build([
    Buffer.alloc(0x200, 0xcc), sboxBytes(randomSbox(7)), Buffer.alloc(0x400, 0xcc),
    aesRcon(), Buffer.alloc(0x200, 0xcc), randomBlob(48, 7), Buffer.alloc(0x100, 0xcc),
  ], 'aes_rcon');
  const { an, scripts } = analyze(f);
  ok(an.length === 1, '识别到自定义 S 盒 → 做常量分析');
  ok(an[0].ckFileOffset === null, '未把 Rcon 误认成 SM4 CK 表');
  ok(scripts.length === 0, '**不生成 SM4 解密脚本**（能力边界正确）');
}

console.log('\nB) 只有自定义 S 盒，无任何轮常量 → 不生成脚本');
{
  const f = build([
    Buffer.alloc(0x200, 0xcc), sboxBytes(randomSbox(11)), Buffer.alloc(0x400, 0xcc),
  ], 'sbox_only');
  const { an, scripts } = analyze(f);
  ok(an.length === 1 && scripts.length === 0, '不生成脚本');
  ok(/S 盒按 \*\*dword 数组\*\*存放|dword 数组/.test(an[0].notes.join('\n')), '仍给出存放形态线索');
}

console.log('\nC) 标准 AES S 盒 → 识别为 AES，不做 SM4 分析');
{
  const mul = (a, b) => { let q = 0; for (let i = 0; i < 8; i++) { if (b & 1) q ^= a; const hi = a & 0x80; a = (a << 1) & 0xff; if (hi) a ^= 0x1b; b >>= 1; } return q; };
  const inv = new Array(256).fill(0);
  for (let a = 1; a < 256; a++) for (let b = 1; b < 256; b++) if (mul(a, b) === 1) { inv[a] = b; break; }
  const rot = (x, n) => ((x << n) | (x >>> (8 - n))) & 0xff;
  const aes = [];
  for (let i = 0; i < 256; i++) { const x = inv[i]; aes.push((x ^ rot(x, 1) ^ rot(x, 2) ^ rot(x, 3) ^ rot(x, 4) ^ 0x63) & 0xff); }
  const b = Buffer.alloc(256);
  aes.forEach((v, i) => { b[i] = v; });
  const f = build([Buffer.alloc(0x200, 0xcc), b, Buffer.alloc(0x400, 0xcc)], 'std_aes');
  const { r, an } = analyze(f);
  ok((r.summary || []).some(s => /AES/.test(s.algo)), '判定为 AES');
  ok(an.length === 0, '不做 SM4 常量分析');
}

console.log('\nD) 正例：完整 SM4 形态（S 盒 + 32 项 CK + 密文）→ 必须生成脚本');
{
  const f = build([
    Buffer.alloc(0x200, 0xcc),
    sboxBytes(randomSbox(13)),
    Buffer.alloc(0x200, 0xcc),
    sm4CK(1),                       // SM4 形态 CK（每字节 +1）
    Buffer.alloc(0x200, 0xcc),
    Buffer.from('Abcd1234_efgh5678', 'latin1'),  // 16 字节"口令样" key
    Buffer.alloc(8, 0),                          // 8 字节填充
    randomBlob(48, 13),                          // 密文
    Buffer.alloc(0x100, 0xcc),
  ], 'sm4_full');
  const { an, scripts } = analyze(f);
  ok(an.length === 1, '做常量分析');
  ok(an[0].ckFileOffset !== null, '定位到 SM4 形态 CK');
  ok(scripts.length === 1, '**生成解密脚本**（不能过度保守）');
  if (scripts.length) {
    const sk = scripts[0].decryptScript;
    ok(Array.isArray(sk.ciphertextCandidates) && sk.ciphertextCandidates.length > 0, '给出密文候选');
    ok(typeof sk.script === 'string' && sk.script.length > 500, '脚本内容非空');
  }
}

console.log('\nE) 边界声明：summary 必须如实说明"只适用 SM4 骨架"');
{
  // 检查源码里脚本生成器的注释/输出是否声明了适用范围
  const src = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
  ok(/SM4 变体/.test(src), '命名/注释明确是 SM4 变体口径');
  const f = build([
    Buffer.alloc(0x200, 0xcc), sboxBytes(randomSbox(17)), Buffer.alloc(0x400, 0xcc),
  ], 'boundary_claim');
  const { r } = analyze(f);
  const note = (r.summary || []).map(s => s.note).join('\n');
  ok(/SM4 骨架/.test(note) && /AES 骨架/.test(note), 'summary 同时提示 SM4 与 AES 两种骨架（不武断）');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
