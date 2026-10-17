// 通用性实证（防"特解"回归）
//
// 背景：用户质疑"1.1 秒解出 Disguise 是不是针对这题硬编码的"。
// 本测试构造一个**与 Disguise 完全无关**的 SM4 变体，验证工具能自主解出：
//
//   维度         | Disguise           | 本样本
//   ------------ | ------------------ | ------------------
//   S 盒         | 题目自定义          | 另一套随机双射
//   CK 差分      | 标准 CK 每字节 +1   | 每字节 +0x37
//   FK           | 0x12345678…        | 0x0badf00d…
//   key          | We1c0me_t0_xmctf   | Synthetic_Key_42
//   明文长度      | 48 字节 (3 块)      | 32 字节 (2 块)
//   flag 前缀     | xmctf{}            | synth{}（不在已知列表）
//   文件布局      | S盒@0x41EC30 VA…   | 完全不同的偏移
//   输出排列      | 块内 dword 反序     | 状态反序（标准 SM4）
//
// 通过条件：工具**不改任何代码**就能生成可跑脚本并解出注入的 flag。
const fs = require('fs'), os = require('os'), p = require('path');
const { spawnSync } = require('child_process');
const { scanCryptoFingerprints } = require('./scanner_loader.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };

const M = 0xFFFFFFFF;
const rotl = (x, n) => (((x << n) | (x >>> (32 - n))) >>> 0);
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
function stdCK() {
  const out = [];
  for (let i = 0; i < 32; i++) {
    const b = [0, 1, 2, 3].map(j => ((4 * i + j) * 7) & 0xff);
    out.push(((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0);
  }
  return out;
}
const addPb = (x, d) => {
  const b = [0, 1, 2, 3].map(k => (((x >>> (k * 8)) & 0xff) + d) & 0xff);
  return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
};

const SBOX = randomSbox(20261017);
const CK = stdCK().map(x => addPb(x, 0x37));
const FK = [0x0badf00d, 0xdeadbeef, 0xcafebabe, 0xfeedface];
const KEY = Buffer.from('Synthetic_Key_42', 'latin1');
const FLAG = 'synth{generalization_ok_42}';
const PT = Buffer.from(FLAG.padEnd(32, '\0').slice(0, 32), 'latin1');

const tau = a => ((SBOX[(a >>> 24) & 0xff] << 24) | (SBOX[(a >>> 16) & 0xff] << 16)
  | (SBOX[(a >>> 8) & 0xff] << 8) | SBOX[a & 0xff]) >>> 0;
const L = b => (b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)) >>> 0;
const Lp = b => (b ^ rotl(b, 13) ^ rotl(b, 23)) >>> 0;
const mk = [0, 1, 2, 3].map(i => KEY.readUInt32BE(i * 4));
const k = [0, 1, 2, 3].map(i => (mk[i] ^ FK[i]) >>> 0);
const rk = [];
for (let i = 0; i < 32; i++) {
  const t = (k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]) >>> 0;
  k.push((k[i] ^ Lp(tau(t))) >>> 0);
  rk.push(k[i + 4]);
}
function enc(b) {
  let x = [0, 1, 2, 3].map(j => b.readUInt32BE(j * 4));
  for (let i = 0; i < 32; i++) {
    const t = (x[1] ^ x[2] ^ x[3] ^ rk[i]) >>> 0;
    x = [x[1], x[2], x[3], (x[0] ^ L(tau(t))) >>> 0];
  }
  const o = Buffer.alloc(16);
  for (let j = 0; j < 4; j++) o.writeUInt32BE(x[3 - j], j * 4);   // 标准 SM4：状态反序输出
  return o;
}
const CT = Buffer.concat([enc(PT.slice(0, 16)), enc(PT.slice(16, 32))]);

// 布局：与 Disguise 全不同
const parts = [];
parts.push(Buffer.alloc(0x400, 0x11));
const sb = Buffer.alloc(1024); for (let i = 0; i < 256; i++) sb.writeUInt32LE(SBOX[i], i * 4);
parts.push(sb);                                        // S 盒 @0x400
parts.push(Buffer.alloc(0x600, 0x22));
const ckb = Buffer.alloc(128); for (let i = 0; i < 32; i++) ckb.writeUInt32LE(CK[i], i * 4);
parts.push(ckb);                                       // CK @0xa00
parts.push(Buffer.alloc(0x300, 0x33));
const fkb = Buffer.alloc(16); for (let i = 0; i < 4; i++) fkb.writeUInt32LE(FK[i], i * 4);
parts.push(fkb);                                       // FK @0xd80
parts.push(Buffer.alloc(0x1000, 0x44));
parts.push(KEY);                                       // key
parts.push(Buffer.alloc(0x20, 0));                     // 零填充
parts.push(CT);                                        // 密文
parts.push(Buffer.alloc(0x800, 0x55));

const file = p.join(os.tmpdir(), 'ctf_generalization_proof.bin');
fs.writeFileSync(file, Buffer.concat(parts));

console.log('A) 工具能识别这个变体的常量结构');
{
  const r = scanCryptoFingerprints(file);
  const ca = (r.fingerprints || []).map(x => x.constantAnalysis).find(Boolean);
  ok(!!ca, '产出常量分析');
  ok(!!ca && ca.ckFileOffset !== null, '定位到 SM4 形态轮常量表');
  ok(!!ca && /\+0x37/.test(ca.notes.join('\n')), '算出精确差分（每字节 +0x37）——不是靠记题目');
  ok(!!ca && !!ca.decryptScript, '生成可执行解密脚本');
}

console.log('\nB) 工具生成的脚本能自主解出（未改一行代码）');
{
  const r = scanCryptoFingerprints(file);
  const ca = (r.fingerprints || []).map(x => x.constantAnalysis).find(Boolean);
  ok(!!ca && !!ca.decryptScript, '有脚本可跑');
  if (ca && ca.decryptScript) {
    const py = p.join(os.tmpdir(), 'ctf_generalization_solve.py');
    fs.writeFileSync(py, ca.decryptScript.script, 'utf8');
    const out = spawnSync('python', ['-u', py, file], { encoding: 'utf8', timeout: 180000 });
    const txt = (out.stdout || '') + (out.stderr || '');
    const m = txt.match(/FLAG:\s*(.+)/);
    const got = m ? m[1].trim().replace(/\s+$/, '') : '';
    ok(!!m, '脚本报告命中');
    ok(got === FLAG, `解出的 flag 与注入值一致（${got || '未命中'}）`);
  }
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
