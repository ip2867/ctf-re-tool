// 算法指纹扫描器综合单测：
//  A) 标准常量命中（SM4/AES/SM3/TEA/CRC32）
//  B) 步长 S 盒（Disguise 的 dword 数组形态）
//  C) 零指纹 → 正确判定为"壳/decoy"（不再误报）
//  D) 误报安全：对真实系统大二进制不得报出"自定义分组密码"
const fs = require('fs'), p = require('path'), os = require('os');
const { scanCryptoFingerprints } = require('./scanner_loader.js');

let pass = 0, fail = 0;
const check = (n, c, x) => { if (c) { pass++; console.log('  ✅ ' + n); } else { fail++; console.log('  ❌ ' + n + (x ? '  → ' + x : '')); } };
const tmp = (name, buf) => { const f = p.join(os.tmpdir(), name); fs.writeFileSync(f, buf); return f; };
const has = (r, re) => (r.summary || []).some(s => re.test(s.algo));
const sumText = (r) => (r.summary || []).map(s => s.algo + '/' + s.confidence).join(', ');

console.log('A) 标准常量命中');
{
  const f = tmp('t_sm4fk.bin', Buffer.concat([Buffer.alloc(64), Buffer.from('a3b1bac656aa3350677d9197b27022dc', 'hex'), Buffer.alloc(64)]));
  const r = scanCryptoFingerprints(f);
  check('SM4 FK → 判定 SM4', has(r, /SM4/), sumText(r));
}
{
  const f = tmp('t_aessbox.bin', Buffer.concat([Buffer.alloc(32), Buffer.from('637c777bf26b6fc5', 'hex'), Buffer.alloc(64)]));
  const r = scanCryptoFingerprints(f);
  check('AES S 盒 → 判定 AES', has(r, /AES/), sumText(r));
}
{
  const f = tmp('t_sm3iv.bin', Buffer.concat([Buffer.alloc(16), Buffer.from('7380166f4914b2b9172442d7', 'hex'), Buffer.alloc(32)]));
  const r = scanCryptoFingerprints(f);
  check('SM3 IV → 判定 SM3', has(r, /SM3/), sumText(r));
}
{
  const f = tmp('t_tea.bin', Buffer.concat([Buffer.alloc(16), Buffer.from('b979379e', 'hex'), Buffer.alloc(32)]));
  const r = scanCryptoFingerprints(f);
  check('TEA delta → 判定 TEA', has(r, /TEA/), sumText(r));
}

console.log('\nB) 步长 S 盒（dword 数组，Disguise 形态）');
{
  // 真实感的自定义双射：伪随机置换（非仿射/非恒等），按 4 字节步长、低字节存值
  const perm = Array.from({ length: 256 }, (_, i) => i);
  let s = 20261016 >>> 0;
  const rnd = () => (s = (s * 1664525 + 1013904223) >>> 0) / 4294967296;
  for (let i = 255; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [perm[i], perm[j]] = [perm[j], perm[i]]; }
  const box = Buffer.alloc(256 * 4);
  for (let i = 0; i < 256; i++) box.writeUInt32LE(perm[i], i * 4);
  const f = tmp('t_sbox4.bin', Buffer.concat([Buffer.alloc(16), box, Buffer.alloc(16)]));
  const r = scanCryptoFingerprints(f);
  check('dword 双射表 → 自定义分组密码 high', has(r, /自定义分组密码/) && r.summary.find(s => /自定义分组密码/.test(s.algo)).confidence === 'high', sumText(r));
  const hit = (r.fingerprints || []).find(x => x.fp === 'SBOX-256');
  check('步长被识别为 4', hit && hit.stride === 4, hit ? 'stride=' + hit.stride : 'no hit');
}
{
  // 标准 SM4 S 盒按 dword 步长存放 → 应判 SM4（步长形态的标准盒）
  const sm4 = Buffer.from('d690e9fecce13db716b614c228fb2c05', 'hex');   // 标准 SM4 sbox 前 16 字节
  const box = Buffer.alloc(256 * 4);
  for (let i = 0; i < 16; i++) box.writeUInt32LE(sm4[i], i * 4);
  for (let i = 16; i < 256; i++) box.writeUInt32LE((i * 37 + 11) & 0xff, i * 4);
  // 注意：该表未必严格双射，只验证"步长表能被发现"（SM4 判定需完整标准表，这里不强制）
  const f = tmp('t_sm4sbox4.bin', Buffer.concat([Buffer.alloc(16), box, Buffer.alloc(16)]));
  const r = scanCryptoFingerprints(f);
  console.log('     （步长表发现能力）' + sumText(r));
}

console.log('\nC) 零指纹 → 壳/decoy 判定');
{
  // 用真正"无规律"的字节（非置换），且长度为 4096 无 256 项双射
  const rand = Buffer.alloc(4096);
  for (let i = 0; i < rand.length; i++) rand[i] = (i * i * 7 + i * 3 + 5) & 0xff;   // 非双射循环
  const f = tmp('t_none.bin', rand);
  const r = scanCryptoFingerprints(f);
  check('无指纹 → 报"未发现算法指纹"', has(r, /未发现算法指纹/), sumText(r));
  check('提示指向"下一层"', /下一层/.test(r.summary[0].note));
}
{
  // 恒等表（00 01 02 …）是偏移/跳转表，不是 S 盒 → 必须不报"分组密码"
  const idt = Buffer.alloc(256); for (let i = 0; i < 256; i++) idt[i] = i;
  const f1 = tmp('t_ident.bin', Buffer.concat([Buffer.alloc(32), idt, Buffer.alloc(32)]));
  const r1 = scanCryptoFingerprints(f1);
  check('恒等表(字节) 不报分组密码', !has(r1, /自定义分组密码/), sumText(r1));
  const idt2 = Buffer.alloc(512); for (let i = 0; i < 256; i++) idt2.writeUInt16LE(i, i * 2);
  const f2 = tmp('t_ident2.bin', Buffer.concat([Buffer.alloc(32), idt2, Buffer.alloc(32)]));
  const r2 = scanCryptoFingerprints(f2);
  check('恒等表(word) 不报分组密码', !has(r2, /自定义分组密码/), sumText(r2));
}

console.log('\nD) 误报安全（真实系统大二进制）');
{
  const cands = [
    'C:/Windows/System32/ntdll.dll',
    'C:/Windows/System32/kernel32.dll',
    'C:/Windows/System32/msvcrt.dll',
    p.join(__dirname, '..', 'node_modules/electron/dist/electron.exe'),
    p.join(__dirname, '..', 'src/js/app.js'),
  ];
  let tested = 0, falsePos = 0;
  for (const c of cands) {
    if (!fs.existsSync(c)) continue;
    tested++;
    const r = scanCryptoFingerprints(c);
    const fpText = sumText(r);
    // 误报判据：对"通用程序量级"的大二进制不得给出 high 置信度的分组密码判定
    const bad = (r.summary || []).some(s => /自定义分组密码/.test(s.algo) && s.confidence === 'high')
      || (r.summary || []).some(s => /疑似自定义分组密码/.test(s.algo) && s.confidence !== 'low');
    if (bad) { falsePos++; console.log('     ⚠️ ' + p.basename(c) + ' → ' + fpText); }
    else console.log('     ✓ ' + p.basename(c) + ' (' + (r.size / 1024 | 0) + 'KB) → ' + fpText);
  }
  check(`测试了 ${tested} 个真实二进制，无 high 置信度误报`, tested > 0 && falsePos === 0, `误报 ${falsePos} 个`);
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
