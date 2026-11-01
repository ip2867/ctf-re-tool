// 新增算法指纹（来源：Hello-CTF 逆向/密码学知识域「常量指纹表」）。
//
// 覆盖 FindCrypt 系工具里最有辨识度、但本工具原先缺失的几条：
//   · ChaCha20/Salsa20 sigma 常量（字符串 "expand 32-byte k"）
//   · SHA1 IV（必须 16 字节大端，否则与 MD5-IV 小端形态撞车）
//   · SHA256 轮常量首项 0x428A2F98
//   · Blowfish P 数组首 2 项
//
// 每条都带**负向断言**：把常量改 1 个字节后必须不再命中，
// 以及真实大二进制上不得因新增的 4 字节短模式产生 high 置信度误报。
const fs = require('fs'), p = require('path'), os = require('os');
const { scanCryptoFingerprints, CRYPTO_FP } = require('./scanner_loader.js');

let pass = 0, fail = 0;
const check = (n, c, x) => { if (c) { pass++; console.log('  OK   ' + n); } else { fail++; console.log('  FAIL ' + n + (x ? '  → ' + x : '')); } };
const tmp = (name, buf) => { const f = p.join(os.tmpdir(), name); fs.writeFileSync(f, buf); return f; };
const sumText = (r) => (r.summary || []).map(s => s.algo + '/' + s.confidence).join(', ');
const hasAlgo = (r, re) => (r.summary || []).some(s => re.test(s.algo));
const hasFp = (r, name) => (r.fingerprints || []).some(x => x.fp === name);

// 把 hex 常量包在零填充里，模拟"常量表在 .rdata"
const withPad = (hex, pad = 64) => Buffer.concat([Buffer.alloc(pad), Buffer.from(hex, 'hex'), Buffer.alloc(pad)]);

console.log('=== 新增常量指纹（Hello-CTF 常量表对照）===');

console.log('\nA) 四条新指纹各自命中');
{
  const cases = [
    ['CHACHA-SIGMA', '657870616e642033322d6279746520 6b'.replace(/\s/g, ''), /ChaCha|Salsa/],
    ['SHA1-IV', '67452301efcdab8998badcfe10325476', /SHA1/],
    ['BLOWFISH-P', '886a3f24d308a385', /Blowfish/],
  ];
  for (const [name, hex, algoRe] of cases) {
    const r = scanCryptoFingerprints(tmp(`t_hc_${name}.bin`, withPad(hex)));
    check(`${name} → 判定 ${algoRe.source}`, hasFp(r, name) && hasAlgo(r, algoRe), sumText(r));
  }
  // SHA256-K0 只有 4 字节 → 只要求命中常量，置信度 low 可接受
  const rk = scanCryptoFingerprints(tmp('t_hc_K0.bin', withPad('982f8a42')));
  check('SHA256-K0 → 命中常量且给出 SHA256 提示（low 可接受）',
    hasFp(rk, 'SHA256-K0') && hasAlgo(rk, /SHA256/), sumText(rk));
}

console.log('\nB) 负向断言：常量改 1 字节必须不再命中');
{
  const mut = (hex, at) => {
    const b = Buffer.from(hex, 'hex'); b[at] ^= 0xff; return b.toString('hex');
  };
  const pairs = [
    ['CHACHA-SIGMA', '657870616e642033322d62797465206b', 0],
    ['SHA1-IV', '67452301efcdab8998badcfe10325476', 5],
    ['BLOWFISH-P', '886a3f24d308a385', 2],
    ['SHA256-K0', '982f8a42', 1],
  ];
  for (const [name, hex, at] of pairs) {
    const r = scanCryptoFingerprints(tmp(`t_hc_mut_${name}.bin`, withPad(mut(hex, at))));
    check(`${name} 被破坏后不再命中`, !hasFp(r, name), sumText(r));
  }
}

console.log('\nC) SHA1-IV 不得与 MD5-IV 混淆（字节序是唯一区分点）');
{
  const md5 = scanCryptoFingerprints(tmp('t_hc_md5.bin', withPad('0123456789abcdef')));
  check('MD5-IV（小端）不报 SHA1', !hasFp(md5, 'SHA1-IV'), sumText(md5));
  check('MD5-IV（小端）仍报 MD5', hasAlgo(md5, /MD5/), sumText(md5));
  // 反向：只给 MD5 前 8 字节的 SHA1 大端形态，也不该报 MD5
  const only8 = scanCryptoFingerprints(tmp('t_hc_sha1_8.bin', withPad('674523 01efcdab89'.replace(/\s/g, ''))));
  check('只给 SHA1 前 8 字节 → 不误报 SHA1（指纹要求 16B 完整）', !hasFp(only8, 'SHA1-IV'), sumText(only8));
}

console.log('\nD) 误报安全：真实二进制上新增短模式不得产生 high 判定');
{
  const cands = [
    p.join(__dirname, '..', 'node_modules/electron/dist/electron.exe'),
    p.join(__dirname, '..', 'src/js/app.js'),
  ];
  let tested = 0, bad = 0;
  const shortPats = new Set(['SHA256-K0', 'BLOWFISH-P', 'CHACHA-SIGMA', 'SHA1-IV']);
  for (const c of cands) {
    if (!fs.existsSync(c)) continue;
    tested++;
    const r = scanCryptoFingerprints(c);
    const hot = (r.summary || []).filter(s => shortPats.size && /^(ChaCha20\/Salsa20|Blowfish|SHA1|SHA256)$/.test(s.algo) && s.confidence === 'high');
    // 通用大二进制里出现标准库 SHA256 是正常的；关键是不能 high 到"这就是本题算法"
    if (hot.length) { bad++; console.log('     ⚠️ ' + p.basename(c) + ' → ' + hot.map(s => s.algo + '/' + s.confidence + ':' + s.evidence).join(' | ')); }
    else console.log('     ✓ ' + p.basename(c) + ' → ' + (sumText(r) || '(无)'));
  }
  check(`真实二进制 ${tested} 份无新增 high 误报`, tested > 0 && bad === 0, `误报 ${bad} 份`);
}

console.log('\nE) CRYPTO_FP 表结构完整性（防手抄错）');
{
  const names = CRYPTO_FP.map(x => x[0]);
  check('指纹名不重复', new Set(names).size === names.length, names.join(','));
  let badHex = 0;
  for (const [n, hex] of CRYPTO_FP) {
    const clean = String(hex).replace(/\s+/g, '');
    if (!/^[0-9a-fA-F]+$/.test(clean) || clean.length % 2 !== 0 || clean.length < 4) { badHex++; console.log('     ⚠️ ' + n + ' 非法: ' + hex); }
  }
  check('全部指纹 hex 合法且 ≥2 字节', badHex === 0, `${badHex} 条非法`);
  const chacha = CRYPTO_FP.find(x => x[0] === 'CHACHA-SIGMA');
  check('CHACHA-SIGMA 解码等于 "expand 32-byte k"',
    chacha && Buffer.from(chacha[1].replace(/\s+/g, ''), 'hex').toString('latin1') === 'expand 32-byte k',
    chacha && Buffer.from(chacha[1].replace(/\s+/g, ''), 'hex').toString('latin1'));
}

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
