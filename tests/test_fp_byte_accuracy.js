// 常量指纹表的**字节级**校验：表里的每一个 hex 都必须能从它的数学定义重算出来。
//
// 为什么需要：CRYPTO_FP 是一张手写的 hex 表，写错一个字节就是"该算法永远扫不到"，
// 而且没有任何报错——扫描器只是静默返回零命中，AI 会据此判成"本层是壳"。
// 本轮审查实测就抓到两条：
//   ① `TEA-DELTA-INV` 写成 `47 c8 86 61`（应为 0x61C88647 的小端 `47 86 c8 61`）→ 永不命中
//   ② `SM4-FK` / `SM4-FK-BE` 的名字与端序描述写反了（叫 -BE 的其实是 LE 字节）
//
// 做法：用独立重算的期望值逐条比对，任何一条不符立即失败。
// 同时做**正/负双向**验证：正确字节必须命中，端序写反的字节必须不命中。
const assert = require('assert');
const fs = require('fs'), p = require('path'), os = require('os');
const { scanCryptoFingerprints, CRYPTO_FP } = require('./scanner_loader.js');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + (e && e.message)); fail++; }
}

// ── 大端/小端 4 字节 ──
const le = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0, 0); return b; };
const be = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0, 0); return b; };
const cat = (...bs) => Buffer.concat(bs);
const hex = (b) => b.toString('hex');
const fpHex = (name) => {
  const e = CRYPTO_FP.find((x) => x[0] === name);
  assert.ok(e, `CRYPTO_FP 缺少条目 ${name}`);
  return String(e[1]).replace(/\s+/g, '').toLowerCase();
};
const withPad = (buf, pad = 64) => Buffer.concat([Buffer.alloc(pad), buf, Buffer.alloc(pad)]);
const tmp = (name, buf) => { const f = p.join(os.tmpdir(), name); fs.writeFileSync(f, buf); return f; };

console.log('=== CRYPTO_FP 常量指纹字节级校验 ===');

console.log('\nA) 每个条目都能由其数学定义重算出来');
t('SM4 FK 两种端序', () => {
  const FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
  const leBytes = hex(cat(...FK.map(le)));   // c6bab1a3...
  const beBytes = hex(cat(...FK.map(be)));   // a3b1bac6...
  assert.strictEqual(fpHex('SM4-FK-LE'), leBytes, 'SM4-FK-LE 应为 uint32_t 在 x86 上的原始字节');
  assert.strictEqual(fpHex('SM4-FK-BE'), beBytes, 'SM4-FK-BE 应为常量书写序（大端）');
  // 负向：两者必须不同，否则命名毫无意义
  assert.notStrictEqual(leBytes, beBytes, '两种端序字节应不同');
});
t('TEA delta 与其取反的小端字节', () => {
  assert.strictEqual(fpHex('TEA-DELTA'), hex(le(0x9E3779B9)));
  assert.strictEqual(fpHex('TEA-DELTA-INV'), hex(le(0x61C88647)), '0x61C88647 小端应为 4786c861');
  // 负向：旧版写错的字节必须能被识别为错误
  assert.notStrictEqual(fpHex('TEA-DELTA-INV'), '47c88661', '47c88661 是按位错排的版本，不是 0x61C88647');
});
t('CRC32 / SHA256 / Blowfish / ChaCha 小端字节', () => {
  assert.strictEqual(fpHex('CRC32-POLY'), hex(le(0xEDB88320)));
  assert.strictEqual(fpHex('SHA256-IV'), hex(cat(le(0x6a09e667), le(0xbb67ae85))));
  assert.strictEqual(fpHex('SHA256-K0'), hex(le(0x428A2F98)));
  assert.strictEqual(fpHex('BLOWFISH-P'), hex(cat(le(0x243F6A88), le(0x85A308D3))));
  assert.strictEqual(fpHex('CHACHA-SIGMA'), Buffer.from('expand 32-byte k', 'latin1').toString('hex'));
});
t('SHA1 IV 必须是大端 16 字节（否则与 MD5-IV 撞车）', () => {
  const sha1 = hex(cat(be(0x67452301), be(0xefcdab89), be(0x98badcfe), be(0x10325476)));
  assert.strictEqual(fpHex('SHA1-IV'), sha1);
  const md5 = hex(cat(le(0x67452301), le(0xefcdab89)));
  assert.strictEqual(fpHex('MD5-IV').slice(0, 16), md5, 'MD5 IV 是小端');
  assert.notStrictEqual(fpHex('SHA1-IV').slice(0, 16), md5, 'SHA1-IV 前 16 位不得等于 MD5-IV，否则无法区分');
  assert.strictEqual(fpHex('SHA1-IV').length, 32, 'SHA1-IV 必须是 16 字节（32 hex 字符）');
});
t('AES / SM4 S 盒首字节', () => {
  assert.ok(fpHex('AES-SBOX').startsWith('637c777b'), 'AES S 盒首字节应为 63 7c 77 7b');
  assert.ok(fpHex('SM4-SBOX').startsWith('d690e9fe'), 'SM4 S 盒首字节应为 d6 90 e9 fe');
  assert.ok(fpHex('AES-INV-SBOX').startsWith('52096ad5'), 'AES 逆 S 盒首字节应为 52 09 6a d5');
});

console.log('\nB) 正/负双向：正确字节命中，端序写反的不命中');
{
  // SM4 FK-LE 必须命中，且必须被判成 SM4
  const rLe = scanCryptoFingerprints(tmp('t_fk_le.bin', withPad(cat(...[0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc].map(le)))));
  t('SM4-FK-LE → 命中且判 SM4', () => {
    assert.ok((rLe.fingerprints || []).some((x) => x.fp === 'SM4-FK-LE'), 'FK-LE 未命中');
    assert.ok((rLe.summary || []).some((s) => /SM4/.test(s.algo)), 'summary 未判 SM4：' + JSON.stringify(rLe.summary));
  });
  const rBe = scanCryptoFingerprints(tmp('t_fk_be.bin', withPad(cat(...[0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc].map(be)))));
  t('SM4-FK-BE → 命中且判 SM4', () => {
    assert.ok((rBe.fingerprints || []).some((x) => x.fp === 'SM4-FK-BE'), 'FK-BE 未命中');
    assert.ok((rBe.summary || []).some((s) => /SM4/.test(s.algo)), 'summary 未判 SM4');
  });
  t('负向：SM4 FK 中间改 1 字节必须不再命中', () => {
    const bad = Buffer.concat([...[0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc].map(le)]);
    bad[5] ^= 0xff;
    const r = scanCryptoFingerprints(tmp('t_fk_bad.bin', withPad(bad)));
    assert.ok(!(r.fingerprints || []).some((x) => /^SM4-FK/.test(x.fp)), '破坏后仍命中');
  });
}
{
  const rInv = scanCryptoFingerprints(tmp('t_teainv.bin', withPad(le(0x61C88647))));
  t('TEA-DELTA-INV 正确字节 → 命中且判 TEA', () => {
    assert.ok((rInv.fingerprints || []).some((x) => x.fp === 'TEA-DELTA-INV'), 'TEA-DELTA-INV 未命中');
    assert.ok((rInv.summary || []).some((s) => /TEA/.test(s.algo)), 'summary 未判 TEA');
  });
  t('负向：旧版写错的 47c88661 不得命中 TEA-DELTA-INV', () => {
    const r = scanCryptoFingerprints(tmp('t_teainv_bad.bin', withPad(Buffer.from('47c88661', 'hex'))));
    assert.ok(!(r.fingerprints || []).some((x) => x.fp === 'TEA-DELTA-INV'),
      '47c88661 不是 0x61C88647 的小端，却被命中了 —— 指纹表又写错了');
  });
}

console.log('\nC) 全表结构性检查');
t('名称唯一、hex 合法、描述非空', () => {
  const names = CRYPTO_FP.map((x) => x[0]);
  assert.strictEqual(new Set(names).size, names.length, '指纹名重复');
  for (const [n, h, d] of CRYPTO_FP) {
    const clean = String(h).replace(/\s+/g, '');
    assert.ok(/^[0-9a-fA-F]+$/.test(clean), `${n}: hex 非法`);
    assert.strictEqual(clean.length % 2, 0, `${n}: hex 长度为奇数`);
    assert.ok(clean.length >= 4, `${n}: 少于 2 字节，误报风险过高`);
    assert.ok(String(d || '').trim().length > 0, `${n}: 缺少描述`);
  }
});
t('名称里的端序标注与实际字节一致（防再次写反）', () => {
  const fk = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
  const leB = hex(cat(...fk.map(le))), beB = hex(cat(...fk.map(be)));
  for (const name of ['SM4-FK-LE', 'SM4-FK-BE']) {
    const h = fpHex(name);
    if (/-LE$/.test(name)) assert.strictEqual(h, leB, `${name} 名字说 LE，字节却不是小端序`);
    if (/-BE$/.test(name)) assert.strictEqual(h, beB, `${name} 名字说 BE，字节却不是大端序`);
  }
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
