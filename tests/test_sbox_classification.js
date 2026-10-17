// S 盒变体判定专项测试：验证三级判定（精确 / XOR·ADD / GF(2) 仿射）的正确性
const fs = require('fs'), os = require('os'), p = require('path');
const { scanCryptoFingerprints, classifySbox, gf2AffineFit } = require('./scanner_loader.js');
const T = require('../electron/crypto-tables.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };
const tmp = os.tmpdir();

function randomSbox(seed) {
  const a = Array.from({ length: 256 }, (_, i) => i);
  let s = seed;
  for (let i = 255; i > 0; i--) { s = (s * 1103515245 + 12345) & 0x7fffffff; const j = s % (i + 1); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}
const writeSboxFile = (sbox, name) => {
  const b = Buffer.alloc(1024);
  for (let i = 0; i < 256; i++) b.writeUInt32LE(sbox[i], i * 4);
  const f = p.join(tmp, `sbox_${name}.bin`);
  fs.writeFileSync(f, Buffer.concat([Buffer.alloc(0x200, 0xcc), b, Buffer.alloc(0x400, 0xcc)]));
  return f;
};
const scanRel = (f) => {
  const r = scanCryptoFingerprints(f);
  const ca = (r.fingerprints || []).map(x => x.constantAnalysis).find(Boolean);
  return ca ? ca.sboxRelation : null;
};

console.log('A) 精确匹配：标准 AES / SM4 S 盒');
// 注意：标准表会先被"已知常量检测器"命中（走 AES-SBOX 分支，更快更准），
// 不会进入 CUSTOM-BLOCK 的常量分析分支——这是正确行为。此处直接测 classifySbox。
{
  const cls = classifySbox(T.AES_SBOX);
  const aes = cls.find(c => c.name === 'AES');
  ok(!!aes && aes.relation && aes.relation.kind === 'exact', `AES 标准表 → exact（${aes && aes.relation && aes.relation.desc}）`);
}
{
  const cls = classifySbox(T.SM4_SBOX);
  const sm4 = cls.find(c => c.name === 'SM4');
  ok(!!sm4 && sm4.relation && sm4.relation.kind === 'exact', `SM4 标准表 → exact（${sm4 && sm4.relation && sm4.relation.desc}）`);
}
{
  // 扫描链路：标准 AES 表应直接判为 AES（high），而不是"自定义分组密码"
  const f = writeSboxFile(T.AES_SBOX, 'aes_std');
  const r = scanCryptoFingerprints(f);
  ok((r.summary || []).some(s => /AES/.test(s.algo)), '扫描链路：标准 AES 表 → 判定为 AES');
}

console.log('\nB) XOR 变体：标准表每项 ^0x5A → 判定为可精确还原');
{
  const v = T.SM4_SBOX.map(x => x ^ 0x5a);
  const rel = scanRel(writeSboxFile(v, 'sm4_xor'));
  ok(!!rel && rel.kind === 'xor' && /XOR 0x5a/.test(rel.desc), `→ ${rel && rel.desc}`);
}

console.log('\nC) ADD 变体：标准表每项 +0x11 → 判定为可精确还原');
{
  const v = T.AES_SBOX.map(x => (x + 0x11) & 0xff);
  const rel = scanRel(writeSboxFile(v, 'aes_add'));
  ok(!!rel && rel.kind === 'add' && /\+0x11/.test(rel.desc), `→ ${rel && rel.desc}`);
}

console.log('\nD) GF(2) 仿射变体：构造一个可逆矩阵作用于 SM4 标准表');
{
  // 仿射：out = A·x ⊕ c，A 是行循环移位的可逆矩阵（bit i -> bit (i+1)%8），c=0x3c
  const apply = (x) => {
    const rot = ((x << 1) | (x >>> 7)) & 0xff;   // A: 循环左移 1 位（可逆）
    return rot ^ 0x3c;
  };
  const v = T.SM4_SBOX.map(x => apply(x));
  // 先直接验证求解器
  const fit = gf2AffineFit(v, T.SM4_SBOX);
  ok(!!fit, 'gf2AffineFit 找到仿射关系');
  ok(!!fit && fit.invertible, '判定矩阵可逆（可精确还原）');
  ok(!!fit && !fit.identity, '判定为非恒等变换');
  // 再走完整扫描链路
  const rel = scanRel(writeSboxFile(v, 'sm4_affine'));
  ok(!!rel && rel.relatedTo === 'SM4' && /仿射/.test(rel.desc), `扫描链路 → ${rel && rel.desc}`);
}

console.log('\nE) 仿射矩阵回代：求解器给出的 A/c 能从变体表还原标准表');
{
  const apply = (x) => {
    const rot = ((x << 1) | (x >>> 7)) & 0xff;
    return rot ^ 0x3c;
  };
  const variant = T.SM4_SBOX.map(x => apply(x));
  const fit = gf2AffineFit(variant, T.SM4_SBOX);
  // 用 fit 的解构造 f(x)，验证 f(标准[i]) == 变体[i] 对全部 256 项
  let allMatch = true;
  for (let i = 0; i < 256; i++) {
    let out = 0;
    for (let b = 0; b < 8; b++) {
      const s = fit.cols[b];
      let v = s[8];
      for (let kk = 0; kk < 8; kk++) if ((T.SM4_SBOX[i] >>> kk) & 1) v ^= s[kk];
      out |= (v & 1) << b;
    }
    if (out !== variant[i]) { allMatch = false; break; }
  }
  ok(allMatch, '回代验证 256/256 项一致');
}

console.log('\nF) 全新随机表 → 明确报告"无关系"，不编造');
{
  const v = randomSbox(123456789);
  const rel = scanRel(writeSboxFile(v, 'random'));
  ok(!!rel && rel.relatedTo === null && rel.kind === 'custom', '→ custom（无关系）');
}

console.log('\nG) classifySbox 排序：有关系者排前');
{
  const v = T.AES_SBOX.map(x => x ^ 0x77);   // 与 AES 有 XOR 关系
  const cls = classifySbox(v);
  ok(cls[0].name === 'AES' && !!cls[0].relation, `第一位是 AES（有关系）`);
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
