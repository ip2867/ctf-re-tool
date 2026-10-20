// MD5 摘要目标"存在性"闸门单测。
//
// 旧判据（零占比+重复率的 looksHighEntropy）在真样本上命中上万次，不能作为
// "目标存在"的证据。校准后：16 字节对齐窗口 + Shannon>=7.5，排除 .rsrc/.reloc
// 与非可执行节；全文件 32-hex ASCII 字面量单独统计。
const fs = require('fs');
const path = require('path');
const {
  assessHashTarget, buildMd5Note, extractDigestCallSites, shannonEntropy,
} = require('../electron/hash-hint.js');
const { parseImageMap } = require('../electron/binary-map.js');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

const MD5_K = [
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
  0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
];

// 构造最小 PE：可选追加一个 16 字节随机数据节
function buildPE(opts) {
  const o = opts || {};
  const secCount = 2 + (o.extraData ? 1 : 0);
  const buf = Buffer.alloc(0x400 + 0x400 * secCount);
  buf.writeUInt16LE(0x5a4d, 0);
  buf.writeUInt32LE(0x80, 0x3c);
  buf.writeUInt32LE(0x00004550, 0x80);
  const coff = 0x84;
  buf.writeUInt16LE(0x14c, coff);           // x86
  buf.writeUInt16LE(secCount, coff + 2);
  buf.writeUInt16LE(0xe0, coff + 16);
  const opt = coff + 20;
  buf.writeUInt16LE(0x10b, opt);
  buf.writeUInt32LE(0x400000, opt + 28);
  buf.writeUInt32LE(0x100000, opt + 56);
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
  // .text: X, !W
  putSec(0, '.text', 0x1000, 0x400, 0x400, 0x60000020);
  // .data: !X, W（放 MD5 K 常量）
  putSec(1, '.data', 0x2000, 0x400, 0x800, 0xC0000040);
  for (let i = 0; i < MD5_K.length; i++) buf.writeUInt32LE(MD5_K[i] >>> 0, 0x800 + i * 4);
  if (o.extraData) {
    // 第三个节：.rsrc 或 .data2，放 16 字节随机（独立小区域 → 走"无零字节 + 16 字节互不相同"判据）
    putSec(2, o.extraName || '.data2', 0x3000, 0x10, 0xc00, 0xC0000040);
    Buffer.from('9f3c1d7e4b8a2506cd11fe30a7b45c92', 'hex').copy(buf, 0xc00);
  }
  return buf;
}

console.log('[1] 只有 MD5 K 常量、无 32-hex、无高熵窗口 → hasTarget=false 且 note 是 KDF 措辞');
{
  const buf = buildPE({});
  const map = parseImageMap(buf);
  const a = assessHashTarget(buf, map);
  ok(a.hexLiterals === 0, `无 32-hex 字面量（${a.hexLiterals}）`);
  ok(a.highEntropy16 === 0, `无高熵窗口（${a.highEntropy16}）`);
  ok(a.hasTarget === false, 'hasTarget=false');
  const note = buildMd5Note(a, ['MD5_Update(buf, len, 7);']);
  ok(/KDF\/掩码派生/.test(note), 'note 含 KDF/掩码派生');
  ok(!/==目标/.test(note), 'note 不含「==目标」');
}

console.log('\n[2] 追加 16 字节高度随机数据 → hasTarget=true 且保留爆破措辞');
{
  const buf = buildPE({ extraData: true });
  // 让 16 字节窗口熵 > 7.5：16 个互不相同的字节在 16 字节窗口里最大熵 = 4 bit —— 不可能到 7.5！
  // 因此判据必须是"窗口内容接近均匀随机"，而 16 字节样本的理论上限就是 log2(16)=4。
  // 这说明 7.5 阈值只能用于 >=256 字节窗口；16 字节窗口改用"零字节=0 且重复=0"。
  const map = parseImageMap(buf);
  const a = assessHashTarget(buf, map);
  ok(a.hasTarget === true, `hasTarget=true（hex=${a.hexLiterals}, hiEnt=${a.highEntropy16}）`);
}

console.log('\n[3] .rsrc 中的随机数据不得改变结论');
{
  // 无额外数据 + .rsrc 节放随机 16 字节
  const buf = buildPE({ extraData: true, extraName: '.rsrc' });
  const map = parseImageMap(buf);
  const a = assessHashTarget(buf, map);
  ok(a.hasTarget === false, `.rsrc 被排除（hex=${a.hexLiterals}, hiEnt=${a.highEntropy16}）`);
}

console.log('\n[4] extractDigestCallSites 抽出 Update/Final 邻近行');
{
  const text = [
    'int sub_4016B0(int a1) {',
    '  MD5_Init(&ctx);',
    '  MD5_Update(&ctx, a1, 7);     // <<< 长度实参 7',
    '  MD5_Final(digest, &ctx);',
    '  return digest[0];',
    '}',
  ].join('\n');
  const sites = extractDigestCallSites(text);
  ok(sites.length > 0, `有命中（${sites.length}）`);
  ok(sites.some(s => /\b7\b/.test(s)), '包含长度实参 7');
  ok(sites.some(s => /MD5_Update/.test(s)), '含 Update 邻近行');
}

console.log('\n[5] 熵函数基线');
{
  ok(shannonEntropy(Buffer.from('aaaaaaaa')) === 0, '单字节重复熵为 0');
  ok(shannonEntropy(Buffer.from([0,1,2,3,4,5,6,7])) > 2.9, '8 个不同字节熵接近 3');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
