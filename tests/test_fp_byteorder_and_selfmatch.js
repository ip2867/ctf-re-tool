#!/usr/bin/env node
'use strict';

/**
 * 常量指纹字节序 + 内嵌载荷自匹配 —— 两个实测抓到的误判。
 *
 * ① **多 word 常量表必须两种字节序都搜**（真实教训）：
 *    fw_a 是静态链接 + SIMD SM3 实现，它的 SM3 IV 以 **小端 word** 存放。
 *    指纹表原来只搜大端 `73 80 16 6f...`，于是扫 fw_a 报"未发现算法指纹" —
 *    而它确实是 SM3。补齐 LE 变体后正确报 high。
 *
 * ② **key=0 的内嵌载荷是自匹配误报**（真实教训）：
 *    静态链接的 fw_a / license 各报了 4 处"内嵌 ELF（XOR 0x00 掩盖）"。
 *    XOR 0x00 意味着那就是明文本身 —— 文件内部恰好含 ELF 魔数字节序列而已。
 *    真正的内嵌载荷必然被某种变换掩盖过（k != 0）。
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const ROOT = path.resolve(__dirname, '..');
const { scanCryptoFingerprints, CRYPTO_FP } = require('./scanner_loader.js');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + ((e && e.message) || e)); fail++; }
}

const tmp = (name, buf) => { const f = path.join(os.tmpdir(), name); fs.writeFileSync(f, buf); return f; };
const withPad = (buf, pad = 64) => Buffer.concat([Buffer.alloc(pad), buf, Buffer.alloc(pad)]);
const hasFp = (r, n) => (r.fingerprints || []).some((x) => x.fp === n);
const hasAlgo = (r, re) => (r.summary || []).some((s) => re.test(s.algo));

console.log('=== ① 多 word 常量表的字节序 ===');

t('SM3 IV 大端形式能命中', () => {
  const be = '7380166f4914b2b9172442d7da8a0600';
  const r = scanCryptoFingerprints(tmp('t_sm3_be.bin', withPad(Buffer.from(be, 'hex'))));
  assert.ok(hasFp(r, 'SM3-IV'), 'SM3-IV(BE) 未命中');
  assert.ok(hasAlgo(r, /SM3/), 'summary 未判 SM3：' + JSON.stringify(r.summary.map(s => s.algo)));
});

t('SM3 IV 小端 word 形式也必须命中（fw_a 的真实形态）', () => {
  const le = '6f168073b9b21449d742241700068ada';
  const r = scanCryptoFingerprints(tmp('t_sm3_le.bin', withPad(Buffer.from(le, 'hex'))));
  assert.ok(hasFp(r, 'SM3-IV-LE'), 'SM3-IV-LE 未命中 —— 会误判成"没有 SM3"');
  assert.ok(hasAlgo(r, /SM3/), 'summary 未判 SM3');
});

t('负向断言：两种字节序确实不同（否则补 LE 毫无意义）', () => {
  const be = '7380166f4914b2b9172442d7da8a0600';
  const le = '6f168073b9b21449d742241700068ada';
  assert.notStrictEqual(be, le, 'BE 与 LE 字节序列不应相同');
  const rBe = scanCryptoFingerprints(tmp('t_sm3_be2.bin', withPad(Buffer.from(be, 'hex'))));
  assert.ok(!hasFp(rBe, 'SM3-IV-LE'), '大端数据不该命中 LE 指纹');
});

t('SM4 CK 也支持小端 word', () => {
  const r = scanCryptoFingerprints(tmp('t_sm4_ck_le.bin', withPad(Buffer.from('150e0700', 'hex'))));
  assert.ok(hasFp(r, 'SM4-CK-LE'), 'SM4-CK-LE 未命中');
});

t('负向断言：只命中 Tj 常量时置信度不能给 high（单条常量证据弱）', () => {
  const r = scanCryptoFingerprints(tmp('t_sm3_tj.bin', withPad(Buffer.from('7945cc19'.replace(/^/, '79cc4519').slice(0, 8), 'hex'))));
  const sm3 = (r.summary || []).find((s) => /SM3/.test(s.algo));
  if (sm3 && !hasFp(r, 'SM3-IV') && !hasFp(r, 'SM3-IV-LE')) {
    assert.notStrictEqual(sm3.confidence, 'high', '只有 Tj 常量却给了 high 置信度');
  }
});

console.log('\n=== ② 内嵌载荷 key=0 自匹配 ===');

// 造一个"看起来像真 ELF"的头部：必须有 e_type / e_machine，
// 检测器现在会校验它们（否则 .eh_frame 里的 7f 45 4c 46 会被误判）
function realElfHead() {
  const b = Buffer.alloc(0x120, 0x00);
  Buffer.from('7f454c4602010100', 'hex').copy(b, 0);
  b.writeUInt16LE(2, 16);    // e_type = ET_EXEC
  b.writeUInt16LE(62, 18);   // e_machine = x86-64
  b.writeBigUInt64LE(0x40n, 0x20);   // e_phoff
  b.writeUInt16LE(56, 0x36);         // e_phentsize
  b.writeUInt16LE(1, 0x38);          // e_phnum
  return b;
}

t('负向断言：文件内部含明文 ELF 魔数（XOR 0x00）不得报成内嵌载荷', () => {
  // 造一个"文件内部某处恰好有 ELF 头"的样本（非偏移 0）
  const fakeElf = Buffer.concat([
    Buffer.from('7f454c4602010100', 'hex'),
    Buffer.alloc(200, 0x90),
  ]);
  const buf = Buffer.concat([Buffer.alloc(256, 0x41), fakeElf, Buffer.alloc(256, 0x41)]);
  const r = scanCryptoFingerprints(tmp('t_selfelf.bin', buf));
  const selfMatch = (r.payloads || []).filter((p) => p.encode && p.encode.kind === 'xor' && p.encode.key === 0);
  assert.deepStrictEqual(selfMatch, [],
    'key=0 的自匹配被报成内嵌载荷：' + JSON.stringify(selfMatch.map(p => [p.type, p.offset])));
});

t('正向：被 XOR 0x5c 编码的**合法** ELF 仍必须报出（真载荷不能漏）', () => {
  const fakeElf = realElfHead();
  const enc = Buffer.from(fakeElf.map((b) => b ^ 0x5c));
  const buf = Buffer.concat([Buffer.alloc(256, 0x41), enc, Buffer.alloc(256, 0x41)]);
  const r = scanCryptoFingerprints(tmp('t_encelf.bin', buf));
  const hit = (r.payloads || []).filter((p) => p.encode && p.encode.kind === 'xor' && p.encode.key === 0x5c);
  assert.ok(hit.length > 0, '编码过的 ELF 载荷漏报了：' + JSON.stringify((r.payloads || []).map(p => [p.type, p.encode])));
});

t('负向断言：e_type/e_machine 非法的假 ELF 头不算载荷（.eh_frame 那种噪声）', () => {
  // 复刻真实误报形态：ident 合法但 e_type=0、e_machine 随机
  const junk = Buffer.concat([
    Buffer.from('7f454c4602010100493956080f859401', 'hex'),   // 前 16 字节：合法 ident + 垃圾
    Buffer.alloc(200, 0x90),
  ]);
  const buf = Buffer.concat([Buffer.alloc(256, 0x41), junk, Buffer.alloc(256, 0x41)]);
  const r = scanCryptoFingerprints(tmp('t_junkelf.bin', buf));
  const bad = (r.payloads || []).filter((p) => p.type === 'elf');
  assert.deepStrictEqual(bad, [],
    'e_type=0/e_machine 随机的假 ELF 被当成载荷：' + JSON.stringify(bad.map(p => [p.offset, p.encode])));
});

t('真实静态链接二进制上不得出现 key=0 的内嵌载荷', () => {
  const cands = [
    'C:\\Users\\Administrator\\Desktop\\工具\\_work\\fw\\fw_a',
    'C:\\Users\\Administrator\\Desktop\\工具\\_work\\license',
  ].filter((p) => fs.existsSync(p));
  assert.ok(cands.length > 0, '没有可用的真实样本');
  for (const p of cands) {
    const r = scanCryptoFingerprints(p);
    const bad = (r.payloads || []).filter((x) => x.encode && x.encode.kind === 'xor' && x.encode.key === 0);
    assert.deepStrictEqual(bad, [],
      `${path.basename(p)} 上有 ${bad.length} 处 key=0 的自匹配误报`);
  }
});

t('真实 fw_a（静态链接 + 小端 SM3 IV）必须被识别为 SM3', () => {
  const p = 'C:\\Users\\Administrator\\Desktop\\工具\\_work\\fw\\fw_a';
  if (!fs.existsSync(p)) { console.log('     （样本不存在，跳过）'); return; }
  const r = scanCryptoFingerprints(p);
  assert.ok(hasAlgo(r, /SM3/),
    'fw_a 未被识别为 SM3 —— 字节序只搜了一种。命中：' + [...new Set((r.fingerprints || []).map(x => x.fp))].join(','));
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
