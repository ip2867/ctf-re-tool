// crypto 工具单测：所有输出必须与标准测试向量逐字节一致。
// 这些向量来自各算法规范/公开测试集，不是"跑一遍看像不像"。
const fs = require('fs');
const path = require('path');
const { runCryptoTool, normalizeKeyHex } = require('../electron/crypto-tool.js');

const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8').replace(/\r\n/g, '\n');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };
const eq = (actual, expected, m) => ok(actual === expected, m, `expected ${expected} got ${actual}`);

console.log('[1] 摘要：标准测试向量');
{
  eq(runCryptoTool({ op: 'digest', algo: 'md5', data: 'abc' }).output, '900150983cd24fb0d6963f7d28e17f72', 'MD5("abc")');
  eq(runCryptoTool({ op: 'digest', algo: 'md5', data: '' }).output, 'd41d8cd98f00b204e9800998ecf8427e', 'MD5("")');
  eq(runCryptoTool({ op: 'digest', algo: 'sha1', data: 'abc' }).output, 'a9993e364706816aba3e25717850c26c9cd0d89d', 'SHA1("abc")');
  eq(runCryptoTool({ op: 'digest', algo: 'sha256', data: 'abc' }).output,
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'SHA256("abc")');
  eq(runCryptoTool({ op: 'digest', algo: 'sha512', data: 'abc' }).output.slice(0, 32),
    'ddaf35a193617abacc417349ae204131', 'SHA512("abc") 前 32 hex');
  eq(runCryptoTool({ op: 'digest', algo: 'sm3', data: 'abc' }).output,
    '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0', 'SM3("abc")（国标向量）');
  eq(runCryptoTool({ op: 'digest', algo: 'crc32', data: 'abc' }).output, '352441c2', 'CRC32("abc")');
  // 二进制输入（hex 形式）
  eq(runCryptoTool({ op: 'digest', algo: 'md5', data: '616263', data_format: 'hex' }).output,
    '900150983cd24fb0d6963f7d28e17f72', 'MD5(hex 616263) 与 MD5("abc") 一致');
}

console.log('\n[2] HMAC 标准向量（RFC 4231 Test Case 2）');
{
  const r = runCryptoTool({
    op: 'hmac', algo: 'sha256', key: 'Jefe', data: 'what do ya want for nothing?',
  });
  eq(r.output, '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843', 'HMAC-SHA256(Jefe, ...)');
}

console.log('\n[3] AES：NIST 向量与往返');
{
  // NIST SP 800-38A F.1.1 AES-128-CBC 首块
  const key = '2b7e151628aed2a6abf7158809cf4f3c';
  const iv = '000102030405060708090a0b0c0d0e0f';
  const pt = '6bc1bee22e409f96e93d7e117393172a';
  const enc = runCryptoTool({
    op: 'symmetric', algo: 'aes', action: 'encrypt',
    data: pt, data_format: 'hex', key, key_format: 'hex', iv, iv_format: 'hex', mode: 'cbc', padding: 'none',
  });
  eq(enc.output, '7649abac8119b246cee98e9b12e9197d', 'AES-128-CBC NIST F.1.1 首块');

  const dec = runCryptoTool({
    op: 'symmetric', algo: 'aes', action: 'decrypt',
    data: enc.output, data_format: 'hex', key, key_format: 'hex', iv, iv_format: 'hex', mode: 'cbc', padding: 'none',
  });
  eq(dec.output, pt, 'AES-CBC 解密回原文');

  // NIST AES-128-ECB F.1.1
  const ecb = runCryptoTool({
    op: 'symmetric', algo: 'aes', action: 'encrypt',
    data: pt, data_format: 'hex', key, key_format: 'hex', mode: 'ecb', padding: 'none',
  });
  eq(ecb.output, '3ad77bb40d7a3660a89ecaf32466ef97', 'AES-128-ECB NIST F.1.1 首块');
}

console.log('\n[4] DES / 3DES / RC4');
{
  // DES-CBC 往返（用 utf8 明文，让 padding 处理长度）
  const d = runCryptoTool({
    op: 'symmetric', algo: 'des', action: 'encrypt',
    data: 'hello des', key: '0123456789abcdef', key_format: 'hex',
    iv: '0000000000000000', iv_format: 'hex', mode: 'cbc', padding: 'pkcs7',
  });
  ok(d.ok && d.output.length === 32, 'DES-CBC 8 字节明文 + PKCS7 → 2 块（32 hex）', d.error || d.output);
  const dBack = runCryptoTool({
    op: 'symmetric', algo: 'des', action: 'decrypt', data: d.output, data_format: 'hex',
    key: '0123456789abcdef', key_format: 'hex',
    iv: '0000000000000000', iv_format: 'hex', mode: 'cbc', padding: 'pkcs7',
  });
  eq(dBack.output, 'hello des', 'DES-CBC 往返');

  // RC4 往返
  const r1 = runCryptoTool({ op: 'symmetric', algo: 'rc4', action: 'encrypt', data: 'secret message', key: 'Key' });
  const r2 = runCryptoTool({
    op: 'symmetric', algo: 'rc4', action: 'decrypt', data: r1.output, data_format: 'hex', key: 'Key',
  });
  eq(r2.output, 'secret message', 'RC4 往返');

  // 3DES 往返
  const t1 = runCryptoTool({
    op: 'symmetric', algo: 'tripledes', action: 'encrypt', data: 'hello world',
    key: '0123456789abcdef0123456789abcdef', key_format: 'hex',
    iv: '0000000000000000', iv_format: 'hex', mode: 'cbc',
  });
  const t2 = runCryptoTool({
    op: 'symmetric', algo: 'tripledes', action: 'decrypt', data: t1.output, data_format: 'hex',
    key: '0123456789abcdef0123456789abcdef', key_format: 'hex',
    iv: '0000000000000000', iv_format: 'hex', mode: 'cbc',
  });
  eq(t2.output, 'hello world', '3DES 往返');
}

console.log('\n[5] SM4（国标 GB/T 32907 向量）');
{
  // 标准向量：key=0123456789abcdeffedcba9876543210, pt=0123456789abcdeffedcba9876543210
  // padding:none —— 国标向量是整块数据，不能加 PKCS7 填充
  const r = runCryptoTool({
    op: 'sm4', action: 'encrypt', data: '0123456789abcdeffedcba9876543210',
    data_format: 'hex', key: '0123456789abcdeffedcba9876543210', key_format: 'hex', mode: 'ecb', padding: 'none',
  });
  eq(r.output, '681edf34d206965e86b3e94f536e4246', 'SM4-ECB 国标向量（padding:none）');

  const back = runCryptoTool({
    op: 'sm4', action: 'decrypt', data: r.output,
    data_format: 'hex', key: '0123456789abcdeffedcba9876543210', key_format: 'hex', mode: 'ecb',
    padding: 'none', output_format: 'hex',
  });
  eq(back.output, '0123456789abcdeffedcba9876543210', 'SM4 解密回原文');

  // SM4-CBC 往返（utf8）
  const c1 = runCryptoTool({
    op: 'sm4', action: 'encrypt', data: 'hello', key: '0123456789abcdeffedcba9876543210', key_format: 'hex',
    mode: 'cbc', iv: '00000000000000000000000000000000', iv_format: 'hex',
  });
  const c2 = runCryptoTool({
    op: 'sm4', action: 'decrypt', data: c1.output, data_format: 'hex', key: '0123456789abcdeffedcba9876543210',
    key_format: 'hex', mode: 'cbc', iv: '00000000000000000000000000000000', iv_format: 'hex',
  });
  eq(c2.output, 'hello', 'SM4-CBC 往返');
}

console.log('\n[6] 错误必须显式');
{
  ok(runCryptoTool({ op: 'nope' }).ok === false, '未知 op 报错');
  ok(runCryptoTool({ op: 'digest', algo: 'nope', data: 'x' }).ok === false, '未知摘要算法报错');
  ok(runCryptoTool({ op: 'symmetric', algo: 'aes', action: 'encrypt', data: 'x', key: 'k', mode: 'cbc' }).ok === false,
    'CBC 缺 iv 报错');
  ok(runCryptoTool({ op: 'sm4', action: 'encrypt', data: 'x', key: 'short', mode: 'ecb' }).ok === false,
    'SM4 key 长度不符报错');
  ok(/长度不符/.test(runCryptoTool({ op: 'sm4', action: 'encrypt', data: 'x', key: 'short', mode: 'ecb' }).error),
    '错误信息说明长度问题');
  ok(runCryptoTool({ op: 'sm4', action: 'encrypt', data: 'x', key: '0123456789abcdeffedcba9876543210', key_format: 'hex', mode: 'ctr' }).ok === false,
    'SM4 不支持的 mode 报错');
}

console.log('\n[7] 工具注册');
{
  ok(/name: "crypto"/.test(mainSrc), '工具定义存在');
  ok(/case 'crypto':/.test(mainSrc), 'dispatch 存在');
  ok(/'crypto',/.test(mainSrc), 'KNOWN 含 crypto');
  ok(/case 'crypto': return/.test(mainSrc), 'toolLabel 存在');
  const pre = mainSrc.slice(mainSrc.indexOf('function precheckToolCall'), mainSrc.indexOf('function levenshtein'));
  ok(/name === 'crypto'/.test(pre), 'precheck 存在');
  const def = mainSrc.slice(mainSrc.indexOf('name: "crypto"'), mainSrc.indexOf('name: "browser_search"'));
  ok(/哈希不可逆/.test(def), '描述说明哈希不可逆');
  ok(/不出网|本机算/.test(def), '描述说明离线计算');
  ok(/sm3|crc32/.test(def), '描述列出 sm3/crc32');
}

console.log('\n[8] package.json 依赖已声明');
{
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  ok(!!(pkg.dependencies && pkg.dependencies['crypto-js']), 'crypto-js 在 dependencies');
  ok(!!(pkg.dependencies && pkg.dependencies['sm-crypto']), 'sm-crypto 在 dependencies');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
