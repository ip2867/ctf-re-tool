// 候选排序单测（Phase 3.3）：按信息增益排，而不是随机顺序。
const fs = require('fs'), p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const start = src.indexOf('function rankAttempts(');
const end = src.indexOf('// 本地枚举：解析 [HYPOTHESES]');
if (start < 0 || end < 0) throw new Error('未能定位 rankAttempts');
const mod = { exports: {} };
new Function('module', 'exports', src.slice(start, end) + '\nmodule.exports = { rankAttempts };')(mod, mod.exports);
const { rankAttempts } = mod.exports;

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };

console.log('A) 工具识别的算法优先');
{
  const attempts = [
    { algo: 'rc4', key_encoding: 'ascii', key: 'abc', ciphertext: '00'.repeat(16), expected: 'x' },
    { algo: 'sm4_ecb', key_encoding: 'ascii', key: 'abc', ciphertext: '00'.repeat(16), expected: 'x' },
    { algo: 'aes_ecb', key_encoding: 'ascii', key: 'abc', ciphertext: '00'.repeat(16), expected: 'x' },
  ];
  const r = rankAttempts(attempts, { knownAlgos: ['SM4'] });
  ok(r[0].algo === 'sm4_ecb', `SM4 排第一（实际 ${r[0].algo}）`);
}

console.log('\nB) 已排除组合降权到末尾');
{
  const attempts = [
    { algo: 'aes_ecb', key_encoding: 'hex', key: '00'.repeat(16), ciphertext: '00'.repeat(16), expected: 'x' },
    { algo: 'sm4_ecb', key_encoding: 'hex', key: '00'.repeat(16), ciphertext: '00'.repeat(16), expected: 'x' },
  ];
  const r = rankAttempts(attempts, { knownAlgos: [], excluded: new Set(['aes_ecb|hex']) });
  ok(r[0].algo === 'sm4_ecb', `排除 aes 后 sm4 在前（实际 ${r[0].algo}）`);
  ok(r[1].algo === 'aes_ecb', '被排除的仍在列表末尾（保留一次机会，不硬删）');
}

console.log('\nC) 标准算法优先于 custom');
{
  const attempts = [
    { algo: 'custom', key_encoding: 'ascii', key: 'k', ciphertext: '00'.repeat(16), expected: 'x' },
    { algo: 'aes_ecb', key_encoding: 'ascii', key: 'k', ciphertext: '00'.repeat(16), expected: 'x' },
  ];
  const r = rankAttempts(attempts, {});
  ok(r[0].algo === 'aes_ecb', `标准算法在前（实际 ${r[0].algo}）`);
}

console.log('\nD) 无密文的候选降权');
{
  const attempts = [
    { algo: 'aes_ecb', key_encoding: 'ascii', key: 'k', ciphertext: '', expected: 'x' },
    { algo: 'aes_ecb', key_encoding: 'ascii', key: 'k', ciphertext: '00'.repeat(16), expected: 'x' },
  ];
  const r = rankAttempts(attempts, {});
  ok(r[0].ciphertext.length > 0, '有密文的在前');
}

console.log('\nE) 稳定性：同分保持原顺序');
{
  const attempts = [
    { algo: 'aes_ecb', key_encoding: 'hex', key: 'k', ciphertext: 'aa'.repeat(16), expected: 'x' },
    { algo: 'aes_cbc', key_encoding: 'hex', key: 'k', ciphertext: 'aa'.repeat(16), expected: 'x' },
    { algo: 'des_ecb', key_encoding: 'hex', key: 'k', ciphertext: 'aa'.repeat(16), expected: 'x' },
  ];
  const r = rankAttempts(attempts, {});
  ok(r[0].algo === 'aes_ecb' && r[1].algo === 'aes_cbc' && r[2].algo === 'des_ecb', '同分时保持输入顺序（稳定排序）');
}

console.log('\nF) 空输入 / 缺字段不崩');
{
  ok(rankAttempts([], {}).length === 0, '空数组不崩');
  ok(rankAttempts([{}], {}).length === 1, '缺字段不崩');
  ok(rankAttempts(null, {}).length === 0, 'null 输入返回空数组');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
