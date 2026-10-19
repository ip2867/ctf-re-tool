// 回归：契约自动枚举（P1）——补齐 IV / 密文候选 / 字节序三个维度。
// 背景：本轮 7 道题「有契约但本地复现失败」，根因多为
//   ① AI 抄错密文（从反编译里挑了一条像的，真正被校验的那条在别处）
//   ② IV 其实是全零或密文首块
//   ③ TEA 族字节序（le32/be32）
// 这些都不该靠 AI 再猜一次，工具应当自动枚举。
const fs = require('fs');
const p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');

function extract(name) {
  const s = src.indexOf('function ' + name + '(');
  if (s < 0) throw new Error('未定位 ' + name);
  let depth = 0, e = -1, inS = null, inRe = false, esc = false, prev = '';
  for (let i = src.indexOf('{', s); i < src.length; i++) {
    const c = src[i];
    if (inS) { if (esc) { esc = false; continue; } if (c === '\\') { esc = true; continue; } if (c === inS) inS = null; continue; }
    if (inRe) { if (esc) { esc = false; continue; } if (c === '\\') { esc = true; continue; } if (c === '/') { inRe = false; prev = '/'; } continue; }
    if (c === '"' || c === "'" || c === '`') { inS = c; continue; }
    if (c === '/' && /[=(:,!&|?{;\n]|return|=>/.test(prev)) { inRe = true; prev = ''; continue; }
    if (!/\s/.test(c)) prev = c;
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) { e = i + 1; break; } }
  }
  return src.slice(s, e);
}

const mod = { exports: {} };
new Function('module', 'exports',
  'let state = { lastAlgScan: null };\n'
  + 'function setState(s){ state = s; }\n'
  + extract('synthesizeHypotheses')
  + '\nmodule.exports={synthesizeHypotheses,setState};')(mod, mod.exports);
const { synthesizeHypotheses, setState } = mod.exports;

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m + (extra ? ' → ' + extra : '')); } };

console.log('[IV 维度：声明的 + 全零 + 空]');
{
  setState({ lastAlgScan: null });
  const r = synthesizeHypotheses([{ algo: 'aes_cbc', key: 'k', key_encoding: 'ascii', ciphertext: 'aabbccdd11223344', iv: '1122334455667788' }]);
  const ivs = new Set(r.map(x => x.iv));
  ok(ivs.has('1122334455667788'), '包含声明的 IV');
  ok(ivs.has('0000000000000000'), '包含全零 IV');
  ok(ivs.has(''), '包含"无 IV"候选');
  ok(r.length > 3, `展开出 ${r.length} 组`);
}

console.log('[密文候选：扫描器抽到的常量也进入枚举]');
{
  setState({
    lastAlgScan: {
      highEntropy: [{ hex: 'deadbeef00112233445566778899aabb' }],
      summary: [{ evidence: '常量 @0x4020: cafe1234567890abcdef' }],
    },
  });
  const r = synthesizeHypotheses([{ algo: 'aes_ecb', key: 'k', key_encoding: 'ascii', ciphertext: '00112233445566778899aabbccddeeff' }]);
  const cts = new Set(r.map(x => x.ciphertext));
  ok(cts.has('00112233445566778899aabbccddeeff'), '保留 AI 给的密文');
  ok(cts.has('deadbeef00112233445566778899aabb'), '加入扫描器高熵块');
  ok([...cts].some(c => /cafe1234/.test(c)), '加入 summary 证据里的常量');
  ok(cts.size >= 3, `共 ${cts.size} 条候选`);
}

console.log('[字节序维度：TEA 族展开 le32/be32]');
{
  setState({ lastAlgScan: null });
  const r = synthesizeHypotheses([{ algo: 'xtea', key: '00112233445566778899aabbccddeeff', key_encoding: 'hex', ciphertext: 'aabbccdd11223344' }]);
  const vars = new Set(r.map(x => x.variant));
  ok(vars.has('le32'), '包含 le32');
  ok(vars.has('be32'), '包含 be32');
}

console.log('[非 TEA 算法不受影响]');
{
  setState({ lastAlgScan: null });
  const r = synthesizeHypotheses([{ algo: 'aes_ecb', key: 'k', key_encoding: 'ascii', ciphertext: '00112233445566778899aabbccddeeff' }]);
  ok(r.length > 0, '仍产生候选');
  ok(r.every(x => x.variant === undefined), '不注入 variant 字段');
}

console.log('[上限 40]');
{
  setState({ lastAlgScan: { highEntropy: Array.from({ length: 8 }, (_, i) => ({ hex: 'a'.repeat(32) + i.toString(16) })) } });
  const r = synthesizeHypotheses([{ algo: 'aes_cbc', key: 'k1', key_encoding: 'ascii', ciphertext: '0011223344556677' }]);
  ok(r.length <= 40, `不超过 40（实际 ${r.length}）`);
}

console.log('[去重]');
{
  setState({ lastAlgScan: null });
  const r = synthesizeHypotheses([{ algo: 'aes_ecb', key: 'k', key_encoding: 'ascii', ciphertext: '00112233445566778899aabbccddeeff', iv: '' }]);
  const keys = new Set(r.map(x => [x.algo, x.key_encoding, x.key, x.iv, x.ciphertext].join('|')));
  ok(keys.size === r.length, '无重复组合');
}

console.log('[边界]');
{
  setState({ lastAlgScan: null });
  ok(synthesizeHypotheses([]).length === 0, '空契约无候选');
  ok(synthesizeHypotheses(null).length === 0, 'null 不崩');
  ok(synthesizeHypotheses([{ algo: 'aes_ecb' }]).length === 0, '缺 ciphertext 不产生');
}

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
