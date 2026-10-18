// 回归：中间值形态识别（P0.4）。
// 实测（CrackMe）：本地复现命中 55a54008ad1ba589aa210d2629c1df41，
// 工具只说"命中中间值/密钥，非 flag"，AI 不知道下一步 → 重试 17 秒空转。
// 正确做法：识别形态并给出定向动作（md5 → 爆破；密钥 → 解下一层）。
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
  if (e < 0) throw new Error('未找到 ' + name + ' 结尾');
  return src.slice(s, e);
}

const mod = { exports: {} };
new Function('module', 'exports', extract('classifyIntermediateValues') + '\nmodule.exports={classifyIntermediateValues};')(mod, mod.exports);
const { classifyIntermediateValues } = mod.exports;

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m + (extra ? ' → ' + extra : '')); } };
const kinds = (v) => classifyIntermediateValues([v]).map(x => x.kind).join('|');

console.log('[CrackMe 实测值：32 位 hex 应识别为 MD5 长度并给出爆破建议]');
{
  const r = classifyIntermediateValues(['55a54008ad1ba589aa210d2629c1df41']);
  ok(r.length === 1, '识别出 1 条');
  ok(/MD5/.test(r[0].kind), `类型含 MD5（${r[0].kind}）`);
  ok(/爆破|字典/.test(r[0].next), '下一步含爆破/字典');
}

console.log('[其他哈希长度]');
ok(/SHA1/.test(kinds('da39a3ee5e6b4b0d3255bfef95601890afd80709')), '40 位 → SHA1');
ok(/SHA256/.test(kinds('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')), '64 位 → SHA256');

console.log('[其他形态]');
ok(/字节/.test(kinds('deadbeefcafebabe')), '8 字节 hex → 原始字节');
ok(/UUID/.test(kinds('550e8400-e29b-41d4-a716-446655440000')), 'UUID 形态');
ok(/URL/.test(kinds('https://example.com/check')), 'URL');
ok(/Base64/.test(kinds('ZmFrZV9mbGFnX2hlcmU=')), 'Base64 形态');
ok(/可打印明文/.test(kinds('this_is_serial_number')), '可打印明文');

console.log('[边界]');
ok(classifyIntermediateValues([]).length === 0, '空数组不产生结果');
ok(classifyIntermediateValues(['ab']).length === 0, '过短的值忽略');
ok(classifyIntermediateValues(null).length === 0, 'null 不崩');
ok(classifyIntermediateValues(['A'.repeat(32)]).length === 1, '32 位纯字母 hex-length 也识别（宽容）');

console.log('[去重与上限]');
{
  const dup = classifyIntermediateValues(['55a54008ad1ba589aa210d2629c1df41', '55a54008ad1ba589aa210d2629c1df41']);
  ok(dup.length === 1, '同值去重');
  const many = Array.from({ length: 20 }, (_, i) => (i + 1).toString(16).padStart(32, 'a'));
  ok(classifyIntermediateValues(many).length <= 8, '最多 8 条');
}

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
