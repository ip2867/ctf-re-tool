// 回归：可打印明文自动加外壳（P0.4b）。
// 实测三道题明明拿到了近乎完整的答案，只因不是 flag{...} 形态而失败：
//   reverse3   → {i_l0ve_you}          （已在花括号内，只差 flag 前缀）
//   新年快乐    → HappyNewYear!          （裸明文）
//   Crackme7   → THISiSsERIALnUMBER     （裸明文）
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
  'const recorded = [];\n'
  + 'function looksLikeFlag(v){ const s=String(v||"").trim(); return /^[A-Za-z][A-Za-z0-9_]*\\{[^}]{1,250}\\}$/.test(s); }\n'
  + 'function recordFlag(f,src,ver){ recorded.push({f,src,ver}); }\n'
  + 'function addSolveNote(){}\n'
  + extract('wrapPrintableHit')
  + '\nmodule.exports={wrapPrintableHit,recorded};')(mod, mod.exports);
const { wrapPrintableHit, recorded } = mod.exports;

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m + (extra ? ' → ' + extra : '')); } };

console.log('[reverse3 实测：{i_l0ve_you} → flag{i_l0ve_you}]');
{
  recorded.length = 0;
  ok(wrapPrintableHit(['{i_l0ve_you}']) === true, '命中');
  ok(recorded.length === 1 && recorded[0].f === 'flag{i_l0ve_you}', `记录值 ${recorded[0] && recorded[0].f}`);
  ok(recorded[0] && recorded[0].ver === true, '标记为已验证');
}

console.log('[新年快乐 / Crackme7 实测：裸明文]');
{
  recorded.length = 0;
  ok(wrapPrintableHit(['HappyNewYear!']) === true, 'HappyNewYear! 命中');
  ok(recorded[0] && recorded[0].f === 'flag{HappyNewYear!}', `值得 ${recorded[0] && recorded[0].f}`);
}
{
  recorded.length = 0;
  ok(wrapPrintableHit(['THISiSsERIALnUMBER']) === true, 'THISiSsERIALnUMBER 命中');
  ok(recorded[0] && recorded[0].f === 'flag{THISiSsERIALnUMBER}', `值得 ${recorded[0] && recorded[0].f}`);
}

console.log('[不误伤]');
{
  recorded.length = 0;
  ok(wrapPrintableHit(['this is a sentence with spaces']) === false, '含空白的句子不尝试');
  ok(wrapPrintableHit(['flag{already_wrapped}']) === false, '已是 flag 形态不重复包裹');
  ok(wrapPrintableHit(['']) === false, '空串不处理');
  ok(wrapPrintableHit(['ab']) === false, '过短不处理');
  ok(wrapPrintableHit(['中文答案']) === false, '非 ASCII 不处理');
  ok(wrapPrintableHit(['a'.repeat(200)]) === false, '超长不处理');
  ok(wrapPrintableHit(null) === false, 'null 不崩');
  // 实测（CrackMe）：CBAADEB0A8ABAEB1B4B7BABDC0C3C6C9 是字节数据不是明文，
  // 包成 flag{...} 只会在平台留一条错误提交记录。
  ok(wrapPrintableHit(['CBAADEB0A8ABAEB1B4B7BABDC0C3C6C9']) === false, '纯 hex 串不包外壳');
  ok(wrapPrintableHit(['55a54008ad1ba589aa210d2629c1df41']) === false, '小写 hex 串不包外壳');
}
{
  recorded.length = 0;
  ok(wrapPrintableHit(['deadbeefcafebabe', 'THISiSsERIALnUMBER']) === true, '混合候选：跳过 hex、命中明文');
  ok(recorded.length === 1 && recorded[0].f === 'flag{THISiSsERIALnUMBER}', `只记录明文那个（${recorded[0] && recorded[0].f}）`);
}

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
