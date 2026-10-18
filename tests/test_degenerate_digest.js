// 回归：退化哈希（空输入摘要）不得被当成 flag。
// 实测（findKey）：工具算出 d41d8cd98f00b204e9800998ecf8427e（空串 MD5）并提交，平台拒绝。
const fs = require('fs');
const p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');

function extract(name) {
  const s = src.indexOf('function ' + name + '(');
  if (s < 0) throw new Error('未定位 ' + name);
  // 花括号配对扫描必须跳过正则字面量：源码里有 /\{([^}]+)\}/ 这类模式，
  // 直接按 { } 计数会在正则内部提前结束（实测报 "Invalid regular expression"）。
  let depth = 0, e = -1, inS = null, inRe = false, esc = false, prevSig = '';
  for (let i = src.indexOf('{', s); i < src.length; i++) {
    const c = src[i];
    if (inS) {
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (c === inS) inS = null;
      continue;
    }
    if (inRe) {
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (c === '/') { inRe = false; prevSig = '/'; }
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { inS = c; continue; }
    // 正则字面量起点：前一个有效字符是 ( , = : [ ! & | ? { ; return
    if (c === '/' && /[=(:,!&|?{;\n]|return|=>/.test(prevSig)) { inRe = true; prevSig = ''; continue; }
    if (!/\s/.test(c)) prevSig = c;
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) { e = i + 1; break; } }
  }
  if (e < 0) throw new Error('未找到 ' + name + ' 结尾');
  return src.slice(s, e);
}

// 需要 DECOY_FLAG_RE + isDecoyFlag + DEGENERATE_DIGESTS + isDegenerateDigest + looksLikeFlag
const decoyStart = src.indexOf('const DECOY_FLAG_RE');
const decoyEnd = src.indexOf('function looksLikeFlag(');
const headerStart = src.indexOf('const DEGENERATE_DIGESTS');
const digStart = src.indexOf('function isDegenerateDigest(');
// DEGENERATE 定义在 isDecoyFlag 之后，所以要分开拼：先退化表，再 decoy，再 degenerat，再 looksLikeFlag
const body = src.slice(headerStart, decoyStart) + '\n'
  + src.slice(decoyStart, decoyEnd) + '\n'
  + extract('isDegenerateDigest') + '\n'
  + extract('looksLikeFlag');
const mod = { exports: {} };
new Function('module', 'exports', body + '\nmodule.exports={looksLikeFlag,isDegenerateDigest};')(mod, mod.exports);
const { looksLikeFlag, isDegenerateDigest } = mod.exports;

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m + (extra ? ' → ' + extra : '')); } };

console.log('[退化摘要必须被拒]');
ok(looksLikeFlag('flag{D41D8CD98F00B204E9800998ECF8427E}') === false, '空串 MD5（大写）被拒');
ok(looksLikeFlag('flag{d41d8cd98f00b204e9800998ecf8427e}') === false, '空串 MD5（小写）被拒');
ok(looksLikeFlag('flag{da39a3ee5e6b4b0d3255bfef95601890afd80709}') === false, '空串 SHA1 被拒');
ok(looksLikeFlag('flag{e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855}') === false, '空串 SHA256 被拒');
ok(isDegenerateDigest('d41d8cd98f00b204e9800998ecf8427e') === true, '裸摘要也识别');

console.log('[正常 flag 不受影响]');
ok(looksLikeFlag('flag{this_Is_a_EaSyRe}') === true, '普通 flag 仍通过');
ok(looksLikeFlag('flag{e10adc3949ba59abbe56e057f20f883e}') === true, '非退化的 32 位 md5 仍通过');
ok(looksLikeFlag('dice{P4ral1isM}') === true, '自定义前缀仍通过');
ok(looksLikeFlag('DBAPP{49d3c93df25caad81232130f3d2ebfad}') === true, 'DBAPP 形态仍通过');

console.log('[诱饵仍被拒]');
ok(looksLikeFlag('flag{this_is_a_fake_flag}') === false, 'fake 诱饵被拒');
ok(looksLikeFlag('CTF{f5_is_not_real_reversing_}') === false, 'not_real 诱饵被拒');

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
