// 诱饵 flag 过滤单测（举一反三：多阶段题第一层普遍埋假 flag）
// 直接抽取 app.js 里的 isDecoyFlag / looksLikeFlag / extractFlags 语义做独立校验。
// 由于这三个函数在 app.js 内耦合了 window/state，这里用"同源正则 + 同源规则"复刻校验，
// 并在下方用「规则快照」断言与源码一致（防止实现漂移却测试仍绿）。
const fs = require('fs'), p = require('path');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };

const src = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');

// --- 1) 源码一致性：确认关键规则确实存在于 app.js（实现漂移则本测试失败）---
console.log('A) 源码一致性（规则必须存在于 app.js）');
ok(/const DECOY_FLAG_RE\s*=\s*\/\(fake\|decoy\|dummy/.test(src), 'DECOY_FLAG_RE 已定义且含 fake|decoy|dummy');
ok(/function isDecoyFlag\(/.test(src), 'isDecoyFlag() 已定义');
ok(/if \(isDecoyFlag\(s\)\) return false;/.test(src), 'looksLikeFlag 内已调用 isDecoyFlag 过滤');
ok(/isDecoyFlag\(v\) \|\| isDecoyFlag\(inner\)/.test(src), 'extractFlags 的 isPlaceholder 已调用 isDecoyFlag');

// --- 2) 复刻规则做行为校验（与 app.js 同源正则 + 同源逻辑）---
const DECOY_FLAG_RE = /(fake|decoy|dummy|placeholder|not[\s_-]*the[\s_-]*real|try[\s_-]*again|wrong[\s_-]*flag|假\s*flag|这不是|诱饵)/i;
const isDecoyFlag = (s) => DECOY_FLAG_RE.test(String(s || ''));
function looksLikeFlag(v) {
  const s = String(v == null ? '' : v).trim();
  if (!s || s.length < 5 || s.length > 300) return false;
  if (isDecoyFlag(s)) return false;
  if (/^[A-Za-z][A-Za-z0-9_]*\{[^}]{1,250}\}$/.test(s)) return true;
  if (/^(flag|ctf|nctf|nssctf|sctf|dasctf|hgame|iscc|sictf|moectf|hnctf|bjdctf|gwht|picoctf|cyberpeace)/i.test(s) && /\{/.test(s)) return true;
  return false;
}

console.log('\nB) 诱饵识别（多阶段题第一层常见形态）');
const decoys = [
  'This is a fake flag',
  'fake_flag',
  'fakeflag{test}',
  'flag{fake_flag_here}',
  'xmctf{this_is_a_decoy}',
  'flag{dummy_value}',
  'FLAG{WRONG_FLAG}',
  'flag{not_the_real_one}',
  'flag{try_again}',
  'flag{假flag}',
  '这是诱饵',
];
decoys.forEach(d => ok(isDecoyFlag(d) === true, `识别为诱饵: ${d}`));

console.log('\nC) 真 flag 不得被误判为诱饵');
const real = [
  'xmctf{We1c0me_t0_the_w0r1d}',
  'flag{SM4_regression_ok!!}',
  'dasctf{hello_world_2024}',
  'nssctf{a1b2c3d4e5}',
  'ctf{real_answer}',
  'picoCTF{abc123}',
];
real.forEach(r => ok(looksLikeFlag(r) === true, `真 flag 正常通过: ${r}`));

console.log('\nD) 诱饵不进 flag 库；诱饵形态即使像 flag 也被剔除');
ok(looksLikeFlag('flag{fake_flag_here}') === false, 'flag{fake_flag_here} 被剔除（虽符合 flag 形态）');
ok(looksLikeFlag('This is a fake flag') === false, '"This is a fake flag" 被剔除（本就不是 flag 形态）');
ok(looksLikeFlag('xmctf{We1c0me_t0_the_w0r1d}') === true, '真答案不受影响');

console.log('\nE) 边界：含 fake 子串的"真词"是否误伤（保守性检查）');
// 注意：正则用 fake/decoy 等词做子串匹配，单词内出现（如 "fakebook"）也会命中——这是**有意保守**：
// 宁可漏记一个可疑 flag（人工复核），也不让诱饵被当成验证通过。此处记录该取舍。
ok(isDecoyFlag('flag{fakebook_survey}') === true, '保守策略：含 fake 子串即过滤（宁可漏记，不可假成功）');

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
