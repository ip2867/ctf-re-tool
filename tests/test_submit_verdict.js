// 回归：平台提交结果判定。
// 实测事故（内涵的软件）：平台返回 {"accepted":false,...}，旧实现用 /accepted/ 匹配整个 JSON，
// 把错误 flag 记为"解出"，驱动停止重试，报告失真。
const fs = require('fs');
const p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');

const s = src.indexOf('function ctf2SubmitAccepted(');
let depth = 0, e = -1, inS = null, esc = false;
for (let i = src.indexOf('{', s); i < src.length; i++) {
  const c = src[i];
  if (inS) {
    if (esc) { esc = false; continue; }
    if (c === '\\') { esc = true; continue; }
    if (c === inS) inS = null;
    continue;
  }
  if (c === '"' || c === "'" || c === '`') { inS = c; continue; }
  if (c === '{') depth++;
  else if (c === '}') { depth--; if (depth === 0) { e = i + 1; break; } }
}
const mod = { exports: {} };
new Function('module', 'exports', src.slice(s, e) + '\nmodule.exports={ctf2SubmitAccepted};')(mod, mod.exports);
const { ctf2SubmitAccepted } = mod.exports;

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m + (extra ? ' → ' + extra : '')); } };

console.log('[关键回归：accepted=false 必须判失败]');
{
  const real = { accepted: false, attempt: 1, earned_points: 0, is_solved: false, points: 0, solved_sub_flag_count: 0, submission_id: '961fba48', total_sub_flag_count: 1 };
  ok(ctf2SubmitAccepted(real, JSON.stringify(real)) === false, 'accepted=false 判为失败');
}
{
  const real = { accepted: true, attempt: 1, earned_points: 1, is_solved: true, points: 1 };
  ok(ctf2SubmitAccepted(real, JSON.stringify(real)) === true, 'accepted=true 判为成功');
}

console.log('[嵌套结构]');
{
  const nested = { success: true, result: { accepted: false, is_solved: false } };
  ok(ctf2SubmitAccepted(nested, JSON.stringify(nested)) === false, '嵌套 accepted=false 判失败');
}
{
  const nested = { result: { accepted: true } };
  ok(ctf2SubmitAccepted(nested, JSON.stringify(nested)) === true, '嵌套 accepted=true 判成功');
}

console.log('[只有 is_solved 时]');
{
  const d = { is_solved: false, message: 'correct format but wrong flag' };
  ok(ctf2SubmitAccepted(d, JSON.stringify(d)) === false, 'is_solved=false 优先于文本 "correct"');
}
{
  const d = { is_solved: true };
  ok(ctf2SubmitAccepted(d, JSON.stringify(d)) === true, 'is_solved=true 判成功');
}

console.log('[纯文本兜底]');
{
  ok(ctf2SubmitAccepted({}, 'Flag correct!') === true, 'correct 判成功');
  ok(ctf2SubmitAccepted({}, 'incorrect flag') === false, 'incorrect 判失败');
  ok(ctf2SubmitAccepted({}, 'flag 不正确') === false, '中文否定判失败');
  ok(ctf2SubmitAccepted({}, '提交成功') === true, '中文肯定判成功');
  ok(ctf2SubmitAccepted({}, '') === false, '空文本判失败（不默认成功）');
}

console.log('[异常输入不崩]');
{
  ok(ctf2SubmitAccepted(null, null) === false, 'null 不崩且判失败');
  ok(ctf2SubmitAccepted('accepted', 'accepted') === false, '字符串 accepted 不再误判（无布尔字段时需 true 语义）');
}

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
