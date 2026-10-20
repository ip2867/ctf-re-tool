// 包装去重壳：历史缺陷 A（[WUSTCTF2020]level1 失败根因）
//
// 题面常要求 "把结果包成 flag{...}"，而求解得到的裸值本身可能已经带着
// 题目自定义的壳（如 hack1ng_fo1_fun{...}）。旧实现看到"已有外壳"就直接返回，
// 产出不符合目标形态的答案 → 平台判错。
//
// 正确行为：
//   内层前缀 == 目标前缀  → 原样返回（避免 flag{flag{x}}）
//   内层前缀 != 目标前缀  → 先脱内层，再套目标壳
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, n, d) => {
  if (c) { pass++; console.log('  OK   ' + n); }
  else { fail++; console.log('  FAIL ' + n + (d ? '  → ' + d : '')); }
};

// 从生产代码抽取 applyWrap 并执行，保证测的是真实实现
const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
const m = /function applyWrap\(value, tpl\) \{[\s\S]*?\n\}/.exec(appSrc);
if (!m) { console.log('  FAIL 找不到 applyWrap 实现'); process.exit(1); }
const applyWrap = eval('(' + m[0] + ')');

console.log('\n[1] 同前缀不重复套壳');
ok(applyWrap('flag{abc}', 'flag{%s}') === 'flag{abc}', 'flag{abc} + flag{%s} → flag{abc}');
ok(applyWrap('ctf{x}', 'ctf{%s}') === 'ctf{x}', 'ctf{x} + ctf{%s} → ctf{x}');

console.log('\n[2] 裸值正常套壳');
ok(applyWrap('hello', 'flag{%s}') === 'flag{hello}', 'hello → flag{hello}');
ok(applyWrap('1234567', 'flag{%s}') === 'flag{1234567}', '数字串也能套');
ok(applyWrap('', 'flag{%s}') === '', '空值原样返回');

console.log('\n[3] 异前缀先脱内层再套（历史缺陷 A）');
ok(applyWrap('hack1ng_fo1_fun{abc}', 'flag{%s}') === 'flag{abc}',
  'hack1ng_fo1_fun{abc} + flag{%s} → flag{abc}',
  applyWrap('hack1ng_fo1_fun{abc}', 'flag{%s}'));
ok(applyWrap('inner{payload}', 'flag{%s}') === 'flag{payload}',
  'inner{payload} → flag{payload}',
  applyWrap('inner{payload}', 'flag{%s}'));
ok(applyWrap('AAA{bbb_ccc}', 'flag{%s}') === 'flag{bbb_ccc}',
  'AAA{bbb_ccc} → flag{bbb_ccc}');

console.log('\n[4] 模板无前缀时不擅自改值');
ok(applyWrap('flag{abc}', '%s') === 'flag{abc}',
  '模板 %s（无前缀）→ 原样返回');
ok(applyWrap('raw', '%s') === 'raw', '模板 %s + 裸值 → 裸值');

console.log('\n[5] 嵌套不被二次破坏');
ok(applyWrap(applyWrap('hack1ng_fo1_fun{abc}', 'flag{%s}'), 'flag{%s}') === 'flag{abc}',
  '连续两次包装保持稳定（幂等）');

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
