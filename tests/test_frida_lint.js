// Frida 脚本结构 lint 回归
//
// 实测缺陷（NaughtyBoy）：AI 重新生成 hook 脚本时把区块注释写成了
//     / ============ 1. Java 层 ============ /
// 这在语法上是**合法**的（一个正则字面量表达式），vm.Script 解析通过、
// 校验器返回 ok、脚本照常注入 —— 然后整段注释失效，那一轮 0 条 [DATA]。
//
// 本测试锁三件事：
//   1) 坏注释能被识别（而不只是"语法是否合法"）
//   2) 修复是**定点**的：只改坏横幅，不碰正常正则/字符串
//   3) 修复后的脚本语义完整（区块标记恢复成注释，后续代码不被误改）
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const { lintFridaScript, repairFridaScript, lintAndRepair } = require('../electron/frida-lint.js');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

// 实测的坏形态（从日志原文摘出）
const BROKEN = `(function () {
    'use strict';
    var LOG_HIT = '[HIT] ';
    / ============ 1. Java 层：SignTools ============ /
    Java.perform(function () {
        var noise = /AndroidNSSP|code_cache/;
        console.log('[*] loaded');
    });
    / ============ 2. 通用 hook ============ /
    Java.perform(function () {
        var ok = /^[0-9a-f]+$/.test('abc');
    });
})();`;

console.log('[1] 坏注释语法合法但结构非法（这正是漏洞所在）');
{
  let parseOk = true, parseErr = '';
  try { new vm.Script(BROKEN); } catch (e) { parseOk = false; parseErr = e.message; }
  ok(parseOk, 'vm.Script 解析通过 —— 语法层面看不出来', parseErr);

  const r = lintFridaScript(BROKEN);
  ok(!r.ok, '结构 lint 判为不通过');
  const banners = r.issues.filter(x => x.code === 'BROKEN_BANNER_COMMENT');
  ok(banners.length === 2, '识别出 2 处坏横幅注释', String(banners.length));
  ok(banners[0].line === 4, '定位到第 4 行', String(banners[0].line));
}

console.log('\n[2] 正常脚本不应误报');
{
  const GOOD = `(function () {
  // ============ 1. Java 层 ============
  Java.perform(function () {
    var re = /^[0-9a-f]+$/;
    var s = 'http://x/y';
    if (re.test(s)) { console.log('ok'); }
  });
  /* ============ 2. native ============ */
  Interceptor.attach(ptr(0x1234), { onEnter: function () {} });
})();`;
  const r = lintFridaScript(GOOD);
  ok(r.ok, '规范注释（// 与 /* */）不报', JSON.stringify(r.issues));
  let p = true; try { new vm.Script(GOOD); } catch (e) { p = false; }
  ok(p, '规范脚本语法也合法');
}

console.log('\n[3] 修复是定点的：只改坏横幅');
{
  const { script, fixed } = repairFridaScript(BROKEN);
  ok(fixed === 2, '修复 2 处', String(fixed));
  ok(/\/\/ ============ 1\. Java 层：SignTools ============/.test(script), '第一处恢复成 // 注释');
  ok(/\/\/ ============ 2\. 通用 hook ============/.test(script), '第二处恢复成 // 注释');
  // 不能误伤正常正则
  ok(/var noise = \/AndroidNSSP\|code_cache\//.test(script), '正常正则 /AndroidNSSP|code_cache/ 未被改动');
  ok(/var ok = \/\^\[0-9a-f\]\+\$\/\.test/.test(script), '正常正则 /^[0-9a-f]+$/ 未被改动');
  // 修完语法仍合法
  let p = true, e = '';
  try { new vm.Script(script); } catch (x) { p = false; e = x.message; }
  ok(p, '修复后仍是合法 JS', e);
  // 修完结构通过
  ok(lintFridaScript(script).ok, '修复后结构检查通过');
}

console.log('\n[4] lintAndRepair 一步到位');
{
  const r = lintAndRepair(BROKEN);
  ok(r.ok, '最终 ok=true');
  ok(r.repairs.length === 2, '报告 2 处修复', String(r.repairs.length));
  ok(r.remaining.length === 0, '无残留问题');
  // 幂等：再修一次不应再有改动
  const r2 = lintAndRepair(r.script);
  ok(r2.ok && r2.repairs.length === 0, '幂等（二次修复无改动）');
}

console.log('\n[5] 缺 hook 主体时要报出来（防止注入了空脚本）');
{
  const EMPTY = `(function(){ var x = 1; })();`;
  const r = lintFridaScript(EMPTY);
  ok(!r.ok, '没有 Java.perform / Interceptor.attach → 不通过');
  ok(r.issues.some(x => x.code === 'MISSING_HOOK_BODY'), '报告 MISSING_HOOK_BODY');
}

console.log('\n[6] 边界：空串 / 只有注释 / 单个 /');
{
  ok(lintFridaScript('').ok === false, '空串 → 不通过（缺 hook 主体）');
  ok(lintFridaScript('// only comment').ok === false, '只有注释 → 不通过');
  // 单个 '/' 是除法或非法，不应被当成横幅
  const r = lintFridaScript('Java.perform(function(){ var a = 4 / 2; });');
  ok(r.ok, '除法 4/2 不误报', JSON.stringify(r.issues));
}

console.log('\n[7] 接线：validate-frida-script 里必须跑 lint');
{
  const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
  ok(/require\('\.\/frida-lint'\)/.test(mainSrc), 'main.js require frida-lint');
  ok(/lintAndRepair/.test(mainSrc), '调用 lintAndRepair');
  ok(/结构检查未通过/.test(mainSrc), 'lint 失败时返回可读错误（触发上层重生成）');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
