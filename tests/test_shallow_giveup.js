// 回归：Tool-Use 循环里的"浅层收工"检测。
// 实测（CrackMe5）：AI 只调了 6 次工具（scan_crypto + 3 次 decompile），7 秒后返回一段
// 描述性文字，既无 [FLAG] 也无 [VERIFY]，流程结束、整题判失败。
//
// 直接抽取 main.js 里的三个判据源码，包成 evaluate(response) 做行为测试（与实现同源）。
const fs = require('fs');
const p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

// ⚠️ 源码是 CRLF，行尾必须写 \r?\n（只写 \n 匹配不到）。
const grab = (re) => { const m = src.match(re); if (!m) throw new Error('未找到: ' + re); return m[0]; };
const wantsActionSrc = grab(/const wantsAction = [\s\S]*?;\r?\n/);
const gaveConclusionSrc = grab(/const gaveConclusion = [^\r\n]*\r?\n/);
const statedBlockerSrc = grab(/const statedBlocker = [^\r\n]*\r?\n/);

const mod = { exports: {} };
new Function('module', 'exports',
  'function evaluate(response) {\n'
  + wantsActionSrc + gaveConclusionSrc + statedBlockerSrc
  + '  return { wantsAction, gaveConclusion, statedBlocker };\n'
  + '}\nmodule.exports={evaluate};')(mod, mod.exports);
const { evaluate } = mod.exports;
const check = (text) => evaluate({ text });

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m + (extra ? ' → ' + extra : '')); } };

console.log('[CrackMe5 实测文本：应被识别为浅层收工]');
{
  const r = check('The program is a 64-bit PE. sub_140001380 recursively enumerates binary strings, '
    + 'and sub_140001300 computes a value from the input. It appears to validate the input against a stored table.');
  ok(r.gaveConclusion === false, '无 FLAG/VERIFY/HYPOTHESES');
  ok(r.statedBlocker === false, '没有明确声明卡点');
}

console.log('[有结论时不催促]');
ok(check('flag is [FLAG]flag{abc}[/FLAG]').gaveConclusion === true, '有 FLAG');
ok(check('验证契约 [VERIFY]{"algo":"rc4"}[/VERIFY]').gaveConclusion === true, '有 VERIFY');
ok(check('[HYPOTHESES][{"algo":"aes"}][/HYPOTHESES]').gaveConclusion === true, '有 HYPOTHESES');

console.log('[明确说明卡点时不催促]');
ok(check('无法继续：需要用户提供 stage2 文件').statedBlocker === true, '需要用户提供');
ok(check('缺少 IDA MCP 连接，工具不可用').statedBlocker === true, '缺少工具');
ok(check('I am unable to proceed without the symbol table').statedBlocker === true, 'unable');

console.log('["只说不做"仍单独工作]');
ok(check('让我先反编译 main 函数看看').wantsAction === true, '中文行动意图');
ok(check('Let me read the constant table').wantsAction === true, '英文行动意图');
ok(check('程序包含一个循环').wantsAction === false, '纯描述不误判');

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
