// 回归：分层收尾第四级「零新数据拦截」（P0.3）。
// 实测教训：前三级催促用的是"继续挖/落地"的话术，模型可以原样把概括性描述再交一遍；
// 若整轮文本里连一个本轮真实读到的字节/数值/代码片段都没有，这道题等于白做。
// 因此第四级只认"硬数据"：hex≥8、反编译代码特征、= 具体数值、≥20 字符的引号串。
//
// 与 test_land_nudge.js 同法：直接抽取 main.js 的判据源码包成 evaluate，
// 避免测试与实现各写一份、悄悄漂移。
const fs = require('fs');
const p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

// ⚠️ 源码是 CRLF，行尾必须写 \r?\n（只写 \n 匹配不到）。
const grab = (re) => { const m = src.match(re); if (!m) throw new Error('未找到: ' + re); return m[0]; };
const gaveConclusionSrc = grab(/const gaveConclusion = [^\r\n]*\r?\n/);
const statedBlockerSrc = grab(/const statedBlocker = [^\r\n]*\r?\n/);
const didUseToolsSrc = grab(/const didUseTools = [\s\S]*?;\r?\n/);
const budgetLeftSrc = grab(/const budgetLeft = [^\r\n]*\r?\n/);
const hasNewDataSrc = grab(/const recentToolText = \(\(\) => \{[\s\S]*?const hasNewData = [^\r\n]*\r?\n/);
const dataNudgeSrc = grab(/const dataNudge = [\s\S]*?;\r?\n/);

const mod = { exports: {} };
new Function('module', 'exports',
  'function evaluate(response, ctx) {\n'
  + '  const conversationHistory = ctx.history;\n'
  + '  const maxIterations = ctx.maxIterations;\n'
  + '  const MAX_TOOL_ITERATIONS = ctx.maxIterationsTotal;\n'
  + '  const dataNudgeCount = ctx.dataNudgeCount || 0;\n'
  + '  const shallowGiveUp = !!ctx.shallowGiveUp;\n'
  + '  const landNudge = !!ctx.landNudge;\n'
  + gaveConclusionSrc + statedBlockerSrc + didUseToolsSrc + budgetLeftSrc
  + hasNewDataSrc + dataNudgeSrc
  + '  return { gaveConclusion, statedBlocker, didUseTools, hasNewData, hexLike, decompiledLike, computedLike, quotedLike, dataNudge };\n'
  + '}\nmodule.exports={evaluate};')(mod, mod.exports);
const { evaluate } = mod.exports;

// 模拟"已用过工具"的对话（didUseTools=true）。最近一条 tool_result 默认是无关内容，
// 保证命中的是 response.text 本身而不是历史噪声。
const usedToolsHistory = (toolResult) => ([
  { role: 'user', content: 'solve it' },
  { role: 'assistant', content: [{ type: 'text', text: 'reading' }, { type: 'tool_use', id: 't1', name: 'decompile', input: {} }] },
  { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: toolResult === undefined ? 'done' : toolResult }] }
]);

// 默认上下文：预算充足（剩余 80%）、未催促过、三级均未命中。
const ctx = (over = {}) => Object.assign({
  history: usedToolsHistory(),
  maxIterations: 48,
  maxIterationsTotal: 60,
  dataNudgeCount: 0
}, over);

const check = (text, over) => evaluate({ text }, ctx(over));
const nudged = (r) => r.dataNudge === true;

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m + (extra ? ' → ' + extra : '')); } };

console.log('[有硬数据 → 不催]');
{
  const r = check('The obfuscated prologue reads 83ec18b065b16388 from the entry point.');
  ok(r.hexLike === true, 'hex≥8（含数字）算新增数据');
  ok(r.hasNewData === true && !nudged(r), '不触发取数催促');
}
{
  const r = check('v6 = 0x9E3779B9');
  ok(r.computedLike === true, '"= 数值"算计算结果');
  ok(r.hasNewData === true && !nudged(r), '不触发取数催促');
}
{
  const r = check('if (v6 == 0x20) { return 0; }');
  ok(r.decompiledLike === true, '反编译代码特征（; { } 与 = / (）');
  ok(r.hasNewData === true && !nudged(r), '不触发取数催促');
}
{
  const r = check('The table entry is "ABCDEFGHIJKLMNOPQRSTUVWX".');
  ok(r.quotedLike === true, '≥20 字符引号串');
  ok(r.hasNewData === true && !nudged(r), '不触发取数催促');
}
{
  // tool_result 里已有真实字节，即使 response.text 没引用，也不算零新数据。
  const r = check('The program validates the input against a table.', {
    history: usedToolsHistory('bytes: 83ec18b065b16388')
  });
  ok(r.hasNewData === true, '紧邻 tool_result 的字节被计入');
  ok(!nudged(r), '不触发取数催促');
}

console.log('[零新数据 → 触发取数催促]');
{
  const text = 'The program validates the input against a table';
  const r = check(text);
  ok(r.hasNewData === false, '纯描述没有任何硬数据');
  ok(r.didUseTools === true && r.gaveConclusion === false && r.statedBlocker === false, '已用工具/无契约/无卡点');
  ok(nudged(r), '触发取数催促');
}
{
  // 纯英文单词形态的 hex 字母（deadbeef 无数字、长度 8）不应被当成字节证据。
  const r = check('The feedback deadbeef string is compared.');
  ok(r.hexLike === false, '纯英文单词形态的 8 位 hex 字母不算');
}

console.log('[dataNudgeCount 上限 2：第 3 次调用直接返回]');
{
  const text = 'The program validates the input against a table';
  ok(nudged(check(text, { dataNudgeCount: 0 })), '第 1 次催促');
  ok(nudged(check(text, { dataNudgeCount: 1 })), '第 2 次催促');
  ok(!nudged(check(text, { dataNudgeCount: 2 })), '第 3 次不再催促（直接返回）');
}

console.log('[有契约 / 声明卡点 → 不催]');
{
  const r = check('flag is [FLAG]flag{abc}[/FLAG]');
  ok(r.gaveConclusion === true, '有 FLAG');
  ok(!nudged(r), '有契约不催');
}
{
  const r = check('验证契约 [VERIFY]{"algo":"rc4"}[/VERIFY]');
  ok(r.gaveConclusion === true && !nudged(r), '有 VERIFY 不催');
}
{
  const r = check('无法继续：需要用户提供 stage2 文件');
  ok(r.statedBlocker === true, '识别为卡点声明');
  ok(!nudged(r), '声明卡点不催');
}

console.log('[同轮只催一次：前三层已命中时不叠加本闸]');
{
  const text = 'The program validates the input against a table';
  ok(!nudged(check(text, { shallowGiveUp: true })), 'shallowGiveUp 同轮命中时不叠加');
  ok(!nudged(check(text, { landNudge: true })), 'landNudge 同轮命中时不叠加');
}

console.log('[预算不足时不再催促]');
{
  const r = check('The program validates the input against a table', { maxIterations: 10 });
  ok(!nudged(r), '剩余预算 < 1/3 时直接返回');
}

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
