// 回归：分层收尾策略（P0.1）的判据。
// 实测教训：86 道题里 49 道（57%）不是"没读代码"，而是读出了函数地址/常量/偏移后，
// 只输出一段"程序先做 A 再做 B"的描述就收工。旧检测只会催"继续挖"，
// 对这类题是错位的——它缺的是"把已知量落成可跑的 run_python 骨架"。
// 因此在"浅层收工"之后再加一级"落地检查单"，两级计数彼此独立。
//
// 与 test_shallow_giveup.js 同法：直接抽取 main.js 里的判据源码，包成 evaluate 做行为测试
// （与实现同源，避免测试写一份、实现写一份，两边悄悄漂移）。
const fs = require('fs');
const p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

// ⚠️ 源码是 CRLF，行尾必须写 \r?\n（只写 \n 匹配不到）。
const grab = (re) => { const m = src.match(re); if (!m) throw new Error('未找到: ' + re); return m[0]; };
const gaveConclusionSrc = grab(/const gaveConclusion = [^\r\n]*\r?\n/);
const statedBlockerSrc = grab(/const statedBlocker = [^\r\n]*\r?\n/);
const didUseToolsSrc = grab(/const didUseTools = [\s\S]*?;\r?\n/);
const budgetLeftSrc = grab(/const budgetLeft = [^\r\n]*\r?\n/);
const toolUseCountSrc = grab(/const toolUseCount = [^\r\n]*\r?\n/);
const concreteEvidenceSrc = grab(/const concreteEvidence = [^\r\n]*\r?\n/);
const hasConcreteProgressSrc = grab(/const hasConcreteProgress = [^\r\n]*\r?\n/);
const shallowGiveUpSrc = grab(/const shallowGiveUp = [^\r\n]*\r?\n/);
const landNudgeSrc = grab(/const landNudge = [^\r\n]*\r?\n/);

const mod = { exports: {} };
new Function('module', 'exports',
  'function evaluate(response, ctx) {\n'
  + '  const conversationHistory = ctx.history;\n'
  + '  const collectedText = ctx.collectedText;\n'
  + '  const maxIterations = ctx.maxIterations;\n'
  + '  const MAX_TOOL_ITERATIONS = ctx.maxIterationsTotal;\n'
  + '  const shallowNudgeCount = ctx.shallowNudgeCount || 0;\n'
  + '  const landNudgeCount = ctx.landNudgeCount || 0;\n'
  + gaveConclusionSrc + statedBlockerSrc + didUseToolsSrc + budgetLeftSrc
  + toolUseCountSrc + concreteEvidenceSrc + hasConcreteProgressSrc
  + shallowGiveUpSrc + landNudgeSrc
  + '  return { gaveConclusion, statedBlocker, didUseTools, hasConcreteProgress, shallowGiveUp, landNudge };\n'
  + '}\nmodule.exports={evaluate};')(mod, mod.exports);
const { evaluate } = mod.exports;

// 模拟"已用过工具"的对话：两条 assistant 消息各带一次 tool_use（toolUseCount=2）。
const usedToolsHistory = () => ([
  { role: 'user', content: 'solve it' },
  { role: 'assistant', content: [{ type: 'text', text: 'reading' }, { type: 'tool_use', id: 't1', name: 'decompile', input: {} }] },
  { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: 'ok' }] },
  { role: 'assistant', content: [{ type: 'text', text: 'reading more' }, { type: 'tool_use', id: 't2', name: 'ida_get_bytes', input: {} }] },
  { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't2', content: 'ok' }] }
]);

// 默认上下文：预算充足（剩余 80%）、未催促过。
const ctx = (over = {}) => Object.assign({
  history: usedToolsHistory(),
  collectedText: '',
  maxIterations: 48,
  maxIterationsTotal: 60,
  shallowNudgeCount: 0,
  landNudgeCount: 0
}, over);

const check = (text, over) => evaluate({ text }, ctx(over));
const noNudge = (r) => !r.shallowGiveUp && !r.landNudge;

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m + (extra ? ' → ' + extra : '')); } };

console.log('[第一级：有契约 → 不触发任何催促]');
{
  const r = check('flag is [FLAG]flag{abc}[/FLAG]');
  ok(r.gaveConclusion === true && noNudge(r), '有 FLAG');
}
{
  const r = check('验证契约 [VERIFY]{"algo":"rc4"}[/VERIFY]');
  ok(r.gaveConclusion === true && noNudge(r), '有 VERIFY');
}
{
  const r = check('[HYPOTHESES][{"algo":"aes"}][/HYPOTHESES]');
  ok(r.gaveConclusion === true && noNudge(r), '有 HYPOTHESES');
}

console.log('[第二级：无契约 + 已用工具 + 进展明确 → 落地检查单（第 1 次）]');
{
  // 典型的 57% 失败形态：手里有地址/常量，但输出是描述性文字。
  const text = 'sub_140001380 at 0x140001380 compares input against a table, constant 0x9E3779B9 used.';
  const r = check(text, { collectedText: text });
  ok(r.gaveConclusion === false, '无契约');
  ok(r.hasConcreteProgress === true, '识别出明确进展（地址/常量）');
  ok(r.landNudge === true && r.shallowGiveUp === false, '只触发落地催促，不再走旧的浅层催促');
  ok(r.statedBlocker === false, '未声明卡点');
}
{
  const text = '常量表位于 0x4020，偏移 = 0x1A0，已验证 XOR 变换。';
  const r = check(text, { collectedText: text });
  ok(r.hasConcreteProgress === true && r.landNudge === true, '中文进展（常量表/偏移）同样触发');
}
{
  // 旧的 shallow 额度已用尽，仍应保留独立的落地机会（计数分开）。
  const text = 'sub_140001380 at 0x140001380 uses 0x9E3779B9.';
  const r = check(text, { collectedText: text, shallowNudgeCount: 2 });
  ok(r.landNudge === true, 'shallowNudgeCount 用满后仍可触发落地催促');
}

console.log('[第三级：无契约且无明确进展 → 保持现有浅层催促]');
{
  const text = 'The program is a 64-bit PE. It recursively enumerates binary strings and validates the input.';
  const r = check(text, { collectedText: text });
  ok(r.hasConcreteProgress === false, '未识别出可落地进展');
  ok(r.shallowGiveUp === true && r.landNudge === false, '走旧的浅层催促');
}
{
  // 只有一次工具调用，不足以说明"进展明确"。
  const hist = usedToolsHistory().filter((m, i) => i < 3);
  const text = 'sub_140001380 at 0x140001380.';
  const r = check(text, { history: hist, collectedText: text });
  ok(r.hasConcreteProgress === false && r.shallowGiveUp === true, '少于 2 次工具调用不算进展明确');
}

console.log('[明确声明卡点时不催促（两级都生效）]');
{
  const text = '无法继续：需要用户提供 stage2 文件。已读到 sub_140001380 @ 0x140001380，常量 0x9E3779B9。';
  const r = check(text, { collectedText: text });
  ok(r.statedBlocker === true, '识别为卡点声明');
  ok(noNudge(r), '需要用户提供 → 不催促');
}
{
  const text = '缺少 IDA MCP 连接，工具不可用。已知 sub_140001380 @ 0x140001380 和常量 0x9E3779B9。';
  const r = check(text, { collectedText: text });
  ok(r.statedBlocker === true && noNudge(r), '缺少工具 → 不催促');
}
{
  const text = 'I am unable to proceed without the symbol table. Known: sub_140001380 at 0x140001380, constant 0x9E3779B9.';
  const r = check(text, { collectedText: text });
  ok(r.statedBlocker === true && noNudge(r), 'unable → 不催促');
}

console.log('[landNudgeCount 上限 2：第 3 次调用直接返回]');
{
  const text = 'sub_140001380 at 0x140001380 uses 0x9E3779B9.';
  const r1 = check(text, { collectedText: text, landNudgeCount: 0 });
  ok(r1.landNudge === true, '第 1 次催促');
  const r2 = check(text, { collectedText: text, landNudgeCount: 1 });
  ok(r2.landNudge === true, '第 2 次催促');
  const r3 = check(text, { collectedText: text, landNudgeCount: 2 });
  ok(r3.landNudge === false && noNudge(r3), '第 3 次调用不再催促（直接返回）');
}

console.log('[预算不足时不再催促]');
{
  const text = 'sub_140001380 at 0x140001380 uses 0x9E3779B9.';
  const r = check(text, { collectedText: text, maxIterations: 10 });
  ok(r.landNudge === false && noNudge(r), '剩余预算 < 1/3 时直接返回');
}

console.log('[第 2 次催促带"最后机会"话术]');
{
  // 第 2 次催促必须给 AI 一个退路：宁可产出候选 [HYPOTHESES]，也不要再用描述性文字收工。
  const lastChanceSrc = grab(/const lastChance = [^\r\n]*\r?\n/);
  const promptBlock = src.slice(src.indexOf('const lastChance ='), src.indexOf('const lastChance =') + 2000);
  ok(/lastChance = landNudgeCount >= 2/.test(lastChanceSrc), '第 2 次才进入最后机会分支');
  ok(promptBlock.indexOf('最后机会') !== -1, '提示词包含"最后机会"');
  ok(promptBlock.indexOf('[HYPOTHESES]') !== -1, '最后机会要求给出 [HYPOTHESES] 候选');
}

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
