// 回归：P0.2「骨架先行」的预算纪律判据。
// 实测教训：86 道题里大量失败题不是败在"不会解"，而是 AI 把 60 轮预算的
// 前 30-40 轮全花在反编译/读字节上，等意识到该写脚本时预算已所剩无几。
// 软提示词约束不住，因此代码在第 16 轮检查"整个会话有没有跑过脚本"，
// 第 45 轮检查"有没有开始收敛到契约"。两处各管一段，且与 SPRINT_AT=50 的冲刺并存。
//
// 与 test_land_nudge.js 同法：直接抽取 main.js 里的判据源码包成 evaluate，
// 保证测试与实现同源，不会两边各写一份悄悄漂移。
const fs = require('fs');
const p = require('path');
const src = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

// ⚠️ 源码是 CRLF，行尾必须写 \r?\n。
const grab = (re) => { const m = src.match(re); if (!m) throw new Error('未找到: ' + re); return m[0]; };
const scriptToolReSrc = grab(/const SCRIPT_TOOL_RE = [^\r\n]*\r?\n/);
// 骨架判据：从 reduce 一直抓到 skeletonNudge 赋值语句的结尾（跨两行，必须匹配到分号）。
const skeletonSrc = grab(/const scriptCallsSeen = [\s\S]*?const skeletonNudge = [\s\S]*?;\r?\n/);
const contractSrc = grab(/const hasContractSoFar = [^\r\n]*\r?\n/);
const convergeSrc = grab(/const convergeNudge = [\s\S]*?conversationHistory\.length > 2;\r?\n/);

const mod = { exports: {} };
new Function('module', 'exports',
  'function evaluate(ctx) {\n'
  + '  const conversationHistory = ctx.history;\n'
  + '  const collectedText = ctx.collectedText || "";\n'
  + '  const sawScriptTool = !!ctx.sawScriptTool;\n'
  + '  const skeletonNudgeCount = ctx.skeletonNudgeCount || 0;\n'
  + '  const convergeNudged = !!ctx.convergeNudged;\n'
  + '  const roundsUsed = ctx.roundsUsed;\n'
  + '  const SKELETON_AT = ctx.SKELETON_AT || 16;\n'
  + '  const CONVERGE_AT = ctx.CONVERGE_AT || 45;\n'
  + scriptToolReSrc + skeletonSrc + contractSrc + convergeSrc
  + '  return { scriptCallsSeen, hasScriptCall, skeletonNudge, hasContractSoFar, convergeNudge };\n'
  + '}\nmodule.exports={evaluate};')(mod, mod.exports);
const { evaluate } = mod.exports;

// 模拟"只做侦察"的对话：有工具调用，但全是反编译/读字节，从未跑过脚本。
const reconHistory = () => ([
  { role: 'user', content: 'solve it' },
  { role: 'assistant', content: [{ type: 'text', text: 'reading' }, { type: 'tool_use', id: 't1', name: 'ida_decompile', input: {} }] },
  { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: 'ok' }] },
  { role: 'assistant', content: [{ type: 'text', text: 'reading more' }, { type: 'tool_use', id: 't2', name: 'ida_get_bytes', input: {} }] },
  { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't2', content: 'ok' }] }
]);

// 在侦察历史后追加一次 run_python 调用（会话里出现过脚本）。
const scriptHistory = () => reconHistory().concat([
  { role: 'assistant', content: [{ type: 'text', text: 'write skeleton' }, { type: 'tool_use', id: 't3', name: 'run_python', input: { script: 'print(1)' } }] },
  { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't3', content: '1' }] }
]);

const ctx = (over = {}) => Object.assign({
  history: reconHistory(),
  collectedText: '',
  sawScriptTool: false,
  skeletonNudgeCount: 0,
  convergeNudged: false,
  roundsUsed: 16
}, over);

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m + (extra ? ' → ' + extra : '')); } };

console.log('[第 16 轮骨架检查]');
{
  const r = evaluate(ctx({ roundsUsed: 16 }));
  ok(r.scriptCallsSeen === 0 && r.hasScriptCall === false, '0 次脚本工具调用被正确识别');
  ok(r.skeletonNudge === true, '0 次脚本调用 + 已到第 16 轮 → 触发骨架催促');
}
{
  const r = evaluate(ctx({ roundsUsed: 15 }));
  ok(r.skeletonNudge === false, '第 15 轮（侦察期末尾）不触发');
}
{
  const r = evaluate(ctx({ roundsUsed: 20, history: scriptHistory() }));
  ok(r.scriptCallsSeen === 1 && r.hasScriptCall === true, '已有 run_python 调用');
  ok(r.skeletonNudge === false, '已有 run_python 调用 → 不触发');
}
{
  // bash / run_command 同样算"动手跑过"，不能只认 run_python。
  const hist = reconHistory().concat([
    { role: 'assistant', content: [{ type: 'tool_use', id: 't9', name: 'bash', input: { command: 'python x.py' } }] }
  ]);
  const r = evaluate(ctx({ history: hist }));
  ok(r.hasScriptCall === true && r.skeletonNudge === false, 'bash 调用同样视为已有骨架');
}
{
  // 上下文压缩会丢掉早期 assistant 消息，sawScriptTool 标记必须兜住。
  const r = evaluate(ctx({ history: reconHistory(), sawScriptTool: true, roundsUsed: 18 }));
  ok(r.skeletonNudge === false, '压缩后 history 无记录但 sawScriptTool=true → 不误催');
}
{
  const r = evaluate(ctx({ skeletonNudgeCount: 2, roundsUsed: 30 }));
  ok(r.skeletonNudge === false, 'skeletonNudgeCount=2（额度用尽）→ 不再触发');
}
{
  const r = evaluate(ctx({ skeletonNudgeCount: 1, roundsUsed: 17 }));
  ok(r.skeletonNudge === true, '第 1 次催促后仍未跑脚本 → 保留第 2 次额度');
}

console.log('[第 45 轮收敛催促]');
{
  const r = evaluate(ctx({ roundsUsed: 44, history: scriptHistory() }));
  ok(r.convergeNudge === false, '第 44 轮不触发');
}
{
  const r = evaluate(ctx({ roundsUsed: 45, history: scriptHistory() }));
  ok(r.hasContractSoFar === false, '尚无契约');
  ok(r.convergeNudge === true, '第 45 轮仍无契约 → 触发收敛催促');
}
{
  const r = evaluate(ctx({ roundsUsed: 46, collapse: true, history: scriptHistory(), convergeNudged: true }));
  ok(r.convergeNudge === false, 'convergeNudged=true → 只注入一次，后续轮不再触发');
}
{
  const r = evaluate(ctx({ roundsUsed: 45, history: scriptHistory(), collectedText: '[VERIFY]{"algo":"rc4"}[/VERIFY]' }));
  ok(r.hasContractSoFar === true && r.convergeNudge === false, '已有 [VERIFY] → 不催');
}
{
  const r = evaluate(ctx({ roundsUsed: 45, history: scriptHistory(), collectedText: '[HYPOTHESES][{"algo":"aes"}][/HYPOTHESES]' }));
  ok(r.convergeNudge === false, '已有 [HYPOTHESES] → 不催');
}

console.log('[话术与共存关系]');
{
  // 第 2 次骨架催促必须是"硬指令"：把已读到的地址/常量先写进脚本跑起来。
  const idx = src.indexOf('const skeletonLastChance');
  const block = src.slice(idx, idx + 1400);
  ok(/skeletonNudgeCount >= 2/.test(grab(/const skeletonLastChance = [^\r\n]*\r?\n/)), '第 2 次才进入最后提醒分支');
  ok(block.indexOf('函数地址') !== -1 && block.indexOf('常量') !== -1, '硬指令包含「函数地址和常量」');
  ok(block.indexOf('run_python') !== -1, '硬指令点名 run_python');
}
{
  // 第 45 轮必须点名三种契约，且明确"不能只写概括性描述"。
  const block = src.slice(src.indexOf('const convergeNudge ='), src.indexOf('const convergeNudge =') + 1400);
  ok(block.indexOf('[VERIFY]') !== -1 && block.indexOf('[HYPOTHESES]') !== -1, '收敛催促列出 [VERIFY]/[HYPOTHESES]');
  ok(block.indexOf('概括性描述') !== -1, '禁止收工时只写概括性描述');
}
{
  // 三段预算与既有 SPRINT_AT 必须并存而非互相覆盖。
  ok(/SKELETON_AT = parseInt\(process\.env\.CTF_SKELETON_AT, 10\) \|\| 16/.test(src), '骨架检查固定在 16 轮');
  ok(/CONVERGE_AT = parseInt\(process\.env\.CTF_CONVERGE_AT, 10\) \|\| 45/.test(src), '收敛催促固定在 45 轮');
  ok(/SPRINT_AT = parseInt\(process\.env\.CTF_SPRINT_AT, 10\) \|\| 50/.test(src), 'SPRINT_AT=50 的冲刺仍然保留');
  ok(src.indexOf('if (skeletonNudge)') > 0
    && src.indexOf('if (skeletonNudge)') < src.indexOf('if (!sprintInjected'), '骨架检查位于冲刺指令之前，各管一段');
}

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
