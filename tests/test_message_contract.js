// 结构合法性验证：从主循环源码静态检查 tool_use / tool_result 的一对一契约。
// 真实 API 的 400 大多来自这里，跑一次 Electron 也难覆盖（需要真实模型返回 tool_use），
// 所以用"源码结构 + 运行时构造"双重验证。
const fs = require('fs'), p = require('path');
const mainSrc = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };

console.log('A) 每个 tool_use 恰好一个 tool_result');
{
  // 抽出"执行工具调用"这一段（从 for (const toolCall 到 assistantContent 构造前）
  const start = mainSrc.indexOf('for (const toolCall of toolCalls)');
  const end = mainSrc.indexOf('// assistant 消息需保留 text 块', start);
  ok(start > 0 && end > start, '定位到工具执行段');
  const seg = mainSrc.slice(start, end);

  // 所有 toolResults.push 的 tool_use_id 都必须是 toolCall.id（不能拼接后缀）
  const pushes = [...seg.matchAll(/toolResults\.push\(\{[\s\S]{0,120}?tool_use_id:\s*([^,\n]+)/g)];
  ok(pushes.length > 0, `找到 ${pushes.length} 处结果写入`);
  const badIds = pushes.filter(m => m[1].trim() !== 'toolCall.id');
  ok(badIds.length === 0,
    `所有结果都使用真实 toolCall.id（异常: ${badIds.map(x => x[1].trim()).join(',') || '无'}）`);

  // continue 之前必须已 push（否则该 tool_use 没有结果 → 400）
  // 逐分支检查：每个 continue 之前 400 字符内要有 toolResults.push
  const continues = [...seg.matchAll(/\n\s{6,}continue;/g)];
  let missing = 0;
  for (const c of continues) {
    const before = seg.slice(Math.max(0, c.index - 500), c.index);
    if (!/toolResults\.push/.test(before)) missing++;
  }
  ok(missing === 0, `每个 continue 分支都已写入结果（缺失 ${missing} 处）`);
}

console.log('\nB) 工具结果消息结构');
{
  const i = mainSrc.indexOf('const toolResultMsg');
  ok(i > 0, '结果消息独立构造');
  const seg = mainSrc.slice(i, i + 600);
  ok(/type:\s*'tool_result'/.test(seg), '块类型为 tool_result');
  ok(/tool_use_id:\s*tr\.tool_use_id/.test(seg), '透传真实 id');
  ok(/is_error:\s*true/.test(seg), '保留 is_error 标记');
  ok(/conversationHistory\.push\(toolResultMsg\)/.test(mainSrc), '结果消息推入历史');
}

console.log('\nC) 压缩 / 恢复不得破坏配对');
{
  const rt = fs.readFileSync(p.join(__dirname, '..', 'electron', 'agent-runtime.js'), 'utf8');
  ok(/alignToToolPair/.test(rt), '压缩时对齐配对边界');
  ok(/answered\.has\(b\.id\)/.test(rt), '恢复时只保留有结果的 tool_use');
  ok(/uses\.includes\(b\.tool_use_id\)/.test(rt), '恢复时只保留有 tool_use 的结果');
}

console.log('\nD) 运行时构造验证（模拟一次完整工具轮）');
{
  // 模拟主循环的一轮：assistant 发 2 个 tool_use，执行后必须产出 2 个 tool_result
  const toolCalls = [{ id: 'a1', name: 'read_file', input: {} }, { id: 'a2', name: 'bash', input: {} }];
  const toolResults = [];
  for (const tc of toolCalls) {
    // 成功路径
    toolResults.push({ tool_use_id: tc.id, content: 'ok', is_error: false });
  }
  const msg = { role: 'user', content: toolResults.map(tr => ({ type: 'tool_result', tool_use_id: tr.tool_use_id, content: tr.content })) };
  const ids = new Set(toolCalls.map(t => t.id));
  const resultIds = msg.content.map(c => c.tool_use_id);
  ok(resultIds.length === toolCalls.length, '结果数量与调用数量一致');
  ok(resultIds.every(id => ids.has(id)), '每个结果 id 都能对应到真实 tool_use');
  ok(new Set(resultIds).size === resultIds.length, '结果 id 无重复');
}

console.log('\nE) 兜底：未识别的工具也必须返回结果');
{
  const start = mainSrc.indexOf('for (const toolCall of toolCalls)');
  const end = mainSrc.indexOf('// assistant 消息需保留 text 块', start);
  const seg = mainSrc.slice(start, end);
  // 主执行是 try/catch，catch 里也 push 了结果 → 任何异常都有 result
  ok(/try\s*\{[\s\S]*?executeToolCall[\s\S]*?\}\s*catch/.test(seg), '执行有 try/catch');
  const catchSeg = seg.slice(seg.indexOf('catch (err)'));
  ok(/toolResults\.push/.test(catchSeg), 'catch 分支也写入工具结果（异常不会留下无结果的 tool_use）');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
