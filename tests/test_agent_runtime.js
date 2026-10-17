// Agent 运行时单测（借鉴 openclaude 的四块能力）
//   A1 大输出落盘 + 60/40 头尾预览
//   A2 旧工具结果微压缩
//   B1 连续相同调用拦截 / B2 跨轮失败环
//   D1 会话日志 + 恢复清洗
//   A3/C1 确定性压缩与经验检索
const fs = require('fs'), os = require('os'), p = require('path');
const R = require('../electron/agent-runtime.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };
const tmp = fs.mkdtempSync(p.join(os.tmpdir(), 'ctf-rt-'));

console.log('A1) 大输出：头尾都要保留，且能落盘回读');
{
  const total = 100000;
  const text = 'HEAD_MARK\n' + 'x'.repeat(total) + '\nTAIL_MARK_ERROR_STACK';
  const out = R.persistToolResult(text, { maxChars: 2000 });
  ok(out.length <= 2000 + 200, `预览被限制在阈值内（${out.length}）`);
  ok(out.includes('HEAD_MARK'), '保留头部');
  ok(/bytes omitted/.test(out), '无落盘目录时仍给出省略标记与尾部预览');

  const dir = p.join(tmp, 'tool-results');
  const full = R.persistToolResult(text, { maxChars: 2000, dir, id: 'call-1' });
  ok(full.includes('<persisted-output'), '有目录时生成落盘标记');
  ok(full.includes('TAIL_MARK_ERROR_STACK'), '尾部错误信息被保留（旧实现只截头会丢掉）');
  ok(/bytes omitted/.test(full), '包含省略标记');
  const m = full.match(/file="([^"]+)"/);
  ok(!!m && fs.existsSync(m[1]), '落盘文件真实存在');
  ok(fs.readFileSync(m[1], 'utf8').length === text.length, '落盘内容完整');

  // 小输出不处理
  ok(R.persistToolResult('short', { maxChars: 100 }) === 'short', '小输出原样返回');
}

console.log('\nA2) 微压缩：清旧结果、保留现场与错误');
{
  const history = [];
  for (let i = 0; i < 10; i++) {
    history.push({ role: 'assistant', content: [{ type: 'tool_use', id: 'u' + i, name: 'read_file', input: {} }] });
    history.push({
      role: 'user',
      content: [{ type: 'tool_result', tool_use_id: 'u' + i, content: 'BIG_OUTPUT_' + i, ...(i === 2 ? { is_error: true } : {}) }],
    });
  }
  const r = R.microcompact(history, 4);
  const blocks = history.flatMap(m => Array.isArray(m.content) ? m.content.filter(b => b.type === 'tool_result') : []);
  ok(r.cleared > 0, `清理了 ${r.cleared} 条旧结果`);
  ok(blocks.slice(0, 2).every(b => b.content === R.CLEARED), '最旧的结果已被清理');
  ok(blocks.slice(-4).some(b => String(b.content).startsWith('BIG_OUTPUT_')), '最近 4 条保持原样');
  ok(blocks[2].content === 'BIG_OUTPUT_2', 'is_error 的结果不被清理（纠错依据）');
  ok(blocks.every(b => b.tool_use_id), 'tool_use_id 全部保留（否则 API 400）');
}

console.log('\nB1) 连续相同调用：3 次即拦，签名变化重置');
{
  const g = new R.DoomLoopGuard(3);
  ok(!g.check('read_file', { path: 'a' }).blocked, '第 1 次放行');
  ok(!g.check('read_file', { path: 'a' }).blocked, '第 2 次放行');
  const third = g.check('read_file', { path: 'a' });
  ok(third.blocked, '第 3 次拦截');
  ok(g.check('read_file', { path: 'a' }).blocked, '拦截状态保持');
  ok(!g.check('read_file', { path: 'b' }).blocked, '换参数后恢复放行');
  g.reset();
  ok(!g.check('read_file', { path: 'b' }).blocked, 'reset 后重新计数');
  // 完整入参哈希：只差尾部内容也必须视为不同调用
  const h1 = R.signatureOf('write_file', { path: 'a', content: 'x'.repeat(3000) + 'A' });
  const h2 = R.signatureOf('write_file', { path: 'a', content: 'x'.repeat(3000) + 'B' });
  ok(h1 !== h2, '哈希覆盖完整入参（不做前缀截断）');
}

console.log('\nB2) 跨轮失败环：第 2 次提醒、第 3 次判定走不通');
{
  const g = new R.FailureLoopGuard(3);
  const e = 'Error: no such file or directory';
  const r1 = g.recordFailure('read_file', e, '/x/a.bin');
  ok(!r1.tripped && !r1.advisory, '第 1 次仅记录');
  const r2 = g.recordFailure('read_file', e, '/x/a.bin');
  ok(!r2.tripped && !!r2.advisory, '第 2 次给出 advisory');
  ok(/换工具或换假设/.test(r2.advisory), 'advisory 明确要求换路线');
  const r3 = g.recordFailure('read_file', e, '/x/a.bin');
  ok(r3.tripped, '第 3 次判定为失败环');
  ok(r3.category === 'NotFound', `错误类别归一化为 NotFound（实际 ${r3.category}）`);

  // 不同类别不应互相累计
  const g2 = new R.FailureLoopGuard(3);
  g2.recordFailure('bash', 'command not found');
  g2.recordFailure('bash', 'timeout');
  const other = g2.recordFailure('bash', 'permission denied');
  ok(!other.tripped, '不同错误类别不合并计数');

  // 成功写操作重置
  const g3 = new R.FailureLoopGuard(3);
  g3.recordFailure('write_file', 'permission denied', '/x/b.bin');
  g3.recordFailure('write_file', 'permission denied', '/x/b.bin');
  g3.recordSuccess('write_file', '/x/b.bin');
  const after = g3.recordFailure('write_file', 'permission denied', '/x/b.bin');
  ok(!after.tripped, '成功写操作后计数重置');

  // 类别提示覆盖 CTF 常见场景
  const g4 = new R.FailureLoopGuard(3);
  g4.recordFailure('ida_decompile', 'no such function: foo');
  const adv = g4.recordFailure('ida_decompile', 'no such function: foo');
  ok(/main\/_main\/WinMain/.test(adv.advisory || ''), 'NoSymbol 给出候选函数名');
}

console.log('\nD1) 会话日志 + 恢复清洗');
{
  const dir = p.join(tmp, 'sessions');
  const log = new R.SessionLog(dir, 'sess-1');
  log.append('user', 'solve this');
  log.append('assistant', [{ type: 'text', text: 'working' }, { type: 'tool_use', id: 'u1', name: 'read_file', input: {} }]);
  log.append('user', [{ type: 'tool_result', tool_use_id: 'u1', content: 'data' }]);
  // 一条未完成的 tool_use（崩溃现场）
  log.append('assistant', [{ type: 'tool_use', id: 'u2', name: 'bash', input: {} }]);
  ok(fs.existsSync(log.file), 'JSONL 文件已创建');
  ok(fs.readFileSync(log.file, 'utf8').trim().split('\n').length === 4, '追加式写入 4 条');

  const list = R.SessionLog.list(dir);
  ok(list.length === 1 && list[0].id === 'sess-1', '可列出会话');

  const cleaned = R.sanitizeHistoryForResume(R.SessionLog.load(log.file));
  const flat = JSON.stringify(cleaned);
  ok(!flat.includes('"u2"'), '未完成的 tool_use 被剥离');
  ok(flat.includes('"u1"'), '已完成的 tool_use/result 保留');
  ok(/'user'/.test(JSON.stringify(cleaned[cleaned.length - 1].role)) === false, '最后一条不是裸 user（注入了续跑指令后是 user 带指令）');
  ok(/Continue from where you left off/.test(flat), '末尾注入续跑指令');
}

console.log('\nA3) 确定性压缩：保留硬事实，缩短历史');
{
  const history = [
    { role: 'user', content: [{ type: 'text', text: '解题任务' }] },
    { role: 'assistant', content: [{ type: 'text', text: 'S 盒 @0xa00，CK 差分 0x1c1c1c1c，骨架 SM4' }] },
    { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'x', content: 'y'.repeat(5000) }] },
    { role: 'assistant', content: [{ type: 'text', text: '无关的过程描述' }] },
    { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'y', content: 'z'.repeat(5000) }] },
  ];
  for (let i = 0; i < 14; i++) history.push({ role: i % 2 ? 'assistant' : 'user', content: [{ type: 'text', text: 'filler ' + i }] });
  const before = R.estimateTokens(history);
  const out = R.compactHistoryDeterministic(history, 6);
  ok(!!out, '产生压缩结果');
  const after = R.estimateTokens(out);
  ok(after < before, `token 下降 ${before} → ${after}`);
  const flat = JSON.stringify(out);
  ok(flat.includes('0xa00') && flat.includes('SM4'), '硬事实（偏移/骨架）保留');
  ok(out[0].content[0].text === '解题任务', '首条任务保留');
  ok(out.length <= 8, `保留条数受限（${out.length}）`);
  ok(R.compactHistoryDeterministic([{ role: 'user', content: 'x' }], 6) === null, '短历史不压缩');
}

console.log('\nC1) 经验检索：结构化条目按标签命中');
{
  const exp = [
    '- [2026-10-01] SM4 变体 → 先看 CK 差分 → 直接读题目表',
    '- [technique] applies_to=SM4,AES | Rule: dword 数组 S 盒按 4 字节步长取低字节 | Why: C 里是 unsigned int[256] | How: 读表时 stride=4',
    '- [pitfall] applies_to=VM | Rule: 内存覆盖陷阱，必须按执行流更新输入缓冲 | Why: opcode 会写回 | How: 写模拟器而不是符号假设',
    '- [layout] applies_to=PE,loader | Rule: 内嵌载荷常在数据段 XOR 编码 | Why: 明文搜不到 MZ | How: 用 extract_payload',
  ].join('\n');

  const hit = R.rankExperience(exp, ['SM4', 'dword'], { limit: 3, maxChars: 600 });
  ok(/dword 数组/.test(hit), '命中 SM4/dword 的结构化条目');
  ok(!/内存覆盖陷阱/.test(hit), '不相关条目被排除');
  ok(hit.length <= 600, `输出受长度限制（${hit.length}）`);
  ok(/为什么：/.test(hit) && /怎么做：/.test(hit), '输出 Rule/Why/How 三段');

  const legacy = R.rankExperience(exp, ['CK'], { limit: 3 });
  ok(/SM4 变体/.test(legacy), '旧自由文本条目仍可命中');

  // 用一个不会出现在任何条目里的关键词（注意 applies_to/technique 这类结构词会命中格式本身）
  const none = R.rankExperience(exp, ['zzz-absent-keyword'], { limit: 3 });
  ok(none === '', '无命中时返回空串（不塞无关经验）');

  const parsed = R.parseExperienceLine('- [technique] applies_to=SM4 | Rule: r | Why: w | How: h');
  ok(parsed.kind === 'technique' && parsed.tags[0] === 'SM4' && parsed.rule === 'r', 'frontmatter 式条目解析正确');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
