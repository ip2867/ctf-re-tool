#!/usr/bin/env node
'use strict';

/**
 * kali_probe.py 实测结果 → decideDynDebugReadiness() 判定 的**端到端**一致性。
 *
 * 背景：测试单测 decideDynDebugReadiness 的每个分支（11 项），但从未验证
 * "真机探到的值喂进去会得出什么结论"。这两者脱节时，预检可能对一台
 * 明明可用的机器报 blocker（或反过来），而单测全绿。
 *
 * 做法：真跑 kali_probe.py --json，把 results 映射成 decideDynDebugReadiness 的入参，
 * 断言：探测 ok=true 时判定必须 ok，且 blockers 为空。
 * 若 SSH 不通（退出码 2）则跳过，不算失败。
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const { decideDynDebugReadiness } = require(path.join(ROOT, 'electron', 'kali-preflight.js'));

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  PASS ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n      ' + (e && e.message)); fail++; }
}
const skip = (name, why) => console.log('  SKIP ' + name + ' —— ' + why);

/** 跑探测并解析 JSON；返回 null 表示环境不可达 */
function probe() {
  try {
    const out = execFileSync('python', ['-I', '-X', 'utf8', path.join(ROOT, 'tests', 'kali_probe.py'), '--json'],
      { encoding: 'utf8', timeout: 180000 });
    return JSON.parse(out);
  } catch (e) {
    // 退出码 2 = 未配置/不可达，stdout 里仍可能有 JSON
    const txt = String((e.stdout || '')).trim();
    if (txt) { try { return JSON.parse(txt); } catch (_) { /* fall through */ } }
    return null;
  }
}

const r = probe();
if (!r) {
  skip('Kali 实测映射', '探测无输出（SSH 不通或未配置）');
  console.log(`\n结果: ${pass} 通过, ${fail} 失败（含跳过）`);
  if (fail > 0) process.exit(1);
  process.exit(0);
}

const byName = {};
for (const it of (r.results || [])) byName[it.name] = it;

console.log('=== Kali 实测 → 预检判定 一致性 ===');
console.log(`  host=${r.host}  probe.ok=${r.ok}  失败项=${(r.failed || []).join(',') || '(无)'}`);

// probe 的 results → decideDynDebugReadiness 的入参
const input = {
  reachable: true,
  ptraceWorks: byName.ptrace_attach ? byName.ptrace_attach.ok === true : undefined,
  ptraceScope: byName.ptrace_scope ? byName.ptrace_scope.value : undefined,
  hasGdb: byName.gdb ? byName.gdb.ok === true : undefined,
  hasGdbserver: byName.gdbserver ? byName.gdbserver.ok === true : undefined,
  probeTimedOut: false,
};
const d = decideDynDebugReadiness(input);

console.log('  映射入参: ' + JSON.stringify(input));
console.log('  判定结果: ok=' + d.ok + ' blockers=' + JSON.stringify(d.blockers) + ' warns=' + JSON.stringify(d.warns));

t('探测可用的机器 → 预检不得报 blocker', () => {
  if (r.ok !== true) { console.log('     （probe.ok 非 true，跳过该断言）'); return; }
  assert.strictEqual(d.ok, true, 'probe 说可用，预检却说不可用：' + JSON.stringify(d.blockers));
  assert.deepStrictEqual(d.blockers, [], 'blockers 必须为空');
});
t('ptrace 实测通过 → 不得因 scope 值误报', () => {
  if (!(byName.ptrace_attach && byName.ptrace_attach.ok)) { console.log('     （ptrace 未实测通过，跳过）'); return; }
  const noScope = decideDynDebugReadiness({ ...input, ptraceScope: undefined });
  assert.strictEqual(noScope.ok, true, 'scope 未知但 ptrace 实测通过时不应报 blocker');
  const badScope = decideDynDebugReadiness({ ...input, ptraceScope: '3' });
  assert.strictEqual(badScope.ok, true, 'ptrace 实测通过时，scope=3 也只应提示不应阻塞（实测优先）');
});
t('负向断言：把 ptrace 实测改成失败 → 判定必须翻转', () => {
  assert.strictEqual(d.ok, true, '前置条件：真机基线应判可用');
  const flipped = decideDynDebugReadiness({ ...input, ptraceWorks: false });
  assert.strictEqual(flipped.ok, false, 'ptrace 实测失败时 ok 必须为 false');
  assert.ok(flipped.blockers.length > 0, '必须有 blocker 说明');
});
t('负向断言：既无 gdb 也无 gdbserver → 必须报 blocker', () => {
  const noDbg = decideDynDebugReadiness({ ...input, hasGdb: false, hasGdbserver: false });
  assert.strictEqual(noDbg.ok, false, '两者都没有时不该判可用');
  assert.ok(noDbg.blockers.some((b) => /gdb/i.test(b)), 'blocker 应点名 gdb');
});
t('guidance 非空且可操作', () => {
  assert.ok(typeof d.guidance === 'string' || Array.isArray(d.guidance), 'guidance 缺失');
  const txt = Array.isArray(d.guidance) ? d.guidance.join('\n') : d.guidance;
  assert.ok(txt.trim().length > 0, 'guidance 为空');
});

// 与 probe 自身的 ok 字段交叉核对（两套判据不一致时必有一方错）
t('probe.ok 与 预检.ok 结论一致', () => {
  const probeOk = r.ok === true;
  assert.strictEqual(d.ok, probeOk,
    `两套判据不一致：probe.ok=${probeOk} 预检.ok=${d.ok}（blockers=${JSON.stringify(d.blockers)}）`);
});

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
if (fail > 0) process.exit(1);
